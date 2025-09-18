import ssl
import pg8000.native as pg
import json

def get_db_connection():
    ssl_context = ssl.create_default_context()
    return pg.Connection(
        user="bngx_o9tu_user",
        password="D8kA9EfmAiXmGze6OCqLOWaaMuA7KbBo",
        host="dpg-d35ndpbipnbc739k2lhg-a.oregon-postgres.render.com",
        port=5432,
        database="bngx_o9tu",
        ssl_context=ssl_context
    )

# --- Accounts ---
def create_accounts_table():
    conn = get_db_connection()
    conn.run('''
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            uid BIGINT UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            nickname VARCHAR(255) DEFAULT ''
        );
    ''')
    conn.close()

def get_all_accounts():
    conn = get_db_connection()
    rows = conn.run('SELECT * FROM accounts;')
    cols = [col["name"] for col in conn.columns]
    accounts = [dict(zip(cols, row)) for row in rows]
    conn.close()
    return accounts

def get_account_by_id(account_id):
    conn = get_db_connection()
    rows = conn.run('SELECT * FROM accounts WHERE id = :id;', id=account_id)
    cols = [col["name"] for col in conn.columns]
    account = dict(zip(cols, rows[0])) if rows else None
    conn.close()
    return account

def update_account_nickname(account_id, nickname):
    conn = get_db_connection()
    conn.run('UPDATE accounts SET nickname = :nickname WHERE id = :id;', nickname=nickname, id=account_id)
    conn.close()

def add_account(uid, password, nickname=''):
    conn = get_db_connection()
    conn.run('''
        INSERT INTO accounts (uid, password, nickname)
        VALUES (:uid, :password, :nickname)
        ON CONFLICT (uid) DO NOTHING;
    ''', uid=int(uid), password=password, nickname=nickname)
    conn.close()

def insert_accounts_from_json(json_file_path):
    with open(json_file_path, 'r') as f:
        accounts_list = json.load(f)

    conn = get_db_connection()
    for account in accounts_list:
        uid, password = account
        conn.run('''
            INSERT INTO accounts (uid, password, nickname)
            VALUES (:uid, :password, :nickname)
            ON CONFLICT (uid) DO NOTHING;
        ''', uid=int(uid), password=password, nickname='')
    conn.close()
    print(f"✅ تم إدخال حسابات من {json_file_path} إلى قاعدة البيانات.")

# --- Friends ---
def create_friends_table():
    conn = get_db_connection()
    conn.run('''
        CREATE TABLE IF NOT EXISTS account_friends (
            id SERIAL PRIMARY KEY,
            account_id INT NOT NULL,
            friend_uid BIGINT NOT NULL,
            days INT DEFAULT 0,
            UNIQUE(account_id, friend_uid)
        );
    ''')
    conn.close()

def add_friend_to_db(account_id, friend_uid, days=0):
    conn = get_db_connection()
    conn.run('''
        INSERT INTO account_friends (account_id, friend_uid, days)
        VALUES (:account_id, :friend_uid, :days)
        ON CONFLICT (account_id, friend_uid) DO UPDATE SET days=:days;
    ''', account_id=int(account_id), friend_uid=int(friend_uid), days=int(days))
    conn.close()

def remove_friend_from_db(account_id, friend_uid):
    conn = get_db_connection()
    conn.run('DELETE FROM account_friends WHERE account_id=:account_id AND friend_uid=:friend_uid;',
             account_id=int(account_id), friend_uid=int(friend_uid))
    conn.close()

def get_friends_by_account(account_id):
    conn = get_db_connection()
    rows = conn.run('SELECT friend_uid FROM account_friends WHERE account_id=:account_id;', account_id=int(account_id))
    friends = [row[0] for row in rows]
    conn.close()
    return friends
# --- Admin Users ---
def create_admin_users_table():
    conn = get_db_connection()
    conn.run('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        );
    ''')
    conn.close()

def add_admin_user(username, password):
    conn = get_db_connection()
    conn.run('''
        INSERT INTO admin_users (username, password)
        VALUES (:username, :password)
        ON CONFLICT (username) DO NOTHING;
    ''', username=username, password=password)
    conn.close()

def get_all_admins():
    conn = get_db_connection()
    rows = conn.run('SELECT * FROM admin_users;')
    cols = [col["name"] for col in conn.columns]
    admins = [dict(zip(cols, row)) for row in rows]
    conn.close()
    return admins
    

from flask import Flask, request, jsonify, render_template, redirect, session, url_for
import time, secrets, re, threading, requests, random, ssl
from functools import wraps
from collections import defaultdict
from flask_caching import Cache
import pg8000.native as pg
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# إعداد التخزين المؤقت
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 دقائق
cache = Cache(app)

lock = threading.Lock()

# -------------------- DATABASE --------------------
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
    hashed_pw = generate_password_hash(password)
    conn.run('''
        INSERT INTO admin_users (username, password)
        VALUES (:username, :password)
        ON CONFLICT (username) DO NOTHING;
    ''', username=username, password=hashed_pw)
    conn.close()

def get_all_admins():
    conn = get_db_connection()
    rows = conn.run('SELECT id, username FROM admin_users;')
    cols = [col["name"] for col in conn.columns]
    admins = [dict(zip(cols, row)) for row in rows]
    conn.close()
    return admins

def verify_admin_login(username, password):
    conn = get_db_connection()
    rows = conn.run('SELECT password FROM admin_users WHERE username=:username;', username=username)
    conn.close()
    if rows:
        return check_password_hash(rows[0][0], password)
    return False

# إنشاء الجداول عند بدء التطبيق
create_accounts_table()
create_friends_table()
create_admin_users_table()

# -------------------- SECURITY --------------------
S1X_PROTECTION_CONFIG = {
    'enabled': True,
    'max_attempts': 3,
    'block_duration': 15,
    'challenge_timeout': 300,
    'ddos_threshold': 10,
    'session_timeout': 1800,
    'suspicious_patterns': [
        r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
        r'python', r'java', r'php', r'perl', r'ruby', r'node',
        r'automated', r'script', r'tool', r'scanner', r'test'
    ]
}

verification_sessions = {}
failed_challenges = defaultdict(int)
ddos_tracker = defaultdict(lambda: defaultdict(int))
suspicious_ips = defaultdict(list)

# --- Helpers ---
def get_client_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', '')

def is_bot_user_agent(user_agent):
    if not user_agent: return True
    ua = user_agent.lower()
    for pattern in S1X_PROTECTION_CONFIG['suspicious_patterns']:
        if re.search(pattern, ua): return True
    known_browsers = ['mozilla', 'webkit', 'chrome', 'firefox', 'safari', 'edge']
    return not any(browser in ua for browser in known_browsers)

def analyze_request_pattern(ip, endpoint, headers):
    current_time = int(time.time())
    with lock:
        ddos_tracker[ip][current_time] += 1
        old_ticks = [t for t in ddos_tracker[ip] if current_time - t > 60]
        for t in old_ticks: del ddos_tracker[ip][t]

        recent_requests = sum(ddos_tracker[ip].values())
        suspicious_indicator = 0
        if is_bot_user_agent(headers.get('User-Agent', '')): suspicious_indicator += 2
        essential_headers = ['Accept', 'Accept-Language', 'Accept-Encoding']
        missing_headers = sum(1 for h in essential_headers if h not in headers)
        suspicious_indicator += missing_headers
        if not headers.get('Referer') and endpoint not in ['/', '/security/challenge', '/admin/login', '/admin/authenticate']:
            suspicious_indicator += 1
        if recent_requests > 15: suspicious_indicator += 2
        if recent_requests > S1X_PROTECTION_CONFIG['ddos_threshold']:
            return 'ddos_detected'
        if suspicious_indicator >= 5:
            suspicious_ips[ip].append({'time': current_time, 'endpoint': endpoint, 'ua': headers.get('User-Agent', '')})
            return 'suspicious_activity'
    return 'normal'

def should_challenge_request(ip, user_agent, endpoint):
    if not S1X_PROTECTION_CONFIG['enabled']: 
        return False
    session_data = verification_sessions.get(ip)
    session_timeout = S1X_PROTECTION_CONFIG.get('session_timeout', 1800)
    if session_data:
        if session_data.get('captcha_verified', False) and (time.time() - session_data.get('verified_at', 0)) < session_timeout:
            return False
        else:
            verification_sessions.pop(ip, None)
    return True

def verify_challenge_token(token, ip):
    return True

def protection_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = get_client_ip()
        ua = request.headers.get('User-Agent', '')
        endpoint = request.path
        analysis = analyze_request_pattern(ip, endpoint, request.headers)
        if analysis == 'ddos_detected':
            return jsonify({"success": False, "error": "DDoS protection activated"}), 429
        if analysis == 'suspicious_activity' or should_challenge_request(ip, ua, endpoint):
            token = request.headers.get('X-Verification-Token')
            if token and verify_challenge_token(token, ip):
                verification_sessions[ip] = {'captcha_verified': True, 'verified_at': time.time(), 'user_agent': ua}
                return f(*args, **kwargs)
            else:
                return redirect(url_for('security_challenge'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('admin_logged_in'):
            return f(*args, **kwargs)
        return redirect(url_for('admin_login'))
    return decorated

def generate_captcha_challenge():
    op = random.choice(['+', '-'])
    if op == '+': n1, n2 = random.randint(1,50), random.randint(1,50); answer = n1+n2
    else: n1, n2 = random.randint(20,70), random.randint(1,20); answer = n1-n2
    session['captcha_answer'] = answer
    return f"{n1} {op} {n2}"

# -------------------- SECURITY ROUTES --------------------
@app.route('/api/security/generate-challenge')
def generate_challenge(): 
    return jsonify({"question": generate_captcha_challenge()})

@app.route('/api/security/verify-human', methods=['POST'])
def verify_human():
    user_answer = request.json.get('answer')
    ip = get_client_ip()
    try: user_answer = int(user_answer)
    except: return jsonify({"success": False, "message": "الإجابة يجب أن تكون رقم"}), 400
    stored_answer = session.get('captcha_answer')
    if stored_answer is None: return jsonify({"success": False, "message": "التحدي غير موجود"}), 400
    if user_answer == stored_answer:
        verification_sessions[ip] = {'captcha_verified': True, 'verified_at': time.time()}
        session.pop('captcha_answer', None)
        failed_challenges[ip] = 0
        return jsonify({"success": True, "message": "تم التحقق بنجاح"})
    failed_challenges[ip] += 1
    if failed_challenges[ip] >= S1X_PROTECTION_CONFIG['max_attempts']:
        return jsonify({"success": False, "message": "تجاوزت عدد المحاولات. سيتم حظرك مؤقتًا."}), 403
    return jsonify({"success": False, "message": "إجابة غير صحيحة، حاول مرة أخرى"})

@app.route('/security/challenge')
def security_challenge(): 
    return render_template('captcha.html')

# -------------------- ADMIN LOGIN --------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    ip = get_client_ip()
    if not verification_sessions.get(ip, {}).get('captcha_verified'):
        return redirect(url_for('security_challenge'))
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        if verify_admin_login(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            verification_sessions[ip]['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error="اسم المستخدم أو كلمة المرور خاطئة")
    return render_template('admin_login.html')

# -------------------- ADMIN DASHBOARD --------------------
@app.route('/admin/dashboard')
@protection_required
@admin_required
def admin_dashboard():
    admins = get_all_admins()
    return render_template('admin_dashboard.html', admins=admins)

@app.route('/admin/create_user', methods=['POST'])
@protection_required
@admin_required
def admin_create_user():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"success": False, "message": "يجب إدخال اسم المستخدم وكلمة المرور"})
    try:
        add_admin_user(username, password)
        return jsonify({"success": True, "message": "تم إنشاء المستخدم بنجاح"})
    except Exception as e:
        return jsonify({"success": False, "message": f"خطأ داخلي: {str(e)}"})

# -------------------- MAIN ROUTE --------------------
@app.route('/')
@protection_required
@admin_required
def index():
    accounts = get_all_accounts()
    nicknames = {str(acc['id']): acc['nickname'] for acc in accounts}

    registered_uids = {}
    try:
        response = requests.get("https://time-bngx-0c2h.onrender.com/api/list_uids", timeout=10)
        response.raise_for_status()
        api_data = response.json()
        registered_uids = api_data.get("uids", {})
    except Exception as e:
        print("Error fetching API:", e)

    return render_template(
        'index.html',
        nicknames=nicknames,
        registeredUIDs=registered_uids
    )

# -------------------- CREATE / UPDATE ACCOUNT --------------------
@app.route('/api/create_account', methods=['POST'])
@protection_required
@admin_required
def create_account():
    data = request.json or {}
    account_id, nickname = data.get('account_id'), data.get('nickname')
    if not account_id or not nickname: return jsonify({"success": False, "message": "يجب تحديد الحساب والاسم الجديد"}), 400
    account = get_account_by_id(account_id)
    if not account: return jsonify({"success": False, "message": "الحساب المختار غير صحيح"}), 400

    uid, password = account['uid'], account['password']
    try:
        token_res = requests.get(f"https://jwt-silk-xi.vercel.app/api/oauth_guest?uid={uid}&password={password}", timeout=5).json()
        token = token_res.get('token')
        if not token: return jsonify({"success": False, "message": "فشل في الحصول على التوكن من API"}), 500

        nick_res = requests.get(f"https://change-name-gray.vercel.app/lvl_up/api/nickname?jwt_token={token}&nickname={nickname}", timeout=5).json()
        if nick_res.get('success', False):
            update_account_nickname(account_id, nickname)
            return jsonify({"success": True, "message": "تم تغيير الاسم بنجاح", "nicknames": {str(account_id): nickname}})
        return jsonify({"success": False, "message": nick_res.get('message', "تم اضافة الحساب ")})
    except Exception as e:
        return jsonify({"success": False, "message": f"خطأ داخلي: {str(e)}"}), 500

# -------------------- FRIEND MANAGEMENT --------------------
@app.route('/api/add_friend', methods=['POST'])
@protection_required
@admin_required
def add_friend():
    data = request.json or {}
    account_id = data.get('account_id')
    friend_uid = data.get('friend_uid')
    days = data.get('days', 0)

    if not account_id or not friend_uid:
        return jsonify({"success": False, "message": "يجب تحديد الحساب والـ UID لإضافة الصديق"}), 400

    account = get_account_by_id(account_id)
    if not account:
        return jsonify({"success": False, "message": "الحساب المختار غير صحيح"}), 400

    uid = account['uid']
    password = account['password']

    try:
        oauth_url = f"https://jwt-silk-xi.vercel.app/api/oauth_guest?uid={uid}&password={password}"
        oauth_response = requests.get(oauth_url, timeout=5)
        oauth_response.raise_for_status()
        token = oauth_response.json().get('token')
        if not token:
            return jsonify({"success": False, "message": "فشل في الحصول على التوكن"}), 500

        add_url = f"https://add-friend-weld.vercel.app/add_friend?token={token}&uid={friend_uid}"
        add_response = requests.get(add_url, timeout=5)
        add_response.raise_for_status()
        add_data = add_response.json()

        if add_data.get('status') == 'success':
            add_friend_to_db(account_id, friend_uid, days=days)
            cache.delete('index_page')
            return jsonify({"success": True, "message": "تمت إضافة الصديق بنجاح"})
        else:
            error_msg = add_data.get('message', "فشل في إضافة الصديق")
            return jsonify({"success": False, "message": error_msg})
    except Exception as e:
        return jsonify({"success": False, "message": f"خطأ داخلي: {str(e)}"}), 500

@app.route('/api/remove_friend', methods=['POST'])
@protection_required
@admin_required
def remove_friend():
    data = request.json or {}
    account_id = data.get('account_id')
    friend_uid = data.get('friend_uid')

    if not account_id or not friend_uid:
        return jsonify({"success": False, "message": "يرجى تحديد الحساب وUID الصديق"}), 400

    account = get_account_by_id(account_id)
    if not account:
        return jsonify({"success": False, "message": "الحساب غير موجود"}), 400

    try:
        remove_url = f"https://time-bngx-0c2h.onrender.com/api/remove_uid?uid={friend_uid}"
        remove_response = requests.get(remove_url, timeout=5)
        remove_response.raise_for_status()
        remove_data = remove_response.json()

        if remove_data.get('success', False):
            remove_friend_from_db(account_id, friend_uid)
            cache.delete('index_page')
            return jsonify({"success": True, "message": "تم حذف الصديق بنجاح"})
        return jsonify({"success": False, "message": "فشل في حذف الصديق"})
    except Exception as e:
        return jsonify({"success": False, "message": f"خطأ داخلي: {str(e)}"}), 500

# -------------------- RUN APP --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

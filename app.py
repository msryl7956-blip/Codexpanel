from flask import Flask, request, jsonify, render_template, redirect, session, url_for
import time, secrets, re, threading, requests, random
from functools import wraps
from collections import defaultdict
from flask_caching import Cache

from db import (
    create_accounts_table, create_friends_table, get_all_accounts, get_account_by_id,
    update_account_nickname, add_account, add_friend_to_db, get_friends_by_account, get_db_connection
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# إعداد التخزين المؤقت
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 دقائق
cache = Cache(app)

# إنشاء الجداول إذا لم تكن موجودة
create_accounts_table()
create_friends_table()

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
lock = threading.Lock()

ADMIN_CREDENTIALS = {"bHLM": "bHLM"}

# --- Helper Functions ---
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
    if not S1X_PROTECTION_CONFIG['enabled']: return False
    session_data = verification_sessions.get(ip)
    session_timeout = S1X_PROTECTION_CONFIG.get('session_timeout', 1800)
    if session_
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

# --- Admin & Security Routes ---
@app.route('/api/security/generate-challenge')
def generate_challenge(): return jsonify({"question": generate_captcha_challenge()})

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
def security_challenge(): return render_template('captcha.html')

@app.route('/admin/login')
def admin_login():
    ip = get_client_ip()
    if not verification_sessions.get(ip, {}).get('captcha_verified'):
        return redirect(url_for('security_challenge'))
    return render_template('admin_login.html')

@app.route('/admin/authenticate', methods=['POST'])
def admin_authenticate():
    ip = get_client_ip()
    if not verification_sessions.get(ip, {}).get('captcha_verified'):
        return jsonify({"success": False, "message": "يجب تجاوز التحقق الأمني"}), 403
    data = request.json or {}
    username, password = data.get('username'), data.get('password')
    if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
        session['admin_logged_in'] = True
        session['admin_username'] = username
        verification_sessions[ip]['admin_logged_in'] = True
        return jsonify({"success": True, "session_id": secrets.token_hex(16)})
    return jsonify({"success": False, "message": "اسم المستخدم أو كلمة المرور غير صحيحة"})

# --- Main Routes ---

@app.route('/')
@protection_required
@admin_required
def index():
    accounts = get_all_accounts()
    nicknames = {str(acc['id']): acc['nickname'] for acc in accounts}

    registered_uids = {}

    try:
        response = requests.get("https://time-bngx-0c2h.onrender.com/api/list_uids", timeout=10)
        print("API status:", response.status_code)  # DEBUG
        print("API text:", response.text[:500])     # DEBUG (أول 500 كاركتر)
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




# --- Create / Update Account Name ---
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

# --- Add Friend ---
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

            # حذف الكاش لتحديث الصفحة في الزيارات التالية
            cache.delete('index_page')

            if days:
                try:
                    api_url = f"https://time-bngx-0c2h.onrender.com/api/add_uid?uid={friend_uid}&time={days}&type=days&permanent=false"
                    external_resp = requests.get(api_url, timeout=5)
                    external_resp.raise_for_status()
                    external_data = external_resp.json()
                    if external_data.get('success') or external_data.get('message'):
                        return jsonify({"success": True, "message": "تمت إضافة الصديق بنجاح وتم إرسال عدد الأيام بنجاح."})
                    else:
                        return jsonify({"success": True, "message": "تمت إضافة الصديق بنجاح ولكن حدث خطأ في إرسال عدد الأيام."})
                except Exception as e:
                    return jsonify({"success": True, "message": f"تمت إضافة الصديق بنجاح لكن حدث خطأ أثناء إرسال عدد الأيام: {str(e)}"})
            else:
                return jsonify({"success": True, "message": "تمت إضافة الصديق بنجاح"})
        else:
            error_msg = add_data.get('message', "فشل في إضافة الصديق")
            return jsonify({"success": False, "message": error_msg})
    except Exception as e:
        return jsonify({"success": False, "message": f"خطأ داخلي: {str(e)}"}), 500

# --- Remove Friend (using new API without token) ---
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
            # إزالة من قاعدة البيانات محلياً أيضاً
            conn = get_db_connection()
            conn.run('DELETE FROM account_friends WHERE friend_uid = :friend_uid AND account_id = :account_id;',
                     friend_uid=int(friend_uid), account_id=int(account_id))
            conn.close()

            # حذف الكاش لتحديث الصفحة
            cache.delete('index_page')

            return jsonify({"success": True, "message": "تمت إزالة الصديق بنجاح"})
        else:
            return jsonify({"success": False, "message": remove_data.get('message', "فشل إزالة الصديق")})
    except Exception as e:
        return jsonify({"success": False, "message": f"خطأ داخلي: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)

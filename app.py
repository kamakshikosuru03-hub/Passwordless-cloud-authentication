from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from core.crypto_engine import derive_keys_fuzzy, reproduce_key_fuzzy, sign_challenge, verify_challenge, generate_visual_id
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from flask_mail import Mail, Message  # Added for Email Alerts
import json, os, uuid, datetime, time

app = Flask(__name__)
app.secret_key = "secure_ecc_vault_key_2026"

# --- UPDATED EMAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465                  # Changed to SSL Port
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True                  # Enabled SSL
app.config['MAIL_USERNAME'] = 'penkijyothi2004@gmail.com'  # REPLACE WITH YOUR ACTUAL GMAIL
app.config['MAIL_PASSWORD'] = 'uaactsxphtmlkaxt'      # YOUR 16-CHAR CODE (NO SPACES)
mail = Mail(app)

# --- DYNAMIC PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, 'database.json'))
UPLOAD_FOLDER = os.path.normpath(os.path.join(BASE_DIR, 'vault_storage'))
LOG_PATH = os.path.normpath(os.path.join(BASE_DIR, 'admin_logs.json'))

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- DATABASE & LOG HELPERS ---
def get_db():
    if not os.path.exists(DB_PATH): return {}
    with open(DB_PATH, 'r') as f:
        try:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
        except: return {}

def set_db(data):
    with open(DB_PATH, 'w') as f:
        json.dump(data, f, indent=4)

def add_admin_log(username, action, status, proof="N/A"):
    logs = []
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, 'r') as f: logs = json.load(f)
        except: logs = []
    
    logs.append({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "action": action,
        "status": status,
        "proof": proof
    })
    with open(LOG_PATH, 'w') as f: json.dump(logs, f, indent=4)

# --- SECURITY MAIL HELPER ---
def send_security_mail(subject, recipient_email, user_name, status):
    now = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    sender_identity = f"BioCrypt Cloud Vault <{app.config['MAIL_USERNAME']}>"
    msg = Message(subject, sender=sender_identity, recipients=[recipient_email])
    
    if status == "registration":
        msg.body = (f"Hello {user_name},\n\n"
                    f"Welcome to BioCrypt Vault. Your account was created on {now}.\n"
                    f"Your identity is now protected by ECC (Elliptic Curve Cryptography).\n\n"
                    f"Secure ID: {uuid.uuid4().hex[:8].upper()}")
                    
    elif status == "success":
        msg.body = (f"Hello {user_name},\n\n"
                    f"SUCCESS: Biometric match confirmed. New login detected.\n"
                    f"Date/Time: {now}\n\n"
                    f"If this was not you, please secure your biometric vault immediately.")
                    
    elif status == "fail":
        msg.body = (f"CRITICAL ALERT: Biometric Mismatch Detected!\n\n"
                    f"An unauthorized attempt to access the vault for {user_name} was blocked.\n"
                    f"Date/Time: {now}\n"
                    f"Action: Replay protection active. Account locked.")

    try:
        mail.send(msg)
        print(f"[*] Security email sent to {recipient_email}")
    except Exception as e:
        print(f"[!] SMTP Error: {e}")
        add_admin_log("SYSTEM", "Email Delivery Failure", "Failed", proof=str(e)[:50])

# --- UPDATED WEB NAVIGATION ROUTES ---

@app.route('/')
def index(): 
    """NEW Landing page with Register/Login buttons"""
    return render_template('index.html')

@app.route('/register_page')
def registration_page(): 
    """Moved original registration logic here"""
    return render_template('register.html')

@app.route('/login_page')
def login_view(): 
    return render_template('login.html')

@app.route('/audit_screen')
def audit_view():
    if 'audit_user' not in session: return redirect(url_for('login_view'))
    return render_template('audit.html', user=session['audit_user'])

@app.route('/admin')
def admin_view(): 
    logs = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, 'r') as f: logs = json.load(f)
    return render_template('admin.html', logs=reversed(logs))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('login_view'))
    return render_template('dashboard.html', user=session['user'])

# --- HELPER: KEY NORMALIZATION ---
def get_raw_key(pem_string):
    if not pem_string: return ""
    clean = pem_string.replace("-----BEGIN PUBLIC KEY-----", "")
    clean = clean.replace("-----END PUBLIC KEY-----", "")
    clean = clean.replace("\\n", "").replace("\\r", "")
    clean = "".join(clean.split())
    return clean.strip()

# --- BIOMETRIC CORE API ---
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    bio = data.get('biometric_data')
    full_name = data.get('full_name', 'User')
    email = data.get('email', '')
    phone = data.get('phone', '')
    age = data.get('age', '')
    dob = data.get('dob', '')

    if not username or not bio or not email: 
        return jsonify({"status": "Error", "reason": "Missing required details"}), 400
        
    db = get_db()
    if username in db: 
        return jsonify({"status": "Error", "reason": "Username already exists"}), 400
        
    try:
        priv, pub, helper = derive_keys_fuzzy(bio)
        visual_sig = generate_visual_id(priv, username)
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Store as both primary 'public_key' and in 'public_keys' list for multi-finger support
        db[username] = {
            "full_name": full_name, "email": email, "phone": phone, "age": age, "dob": dob,
            "public_key": pub, 
            "public_keys": [pub], # Support for multiple fingers
            "private_key": priv_bytes.hex(), "helper_data": helper.hex(), 
            "vault": [], "role": "admin" if username.lower() == 'admin' else "user",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        set_db(db)
        add_admin_log(username, "Registration", "Success", proof=f"Sig: {visual_sig[:16]}...")
        send_security_mail("Welcome to ECC Vault", email, full_name, "registration")
        return jsonify({"status": "Success", "public_key": pub, "visual_signature": visual_sig})
    except Exception as e: 
        return jsonify({"status": "Error", "reason": str(e)}), 400

@app.route('/get_user_details', methods=['POST'])
def get_user_details():
    data = request.json
    username = data.get('username', '').strip()
    provided_key = get_raw_key(data.get('public_key', ''))
    db = get_db()
    user = db.get(username)
    
    if user:
        # Check against all registered keys to support wounded finger scenario
        registered_keys = user.get('public_keys', [user.get('public_key')])
        if any(get_raw_key(k) == provided_key for k in registered_keys):
            return jsonify({
                "status": "success", "name": user.get('full_name', username),
                "email": user.get('email', 'N/A'), "cloud_id": f"CLOUD-NODE-{username[:3].upper()}"
            })
    return jsonify({"status": "error", "message": "Identity Verification Failed"}), 404

@app.route('/verify_match', methods=['POST'])
def verify_match():
    data = request.json
    username = data.get('username', '').strip()
    bio = data.get('biometric_data')
    provided_pub_pem = data.get('public_key', '').strip()
    
    now = time.time()
    lockout_until = session.get('lockout_until', 0)
    if now < lockout_until:
        remaining = int(lockout_until - now)
        return jsonify({"status": "Locked", "reason": f"Too many failed attempts. Wait {remaining}s."}), 403

    db = get_db()
    user = db.get(username)
    if not user: return jsonify({"status": "Error", "reason": "User not found"}), 404

    # Verification against list of keys
    registered_keys = user.get('public_keys', [user.get('public_key')])
    if get_raw_key(provided_pub_pem) not in [get_raw_key(k) for k in registered_keys]:
        add_admin_log(username, "Access Denied", "Identity Mismatch", proof="Incorrect Public Key")
        send_security_mail("Security Alert: Unauthorized Access", user['email'], user['full_name'], "fail")
        return jsonify({"status": "Error", "reason": "Security Alert: Public key mismatch."}), 401
    
    try:
        helper = bytes.fromhex(user['helper_data'])
        priv = reproduce_key_fuzzy(bio, helper, threshold=5000)
        
        session['failed_attempts'] = 0
        session['lockout_until'] = 0
        
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        session['audit_user'] = username
        session['temp_priv_hex'] = priv_bytes.hex()
        
        add_admin_log(username, "Key Reconstruction", "Matched")
        return jsonify({"status": "Matched", "redirect": "/audit_screen"})

    except Exception as e:
        attempts = session.get('failed_attempts', 0) + 1
        session['failed_attempts'] = attempts
        if attempts >= 3:
            session['lockout_until'] = time.time() + 10
            session['failed_attempts'] = 0
            add_admin_log(username, "Security Alert", "Locked", proof="3 Failed Attempts")
            send_security_mail("Security Alert: Account Locked", user['email'], user['full_name'], "fail")
            return jsonify({"status": "Locked", "reason": "3 Failed attempts. System locked for 10 seconds."}), 403

        add_admin_log(username, "Key Reconstruction", "Failed", proof=f"Attempt {attempts}/3")
        return jsonify({"status": "Error", "reason": f"Biometric mismatch. Attempt {attempts}/3"}), 401

@app.route('/verify_key_integrity', methods=['POST'])
def verify_key_integrity():
    if 'audit_user' not in session or 'temp_priv_hex' not in session:
        return jsonify({"status": "Error", "reason": "No active biometric session"}), 401
    
    username = session['audit_user']
    db = get_db()
    user_data = db.get(username)
    
    reconstructed_hex = session.get('temp_priv_hex')
    stored_hex = user_data.get('private_key')
    
    if reconstructed_hex == stored_hex:
        return jsonify({
            "status": "Verified",
            "reconstructed_snippet": reconstructed_hex[200:235] + "...",
            "stored_snippet": stored_hex[200:235] + "..."
        })
    return jsonify({"status": "Mismatch", "reason": "Key reconstruction integrity check failed."})

@app.route('/verify_ecdsa', methods=['POST'])
def verify_ecdsa():
    data = request.json or {}
    username = data.get('username')
    priv_hex = session.get('temp_priv_hex')
    
    if not username or not priv_hex: 
        return jsonify({"status": "Error", "reason": "Session expired or User ID missing."}), 401
    
    db = get_db()
    user = db.get(username)
    
    if not user:
        return jsonify({"status": "Error", "reason": "User not found in database."}), 404

    try:
        priv_bytes = bytes.fromhex(priv_hex)
        priv = serialization.load_pem_private_key(priv_bytes, password=None)
        
        visual_sig = generate_visual_id(priv, username)
        challenge = str(uuid.uuid4())
        signature = sign_challenge(priv, challenge)
        
        # Verify using primary stored public key
        if verify_challenge(user['public_key'], challenge, signature):
            session['user'] = username
            session.pop('temp_priv_hex', None)
            session.pop('audit_user', None)
            session['failed_attempts'] = 0
            
            add_admin_log(username, "ECDSA Signature", "Verified", proof=f"Verified Sig Match: {visual_sig[:16]}...")
            send_security_mail("New Login Detected", user['email'], user['full_name'], "success")
            return jsonify({"status": "Verified", "visual_signature": visual_sig})
        else:
            raise Exception("Signature verification failed")
            
    except Exception as e:
        add_admin_log(username, "ECDSA Signature", "Failed", proof=str(e)[:50])
        return jsonify({"status": "Error", "reason": "Cryptographic signature verification failed"}), 401

@app.route('/admin/users')
def admin_users():
    db = get_db()
    return jsonify([{"username": u, "role": db[u].get('role', 'user')} for u in db])

@app.route('/get_admin_logs')
def get_admin_logs():
    if not os.path.exists(LOG_PATH): return jsonify([])
    with open(LOG_PATH, 'r') as f:
        try: return jsonify(json.load(f))
        except: return jsonify([])

@app.route('/admin/action', methods=['POST'])
def admin_action():
    data = request.json
    username, action = data.get('username'), data.get('action')
    db = get_db()
    if action == 'remove' and username in db:
        del db[username]
        set_db(db)
        add_admin_log("SYSTEM", f"Deleted: {username}", "Success")
        return jsonify({"status": "Success"})
    return jsonify({"status": "Error"}), 400

@app.route('/admin/clear_logs', methods=['POST'])
def clear_logs():
    with open(LOG_PATH, 'w') as f: json.dump([], f)
    return jsonify({"status": "Success"})

@app.route('/get_vault')
def get_vault():
    user = session.get('user')
    if not user: return jsonify([])
    return jsonify(get_db().get(user, {}).get('vault', []))

@app.route('/view/<filename>')
@app.route('/download/<filename>')
def serve_vault_file(filename):
    if 'user' not in session: return redirect(url_for('login_view'))
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'user' not in session: return jsonify({"status": "Error"}), 401
    file = request.files.get('file')
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        db = get_db()
        db[session['user']]['vault'].append({"type": "File", "name": filename, "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")})
        set_db(db)
        return jsonify({"status": "Success"})
    return jsonify({"status": "Error"}), 400

@app.route('/add_note', methods=['POST'])
def add_note():
    if 'user' not in session: return jsonify({"status": "Error"}), 401
    note_content = request.json.get('note')
    if not note_content: return jsonify({"status": "Error"}), 400
    db = get_db()
    db[session['user']]['vault'].append({
        "type": "Note", "name": note_content[:20] + "...", "content": note_content,
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    })
    set_db(db)
    return jsonify({"status": "Success"})

@app.route('/delete_item', methods=['POST'])
def delete_item():
    if 'user' not in session: return jsonify({"status": "Error"}), 401
    idx = request.json.get('index')
    username = session['user']
    db = get_db()
    vault = db.get(username, {}).get('vault', [])
    if 0 <= idx < len(vault):
        item = vault.pop(idx)
        if item['type'] == 'File':
            try: os.remove(os.path.join(UPLOAD_FOLDER, item['name']))
            except: pass
        db[username]['vault'] = vault
        set_db(db)
        return jsonify({"status": "Success"})
    return jsonify({"status": "Error"}), 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index')) # Redirect back to index landing page

if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
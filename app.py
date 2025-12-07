import os
import secrets
import requests  # <--- NEW DEPENDENCY
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

# --- DATABASE CONFIG ---
DB_URL = os.environ.get("DATABASE_URL")
if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DB_URL)
else:
    engine = create_engine("sqlite:///temp.db")

def init_db():
    with engine.connect() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS licenses (key_code TEXT PRIMARY KEY, status TEXT DEFAULT 'unused', duration_hours INT DEFAULT 24)"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS active_sessions (user_email TEXT PRIMARY KEY, expires_at TIMESTAMP)"))
        conn.commit()
init_db()

@app.route('/')
def home(): return "Secure License Server Online"

@app.route('/admin/create', methods=['POST'])
def create_key_api():
    key = secrets.token_hex(8)
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO licenses (key_code) VALUES (:k)"), {"k": key})
        conn.commit()
    return jsonify({"key": key})

# --- NEW: SECURE TOKEN VERIFICATION ---
def verify_google_token(token):
    try:
        # Ask Google who owns this token
        url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={token}"
        resp = requests.get(url)
        
        if resp.status_code == 200:
            data = resp.json()
            # Return the verified email
            return data.get('email')
    except:
        pass
    return None

@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    token = data.get('token')       # <--- WE READ TOKEN NOW
    provided_key = data.get('key')

    if not token:
        return jsonify({"authorized": False, "error": "Authentication Token Missing"}), 400

    # 1. VERIFY TOKEN WITH GOOGLE (Server-Side)
    email = verify_google_token(token)
    
    if not email:
        return jsonify({"authorized": False, "error": "Invalid or Expired Google Token"}), 401

    # 2. PROCEED WITH AUTHORIZATION USING VERIFIED EMAIL
    with engine.connect() as conn:
        # Check active session
        session = conn.execute(text("SELECT expires_at FROM active_sessions WHERE user_email = :e"), {"e": email}).fetchone()
        
        if session:
            expires_at = session[0]
            if isinstance(expires_at, str): expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                return jsonify({"authorized": True, "message": f"Welcome back, {email}"})
            else:
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # If no session, check Key
        if not provided_key:
            return jsonify({"authorized": False, "error": f"Session expired for {email}. Key required."}), 401

        row = conn.execute(text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"), {"k": provided_key}).fetchone()

        if not row: return jsonify({"authorized": False, "error": "Invalid Key"}), 403
        
        status, duration = row
        if status == 'used': return jsonify({"authorized": False, "error": "Key Already Used"}), 403

        # Activate
        new_expiry = datetime.now() + timedelta(hours=duration)
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
        conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
        conn.commit()

        return jsonify({"authorized": True, "message": "Activated Successfully"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)

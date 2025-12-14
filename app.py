# @title 📡 Updated Server Code (app.py)

server_code = '''import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
import requests as http_requests

app = Flask(__name__)

# --- DATABASE CONNECTION ---
DB_URL = os.environ.get("DATABASE_URL")

if DB_URL:
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DB_URL)
else:
    print("⚠️ WARNING: DATABASE_URL not set. Using temporary local SQLite.")
    engine = create_engine("sqlite:///temp.db")


def init_db():
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS licenses (
                key_code TEXT PRIMARY KEY,
                status TEXT DEFAULT 'unused',
                duration_hours INT DEFAULT 24,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_email TEXT PRIMARY KEY,
                expires_at TIMESTAMP,
                last_key TEXT,
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.commit()

init_db()


def verify_google_token(token):
    """
    Verify Google access token and return email.
    Returns: (email, error)
    """
    try:
        # Method 1: userinfo endpoint
        response = http_requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        
        if response.status_code == 200:
            user_info = response.json()
            email = user_info.get('email')
            if email:
                return email, None
        
        # Method 2: tokeninfo endpoint (fallback)
        response = http_requests.get(
            f"https://oauth2.googleapis.com/tokeninfo?access_token={token}",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            email = data.get('email')
            if email:
                return email, None
            return None, "No email in token"
        
        return None, f"Token validation failed (status {response.status_code})"
        
    except http_requests.exceptions.Timeout:
        return None, "Google API timeout"
    except Exception as e:
        return None, f"Verification error: {str(e)}"


@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "service": "License Server",
        "endpoints": ["/api/authorize", "/api/status", "/admin"]
    })


# --- ADMIN PANEL ---
@app.route('/admin')
def admin_ui():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>License Admin</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .card { background: #f5f5f5; padding: 20px; border-radius: 10px; margin: 20px 0; }
            input, button { padding: 10px 15px; margin: 5px; font-size: 16px; }
            button { background: #4CAF50; color: white; border: none; cursor: pointer; border-radius: 5px; }
            button:hover { background: #45a049; }
            .key { font-family: monospace; font-size: 24px; background: #e0e0e0; padding: 15px; border-radius: 5px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #4CAF50; color: white; }
        </style>
    </head>
    <body>
        <h1>🔑 License Key Generator</h1>
        
        <div class="card">
            <h3>Generate New Key</h3>
            <label>Duration (hours): <input type="number" id="duration" value="24" min="1"></label>
            <button onclick="generateKey()">Generate Key</button>
            <div id="newKey" class="key" style="display:none; margin-top:15px;"></div>
        </div>
        
        <div class="card">
            <h3>📋 Recent Keys</h3>
            <button onclick="loadKeys()">Refresh</button>
            <table id="keysTable">
                <thead><tr><th>Key</th><th>Status</th><th>Duration</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
        
        <div class="card">
            <h3>👥 Active Sessions</h3>
            <button onclick="loadSessions()">Refresh</button>
            <table id="sessionsTable">
                <thead><tr><th>Email</th><th>Expires</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
        
        <script>
            async function generateKey() {
                const duration = document.getElementById('duration').value;
                const res = await fetch('/admin/create', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({duration: parseInt(duration)})
                });
                const data = await res.json();
                const keyDiv = document.getElementById('newKey');
                keyDiv.innerText = data.key;
                keyDiv.style.display = 'block';
                loadKeys();
            }
            
            async function loadKeys() {
                const res = await fetch('/admin/keys');
                const data = await res.json();
                const tbody = document.querySelector('#keysTable tbody');
                tbody.innerHTML = data.keys.map(k => 
                    `<tr><td><code>${k.key}</code></td><td>${k.status}</td><td>${k.hours}h</td></tr>`
                ).join('');
            }
            
            async function loadSessions() {
                const res = await fetch('/admin/sessions');
                const data = await res.json();
                const tbody = document.querySelector('#sessionsTable tbody');
                tbody.innerHTML = data.sessions.map(s => 
                    `<tr><td>${s.email}</td><td>${s.expires}</td></tr>`
                ).join('');
            }
            
            loadKeys();
            loadSessions();
        </script>
    </body>
    </html>
    """


@app.route('/admin/create', methods=['POST'])
def create_key():
    data = request.json or {}
    duration = data.get('duration', 24)
    key = secrets.token_hex(8).upper()
    
    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO licenses (key_code, duration_hours) VALUES (:k, :d)"),
            {"k": key, "d": duration}
        )
        conn.commit()
    
    return jsonify({"key": key, "duration_hours": duration})


@app.route('/admin/keys')
def list_keys():
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT key_code, status, duration_hours FROM licenses ORDER BY created_at DESC LIMIT 50")
        ).fetchall()
    
    return jsonify({
        "keys": [{"key": r[0], "status": r[1], "hours": r[2]} for r in rows]
    })


@app.route('/admin/sessions')
def list_sessions():
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT user_email, expires_at FROM active_sessions ORDER BY expires_at DESC")
        ).fetchall()
    
    return jsonify({
        "sessions": [{"email": r[0], "expires": str(r[1])} for r in rows]
    })


# --- AUTHORIZATION API ---
@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    google_token = data.get('google_token')
    provided_key = data.get('key')
    
    # Step 1: Verify Google Token
    if not google_token:
        return jsonify({
            "authorized": False,
            "error": "Google token required. Please authenticate with Google."
        }), 400
    
    email, error = verify_google_token(google_token)
    
    if error:
        return jsonify({
            "authorized": False,
            "error": f"Google verification failed: {error}"
        }), 403
    
    print(f"✅ Verified: {email}")
    
    with engine.connect() as conn:
        # Step 2: Check existing session
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()
        
        if session:
            expires_at = session[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                remaining = (expires_at - datetime.now()).total_seconds() / 3600
                return jsonify({
                    "authorized": True,
                    "message": "Session valid",
                    "email": email,
                    "hours_remaining": round(remaining, 2)
                })
            else:
                # Expired - delete it
                conn.execute(
                    text("DELETE FROM active_sessions WHERE user_email = :e"),
                    {"e": email}
                )
                conn.commit()
        
        # Step 3: Need license key
        if not provided_key:
            return jsonify({
                "authorized": False,
                "error": "No active license. Please enter a license key.",
                "email": email,
                "needs_key": True
            }), 401
        
        # Step 4: Validate license key
        row = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key.upper().strip()}
        ).fetchone()
        
        if not row:
            return jsonify({
                "authorized": False,
                "error": "Invalid license key"
            }), 403
        
        status, duration = row
        
        if status == 'used':
            return jsonify({
                "authorized": False,
                "error": "License key already used"
            }), 403
        
        # Step 5: Activate license
        new_expiry = datetime.now() + timedelta(hours=duration)
        
        conn.execute(
            text("UPDATE licenses SET status = 'used' WHERE key_code = :k"),
            {"k": provided_key.upper().strip()}
        )
        conn.execute(
            text("DELETE FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        )
        conn.execute(
            text("""INSERT INTO active_sessions (user_email, expires_at, last_key) 
                    VALUES (:e, :t, :k)"""),
            {"e": email, "t": new_expiry, "k": provided_key.upper().strip()}
        )
        conn.commit()
        
        return jsonify({
            "authorized": True,
            "message": f"License activated! Access granted for {duration} hours.",
            "email": email,
            "hours_remaining": duration
        })


@app.route('/api/status', methods=['POST'])
def check_status():
    """Check license status without consuming a key."""
    data = request.json or {}
    google_token = data.get('google_token')
    
    if not google_token:
        return jsonify({"error": "Google token required"}), 400
    
    email, error = verify_google_token(google_token)
    
    if error:
        return jsonify({"error": f"Verification failed: {error}"}), 403
    
    with engine.connect() as conn:
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()
        
        if session:
            expires_at = session[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                remaining = (expires_at - datetime.now()).total_seconds() / 3600
                return jsonify({
                    "has_license": True,
                    "email": email,
                    "hours_remaining": round(remaining, 2)
                })
    
    return jsonify({
        "has_license": False,
        "email": email,
        "message": "No active license"
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
'''

# Save to file
with open('/content/app.py', 'w') as f:
    f.write(server_code)

# Also create requirements.txt
requirements = """Flask
psycopg2-binary
sqlalchemy
gunicorn
requests
"""

with open('/content/requirements.txt', 'w') as f:
    f.write(requirements)

print("✅ Created: /content/app.py")
print("✅ Created: /content/requirements.txt")
print("\n📤 Uploading to download...")

from google.colab import files
files.download('/content/app.py')
files.download('/content/requirements.txt')

print("""
📌 DEPLOY TO RENDER.COM:
   
   1. Create new Web Service on Render
   2. Upload app.py and requirements.txt
   3. Set environment variable: DATABASE_URL (use Render PostgreSQL)
   4. Start command: gunicorn app:app
   5. Copy your URL and update licenseguard.py!
""")

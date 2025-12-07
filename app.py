import requests  # <--- Make sure this is imported at the top

# ... (Previous database setup code remains the same) ...

@app.route('/api/authorize', methods=['POST'])
def authorize():
    data = request.json or {}
    token = data.get('token')      # We expect a Token now, not just an email
    provided_key = data.get('key')
    
    email = None

    # 1. VERIFY TOKEN WITH GOOGLE
    if token:
        try:
            # Ask Google who owns this token
            google_res = requests.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={token}")
            
            if google_res.status_code == 200:
                google_data = google_res.json()
                email = google_data.get('email')
                # verify that the token actually belongs to the intended app/scope if necessary
            else:
                return jsonify({"authorized": False, "error": "Invalid or Expired Google Token"}), 401
        except Exception as e:
            return jsonify({"authorized": False, "error": f"Google Verification Failed: {str(e)}"}), 500
    
    if not email:
        return jsonify({"authorized": False, "error": "Authentication Failed. No valid email found."}), 401

    # ... (The rest of the logic remains the same: Check DB, Check Key, etc.) ...
    
    with engine.connect() as conn:
        # Check active session for THIS email (verified by Google)
        session = conn.execute(
            text("SELECT expires_at FROM active_sessions WHERE user_email = :e"),
            {"e": email}
        ).fetchone()

        if session:
            expires_at = session[0]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            if datetime.now() < expires_at:
                return jsonify({"authorized": True, "message": f"Welcome back, {email}"})
            else:
                conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
                conn.commit()

        # Check Key if no session
        if not provided_key:
            return jsonify({"authorized": False, "error": "Session expired. License Key required."}), 401

        row = conn.execute(
            text("SELECT status, duration_hours FROM licenses WHERE key_code = :k"),
            {"k": provided_key}
        ).fetchone()

        if not row:
            return jsonify({"authorized": False, "error": "Invalid Key"}), 403
        
        status, duration = row
        if status == 'used':
            return jsonify({"authorized": False, "error": "Key already used"}), 403

        # Activate
        new_expiry = datetime.now() + timedelta(hours=duration)
        conn.execute(text("UPDATE licenses SET status = 'used' WHERE key_code = :k"), {"k": provided_key})
        
        # Upsert session
        conn.execute(text("DELETE FROM active_sessions WHERE user_email = :e"), {"e": email})
        conn.execute(text("INSERT INTO active_sessions (user_email, expires_at) VALUES (:e, :t)"), {"e": email, "t": new_expiry})
        conn.commit()

        return jsonify({"authorized": True, "message": "License Activated."})

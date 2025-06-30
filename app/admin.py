from flask import Flask, request, session, jsonify
from functools import wraps
import sqlite3
import os
import hashlib
import binascii

app = Flask(__name__)
app.secret_key = 'securenet-secret-key'

DATABASE = 'app.db'

def hash_password(password):
    salt = os.urandom(16)
    pwdhash = hashlib.sha256(salt + password.encode('utf-8')).digest()
    return binascii.hexlify(salt + pwdhash).decode('utf-8')

def verify_password(stored_password, provided_password):
    stored_password = binascii.unhexlify(stored_password.encode('utf-8'))
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    pwdhash = hashlib.sha256(salt + provided_password.encode('utf-8')).digest()
    return pwdhash == stored_hash

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    conn.commit()

    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    c.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not c.fetchone():
        hashed = hash_password(admin_password)
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", hashed, "admin"))
        conn.commit()

    conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({"message": "Invalid request"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if user and verify_password(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return jsonify({"message": "Login successful"})
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    return jsonify({"message": "Upload successful (authenticated)"})

@app.route('/logs', methods=['GET'])
@login_required
def logs():
    return jsonify({"logs": [
        "[INFO] Login userID_01",
        "[WARN] Anomaly userID_12",
        "[ALERT] Unauthorized login userID_99"
    ]})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

from flask import Flask, request, session, jsonify
from functools import wraps
from models import db, User  # import your SQLAlchemy model
import os

app = Flask(__name__)
app.secret_key = 'securenet-secret-key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def init_db():
    with app.app_context():
        db.create_all()
        User.create_default_admin()  # use standard method

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data:
        return jsonify({"message": "Invalid request"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
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

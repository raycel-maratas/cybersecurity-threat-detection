from flask import Blueprint, request, jsonify, session
from functools import wraps
from app.models import db, User
from app.hash_utils import hash_password, verify_password

admin_bp = Blueprint('admin', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and verify_password(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        return jsonify({"message": "Login successful"})
    return jsonify({"message": "Invalid credentials"}), 401

@admin_bp.route('/logout')
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@admin_bp.route('/logs', methods=['GET'])
@login_required
def logs():
    return jsonify({"logs": [
        "[INFO] Login userID_01",
        "[WARN] Anomaly userID_12",
        "[ALERT] Unauthorized login userID_99"
    ]})

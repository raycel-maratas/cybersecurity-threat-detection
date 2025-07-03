from flask import Blueprint, request, jsonify, session, redirect, url_for
from functools import wraps
from app.models import db, User, Log
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

# router for admin/user login
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

        redirect_url = "/admin-dashboard" if user.role == "admin" else "/user-page"

        return jsonify({
            "message": "Login successful",
            "role": user.role,
            "redirect": redirect_url
        }), 200

    return jsonify({"message": "Invalid credentials"}), 401


# logout route
@admin_bp.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('log.login_page'))

# route to retrieve all uploaded logs, protected by login
@admin_bp.route('/logs', methods=['GET'])
@login_required
def logs():
    logs = Log.query.order_by(Log.timestamp_uploaded.desc()).all()
    return jsonify({
        "logs": [{
            "filename": log.filename,
            "timestamp": log.timestamp_uploaded.isoformat(),
            "uploader": log.uploaded_by,
            "content": log.content
        } for log in logs]
    })


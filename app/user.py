import hashlib
from datetime import datetime

from flask import Blueprint, request, jsonify, session, redirect, url_for
from functools import wraps

from app.extensions import db
from app.anomaly_utils import is_anomaly
from app.models import User, Alert, FailedLoginAttempt
from app.hash_utils import verify_password
from app.evaluate import evaluate_threat


user_bp = Blueprint('user', __name__)

# login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# login route
@user_bp.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')
    ip_address = request.remote_addr

    print("Login Attempt:", username, password)

    user = User.query.filter_by(username=username).first()
    if not user:
        print("User not found.")
        return jsonify({"error": "Invalid credentials"}), 401

    print("User found.", user.username)
    print("Stored Hash:", user.password)

    if user.failed_attempts >= 3:
        print(f"Account locked for {username}")
        alert = evaluate_threat(
            log_id=None,
            username=username,
            ip_address=ip_address,
            hash_match=False,
            anomaly=True
        )
        if alert:
            db.session.add(alert)
            db.session.commit()
        return jsonify({"error": "Account locked after 3 failed attempts"}), 403

    if not verify_password(user.password, password):
        print("Incorrect Password")

        attempt_str = f"{username}:{ip_address}:{datetime.utcnow().isoformat()}"
        attempt_hash = hashlib.sha256(attempt_str.encode()).hexdigest()

        existing = FailedLoginAttempt.query.filter_by(attempt_hash=attempt_hash).first()
        if existing:
            alert = Alert(
                log_id=None,
                type="Repeated Failed Login Attempt",
                description=f"Repeated failed login for user '{username}' from IP {ip_address}.",
                severity="High",
                timestamp_detected=datetime.utcnow()
            )
            db.session.add(alert)

        failed_attempt = FailedLoginAttempt(
            username=username,
            ip_address=ip_address,
            attempt_hash=attempt_hash
        )
        db.session.add(failed_attempt)

        user.failed_attempts += 1
        if user.failed_attempts >= 3:
            alert = Alert(
                log_id=None,
                type="Login Anomaly",
                description=f"User '{username}' account locked after 3 failed login attempts.",
                severity="High",
                timestamp_detected=datetime.utcnow()
            )
            db.session.add(alert)

        db.session.commit()
        return jsonify({"error": "Invalid credentials"}), 401

    # password correct, check for anomaly before allowing login
    known_users = [u.username for u in User.query.all()]
    if is_anomaly(username, known_users):
        alert = evaluate_threat(
            log_id=None,
            username=username,
            ip_address=ip_address,
            hash_match=False,
            anomaly=True
        )
        if alert:
            db.session.add(alert)
            db.session.commit()
        return jsonify({"error": "Anomalous username detected. Incident logged."}), 401

    # logged in: set session and reset failed attempts
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role

    user.failed_attempts = 0
    db.session.commit()

    print(f"Login successful for {username}")
    return jsonify({
        "message": "Login successful",
        "role": user.role,
        "redirect": "/admin-dashboard" if user.role == "admin" else "/user-page"
    }), 200


# logout route
@user_bp.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('log.login_page'))


# dashboard
@user_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return jsonify({
        "message": f"Welcome to the user dashboard, {session.get('username')}"
    })

# get current user info
@user_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        "id": session.get("user_id"),
        "username": session.get("username"),
        "role": session.get("role")
    })

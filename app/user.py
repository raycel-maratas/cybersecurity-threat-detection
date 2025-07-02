import hashlib
from datetime import datetime

from flask import Blueprint, request, jsonify, session
from functools import wraps

from app import db
from app.anomaly_utils import is_anomaly
from app.models import User, Alert, FailedLoginAttempt
from app.hash_utils import verify_password

user_bp = Blueprint('user', __name__)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)

    return decorated_function


@user_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    ip_address = request.remote_addr or 'unknown'

    # get all known usernames from db
    known_users = [user.username for user in User.query.all()]

    # check if username is anomalous
    if is_anomaly(username, known_users):
        # save alert in database
        alert = Alert(
            log_id=None,
            type="Anomalous Username",
            description=f"Login attempt with unknown/anomalous username: '{username}' from IP {ip_address}.",
            severity="High",
            timestamp_detected=datetime.utcnow()
        )
        db.session.add(alert)
        db.session.commit()

        # return error response
        return jsonify({
            "error": "Anomalous username detected. This incident has been logged."
        }), 401

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if user.failed_attempts >= 3:
        return jsonify({"error": "Account locked after 3 failed attempts"}), 403

    if verify_password(user.password, password) and user.role == 'user':
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        user.failed_attempts = 0
        db.session.commit()
        return jsonify({"message": "Login successful", "role": user.role})

    # failed login: create hash for the attempt
    attempt_str = f"{username}:{ip_address}:{datetime.utcnow().isoformat()}"
    attempt_hash = hashlib.sha256(attempt_str.encode()).hexdigest()

    # check if this failed attempt hash exists to detect repeat attempts
    existing = FailedLoginAttempt.query.filter_by(attempt_hash=attempt_hash).first()
    if existing:
        # suspicious repeated attempt
        alert = Alert(
            log_id=None,
            type="Repeated Failed Login Attempt",
            description=f"Repeated failed login detected for user '{username}' from IP {ip_address}.",
            severity="High",
            timestamp_detected=datetime.utcnow()
        )
        db.session.add(alert)

    # save the new failed login attempt hash
    failed_attempt = FailedLoginAttempt(
        username=username,
        ip_address=ip_address,
        attempt_hash=attempt_hash
    )
    db.session.add(failed_attempt)

    # increment user failed attempts and alert on 3rd fail
    user.failed_attempts += 1
    if user.failed_attempts >= 3:
        print(f"FAILED ATTEMPTS: {user.failed_attempts}")
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

# frontend route: logout endpoint
# clears the user session to log them out
@user_bp.route('/logout')
@login_required
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

# frontend route: user dashboard data
# simple protected route returning a welcome message with username
# you can edit this if you want
# this is just an example
@user_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return jsonify({
        "message": f"Welcome to the user dashboard, {session.get('username')}"
    })

# frontend route: Get current logged-in user info
# returns the current user's id, username, and role
@user_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        "id": session.get("user_id"),
        "username": session.get("username"),
        "role": session.get("role")
    })


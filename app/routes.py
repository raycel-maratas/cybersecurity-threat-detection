from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for
from app.models import Log, Alert, User
from app.parser import parse_log_file
from app.hash_utils import is_malware_hash
from app.anomaly_utils import is_anomaly
from app.utils import log_action
from app.evaluate import evaluate_threat
from app.extensions import db
from app import socketio
import traceback

log_bp = Blueprint('log', __name__)

# render the homepage (admin/user dashboard)
@log_bp.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('log.login_page'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)

    if not current_user:
        session.clear()
        return redirect(url_for('log.login_page'))

    if current_user.role == 'admin':
        # admin sees all logs and alerts
        alerts = Alert.query.order_by(Alert.timestamp_detected.desc()).all()
        logs = Log.query.all()

        user_map = {u.id: u.username for u in User.query.all()}
        users = {log.id: user_map.get(log.uploaded_by, 'Unknown') for log in logs}

        return render_template('admin_dashboard.html', alerts=alerts, users=users)
    else:
        # user sees only their logs and alerts
        user_logs = Log.query.filter_by(uploaded_by=current_user.id).all()
        log_ids = [log.id for log in user_logs]

        # alerts linked to their logs
        user_alerts = Alert.query.filter(Alert.log_id.in_(log_ids)) \
            .order_by(Alert.timestamp_detected.desc()).all()

        # alerts from login anomalies
        login_alerts = Alert.query.filter(
            Alert.log_id == None,
            Alert.description.ilike(f"%{current_user.username}%")
        ).all()

        from app.models import FailedLoginAttempt

        # combine all alerts
        all_user_alerts = user_alerts + login_alerts

        # map alerts to user
        users = {
            alert.log_id: current_user.username for alert in user_alerts if alert.log_id is not None
        }
        for alert in login_alerts:
            users[alert.id] = current_user.username

        # Get failed login attempts for this user
        failed_logins = FailedLoginAttempt.query.filter_by(username=current_user.username).order_by(
            FailedLoginAttempt.timestamp.desc()).all()

        return render_template('user.html', alerts=all_user_alerts, users=users, failed_logins=failed_logins)


@log_bp.route('/login-page')
def login_page():
    return render_template('login.html')

@log_bp.route('/upload-page')
def upload_page():
    return render_template('upload.html')

@log_bp.route('/user-page')
def user_page():
    return render_template('user.html')

# upload and process log file
@log_bp.route('/upload-log', methods=['POST'])
def upload_log():
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({'error': 'No file uploaded'}), 400

        content = file.read().decode('utf-8')
        logs = parse_log_file(content)

        for log in logs:
            print("Parsed log entry:", log)

            hash_match = is_malware_hash(log.get('hash'))
            print("Hash match result:", hash_match, "| Hash:", log.get('hash'))

            anomaly = is_anomaly(log.get('user', ''), [u.username for u in User.query.all()])
            print("Anomaly result:", anomaly, "| User:", log.get('user'))

            new_entry = Log(
                filename=file.filename,
                content=log['message'],
                timestamp_uploaded=datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S"),
                uploaded_by=session.get('user_id')
            )
            db.session.add(new_entry)
            db.session.flush()

            alert = evaluate_threat(
                log_id=new_entry.id,
                username=session.get('username', 'unknown'),
                ip_address=request.remote_addr or 'unknown',
                hash_match=hash_match,
                anomaly=anomaly
            )

            print("Generated alert:", alert)

            if alert:
                db.session.add(alert)

            socketio.emit('log_update', {
                'filename': file.filename,
                'message': log['message'],
                'timestamp': log['timestamp']
            })

        db.session.commit()
        log_action(f"Uploaded file {file.filename}")
        return jsonify({'message': 'Logs uploaded and threats checked.'}), 201

    except Exception as e:
        print("Exception occurred in /upload-log route:")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500


# get a specific log
@log_bp.route('/log/<int:log_id>', methods=['GET'])
def get_log(log_id):
    entry = Log.query.get(log_id)
    if not entry:
        return jsonify({'error': 'Log not found'}), 404

    return jsonify({
        'id': entry.id,
        'filename': entry.filename,
        'content': entry.content,
        'timestamp_uploaded': entry.timestamp_uploaded.isoformat(),
        'uploaded_by': entry.uploaded_by
    })

# get all alerts
@log_bp.route('/alerts', methods=['GET'])
def get_alerts():
    sort_by = request.args.get('sort_by', 'timestamp_detected')
    order = request.args.get('order', 'desc')

    valid_sort_fields = {'id', 'type', 'severity', 'timestamp_detected'}
    if sort_by not in valid_sort_fields:
        return jsonify({'error': f'Invalid sort_by field. Must be one of: {valid_sort_fields}'}), 400

    sort_attr = getattr(Alert, sort_by)
    alerts = Alert.query.order_by(sort_attr.asc() if order == 'asc' else sort_attr.desc()).all()

    return jsonify([
        {
            'id': alert.id,
            'log_id': alert.log_id,
            'type': alert.type,
            'description': alert.description,
            'timestamp_detected': alert.timestamp_detected.isoformat(),
            'severity': alert.severity
        } for alert in alerts
    ])

# anomaly detection for username
@log_bp.route('/check-user', methods=['POST'])
def check_user():
    data = request.get_json()
    username = data.get('username', '').strip()

    known_users = [user.username.lower() for user in User.query.all()]

    if is_anomaly(username, known_users):
        return jsonify({'status': 'anomaly', 'message': f'️Anomalous user: {username}'}), 200

    return jsonify({'status': 'normal', 'message': f'Known user: {username}'}), 200

# admin dashboard
@log_bp.route('/admin-dashboard')
def admin_dashboard():
    from app.models import Log, Alert, FailedLoginAttempt

    logs = Log.query.order_by(Log.timestamp_uploaded.desc()).all()
    alerts = Alert.query.order_by(Alert.timestamp_detected.desc()).all()
    failed_logins = FailedLoginAttempt.query.order_by(FailedLoginAttempt.timestamp.desc()).all()

    users = {
        log.id: (
            User.query.get(log.uploaded_by).username
            if log.uploaded_by and User.query.get(log.uploaded_by)
            else 'Unknown'
        )
        for log in logs
    }

    return render_template(
        'admin_dashboard.html',
        logs=logs,
        alerts=alerts,
        failed_logins=failed_logins,
        users=users
    )

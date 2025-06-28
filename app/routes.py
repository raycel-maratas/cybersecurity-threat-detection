from datetime import datetime
from flask import Blueprint, request, jsonify

from app.models import db, Log, Alert
from app.parser import parse_log_file
from app.hash_utils import KNOWN_BAD_HASHES
from app.anomaly_utils import is_anomaly


log_bp = Blueprint('log', __name__)

@log_bp.route('/')
def index():
    return 'Upload page placeholder'

@log_bp.route('/upload-log', methods=['POST'])
def upload_log():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    content = file.read().decode('utf-8')
    logs = parse_log_file(content)

    for log in logs:
        # Save log entry
        new_entry = Log(
            filename=file.filename,
            content=log['message'],
            timestamp_uploaded=datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S"),
            uploaded_by=1  # Placeholder for actual user ID
        )
        db.session.add(new_entry)
        db.session.flush()  # Get new_entry.id before commit

        # Detect threat based on known malware hash
        if log.get('hash') in KNOWN_BAD_HASHES:
            alert = Alert(
                log_id=new_entry.id,
                type="Malware Hash Detected",
                description=f"Known malware hash detected: {log['hash']}",
                severity="High"
            )
            db.session.add(alert)

    db.session.commit()

    return jsonify({'message': 'Logs uploaded and threats checked.'}), 201



@log_bp.route('/logs', methods=['GET'])
def get_logs():
    sort_by = request.args.get('sort_by', 'timestamp_uploaded')
    order = request.args.get('order', 'desc')

    valid_sort_fields = {'id', 'filename', 'timestamp_uploaded', 'uploaded_by'}
    if sort_by not in valid_sort_fields:
        return jsonify({'error': f'Invalid sort_by field. Must be one of: {valid_sort_fields}'}), 400

    sort_attr = getattr(Log, sort_by)
    if order == 'asc':
        entries = Log.query.order_by(sort_attr.asc()).all()
    else:
        entries = Log.query.order_by(sort_attr.desc()).all()

    return jsonify([
        {
            'id': e.id,
            'filename': e.filename,
            'content': e.content,
            'timestamp_uploaded': e.timestamp_uploaded.isoformat(),
            'uploaded_by': e.uploaded_by
        } for e in entries
    ])


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

@log_bp.route('/check-user', methods=['POST'])
def check_user():
    data = request.get_json()
    username = data.get('username', '').strip()

    # Load known usernames from the database
    known_users = [user.username.lower() for user in User.query.all()]

    if is_anomaly(username, known_users):
        return jsonify({'status': 'anomaly', 'message': f'⚠️ Anomalous user: {username}'}), 200

    return jsonify({'status': 'normal', 'message': f'✅ Known user: {username}'}), 200



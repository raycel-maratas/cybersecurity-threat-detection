from flask import Blueprint, jsonify
from datetime import datetime, timedelta
from app.models import Alert
import re

correlation_bp = Blueprint('correlation', __name__)

@correlation_bp.route('/correlate', methods=['GET'])
def correlate_threats():
    suspicious_alerts = []

    anomalies = Alert.query.filter(Alert.type == "Anomalous Username").all()

    for anomaly in anomalies:
        match = re.search(r"IP ([\d\.]+)", anomaly.description)
        if not match:
            continue
        ip = match.group(1)

        related = Alert.query.filter(
            Alert.description.like(f"%{ip}%"),
            Alert.id != anomaly.id
        ).all()

        if related:
            suspicious_alerts.append({
                "anomaly_id": anomaly.id,
                "ip": ip,
                "related_alerts": [
                    {
                        "id": a.id,
                        "type": a.type,
                        "description": a.description,
                        "severity": a.severity
                    } for a in related
                ]
            })

    return jsonify(suspicious_alerts)

time_threshold = datetime.utcnow() - timedelta(minutes=15)
anomalies = Alert.query.filter(
    Alert.type == "Anomalous Username",
    Alert.timestamp_detected >= time_threshold
).all()

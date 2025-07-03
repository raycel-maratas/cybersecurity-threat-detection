from flask import Blueprint, jsonify
from datetime import datetime, timedelta

from app import db
from app.models import Alert
from app.alert import evaluate
import re

correlation_bp = Blueprint('correlation', __name__)

@correlation_bp.route('/correlate', methods=['GET'])
def correlate_threats():
    suspicious_alerts = []

    time_threshold = datetime.utcnow() - timedelta(minutes=15)

    anomalies = Alert.query.filter(
        Alert.type == "Anomalous Username",
        Alert.timestamp_detected >= time_threshold
    ).all()

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
            # simulate correlation result
            match_result = {
                "hash_match": any("Threat" in r.type or "Hash" in r.description for r in related),
                "anomaly": True
            }

            alert_data = evaluate(match_result)

            if alert_data and alert_data["severity"] != "Low":
                # check if similar alert already exists
                existing = Alert.query.filter_by(
                    type=alert_data["type"],
                    description=alert_data["description"]
                ).first()

                if not existing:
                    new_alert = Alert(
                        log_id=None,
                        type=alert_data["type"],
                        description=alert_data["description"] + f" Correlated IP: {ip}",
                        severity=alert_data["severity"],
                        timestamp_detected=datetime.utcnow()
                    )
                    db.session.add(new_alert)
                    db.session.commit()

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

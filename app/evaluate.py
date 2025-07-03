# app/evaluate.py

from app.models import Alert
from datetime import datetime
from app.alert_rules import ALERT_RULES

def evaluate_threat(log_id=None, username=None, ip_address=None, hash_match=False, anomaly=False):
    for rule in ALERT_RULES:
        cond = rule['conditions']
        if cond['hash_match'] == hash_match and cond['anomaly'] == anomaly:
            alert = Alert(
                log_id=log_id,
                type=rule['type'],
                description=rule['description'] + f" (User: {username}, IP: {ip_address})",
                severity=rule['severity'],
                timestamp_detected=datetime.utcnow()
            )
            return alert  # return alert instance (not committed yet)
    return None

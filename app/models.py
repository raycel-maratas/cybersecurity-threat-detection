from .app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp_uploaded = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey('log.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    timestamp_detected = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20), default="Medium")

class ThreatHash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash_value = db.Column(db.String(128), unique=True, nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)

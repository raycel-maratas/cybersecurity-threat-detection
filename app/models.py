import os

from app.__init__ import db
from datetime import datetime
from app.hash_utils import hash_password

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_attempts = db.Column(db.Integer, default=0)

    @classmethod
    def create_default_admin(cls):
        if not cls.query.filter_by(username='admin').first():
            admin = cls(
                username='admin',
                password=hash_password(os.getenv("ADMIN_PASSWORD", "admin123")),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp_uploaded = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey('log.id'))
    type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    timestamp_detected = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20), default="Medium")


class ThreatHash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash_value = db.Column(db.String(128), unique=True, nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)

class FailedLoginAttempt(db.Model):
    __tablename__ = 'failed_login_attempt'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    attempt_hash = db.Column(db.String(64), unique=True, nullable=False)  # SHA-256 hex digest
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.Index('idx_attempt_hash', 'attempt_hash'),)

class UserActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


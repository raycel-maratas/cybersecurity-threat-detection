from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @classmethod
    def create_default_admin(cls):
        existing = cls.query.filter_by(username='admin').first()
        if not existing:
            default_pw = os.environ.get('ADMIN_PASSWORD', 'admin123')
            admin = cls(username='admin', role='admin')
            admin.set_password(default_pw)
            db.session.add(admin)
            db.session.commit()

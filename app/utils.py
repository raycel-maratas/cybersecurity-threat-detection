from app.models import db, UserActionLog
from flask import session

def log_action(action):
    if 'user_id' in session:
        entry = UserActionLog(user_id=session['user_id'], action=action)
        db.session.add(entry)
        db.session.commit()
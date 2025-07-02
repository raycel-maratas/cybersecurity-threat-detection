# this is just temporary

from app import create_app, db
from app.models import User
from app.hash_utils import hash_password

app = create_app()

with app.app_context():
    users_to_add = [
        {"username": "AliceGrace", "password": "alice123", "role": "user"},
        {"username": "DianaTaurasi", "password": "diana938", "role": "user"},
        {"username": "JonSnow", "password": "snow013", "role": "user"},
        {"username": "JuanCruz", "password": "crus938juan", "role": "user"},
    ]

    for u in users_to_add:
        if not User.query.filter_by(username=u["username"]).first():
            new_user = User(
                username=u["username"],
                password=hash_password(u["password"]),
                role=u["role"]
            )
            db.session.add(new_user)
            print(f"Added user {u['username']} ({u['role']})")
        else:
            print(f"User {u['username']} already exists")

    db.session.commit()

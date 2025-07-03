from app.hash_utils import hash_password
from app.models import User
from app import db

users = [
    {"username": "AnnaGrace", "password": "anna021"},
    {"username": "NicoJohn", "password": "nico182"},
    {"username": "PaigeFudd", "password": "paige535"},
    {"username": "AliceGrace", "password": "alice123"},
    {"username": "DianaTaurasi", "password": "diana938"},
    {"username": "JonSnow", "password": "snow013"},
    {"username": "JuanCruz", "password": "crus938juan"},
]

for u in users:
    hashed_pw = hash_password(u["password"])
    user = User(username=u["username"], password=hashed_pw, role="user")
    db.session.add(user)

db.session.commit()
print("Users created successfully with hashed passwords.")

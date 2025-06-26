from flask import Flask
import sqlite3
from werkzeug.security import generate_password_hash

app = Flask(__name__)
DATABASE = "app.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.cli.command("init-db")
def init_db():

    db = get_db()
    with open("schema.sql", "r") as f:
        db.executescript(f.read())
    print("✅ Database schema created.")

    cur = db.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        password_hash = generate_password_hash("admin123")
        db.execute(
            "INSERT INTO users (username, password_hash, admin) VALUES (?, ?, ?)",
            ("admin", password_hash, True)
        )
        db.commit()
        print("✅ Default admin user created.")
    else:
        print("ℹ️ Admin user already exists.")

    db.close()

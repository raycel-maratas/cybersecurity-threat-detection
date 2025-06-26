import click
from flask.cli import with_appcontext
from app import create_app
from models import db, User

app = create_app()

@app.cli.command("init-db")
@with_appcontext
def init_db():
    db.create_all()  # ✅ idempotent: won't recreate if already exists
    User.create_default_admin()
    click.echo("✅ Database initialized with default admin.")

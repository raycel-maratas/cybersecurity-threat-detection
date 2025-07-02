import os
import click

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask.cli import with_appcontext

# Initialize extensions
db = SQLAlchemy()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    db.init_app(app)
    socketio.init_app(app)

    from app.routes import log_bp
    from app.admin import admin_bp
    from app.user import user_bp
    from app.correlation import correlation_bp
    from app.models import ThreatHash, User  # now safe

    app.register_blueprint(log_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(correlation_bp)

    # Register CLI commands
    app.cli.add_command(init_db)
    app.cli.add_command(list_users)
    app.cli.add_command(seed_threats)

    return app

@click.command("init-db")
@with_appcontext
def init_db():
    db.create_all()
    from app.models import User
    User.create_default_admin()
    click.echo("Database tables and default admin created")

@click.command("list-users")
@with_appcontext
def list_users():
    from app.models import User
    users = User.query.all()
    for u in users:
        print(f"{u.id} | {u.username} | {u.role}")

@click.command("seed-threats")
@with_appcontext
def seed_threats():
    from app.models import ThreatHash
    file_path = 'VirusShare.txt'
    if not os.path.exists(file_path):
        click.echo("VirusShare.txt not found.")
        return

    count = 0
    with open(file_path, 'r') as f:
        for line in f:
            h = line.strip()
            if h and h != "################################":
                db.session.add(ThreatHash(
                    hash_value=h,
                    threat_level='High',
                    description='Imported from VirusShare'
                ))
                count += 1
    db.session.commit()
    click.echo(f"{count} threat hashes seeded.")

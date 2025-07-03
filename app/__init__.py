import os
import click
from dotenv import load_dotenv

from flask import Flask
from flask.cli import with_appcontext
from flask_migrate import Migrate

from app.extensions import db, socketio

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-key')
    app.config.from_object('app.config.Config')

    # initialize extensions
    db.init_app(app)
    socketio.init_app(app)
    Migrate(app, db)

    # register Blueprints
    from app.routes import log_bp
    from app.admin import admin_bp
    from app.user import user_bp
    from app.correlation import correlation_bp
    from app.models import ThreatHash, User

    app.register_blueprint(log_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(correlation_bp)

    # Register CLI commands
    app.cli.add_command(init_db)
    app.cli.add_command(list_users)
    app.cli.add_command(seed_threats)
    app.cli.add_command(seed_users)

    return app


@click.command("seed-users")
@with_appcontext
def seed_users():
    from app.models import User
    from app.hash_utils import hash_password

    db.session.query(User).delete()

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
        db.session.add(User(
            username=u["username"],
            password=hash_password(u["password"]),
            role="user"
        ))

    db.session.commit()
    print("Users seeded successfully.")


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
                # Skip if already exists
                if ThreatHash.query.filter_by(hash_value=h).first():
                    continue

                db.session.add(ThreatHash(
                    hash_value=h,
                    threat_level='High',
                    description='Imported from VirusShare'
                ))
                count += 1
    db.session.commit()
    click.echo(f"{count} new threat hashes seeded.")

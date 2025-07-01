from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask.cli import with_appcontext
import click

db = SQLAlchemy()

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

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    db.init_app(app)

    from app.routes import log_bp
    from app.admin import admin_bp
    from app.user import user_bp
    from app.correlation import correlation_bp

    app.register_blueprint(log_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(correlation_bp)

    app.cli.add_command(init_db)
    app.cli.add_command(list_users)

    return app

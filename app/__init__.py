from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask.cli import with_appcontext
import click

db = SQLAlchemy()

@click.command("init-db")
@with_appcontext
def init_db():
    db.create_all()
    click.echo("✅ Database tables created")

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)

    from app.routes import log_bp
    app.register_blueprint(log_bp)

    app.cli.add_command(init_db)
    return app

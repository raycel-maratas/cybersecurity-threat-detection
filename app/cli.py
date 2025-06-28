import click
import logging
from flask.cli import with_appcontext
from app import create_app
from app.models import db, User


app = create_app()

logging.basicConfig(
    filename='init_db.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logging.info("Tables created.")


@app.cli.command("init-db")
@with_appcontext
def init_db():
    print("Connecting to the database...")

    db.create_all()
    print("Tables created.")

    User.create_default_admin()
    print("Default admin check complete.")

    click.echo("Done initializing database.")

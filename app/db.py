
import sqlite3
import click

from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"]
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def close_db(error=None):
    database = g.pop("db", None)

    if database is not None:
        database.close()


def init_db():
    database = get_db()

    schema_path = current_app.root_path + "/schema.sql"

    with open(schema_path, "r", encoding="utf-8") as file:
        database.executescript(file.read())

    # Safe, additive migration for databases created by earlier LogicShield versions.
    columns = {row[1] for row in database.execute("PRAGMA table_info(files)").fetchall()}
    additions = {
        "category": "TEXT NOT NULL DEFAULT 'study_material'",
        "department": "TEXT NOT NULL DEFAULT 'ALL'",
        "subject": "TEXT DEFAULT ''",
        "term": "TEXT DEFAULT ''",
        "description": "TEXT DEFAULT ''",
    }
    for name, definition in additions.items():
        if name not in columns:
            database.execute(f"ALTER TABLE files ADD COLUMN {name} {definition}")

    # Add first-login password enforcement for teacher accounts.
    # Existing accounts default to 0; newly created teachers are set to 1.
    user_columns = {row[1] for row in database.execute("PRAGMA table_info(users)").fetchall()}
    if "must_change_password" not in user_columns:
        database.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")

    database.commit()


@click.command("init-db")
def init_db_command():
    init_db()
    click.echo("LogicShield database initialized successfully!")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

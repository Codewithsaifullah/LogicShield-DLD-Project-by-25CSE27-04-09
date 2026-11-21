import os
from flask import Flask, redirect, url_for

from .db import init_app as init_db_app
from .auth import auth, login_manager
from .files import files
from .ui import install_ui


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    os.makedirs(app.instance_path, exist_ok=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("LOGICSHIELD_SECRET_KEY", "dev-only-change-this-secret"),
        DATABASE=os.path.join(app.instance_path, "logicshield.sqlite"),
        UPLOAD_FOLDER=os.path.join(app.instance_path, "uploads"),
    )

    if test_config is not None:
        app.config.update(test_config)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(os.path.join(app.instance_path, "secure_files"), exist_ok=True)

    login_manager.init_app(app)
    init_db_app(app)

    app.register_blueprint(auth)
    app.register_blueprint(files)

    @app.route("/")
    def home():
        return redirect(url_for("auth.login"))

    install_ui(app)

    return app

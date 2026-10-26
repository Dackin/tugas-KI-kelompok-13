import os

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Silakan masuk terlebih dahulu."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


def _env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "development-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///secure_rt_dev.sqlite3"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        PRIVATE_STORAGE_DIR=os.getenv("PRIVATE_STORAGE_DIR", "private_storage"),
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH_MB", "50")) * 1024 * 1024,
        ADMIN_INVITE_CODE=os.getenv("ADMIN_INVITE_CODE") or None,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_env_flag("SESSION_COOKIE_SECURE"),
        REMEMBER_COOKIE_SECURE=_env_flag("SESSION_COOKIE_SECURE"),
    )
    if test_config:
        app.config.update(test_config)
    db.init_app(app)
    login_manager.init_app(app)
    os.makedirs(app.config["PRIVATE_STORAGE_DIR"], exist_ok=True)

    # Import model sebelum create_all agar seluruh tabel terdaftar.
    from app import models  # noqa: F401
    from app.auth.routes import auth_bp

    app.register_blueprint(auth_bp)

    @app.get("/")
    def index():
        return {"project": "Secure RT", "status": "starter"}
    with app.app_context():
        db.create_all()
    return app

import os

from flask import Flask, redirect, render_template
from dotenv import load_dotenv

from app.extensions import csrf, db, login_manager

load_dotenv()

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
        CRYPTO_MASTER_KEY_B64=os.getenv("CRYPTO_MASTER_KEY_B64"),
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
    csrf.init_app(app)
    os.makedirs(app.config["PRIVATE_STORAGE_DIR"], exist_ok=True)

    # Import model sebelum create_all agar seluruh tabel terdaftar.
    from app import models  # noqa: F401
    from app.admin.routes import admin_bp
    from app.auth.routes import auth_bp
    from app.resident.routes import resident_bp
    from app.tickets.routes import tickets_bp

    for blueprint in (auth_bp, resident_bp, tickets_bp, admin_bp):
        app.register_blueprint(blueprint)

    @app.get("/")
    def index():
        from flask_login import current_user

        from app.auth.utils import default_dashboard_url

        if current_user.is_authenticated:
            return redirect(default_dashboard_url())
        return render_template("index.html")

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html"), 403

    with app.app_context():
        db.create_all()
    return app

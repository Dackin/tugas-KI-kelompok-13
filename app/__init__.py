import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import load_dotenv

load_dotenv()
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "development-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///secure_rt_dev.sqlite3"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        CRYPTO_MASTER_KEY_B64=os.getenv("CRYPTO_MASTER_KEY_B64"),
        PRIVATE_STORAGE_DIR=os.getenv("PRIVATE_STORAGE_DIR", "private_storage"),
        MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH_MB", "50")) * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    db.init_app(app)
    login_manager.init_app(app)
    os.makedirs(app.config["PRIVATE_STORAGE_DIR"], exist_ok=True)
    @app.get("/")
    def index():
        return {"project": "Secure RT", "status": "starter"}
    with app.app_context():
        db.create_all()
    return app

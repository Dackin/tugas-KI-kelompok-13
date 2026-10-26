import pytest
from werkzeug.security import generate_password_hash
from app import create_app, db
from app.models import User, Resident   # import modul ini mendaftarkan semua tabel

@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "PRIVATE_STORAGE_DIR": str(tmp_path / "storage"),
        "SECRET_KEY": "test",
        "WTF_CSRF_ENABLED": False,
    })
    with app.app_context():
        db.drop_all(); db.create_all()
        admin = User(username="admin", password_hash=generate_password_hash("rahasia"), role="admin")
        a = User(username="warga_a", password_hash=generate_password_hash("rahasia"), role="warga")
        b = User(username="warga_b", password_hash=generate_password_hash("rahasia"), role="warga")
        db.session.add_all([admin, a, b]); db.session.flush()
        db.session.add_all([
            Resident(user_id=a.id, full_name="Warga A", address="Jl. A"),
            Resident(user_id=b.id, full_name="Warga B", address="Jl. B"),
        ])
        db.session.commit()
    yield app

@pytest.fixture
def client(app):
    return app.test_client()

PASSWORD = "rahasia"

@pytest.fixture
def login(client):
    """Login lewat route asli, bukan memalsukan session."""
    def _login(username, password=PASSWORD):
        return client.post(
            "/auth/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )
    return _login
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app, db
from app.auth.utils import admin_required, role_required
from app.models import Document, Resident, Ticket, TicketMessage, User


PASSWORD = "Password123"


def registration_payload(**overrides):
    data = {
        "username": "warga.baru",
        "full_name": "Warga Baru",
        "address": "Jl. Contoh No. 1",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    }
    data.update(overrides)
    return data


def login(client, username="warga1", password=PASSWORD, remember_me=False, **kwargs):
    data = {"username": username, "password": password}
    if remember_me:
        data["remember_me"] = "y"
    return client.post("/auth/login", data=data, **kwargs)


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key",
            "SQLALCHEMY_DATABASE_URI": (
                f"sqlite:///{(tmp_path / 'test.sqlite3').as_posix()}"
            ),
            "WTF_CSRF_ENABLED": False,
            "PRIVATE_STORAGE_DIR": str(tmp_path / "storage"),
            "ADMIN_INVITE_CODE": None,
        }
    )

    @application.get("/_test/admin")
    @admin_required
    def admin_only():
        return "admin-ok"

    @application.get("/_test/warga")
    @role_required("warga")
    def warga_only():
        return "warga-ok"

    with application.app_context():
        db.drop_all()
        db.create_all()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def make_user(app):
    def _make_user(
        username="warga1",
        password=PASSWORD,
        role="warga",
        is_active=True,
        full_name="Warga Test",
        address="Jl. Test No. 1",
    ):
        with app.app_context():
            user = User(
                username=username.strip().lower(),
                role=role,
                is_active=is_active,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.add(
                Resident(
                    user=user,
                    full_name=full_name,
                    address=address,
                )
            )
            db.session.commit()
            return user.id

    return _make_user


def test_login_and_register_pages_render(client):
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert b"Masuk ke Secure RT" in response.data
    assert b'name="username"' in response.data
    assert b'name="password"' in response.data

    response = client.get("/auth/register")
    assert response.status_code == 200
    assert b"Daftar Akun" in response.data
    assert b'name="full_name"' in response.data
    assert b'name="address"' in response.data
    assert b'name="admin_code"' not in response.data


def test_register_creates_warga_and_resident(app, client):
    response = client.post(
        "/auth/register",
        data=registration_payload(),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Registrasi berhasil" in response.data

    with app.app_context():
        user = User.query.filter_by(username="warga.baru").one()
        assert user.role == "warga"
        assert user.is_active is True
        assert user.password_hash != PASSWORD
        assert user.check_password(PASSWORD)
        assert user.resident is not None
        assert user.resident.full_name == "Warga Baru"
        assert user.resident.address == "Jl. Contoh No. 1"


def test_register_rejects_duplicate_username_case_insensitive(app, client, make_user):
    make_user(username="budi")

    response = client.post(
        "/auth/register",
        data=registration_payload(username="Budi"),
    )
    assert response.status_code == 200
    assert b"Username sudah digunakan" in response.data

    with app.app_context():
        assert User.query.count() == 1


@pytest.mark.parametrize(
    ("password", "expected_message"),
    [
        ("pendek1", b"minimal 8 karakter"),
        ("password", b"minimal satu angka"),
        ("12345678", b"minimal satu huruf"),
    ],
)
def test_register_rejects_weak_password(app, client, password, expected_message):
    response = client.post(
        "/auth/register",
        data=registration_payload(
            password=password,
            confirm_password=password,
        ),
    )
    assert response.status_code == 200
    assert expected_message in response.data

    with app.app_context():
        assert User.query.count() == 0


def test_register_rejects_password_mismatch(app, client):
    response = client.post(
        "/auth/register",
        data=registration_payload(confirm_password="Password124"),
    )
    assert response.status_code == 200
    assert b"Konfirmasi password tidak sama" in response.data

    with app.app_context():
        assert User.query.count() == 0


def test_register_with_valid_admin_code_creates_admin(app, client):
    app.config["ADMIN_INVITE_CODE"] = "kode-admin-rahasia"

    response = client.post(
        "/auth/register",
        data=registration_payload(admin_code="kode-admin-rahasia"),
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")

    with app.app_context():
        user = User.query.filter_by(username="warga.baru").one()
        assert user.role == "admin"


def test_register_with_wrong_admin_code_is_rejected(app, client):
    app.config["ADMIN_INVITE_CODE"] = "kode-admin-rahasia"

    response = client.post(
        "/auth/register",
        data=registration_payload(admin_code="kode-salah"),
    )
    assert response.status_code == 200
    assert b"Kode admin tidak valid" in response.data

    with app.app_context():
        assert User.query.count() == 0


def test_admin_code_field_only_shown_when_enabled(app, client):
    app.config["ADMIN_INVITE_CODE"] = "kode-admin-rahasia"
    response = client.get("/auth/register")
    assert response.status_code == 200
    assert b'name="admin_code"' in response.data


def test_login_success_sets_session_and_last_login(app, client, make_user):
    user_id = make_user()

    response = login(client)
    assert response.status_code == 302
    assert "/auth/login" not in response.headers["Location"]

    with client.session_transaction() as session:
        assert session["_user_id"] == str(user_id)

    with app.app_context():
        user = db.session.get(User, user_id)
        assert user.last_login_at is not None


def test_login_wrong_password_fails(app, client, make_user):
    make_user()

    response = login(client, password="PasswordSalah9")
    assert response.status_code == 200
    assert b"Username atau password salah" in response.data

    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_login_unknown_username_uses_generic_message(app, client, make_user):
    make_user()

    response = login(client, username="tidak-ada")
    assert response.status_code == 200
    assert b"Username atau password salah" in response.data
    assert b"tidak ditemukan" not in response.data
    assert b"tidak terdaftar" not in response.data

    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_inactive_account_cannot_login(app, client, make_user):
    make_user(is_active=False)

    response = login(client)
    assert response.status_code == 200
    assert b"Username atau password salah" in response.data

    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_deactivated_user_session_is_invalidated(app, client, make_user):
    user_id = make_user()
    login(client)

    with app.app_context():
        user = db.session.get(User, user_id)
        user.is_active = False
        db.session.commit()

    response = client.get("/_test/warga")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_login_is_case_insensitive_for_username(app, client, make_user):
    make_user(username="budi")

    response = login(client, username="BUDI")
    assert response.status_code == 302

    with client.session_transaction() as session:
        assert "_user_id" in session


def test_logout_clears_session_and_get_is_rejected(app, client, make_user):
    make_user()
    login(client)

    response = client.post("/auth/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"Anda telah keluar" in response.data

    with client.session_transaction() as session:
        assert "_user_id" not in session

    assert client.get("/auth/logout").status_code == 405


def test_logout_with_remember_me_clears_remember_cookie(app, client, make_user):
    make_user()
    response = login(client, remember_me=True)
    assert any(
        "remember_token=" in header
        for header in response.headers.getlist("Set-Cookie")
    )

    response = client.post("/auth/logout")
    assert response.status_code == 302

    response = client.get("/_test/warga")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_logout_requires_csrf_token_when_enabled(app, client, make_user):
    make_user()
    login(client)
    app.config["WTF_CSRF_ENABLED"] = True

    response = client.post("/auth/logout")
    assert response.status_code == 400

    with client.session_transaction() as session:
        assert "_user_id" in session


def test_role_based_access_control(app, client, make_user):
    response = client.get("/_test/admin")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    make_user(username="warga1", role="warga")
    login(client)
    assert client.get("/_test/warga").status_code == 200
    assert client.get("/_test/admin").status_code == 403

    client.post("/auth/logout")

    make_user(username="admin1", role="admin")
    login(client, username="admin1")
    assert client.get("/_test/admin").status_code == 200
    assert client.get("/_test/warga").status_code == 403


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/steal",
        "//evil.example/steal",
        "http://evil.example",
    ],
)
def test_login_blocks_open_redirect(app, client, make_user, target):
    make_user()

    response = client.post(
        "/auth/login",
        query_string={"next": target},
        data={"username": "warga1", "password": PASSWORD},
    )
    assert response.status_code == 302
    assert "evil.example" not in response.headers["Location"]


def test_login_honors_safe_local_next(app, client, make_user):
    make_user()

    response = client.post(
        "/auth/login",
        query_string={"next": "/?from=login"},
        data={"username": "warga1", "password": PASSWORD},
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/?from=login")


def test_login_requires_csrf_token_when_enabled(app, client, make_user):
    make_user()
    app.config["WTF_CSRF_ENABLED"] = True

    response = client.post(
        "/auth/login",
        data={"username": "warga1", "password": PASSWORD},
    )
    assert response.status_code == 200

    with client.session_transaction() as session:
        assert "_user_id" not in session


def test_password_hashes_are_salted(app, make_user):
    first_id = make_user(username="warga1")
    second_id = make_user(username="warga2")

    with app.app_context():
        first = db.session.get(User, first_id)
        second = db.session.get(User, second_id)
        assert first.password_hash != second.password_hash


def test_model_defaults_and_relationships(app, make_user):
    user_id = make_user()

    with app.app_context():
        user = db.session.get(User, user_id)
        ticket = Ticket(
            resident=user.resident,
            service_type="Surat Domisili",
            description="Mohon dibuatkan surat domisili.",
        )
        db.session.add(ticket)
        db.session.commit()
        assert ticket.status == "Diajukan"
        assert ticket.updated_at is not None

        document = Document(
            ticket=ticket,
            uploaded_by=user,
            original_filename="dokumen-dummy.pdf",
            ciphertext_path="private_storage/dokumen-dummy.pdf.enc",
            algorithm="AES-GCM",
        )
        message = TicketMessage(
            ticket=ticket,
            author=user,
            message="Dokumen sudah saya unggah.",
        )
        db.session.add_all([document, message])
        db.session.commit()

        assert ticket.documents[0].uploaded_by.username == "warga1"
        assert ticket.messages[0].author.username == "warga1"
        assert user.uploaded_documents[0].original_filename == "dokumen-dummy.pdf"

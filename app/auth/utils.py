from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import abort, request, url_for
from flask_login import current_user, login_required
from werkzeug.routing import BuildError
from werkzeug.security import check_password_hash, generate_password_hash

from app import db, login_manager
from app.models import Resident, User, utcnow


# Hash dummy dipakai agar username yang tidak ada tetap membutuhkan waktu
# verifikasi yang mirip dengan username yang ada (mengurangi timing attack).
_DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing-only")

VALID_ROLES = {"admin", "warga"}


def normalize_username(username):
    return (username or "").strip().lower()


def create_user(username, password, full_name, address, role="warga"):
    """Buat User beserta data Resident dan simpan ke database."""
    if role not in VALID_ROLES:
        raise ValueError("Role tidak valid.")

    normalized = normalize_username(username)
    if not normalized:
        raise ValueError("Username tidak boleh kosong.")

    user = User(username=normalized, role=role)
    user.set_password(password)
    resident = Resident(
        user=user,
        full_name=(full_name or "").strip(),
        address=(address or "").strip(),
    )
    db.session.add(user)
    db.session.add(resident)
    db.session.commit()
    return user


def authenticate(username, password):
    """Kembalikan User jika kredensial valid dan akun aktif."""
    normalized = normalize_username(username)
    user = User.query.filter(db.func.lower(User.username) == normalized).first()

    if user is None:
        check_password_hash(_DUMMY_PASSWORD_HASH, password or "")
        return None

    if not user.check_password(password or ""):
        return None

    if not user.is_active:
        return None

    return user


def record_login(user):
    user.last_login_at = utcnow()
    db.session.commit()


def role_required(*roles):
    """Batasi route untuk role tertentu; role salah mendapat HTTP 403."""
    allowed = set(roles)

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in allowed:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


admin_required = role_required("admin")


def is_safe_url(target):
    """Pastikan redirect hanya menuju host aplikasi sendiri."""
    if not target:
        return False
    if "\\" in target or "\n" in target or "\r" in target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def default_dashboard_url(user=None):
    """Pilih dashboard yang tersedia, dengan fallback ke halaman index."""
    if user is None and current_user.is_authenticated:
        user = current_user

    endpoints = []
    if user is not None and getattr(user, "is_admin", False):
        endpoints.append("admin.dashboard")
    else:
        endpoints.append("resident.dashboard")
    endpoints.append("index")

    for endpoint in endpoints:
        try:
            return url_for(endpoint)
        except BuildError:
            continue
    return "/"


def safe_next_url(target, user=None):
    if target and is_safe_url(target):
        return target
    return default_dashboard_url(user)


@login_manager.user_loader
def load_user(user_id):
    try:
        user = db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
    if user is None or not user.is_active:
        return None
    return user

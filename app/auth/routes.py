from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from app import db
from app.auth.forms import LoginForm, LogoutForm, RegistrationForm
from app.auth.utils import (
    authenticate,
    create_user,
    default_dashboard_url,
    record_login,
    safe_next_url,
)


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _admin_registration_enabled():
    return bool(current_app.config.get("ADMIN_INVITE_CODE"))


def _render_register(form):
    return render_template(
        "auth/login.html",
        mode="register",
        form=form,
        admin_registration_enabled=_admin_registration_enabled(),
    )


def _render_login(form, next_url=""):
    return render_template(
        "auth/login.html",
        mode="login",
        form=form,
        next_url=next_url,
    )


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(default_dashboard_url(current_user))

    form = RegistrationForm()
    if form.validate_on_submit():
        role = "admin" if form.admin_code.data else "warga"
        try:
            create_user(
                username=form.username.data,
                password=form.password.data,
                full_name=form.full_name.data,
                address=form.address.data,
                role=role,
            )
        except IntegrityError:
            db.session.rollback()
            form.username.errors.append("Username sudah digunakan.")
        else:
            flash("Registrasi berhasil. Silakan masuk.", "success")
            return redirect(url_for("auth.login"))

    return _render_register(form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(default_dashboard_url(current_user))

    form = LoginForm()
    next_url = request.args.get("next") or request.form.get("next") or ""

    if form.validate_on_submit():
        user = authenticate(form.username.data, form.password.data)
        if user is None:
            flash(
                "Username atau password salah, atau akun tidak aktif.",
                "danger",
            )
            return _render_login(form, next_url)

        # Bersihkan session lama sebelum membuat session login baru.
        session.clear()
        login_user(user, remember=form.remember_me.data)
        record_login(user)
        flash(f"Selamat datang, {user.username}.", "success")
        return redirect(safe_next_url(next_url, user=user))

    return _render_login(form, next_url)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    form = LogoutForm()
    if not form.validate_on_submit():
        abort(400)

    session.clear()
    logout_user()
    flash("Anda telah keluar.", "success")
    return redirect(url_for("auth.login"))

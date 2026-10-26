import hmac
import re

from flask import current_app
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import (
    DataRequired,
    EqualTo,
    Length,
    Optional,
    Regexp,
    ValidationError,
)

from app import db
from app.models import User


USERNAME_PATTERN = r"^[A-Za-z0-9_.-]+$"


def strip_filter(value):
    return value.strip() if isinstance(value, str) else value


def strong_password(form, field):
    value = field.data or ""
    if len(value) < 8:
        raise ValidationError("Password minimal 8 karakter.")
    if len(value) > 128:
        raise ValidationError("Password maksimal 128 karakter.")
    if not re.search(r"[A-Za-z]", value):
        raise ValidationError("Password harus mengandung minimal satu huruf.")
    if not re.search(r"\d", value):
        raise ValidationError("Password harus mengandung minimal satu angka.")


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username wajib diisi."),
            Length(
                min=3,
                max=32,
                message="Username harus terdiri dari 3-32 karakter.",
            ),
            Regexp(
                USERNAME_PATTERN,
                message=(
                    "Username hanya boleh berisi huruf, angka, titik, "
                    "garis bawah, atau tanda hubung."
                ),
            ),
        ],
        filters=[strip_filter],
    )
    full_name = StringField(
        "Nama lengkap",
        validators=[
            DataRequired(message="Nama lengkap wajib diisi."),
            Length(
                min=3,
                max=160,
                message="Nama lengkap harus terdiri dari 3-160 karakter.",
            ),
        ],
        filters=[strip_filter],
    )
    address = TextAreaField(
        "Alamat",
        validators=[
            DataRequired(message="Alamat wajib diisi."),
            Length(
                min=5,
                max=255,
                message="Alamat harus terdiri dari 5-255 karakter.",
            ),
        ],
        filters=[strip_filter],
        render_kw={"rows": 3},
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password wajib diisi."),
            strong_password,
        ],
    )
    confirm_password = PasswordField(
        "Konfirmasi password",
        validators=[
            DataRequired(message="Konfirmasi password wajib diisi."),
            EqualTo("password", message="Konfirmasi password tidak sama."),
        ],
    )
    admin_code = PasswordField(
        "Kode admin (opsional)",
        validators=[
            Optional(),
            Length(max=128, message="Kode admin terlalu panjang."),
        ],
        filters=[strip_filter],
    )
    submit = SubmitField("Daftar")

    def validate_username(self, field):
        normalized = (field.data or "").strip().lower()
        existing = User.query.filter(
            db.func.lower(User.username) == normalized
        ).first()
        if existing is not None:
            raise ValidationError("Username sudah digunakan.")

    def validate_admin_code(self, field):
        code = field.data or ""
        if not code:
            return
        expected = current_app.config.get("ADMIN_INVITE_CODE")
        if not expected:
            raise ValidationError("Registrasi admin tidak diaktifkan.")
        if not hmac.compare_digest(
            str(code).encode("utf-8"), str(expected).encode("utf-8")
        ):
            raise ValidationError("Kode admin tidak valid.")


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username wajib diisi."),
            Length(max=80, message="Username terlalu panjang."),
        ],
        filters=[strip_filter],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password wajib diisi."),
            Length(max=128, message="Password terlalu panjang."),
        ],
    )
    remember_me = BooleanField("Ingat saya")
    submit = SubmitField("Masuk")


class LogoutForm(FlaskForm):
    submit = SubmitField("Keluar")

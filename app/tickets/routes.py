# Anggota 3: pembuatan tiket, revisi, upload/download. Wajib cek autentikasi dan kepemilikan.

import io
import logging
import uuid
from pathlib import PurePath

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import User, Resident, Ticket, Document

# Kontrak yang harus disediakan oleh anggota tim kriptografi.
from app.crypto.storage import (
    save_encrypted_file,
    load_decrypted_file,
    delete_encrypted_file,
)


tickets_bp = Blueprint(
    "tickets",
    __name__,
    url_prefix="/tiket",
)

# Sesuaikan daftar ini dengan layanan resmi Secure RT.
ALLOWED_SERVICE_TYPES = {
    "Administrasi",
    "Keamanan",
    "Kebersihan",
    "Infrastruktur",
    "Lainnya",
}

MAX_DESCRIPTION_LENGTH = 3000
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB

# Hanya format yang didukung pemeriksaan signature di bawah.
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}

logger = logging.getLogger(__name__)


def _is_resident():
    """Periksa role tanpa mempercayai input dari browser."""
    return (
        current_user.is_authenticated
        and getattr(current_user, "role", None) == "warga"
    )


def _get_current_resident():
    """Cari profil warga berdasarkan akun yang sedang login."""
    return Resident.query.filter_by(
        user_id=current_user.id
    ).first()


def _get_owned_ticket(ticket_id):
    """
    Ambil tiket hanya jika tiket tersebut dimiliki profil warga
    yang terkait dengan akun saat ini.
    """
    resident = _get_current_resident()

    if resident is None:
        # Tidak mengungkap apakah suatu tiket milik orang lain.
        abort(404)

    ticket = Ticket.query.filter_by(
        id=ticket_id,
        resident_id=resident.id,
    ).first()

    if ticket is None:
        abort(404)

    return ticket


def _validate_and_read_upload(upload):
    """
    Validasi nama, ekstensi, ukuran, dan signature file.
    Mengembalikan (safe_display_name, extension, content_type, data).
    """
    if upload is None or not upload.filename:
        abort(400, description="Lampiran tidak tersedia.")

    # Nama ini hanya untuk metadata, tidak pernah digunakan sebagai path.
    display_name = secure_filename(
        PurePath(upload.filename.replace("\\", "/")).name
    )

    if not display_name:
        abort(400, description="Nama file tidak valid.")

    extension = PurePath(display_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        abort(400, description="Format lampiran tidak didukung.")

    # Baca maksimal satu byte di atas batas agar ukuran dapat diperiksa.
    data = upload.stream.read(MAX_FILE_SIZE + 1)

    if not data:
        abort(400, description="File kosong tidak dapat diunggah.")

    if len(data) > MAX_FILE_SIZE:
        abort(413, description="Ukuran lampiran melebihi batas 5 MiB.")

    # Pemeriksaan signature dasar untuk format yang diizinkan.
    if extension == ".pdf":
        valid_signature = data.startswith(b"%PDF-")
        content_type = "application/pdf"

    elif extension == ".png":
        valid_signature = data.startswith(
            b"\x89PNG\r\n\x1a\n"
        )
        content_type = "image/png"

    elif extension in {".jpg", ".jpeg"}:
        valid_signature = (
            len(data) >= 3
            and data.startswith(b"\xff\xd8\xff")
        )
        content_type = "image/jpeg"

    else:
        valid_signature = False
        content_type = "application/octet-stream"

    if not valid_signature:
        abort(
            400,
            description="Isi file tidak sesuai dengan format yang diizinkan.",
        )

    return display_name, extension, content_type, data


@tickets_bp.route("/buat", methods=["GET", "POST"])
@login_required
def create_ticket():
    """Menampilkan dan memproses pengajuan tiket baru."""

    if not _is_resident():
        abort(403)

    resident = _get_current_resident()

    if resident is None:
        flash(
            "Profil warga belum tersedia. Hubungi pengurus RT.",
            "warning",
        )
        return redirect(url_for("tickets.create_ticket"))

    if request.method == "GET":
        return render_template(
            "tickets/create.html",
            service_types=sorted(ALLOWED_SERVICE_TYPES),
        )

    # Validasi seluruh input sebelum membuat record.
    service_type = request.form.get("service_type", "").strip()
    description = request.form.get("description", "").strip()

    if service_type not in ALLOWED_SERVICE_TYPES:
        flash("Jenis layanan tidak valid.", "danger")
        return render_template(
            "tickets/create.html",
            service_types=sorted(ALLOWED_SERVICE_TYPES),
        ), 400

    if not description or len(description) > MAX_DESCRIPTION_LENGTH:
        flash(
            "Deskripsi wajib diisi dan maksimal 3000 karakter.",
            "danger",
        )
        return render_template(
            "tickets/create.html",
            service_types=sorted(ALLOWED_SERVICE_TYPES),
        ), 400

    ticket = Ticket(
        resident_id=resident.id,
        service_type=service_type,
        description=description,
        # Status selalu ditentukan server.
        status="Diajukan",
    )

    try:
        db.session.add(ticket)
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        logger.exception("Gagal membuat tiket baru.")
        flash("Pengajuan tiket gagal diproses. Silakan coba lagi.", "danger")
        return render_template(
            "tickets/create.html",
            service_types=sorted(ALLOWED_SERVICE_TYPES),
        ), 500

    flash("Tiket berhasil diajukan.", "success")
    return redirect(
        url_for("tickets.ticket_detail", ticket_id=ticket.id)
    )


@tickets_bp.route("/<int:ticket_id>", methods=["GET"])
@login_required
def ticket_detail(ticket_id):
    """Detail hanya dapat dibuka oleh pemilik tiket."""

    if not _is_resident():
        abort(403)

    ticket = _get_owned_ticket(ticket_id)

    # Lampiran diambil melalui foreign key tiket, bukan ID pengguna.
    documents = Document.query.filter_by(
        ticket_id=ticket.id
    ).all()

    return render_template(
        "tickets/detail.html",
        ticket=ticket,
        documents=documents,
    )


@tickets_bp.route(
    "/<int:ticket_id>/lampiran",
    methods=["POST"],
)
@login_required
def upload_attachment(ticket_id):
    """Unggah lampiran ke tiket yang dimiliki warga saat ini."""

    if not _is_resident():
        abort(403)

    # Otorisasi harus terjadi sebelum membaca atau menyimpan file.
    ticket = _get_owned_ticket(ticket_id)

    upload = request.files.get("file")
    display_name, extension, content_type, data = (
        _validate_and_read_upload(upload)
    )

    # Batas jumlah lampiran dapat diatur sesuai kebutuhan proyek.
    max_documents = current_app.config.get("MAX_DOCUMENTS_PER_TICKET", 5)

    document_count = Document.query.filter_by(
        ticket_id=ticket.id
    ).count()

    if document_count >= max_documents:
        abort(400, description="Jumlah lampiran tiket sudah mencapai batas.")

    # Identifier acak, bukan nama file dari browser.
    storage_key = uuid.uuid4().hex

    document = Document(
        ticket_id=ticket.id,
        storage_key=storage_key,
        original_filename=display_name,
        content_type=content_type,
        size_bytes=len(data),
    )

    stored = False

    try:
        # Data plaintext hanya diberikan ke layanan kriptografi.
        save_encrypted_file(storage_key, data)
        stored = True

        db.session.add(document)
        db.session.commit()

    except Exception:
        db.session.rollback()

        # Kompensasi jika file tersimpan tetapi metadata gagal.
        if stored:
            try:
                delete_encrypted_file(storage_key)
            except Exception:
                logger.exception(
                    "Pembersihan file yatim gagal; storage_key=%s",
                    storage_key,
                )

        logger.exception("Gagal menyimpan lampiran.")
        flash("Lampiran gagal disimpan. Silakan coba lagi.", "danger")
        return redirect(
            url_for("tickets.ticket_detail", ticket_id=ticket.id)
        ), 500

    flash("Lampiran berhasil diunggah.", "success")
    return redirect(
        url_for("tickets.ticket_detail", ticket_id=ticket.id)
    )


@tickets_bp.route(
    "/<int:ticket_id>/lampiran/<int:document_id>/unduh",
    methods=["GET"],
)
@login_required
def download_attachment(ticket_id, document_id):
    """Unduh lampiran setelah memeriksa kepemilikan tiket."""

    if not _is_resident():
        abort(403)

    # Memastikan tiket memang milik warga yang sedang login.
    ticket = _get_owned_ticket(ticket_id)

    # Pastikan dokumen terhubung ke tiket yang sudah diotorisasi.
    document = Document.query.filter_by(
        id=document_id,
        ticket_id=ticket.id,
    ).first()

    if document is None:
        abort(404)

    try:
        # Layanan mengembalikan plaintext hanya setelah dekripsi berhasil.
        plaintext = load_decrypted_file(document.storage_key)

    except Exception:
        logger.exception(
            "Gagal mengambil lampiran; document_id=%s",
            document.id,
        )
        abort(500, description="Lampiran tidak dapat diunduh saat ini.")

    # File dikirim dari memori setelah dekripsi, bukan dari static/.
    return send_file(
        io.BytesIO(plaintext),
        mimetype=document.content_type,
        as_attachment=True,
        download_name=document.original_filename,
        max_age=0,
    )

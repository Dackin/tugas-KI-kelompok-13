# Anggota 3: pembuatan tiket, revisi, upload/download. Wajib cek autentikasi dan kepemilikan.

import io
import logging
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
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from app.crypto import get_master_key
from app.crypto.errors import CryptoError
from app.crypto.storage import decrypt_file, delete_file, encrypt_file
from app.extensions import db
from app.models import Document, Resident, Ticket, User


tickets_bp = Blueprint(
    "tickets",
    __name__,
    url_prefix="/tiket",
)

# Satu sumber kebenaran untuk dropdown dan validasi server.
ALLOWED_SERVICE_TYPES = {
    "Surat Pengantar KTP",
    "Surat Pengantar KK",
    "Surat Keterangan Domisili",
    "Surat Keterangan Tidak Mampu",
    "Surat Keterangan Usaha",
    "Surat Pengantar Pindah",
    "Lainnya",
}

MAX_DESCRIPTION_LENGTH = 2000
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


def _document_context(ticket, filename):
    """Context yang diautentikasi sebagai AAD saat enkripsi/dekripsi."""
    return {
        "ticket_id": ticket.id,
        "uploaded_by_user_id": current_user.id,
        "original_filename": filename,
    }


def _simpan_lampiran(ticket, upload):
    """Validasi, enkripsi, lalu kembalikan (Document, StoredFile)."""
    display_name, _extension, content_type, data = _validate_and_read_upload(upload)

    batas = current_app.config.get("MAX_DOCUMENTS_PER_TICKET", 5)
    if Document.query.filter_by(ticket_id=ticket.id).count() >= batas:
        abort(400, description="Jumlah lampiran tiket sudah mencapai batas.")

    try:
        stored = encrypt_file(
            data,
            storage_root=current_app.config["PRIVATE_STORAGE_DIR"],
            key=get_master_key(current_app.config),
            context=_document_context(ticket, display_name),
        )
    except CryptoError:
        logger.exception("Gagal mengenkripsi lampiran.")
        abort(500, description="Lampiran gagal diproses.")

    document = Document(
        ticket_id=ticket.id,
        uploaded_by_user_id=current_user.id,
        original_filename=display_name,
        ciphertext_path=stored.ciphertext_path,
        algorithm=stored.algorithm,
        crypto_metadata_json=stored.crypto_metadata_json,
        content_type=content_type,
        size_bytes=len(data),
    )
    return document, stored


def _hapus_ciphertext(document):
    """Kompensasi bila metadata gagal disimpan setelah file terenkripsi."""
    try:
        delete_file(
            ciphertext_path=document.ciphertext_path,
            storage_root=current_app.config["PRIVATE_STORAGE_DIR"],
        )
    except Exception:
        logger.exception(
            "Pembersihan ciphertext yatim gagal: %s", document.ciphertext_path
        )


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
            "Deskripsi wajib diisi dan maksimal 2000 karakter.",
            "danger",
        )
        return render_template(
            "tickets/create.html",
            service_types=sorted(ALLOWED_SERVICE_TYPES),
        ), 400

    if request.form.get("confirm_information") != "yes":
        flash(
            "Centang pernyataan bahwa informasi yang diberikan sudah benar.",
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

    document = None
    try:
        db.session.add(ticket)
        db.session.flush()

        upload = request.files.get("attachment")
        if upload is not None and upload.filename:
            document, _stored = _simpan_lampiran(ticket, upload)
            db.session.add(document)

        db.session.commit()

    except HTTPException:
        db.session.rollback()
        raise

    except Exception:
        db.session.rollback()
        if document is not None:
            _hapus_ciphertext(document)
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
        attachments=documents,
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

    if ticket.status not in {"Diajukan", "Perlu Revisi"}:
        abort(400, description="Lampiran tidak dapat diunggah pada status ini.")

    upload = request.files.get("attachment")

    document = None
    try:
        document, _stored = _simpan_lampiran(ticket, upload)
        db.session.add(document)
        db.session.commit()

    except HTTPException:
        db.session.rollback()
        raise

    except Exception:
        db.session.rollback()
        if document is not None:
            _hapus_ciphertext(document)
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
        plaintext = decrypt_file(
            ciphertext_path=document.ciphertext_path,
            storage_root=current_app.config["PRIVATE_STORAGE_DIR"],
            key=get_master_key(current_app.config),
            context={
                "ticket_id": document.ticket_id,
                "uploaded_by_user_id": document.uploaded_by_user_id,
                "original_filename": document.original_filename,
            },
            algorithm=document.algorithm,
            metadata=document.crypto_metadata_json,
        )

    except CryptoError:
        logger.warning(
            "Lampiran gagal didekripsi; document_id=%s", document.id
        )
        abort(400, description="Lampiran tidak dapat dibuka.")

    except Exception:
        logger.exception(
            "Gagal mengambil lampiran; document_id=%s",
            document.id,
        )
        abort(500, description="Lampiran tidak dapat diunduh saat ini.")

    # File dikirim dari memori setelah dekripsi, bukan dari static/.
    return send_file(
        io.BytesIO(plaintext),
        mimetype=document.content_type or "application/octet-stream",
        as_attachment=True,
        download_name=document.original_filename,
        max_age=0,
    )

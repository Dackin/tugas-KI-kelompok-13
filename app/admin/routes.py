# Anggota 3: antrean tiket admin dan perubahan status.

import io
import logging

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

from app.extensions import db
from app.models import User, Resident, Ticket, Document

# Model audit bersifat opsional. Tim database perlu menyediakan
# model ini jika audit log belum tersedia.
try:
    from app.models import AuditLog
except ImportError:
    AuditLog = None

# Kontrak layanan kriptografi: fungsi ini harus benar-benar
# diimplementasikan dalam app/crypto/storage.py.
from app.crypto.storage import decrypt_file


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
)

logger = logging.getLogger(__name__)

ALLOWED_STATUSES = {
    "Diajukan",
    "Diproses",
    "Perlu Revisi",
    "Selesai",
    "Ditolak",
}

# Kebijakan transisi status. Perubahan harus disepakati
# dengan pemilik proses bisnis, bukan dikirim bebas dari browser.
ALLOWED_TRANSITIONS = {
    "Diajukan": {"Diproses", "Ditolak"},
    "Diproses": {"Perlu Revisi", "Selesai", "Ditolak"},
    "Perlu Revisi": {"Diajukan", "Diproses", "Ditolak"},
    "Selesai": set(),
    "Ditolak": set(),
}

MAX_ADMIN_NOTE_LENGTH = 2000


def _require_admin():
    """
    Tolak akses jika pengguna belum login atau bukan admin.
    @login_required tetap digunakan pada setiap route.
    """
    if not current_user.is_authenticated:
        abort(401)

    if getattr(current_user, "role", None) != "admin":
        abort(403)


def _get_ticket_or_404(ticket_id):
    """Ambil tiket berdasarkan ID atau kembalikan 404."""
    ticket = Ticket.query.filter_by(id=ticket_id).first()

    if ticket is None:
        abort(404)

    return ticket


def _get_status_counts():
    """Hitung jumlah tiket per status langsung di database."""
    from sqlalchemy import func

    rows = (
        db.session.query(
            Ticket.status,
            func.count(Ticket.id),
        )
        .group_by(Ticket.status)
        .all()
    )

    counts = {status: 0 for status in sorted(ALLOWED_STATUSES)}

    for status, count in rows:
        if status in counts:
            counts[status] = count
        else:
            # Jangan diam-diam menyamakan status lama/tidak dikenal.
            counts[status] = count

    return counts


def _validate_admin_note(raw_note):
    """
    Validasi panjang catatan. Escaping HTML dilakukan oleh
    Jinja2 ketika catatan dirender, bukan dengan menyimpan HTML
    yang telah di-escape ke database.
    """
    note = (raw_note or "").strip()

    if len(note) > MAX_ADMIN_NOTE_LENGTH:
        abort(
            400,
            description="Catatan admin maksimal 2000 karakter.",
        )

    return note


def _record_audit(ticket, old_status, new_status, note):
    """
    Catat perubahan dalam transaksi database yang sama.
    Jika model audit belum tersedia, keluarkan peringatan agar
    konfigurasi produksi tidak mengklaim audit sudah aktif.
    """
    if AuditLog is None:
        current_app.logger.warning(
            "AuditLog belum tersedia; perubahan tiket "
            "tidak memiliki audit log permanen. ticket_id=%s",
            ticket.id,
        )
        return

    audit = AuditLog(
        ticket_id=ticket.id,
        admin_user_id=current_user.id,
        old_status=old_status,
        new_status=new_status,
        note=note or None,
    )

    db.session.add(audit)


@admin_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """Ringkasan dan daftar pengajuan untuk admin."""

    _require_admin()

    try:
        status_counts = _get_status_counts()

        # Query eksplisit, tidak mengasumsikan relasi ORM.
        tickets = (
            Ticket.query
            .order_by(
                Ticket.created_at.desc(),
                Ticket.id.desc(),
            )
            .limit(100)
            .all()
        )

        total_tickets = sum(status_counts.values())

    except SQLAlchemyError:
        logger.exception("Gagal memuat dashboard admin.")
        abort(500, description="Dashboard tidak dapat dimuat.")

    return render_template(
        "admin/dashboard.html",
        tickets=tickets,
        status_counts=status_counts,
        total_tickets=total_tickets,
        allowed_statuses=sorted(ALLOWED_STATUSES),
    )


@admin_bp.route("/tiket/<int:ticket_id>", methods=["GET"])
@login_required
def ticket_detail(ticket_id):
    """Detail pengajuan hanya dapat diakses admin."""

    _require_admin()
    ticket = _get_ticket_or_404(ticket_id)

    # Ambil metadata lampiran saja. File tidak didekripsi pada
    # saat halaman detail dirender.
    documents = (
        Document.query
        .filter_by(ticket_id=ticket.id)
        .order_by(Document.id.asc())
        .all()
    )

    audit_logs = []

    if AuditLog is not None:
        audit_logs = (
            AuditLog.query
            .filter_by(ticket_id=ticket.id)
            .order_by(AuditLog.created_at.desc())
            .limit(50)
            .all()
        )

    return render_template(
        "admin/ticket_detail.html",
        ticket=ticket,
        documents=documents,
        audit_logs=audit_logs,
        allowed_statuses=sorted(ALLOWED_STATUSES),
        allowed_transitions=ALLOWED_TRANSITIONS.get(
            ticket.status, set()
        ),
    )


@admin_bp.route(
    "/tiket/<int:ticket_id>/status",
    methods=["POST"],
)
@login_required
def update_ticket_status(ticket_id):
    """Ubah status dan catat tindakan admin."""

    _require_admin()
    ticket = _get_ticket_or_404(ticket_id)

    new_status = request.form.get("status", "").strip()
    note = _validate_admin_note(request.form.get("note", ""))

    # Status dari browser harus cocok persis dengan daftar resmi.
    if new_status not in ALLOWED_STATUSES:
        abort(400, description="Status yang diminta tidak valid.")

    old_status = ticket.status

    # Menolak status yang tidak berubah maupun transisi terlarang.
    allowed_next = ALLOWED_TRANSITIONS.get(old_status)

    if allowed_next is None or new_status not in allowed_next:
        flash(
            "Perubahan status tidak diizinkan dari status saat ini.",
            "danger",
        )
        return redirect(
            url_for("admin.ticket_detail", ticket_id=ticket.id)
        ), 303

    try:
        ticket.status = new_status

        _record_audit(
            ticket=ticket,
            old_status=old_status,
            new_status=new_status,
            note=note,
        )

        # Status dan audit log disimpan dalam satu transaksi.
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        logger.exception(
            "Gagal mengubah status tiket; ticket_id=%s",
            ticket.id,
        )
        flash(
            "Perubahan tidak berhasil disimpan. Silakan coba lagi.",
            "danger",
        )
        return redirect(
            url_for("admin.ticket_detail", ticket_id=ticket.id)
        ), 303

    flash("Status tiket berhasil diperbarui.", "success")
    return redirect(
        url_for("admin.ticket_detail", ticket_id=ticket.id)
    ), 303


@admin_bp.route(
    "/tiket/<int:ticket_id>/lampiran/<int:document_id>/unduh",
    methods=["GET"],
)
@login_required
def download_attachment(ticket_id, document_id):
    """
    Unduh lampiran melalui layanan penyimpanan terenkripsi.
    Tidak membaca file dari static/ atau path yang diberikan user.
    """

    _require_admin()
    ticket = _get_ticket_or_404(ticket_id)

    # Pastikan dokumen memang milik tiket yang telah ditemukan.
    document = Document.query.filter_by(
        id=document_id,
        ticket_id=ticket.id,
    ).first()

    if document is None:
        abort(404)

    try:
        # storage_key berasal dari database tepercaya, bukan request.
        plaintext = decrypt_file(document.storage_key)

    except Exception:
        logger.exception(
            "Gagal mengambil lampiran terenkripsi; document_id=%s",
            document.id,
        )
        abort(500, description="Lampiran tidak dapat diunduh saat ini.")

    # Nama file hanya metadata download, bukan path penyimpanan.
    # Tipe MIME dibatasi ke daftar yang diperbolehkan.
    allowed_mime_types = {
        "application/pdf",
        "image/png",
        "image/jpeg",
    }

    content_type = document.content_type

    if content_type not in allowed_mime_types:
        content_type = "application/octet-stream"

    return send_file(
        io.BytesIO(plaintext),
        mimetype=content_type,
        as_attachment=True,
        download_name=document.original_filename,
        max_age=0,
    )

# Anggota 3: dashboard warga dan daftar tiket milik pengguna yang login.


from flask import Blueprint, abort, flash, render_template, request
from flask_login import current_user, login_required
from sqlalchemy import func

from app.models import User, Resident, Ticket


# Blueprint khusus halaman warga.
resident_bp = Blueprint(
    "resident",
    __name__,
    url_prefix="/warga"
)


def _get_current_resident():
    """
    Mengambil profil Resident berdasarkan akun yang sedang login.
    Tidak menggunakan user ID dari URL maupun form.
    """
    return Resident.query.filter_by(
        user_id=current_user.id
    ).first()


def _get_ticket_status_counts(resident_id):
    """
    Menghitung jumlah tiket milik satu warga berdasarkan status.
    Hasil berupa dictionary: {status: jumlah}.
    """
    rows = (
        Ticket.query
        .with_entities(
            Ticket.status,
            func.count(Ticket.id)
        )
        .filter(Ticket.resident_id == resident_id)
        .group_by(Ticket.status)
        .all()
    )

    return {
        status if status is not None else "Tidak diketahui": count
        for status, count in rows
    }


def _get_ticket_query(resident_id):
    """
    Query dasar tiket yang dibatasi pada profil warga tertentu.
    Semua route yang memakai query ini tetap harus memperoleh
    resident_id dari profil current_user.
    """
    return Ticket.query.filter(
        Ticket.resident_id == resident_id
    )


@resident_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """Menampilkan dashboard warga yang sedang login."""

    # Pastikan hanya akun dengan role warga yang dapat mengakses.
    if current_user.role != "warga":
        abort(403)

    resident = _get_current_resident()

    # Profil mungkin belum dibuat meskipun akun sudah terdaftar.
    if resident is None:
        flash(
            "Profil warga belum tersedia. "
            "Silakan hubungi pengurus RT untuk melengkapi profil.",
            "warning"
        )

        return render_template(
            "resident/dashboard.html",
            resident=None,
            total_tickets=0,
            status_counts={},
            recent_tickets=[]
        )

    # Ambil tiket hanya milik warga yang sedang login.
    ticket_query = _get_ticket_query(resident.id)

    total_tickets = ticket_query.count()

    status_counts = _get_ticket_status_counts(resident.id)

    # Tampilkan maksimal lima tiket terbaru.
    recent_tickets = (
        ticket_query
        .order_by(
            Ticket.created_at.desc(),
            Ticket.id.desc()
        )
        .limit(5)
        .all()
    )

    return render_template(
        "resident/dashboard.html",
        resident=resident,
        total_tickets=total_tickets,
        status_counts=status_counts,
        recent_tickets=recent_tickets
    )


@resident_bp.route("/tiket", methods=["GET"])
@login_required
def ticket_list():
    """Menampilkan daftar tiket milik warga yang sedang login."""

    # Batasi akses berdasarkan role.
    if current_user.role != "warga":
        abort(403)

    resident = _get_current_resident()

    # Tetap tampilkan halaman dengan daftar kosong jika profil
    # belum tersedia, tanpa mengambil tiket milik akun lain.
    if resident is None:
        flash(
            "Profil warga belum tersedia. "
            "Daftar tiket belum dapat ditampilkan.",
            "warning"
        )

        return render_template(
            "resident/ticket_list.html",
            resident=None,
            tickets=[],
            total_tickets=0,
            status_counts={}
        )

    # Filter status hanya mempersempit daftar milik sendiri.
    selected_status = request.args.get("status", "").strip()
    query = _get_ticket_query(resident.id)
    if selected_status in {
        "Diajukan", "Diproses", "Perlu Revisi", "Selesai", "Ditolak"
    }:
        query = query.filter(Ticket.status == selected_status)

    tickets = (
        query
        .order_by(
            Ticket.created_at.desc(),
            Ticket.id.desc()
        )
        .all()
    )

    status_counts = _get_ticket_status_counts(resident.id)

    return render_template(
        "resident/ticket_list.html",
        resident=resident,
        tickets=tickets,
        total_tickets=len(tickets),
        status_counts=status_counts,
        selected_status=selected_status,
    )

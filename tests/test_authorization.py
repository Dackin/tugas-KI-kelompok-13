"""Anggota 4: pastikan warga A tidak bisa melihat/mengunduh dokumen warga B.

Tes ini ditulis terhadap kontrak route (lihat docs/PEMBAGIAN_TUGAS.md).
Selama route belum ada, tes ini MERAH dengan status 404 — itu wajar.
Hijau = Anggota 1 (auth) dan Anggota 3 (tiket/dokumen/admin) sudah selesai.
"""
from app import db
from app.models import Document, Resident, Ticket, User


def _id_warga(app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        resident = Resident.query.filter_by(user_id=user.id).one()
        return user.id, resident.id


def _siapkan_data(app):
    """Buat 1 tiket milik warga A, 1 tiket + 1 dokumen milik warga B."""
    user_b_id, resident_b_id = _id_warga(app, "warga_b")
    _, resident_a_id = _id_warga(app, "warga_a")
    with app.app_context():
        tiket_a = Ticket(
            resident_id=resident_a_id,
            service_type="Surat Domisili (WARGA_A)",
            description="ISI_TIKET_WARGA_A",
        )
        tiket_b = Ticket(
            resident_id=resident_b_id,
            service_type="Surat Usaha (WARGA_B)",
            description="ISI_TIKET_WARGA_B",
        )
        db.session.add_all([tiket_a, tiket_b])
        db.session.commit()

        dokumen_b = Document(
            ticket_id=tiket_b.id,
            uploaded_by_user_id=user_b_id,
            original_filename="ktp_warga_b.pdf",
            ciphertext_path="2026/10/palsu.bin",
            algorithm="AES-GCM",
            crypto_metadata_json="{}",
        )
        db.session.add(dokumen_b)
        db.session.commit()
        return tiket_a.id, tiket_b.id, dokumen_b.id


def test_anonim_diarahkan_ke_login(client):
    r = client.get("/resident/")
    assert r.status_code == 302
    assert "/auth/login" in r.headers["Location"]


def test_anonim_tidak_bisa_unduh_dokumen(client):
    r = client.get("/documents/1/download")
    assert r.status_code == 302
    assert "/auth/login" in r.headers.get("Location", "")


def test_warga_hanya_melihat_tiket_miliknya(app, client, login):
    _siapkan_data(app)
    login("warga_a")
    r = client.get("/resident/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "WARGA_A" in body
    assert "WARGA_B" not in body, "dashboard warga membocorkan tiket warga lain"


def test_warga_bisa_buka_tiket_miliknya(app, client, login):
    """Positive control: tanpa ini, tes negatif di bawah bisa lulus hanya
    karena route-nya belum ada (404)."""
    tiket_a_id, _, _ = _siapkan_data(app)
    login("warga_a")
    r = client.get(f"/tickets/{tiket_a_id}")
    assert r.status_code == 200
    assert b"ISI_TIKET_WARGA_A" in r.data


def test_warga_tidak_bisa_buka_tiket_warga_lain(app, client, login):
    _, tiket_b_id, _ = _siapkan_data(app)
    login("warga_a")
    r = client.get(f"/tickets/{tiket_b_id}")
    assert r.status_code in (403, 404)
    assert b"ISI_TIKET_WARGA_B" not in r.data


def test_warga_tidak_bisa_unduh_dokumen_warga_lain(app, client, login):
    _, _, dokumen_b_id = _siapkan_data(app)
    login("warga_a")
    r = client.get(f"/documents/{dokumen_b_id}/download")
    assert r.status_code in (403, 404), "harus ditolak, bukan error 500"
    assert b"ktp_warga_b" not in r.data


def test_warga_tidak_bisa_masuk_admin(app, client, login):
    login("warga_a")
    r = client.get("/admin/tiket")
    assert r.status_code == 403


def test_admin_bisa_melihat_semua_tiket(app, client, login):
    _siapkan_data(app)
    login("admin")
    r = client.get("/admin/tiket")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "WARGA_A" in body
    assert "WARGA_B" in body


def test_admin_bisa_mengubah_status(app, client, login):
    tiket_a_id, _, _ = _siapkan_data(app)
    login("admin")
    client.post(f"/admin/tiket/{tiket_a_id}/status", data={"status": "Diproses"})
    with app.app_context():
        assert db.session.get(Ticket, tiket_a_id).status == "Diproses"

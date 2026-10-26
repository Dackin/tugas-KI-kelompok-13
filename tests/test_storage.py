"""Anggota 4: uji penyimpanan privat dan download melalui route terproteksi.

Kontrak yang diuji (lihat docs/PEMBAGIAN_TUGAS.md):
- upload  : POST /tiket/<id>/lampiran, multipart field `attachment`
- download: GET  /tiket/<id>/lampiran/<id>/unduh
- `Document.ciphertext_path` relatif terhadap PRIVATE_STORAGE_DIR
- route download memeriksa login + kepemilikan SEBELUM membaca file
"""

import io
import stat
from pathlib import Path

from app import db
from app.models import Document, Resident, Ticket, User

# Harus lolos pemeriksaan signature %PDF- di route upload.
PLAINTEXT = b"%PDF-1.4\n" + b"RAHASIA_KTP_WARGA_A\n" + b"isi-dokumen\n" * 40 + b"%%EOF\n"
NAMA_ASLI = "ktp_asli_warga_a.pdf"


def _tiket_warga_a(app) -> int:
    with app.app_context():
        user = User.query.filter_by(username="warga_a").one()
        resident = Resident.query.filter_by(user_id=user.id).one()
        tiket = Ticket(
            resident_id=resident.id,
            service_type="Administrasi",
            description="Lampiran KTP",
        )
        db.session.add(tiket)
        db.session.commit()
        return tiket.id


def _unggah(client, tiket_id, isi=PLAINTEXT, nama=NAMA_ASLI):
    return client.post(
        f"/tiket/{tiket_id}/lampiran",
        data={"attachment": (io.BytesIO(isi), nama)},
        content_type="multipart/form-data",
    )


def _dokumen_terakhir(app) -> Document:
    with app.app_context():
        dokumen = Document.query.order_by(Document.id.desc()).first()
        assert dokumen is not None, "upload tidak membuat baris Document"
        db.session.expunge(dokumen)
        return dokumen


def _path_ciphertext(app, dokumen: Document) -> Path:
    dasar = Path(app.config["PRIVATE_STORAGE_DIR"])
    relatif = Path(dokumen.ciphertext_path)
    return relatif if relatif.is_absolute() else dasar / relatif


def _semua_file_storage(app) -> list[Path]:
    dasar = Path(app.config["PRIVATE_STORAGE_DIR"])
    return [p for p in dasar.rglob("*") if p.is_file()]


def test_upload_menyimpan_ciphertext_tanpa_plaintext(app, client, login):
    tiket_id = _tiket_warga_a(app)
    login("warga_a")
    r = _unggah(client, tiket_id)
    assert r.status_code in (200, 302), r.get_data(as_text=True)[:300]

    berkas = _semua_file_storage(app)
    assert berkas, "tidak ada file tersimpan di PRIVATE_STORAGE_DIR"
    for path in berkas:
        assert PLAINTEXT not in path.read_bytes(), f"plaintext bocor di {path}"


def test_nama_file_asli_tidak_dipakai_sebagai_nama_penyimpanan(app, client, login):
    tiket_id = _tiket_warga_a(app)
    login("warga_a")
    _unggah(client, tiket_id)

    berkas = _semua_file_storage(app)
    assert berkas, "upload tidak menyimpan file apa pun"
    for path in berkas:
        assert "ktp_asli" not in path.name, f"nama file asli terpakai: {path.name}"


def test_file_tidak_disimpan_di_folder_publik(app, client, login):
    tiket_id = _tiket_warga_a(app)
    login("warga_a")
    _unggah(client, tiket_id)

    dokumen = _dokumen_terakhir(app)
    path = _path_ciphertext(app, dokumen).resolve()
    folder_statis = (Path(app.root_path) / "static").resolve()
    assert folder_statis not in path.parents, f"ciphertext berada di folder publik: {path}"


def test_pemilik_bisa_unduh_dan_isi_identik(app, client, login):
    tiket_id = _tiket_warga_a(app)
    login("warga_a")
    _unggah(client, tiket_id)
    dokumen = _dokumen_terakhir(app)

    r = client.get(f"/tiket/{dokumen.ticket_id}/lampiran/{dokumen.id}/unduh")
    assert r.status_code == 200
    assert r.data == PLAINTEXT
    assert "attachment" in r.headers.get("Content-Disposition", "")


def test_ciphertext_rusak_tidak_menghasilkan_plaintext(app, client, login):
    tiket_id = _tiket_warga_a(app)
    login("warga_a")
    _unggah(client, tiket_id)
    dokumen = _dokumen_terakhir(app)

    path = _path_ciphertext(app, dokumen)
    assert path.is_file(), "file ciphertext tidak ditemukan"
    path.write_bytes(b"rusak")

    r = client.get(f"/tiket/{dokumen.ticket_id}/lampiran/{dokumen.id}/unduh")
    assert r.status_code == 400, "CryptoError harus dipetakan ke 400, bukan 200/500"
    assert PLAINTEXT not in r.data


def test_file_ciphertext_hanya_dapat_dibaca_pemiliknya(tmp_path):
    from app.crypto.storage import encrypt_file

    stored = encrypt_file(
        PLAINTEXT,
        storage_root=tmp_path,
        key=b"k" * 32,
        context={
            "ticket_id": 1,
            "uploaded_by_user_id": 1,
            "original_filename": NAMA_ASLI,
        },
    )
    path = tmp_path / stored.ciphertext_path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_menolak_path_traversal(app, client, login):
    tiket_id = _tiket_warga_a(app)
    login("warga_a")

    with app.app_context():
        user = User.query.filter_by(username="warga_a").one()
        jahat = Document(
            ticket_id=tiket_id,
            uploaded_by_user_id=user.id,
            original_filename="palsu.pdf",
            ciphertext_path="../../../../etc/passwd",
            algorithm="AES-256-GCM",
            crypto_metadata_json='{"algorithm": "AES-256-GCM"}',
            content_type="application/pdf",
            size_bytes=10,
        )
        db.session.add(jahat)
        db.session.commit()
        jahat_id = jahat.id

    r = client.get(f"/tiket/{tiket_id}/lampiran/{jahat_id}/unduh")
    assert r.status_code in (400, 403), "path traversal harus 400/403, bukan 404 (ambigu)"
    assert b"root:" not in r.data

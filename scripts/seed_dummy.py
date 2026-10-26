"""Isi database dengan data dummy: 30 kartu keluarga, tiket, dan lampiran PDF.

Satu kartu keluarga = satu akun warga (kepala keluarga) + satu baris Resident
yang menyimpan nomor KK dan NIK (keduanya terenkripsi di level kolom).

Contoh:
    python scripts/seed_dummy.py --reset --yes
    python scripts/seed_dummy.py --jumlah-kk 10 --password 'rahasia123'

Data yang dihasilkan deterministik (seed tetap), jadi bisa diulang.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app, db  # noqa: E402
from app.auth.utils import create_user  # noqa: E402
from app.crypto import get_master_key  # noqa: E402
from app.crypto.storage import encrypt_file  # noqa: E402
from app.models import AuditLog, Document, Resident, Ticket, User  # noqa: E402

RNG_SEED = 13013
DEPAN_PRIA = ["Budi", "Agus", "Slamet", "Joko", "Hendra", "Rizky", "Fajar", "Andi", "Dedi", "Yusuf"]
DEPAN_WANITA = ["Siti", "Dewi", "Rina", "Ani", "Sri", "Fitri", "Ayu", "Nur", "Maya", "Indah"]
BELAKANG = [
    "Santoso", "Wijaya", "Pratama", "Hidayat", "Nugroho", "Saputra",
    "Kusuma", "Rahmawati", "Lestari", "Handayani",
]
JALAN = [
    "Melati", "Kenanga", "Mawar", "Anggrek", "Cempaka", "Kamboja",
    "Dahlia", "Flamboyan", "Merpati", "Rajawali",
]
WILAYAH = [
    ("Sukamaju", "Cilodong", "Depok"),
    ("Mekarsari", "Cimanggis", "Depok"),
    ("Harapan Jaya", "Bekasi Utara", "Bekasi"),
    ("Ciputat", "Ciputat", "Tangerang Selatan"),
    ("Kebayoran", "Kebayoran Baru", "Jakarta Selatan"),
]
LAYANAN = {
    "Administrasi": [
        "Permohonan surat domisili untuk pendaftaran sekolah anak.",
        "Permohonan surat keterangan usaha untuk keperluan bank.",
        "Permohonan pengantar pembuatan KTP elektronik.",
    ],
    "Keamanan": [
        "Permintaan penambahan lampu penerangan di gang RT.",
        "Laporan pintu gerbang RT rusak dan perlu diperbaiki.",
        "Permintaan jadwal ronda tambahan untuk bulan depan.",
    ],
    "Kebersihan": [
        "Pengangkutan sampah terlambat tiga hari berturut-turut.",
        "Permintaan penambahan tempat sampah di depan balai warga.",
        "Laporan saluran air tersumbat di RT 003.",
    ],
    "Infrastruktur": [
        "Perbaikan jalan berlubang di depan rumah nomor 12.",
        "Permohonan perbaikan selokan yang longsor.",
        "Usulan pengecatan ulang pos ronda.",
    ],
    "Lainnya": [
        "Permohonan izin kegiatan kerja bakti akhir bulan.",
        "Usulan penyelenggaraan posyandu tambahan.",
        "Permintaan data jumlah warga untuk laporan dasawisma.",
    ],
}
STATUS_BERBOBOT = (
    ["Diajukan"] * 40
    + ["Diproses"] * 25
    + ["Perlu Revisi"] * 10
    + ["Selesai"] * 20
    + ["Ditolak"] * 5
)


def buat_pdf(judul: str, baris: list[str]) -> bytes:
    """PDF satu halaman yang valid (ada xref) supaya bisa dibuka penampil PDF."""

    def esc(teks: str) -> str:
        return teks.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

    perintah = [f"BT /F1 14 Tf 50 800 Td ({esc(judul)}) Tj ET"]
    y = 770
    for isi in baris:
        perintah.append(f"BT /F1 11 Tf 50 {y} Td ({esc(isi)}) Tj ET")
        y -= 18
    stream = "\n".join(perintah).encode("latin-1")

    objek = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
        + stream + b"\nendstream",
    ]

    keluaran = bytearray(b"%PDF-1.4\n")
    offset = []
    for nomor, isi_objek in enumerate(objek, start=1):
        offset.append(len(keluaran))
        keluaran += f"{nomor} 0 obj\n".encode() + isi_objek + b"\nendobj\n"

    posisi_xref = len(keluaran)
    keluaran += f"xref\n0 {len(objek) + 1}\n".encode()
    keluaran += b"0000000000 65535 f \n"
    for pos in offset:
        keluaran += f"{pos:010d} 00000 n \n".encode()
    keluaran += (
        f"trailer\n<< /Size {len(objek) + 1} /Root 1 0 R >>\n"
        f"startxref\n{posisi_xref}\n%%EOF\n"
    ).encode()
    return bytes(keluaran)


def _nama(rng: random.Random, jenis_kelamin: str) -> str:
    depan = DEPAN_PRIA if jenis_kelamin == "L" else DEPAN_WANITA
    return f"{rng.choice(depan)} {rng.choice(BELAKANG)}"


def _alamat(rng: random.Random, nomor: int) -> str:
    kelurahan, kecamatan, kota = rng.choice(WILAYAH)
    return (
        f"Jl. {rng.choice(JALAN)} No. {nomor}, "
        f"RT {rng.randint(1, 8):03d}/RW {rng.randint(1, 5):03d}, "
        f"Kel. {kelurahan}, Kec. {kecamatan}, {kota}"
    )


def _nik(rng: random.Random, urutan: int) -> str:
    # 4 digit wilayah + 2 kecamatan + DDMMYY + 4 digit urutan = 16 digit.
    return (
        f"3273{rng.randint(1, 99):02d}"
        f"{rng.randint(1, 28):02d}{rng.randint(1, 12):02d}{60 + urutan % 40:02d}"
        f"{urutan:04d}"
    )


def _nomor_kk(rng: random.Random, urutan: int) -> str:
    # 4 digit wilayah + 2 kecamatan + 4 urutan + 6 acak = 16 digit.
    return f"3273{rng.randint(1, 12):02d}{urutan:04d}{rng.randint(100000, 999999):06d}"


def _hapus_storage(folder: Path) -> None:
    for berkas in folder.iterdir():
        if berkas.is_file() and berkas.name != ".gitkeep":
            berkas.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jumlah-kk", type=int, default=30)
    parser.add_argument("--password", default="rahasia123")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--reset", action="store_true", help="hapus seluruh data dulu")
    parser.add_argument("--yes", action="store_true", help="konfirmasi untuk --reset")
    args = parser.parse_args(argv)

    if len(args.password) < 8:
        print("Password minimal 8 karakter.", file=sys.stderr)
        return 2
    if args.reset and not args.yes:
        print("--reset menghapus semua data. Tambahkan --yes.", file=sys.stderr)
        return 2

    rng = random.Random(RNG_SEED)
    app = create_app()

    with app.app_context():
        if args.reset:
            db.drop_all()
            db.create_all()
            _hapus_storage(Path(app.config["PRIVATE_STORAGE_DIR"]))
        elif User.query.filter(User.username.like("kk%")).first() is not None:
            print(
                "Data KK sudah ada. Jalankan ulang dengan --reset --yes "
                "bila ingin membuat ulang.",
                file=sys.stderr,
            )
            return 1

        admin = User.query.filter(User.username == args.admin_username).first()
        if admin is None:
            admin = create_user(
                username=args.admin_username,
                password=args.password,
                full_name="Administrator RT",
                address="Kantor Sekretariat RT",
                role="admin",
            )
            print(f"Admin dibuat: {args.admin_username!r}")
        elif admin.role != "admin":
            admin.role = "admin"
            db.session.commit()

        now = datetime.now(timezone.utc)
        jumlah_tiket = 0
        jumlah_dokumen = 0
        kk_terbuat = 0

        for urutan in range(1, args.jumlah_kk + 1):
            username = f"kk{urutan:02d}"
            if User.query.filter_by(username=username).first() is not None:
                continue

            jenis = "L" if rng.random() < 0.8 else "P"
            nama = _nama(rng, jenis)
            alamat = _alamat(rng, urutan)
            nik = _nik(rng, urutan)
            nomor_kk = _nomor_kk(rng, urutan)

            user = create_user(
                username=username,
                password=args.password,
                full_name=nama,
                address=alamat,
                role="warga",
            )
            resident = Resident.query.filter_by(user_id=user.id).one()
            resident.nik = nik
            resident.family_card_number = nomor_kk
            db.session.commit()
            kk_terbuat += 1

            for _ in range(rng.randint(1, 3)):
                layanan = rng.choice(list(LAYANAN))
                status = rng.choice(STATUS_BERBOBOT)
                dibuat = now - timedelta(
                    days=rng.randint(0, 90), hours=rng.randint(0, 23)
                )
                tiket = Ticket(
                    resident_id=resident.id,
                    service_type=layanan,
                    description=rng.choice(LAYANAN[layanan]),
                    status="Diajukan",
                    created_at=dibuat,
                    updated_at=dibuat,
                )
                db.session.add(tiket)
                db.session.flush()
                jumlah_tiket += 1

                if status != "Diajukan":
                    tiket.status = status
                    db.session.add(
                        AuditLog(
                            actor_user_id=admin.id,
                            action="ubah_status",
                            resource_type="ticket",
                            resource_id=str(tiket.id),
                            detail=json.dumps(
                                {"old_status": "Diajukan", "new_status": status},
                                ensure_ascii=False,
                            ),
                        )
                    )

                if rng.random() < 0.4:
                    judul = "KARTU KELUARGA (DOKUMEN DUMMY)"
                    nama_berkas = f"kk_{nomor_kk}.pdf"
                    isi_pdf = buat_pdf(
                        judul,
                        [
                            f"Nomor KK      : {nomor_kk}",
                            f"Kepala Keluarga: {nama}",
                            f"NIK           : {nik}",
                            f"Alamat        : {alamat}",
                            "",
                            "Dokumen ini adalah data uji.",
                            "Bukan data pribadi sebenarnya.",
                        ],
                    )
                    stored = encrypt_file(
                        isi_pdf,
                        storage_root=app.config["PRIVATE_STORAGE_DIR"],
                        key=get_master_key(app.config),
                        context={
                            "ticket_id": tiket.id,
                            "uploaded_by_user_id": user.id,
                            "original_filename": nama_berkas,
                        },
                    )
                    db.session.add(
                        Document(
                            ticket_id=tiket.id,
                            uploaded_by_user_id=user.id,
                            original_filename=nama_berkas,
                            ciphertext_path=stored.ciphertext_path,
                            algorithm=stored.algorithm,
                            crypto_metadata_json=stored.crypto_metadata_json,
                            content_type="application/pdf",
                            size_bytes=len(isi_pdf),
                        )
                    )
                    jumlah_dokumen += 1

                db.session.commit()

        print(
            f"Selesai: {kk_terbuat} KK, {jumlah_tiket} tiket, "
            f"{jumlah_dokumen} dokumen PDF."
        )
        print(f"Admin : {args.admin_username} / {args.password}")
        print(f"Warga : kk01 .. kk{args.jumlah_kk:02d} / {args.password}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

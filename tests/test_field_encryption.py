"""Enkripsi kolom data pribadi di database."""

import pytest
from sqlalchemy import text

from app import db
from app.models import Resident, Ticket


def _raw_resident(app):
    with app.app_context():
        row = db.session.execute(
            text("select id, full_name, address from residents order by id limit 1")
        ).one()
        return row


def test_nama_dan_alamat_tidak_tersimpan_plaintext(app):
    row = _raw_resident(app)
    raw_nama, raw_alamat = row[1], row[2]
    assert raw_nama.startswith("enc:v1:")
    assert raw_alamat.startswith("enc:v1:")
    assert "Warga A" not in raw_nama
    assert "Jl. A" not in raw_alamat

    with app.app_context():
        resident = db.session.get(Resident, row[0])
        assert resident.full_name == "Warga A"
        assert resident.address == "Jl. A"


def test_filter_sql_tidak_bisa_mencocokkan_nilai_terenkripsi(app):
    with app.app_context():
        # Enkripsi acak: pencarian langsung tidak akan pernah cocok.
        assert Resident.query.filter_by(full_name="Warga A").count() == 0


def test_deskripsi_tiket_terenkripsi_dan_kembali_utuh(app):
    with app.app_context():
        resident = Resident.query.order_by(Resident.id).first()
        tiket = Ticket(
            resident_id=resident.id,
            service_type="Administrasi",
            description="RAHASIA_DESKRIPSI_WARGA",
        )
        db.session.add(tiket)
        db.session.commit()

        raw = db.session.execute(
            text("select description from tickets where id=:id"), {"id": tiket.id}
        ).scalar()
        assert raw.startswith("enc:v1:")
        assert "RAHASIA" not in raw
        assert db.session.get(Ticket, tiket.id).description == "RAHASIA_DESKRIPSI_WARGA"


def test_kolom_terenkripsi_menolak_tamper(app):
    row = _raw_resident(app)
    rusak = row[1][:-4] + "AAAA"

    with app.app_context():
        db.session.execute(
            text("update residents set full_name=:v where id=:id"),
            {"v": rusak, "id": row[0]},
        )
        db.session.commit()
        db.session.expire_all()

        with pytest.raises(ValueError):
            db.session.get(Resident, row[0]).full_name

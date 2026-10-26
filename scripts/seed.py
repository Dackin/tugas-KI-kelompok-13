"""Buat atau promosikan akun admin untuk pengembangan/demo.

Contoh:
    python scripts/seed.py --username admin --password 'rahasia123'
    SEED_ADMIN_PASSWORD='rahasia123' python scripts/seed.py

Jika username sudah ada, role dijadikan admin dan password diperbarui.
Hanya untuk data dummy; jangan dipakai di produksi.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app, db  # noqa: E402
from app.auth.utils import create_user, normalize_username  # noqa: E402
from app.models import User  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--username",
        default=os.getenv("SEED_ADMIN_USERNAME", "admin"),
        help="username admin (default: admin)",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("SEED_ADMIN_PASSWORD"),
        help="password admin, minimal 8 karakter (atau env SEED_ADMIN_PASSWORD)",
    )
    parser.add_argument("--nama", default="Administrator RT")
    parser.add_argument("--alamat", default="Sekretariat RT")
    args = parser.parse_args(argv)

    if not args.password or len(args.password) < 8:
        print(
            "Password admin wajib diisi dan minimal 8 karakter.\n"
            "Contoh: python scripts/seed.py --password 'rahasia123'",
            file=sys.stderr,
        )
        return 2

    app = create_app()
    with app.app_context():
        username = normalize_username(args.username)
        if not username:
            print("Username tidak boleh kosong.", file=sys.stderr)
            return 2

        existing = User.query.filter(db.func.lower(User.username) == username).first()
        if existing is not None:
            existing.role = "admin"
            existing.set_password(args.password)
            db.session.commit()
            print(f"Akun {username!r} sudah ada: role dijadikan admin, password diperbarui.")
            return 0

        create_user(
            username=username,
            password=args.password,
            full_name=args.nama,
            address=args.alamat,
            role="admin",
        )
        print(f"Admin {username!r} dibuat.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

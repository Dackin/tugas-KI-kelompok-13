"""Anggota 4: benchmark waktu, throughput, ukuran ciphertext, dan integritas.

Mengukur waktu algoritma saja (enkripsi/dekripsi in-memory), terpisah dari
waktu upload/jaringan. Setiap hasil dekripsi dibandingkan SHA-256-nya dengan
plaintext asli; bila berbeda, benchmark berhenti dengan error.

Jalankan dari root project setelah app/crypto/ siap:
    python benchmarks/benchmark.py
    python benchmarks/benchmark.py --algoritma AES-GCM --ulangi 5
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import random
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SEED = 20261026
UKURAN_DEFAULT = {
    "1KB": 1024,
    "100KB": 100 * 1024,
    "1MB": 1024**2,
    "10MB": 10 * 1024**2,
}
HASIL_DIR = Path(__file__).resolve().parent / "results"


@dataclass
class Baris:
    algoritma: str
    ukuran_label: str
    ukuran_byte: int
    ulangi: int
    enkripsi_rata_ms: float
    dekripsi_rata_ms: float
    throughput_enkripsi_mb_s: float
    throughput_dekripsi_mb_s: float
    ciphertext_byte: int
    overhead_persen: float
    sha256_sama: bool


def buat_data(ukuran: int, seed: int = SEED) -> bytes:
    """Plaintext deterministik supaya hasil benchmark bisa direproduksi."""
    return random.Random(seed).randbytes(ukuran)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cipher(algoritma: str):
    from app.crypto import get_cipher

    return get_cipher(algoritma)


def _daftar_algoritma() -> list[str]:
    from app.crypto import ALGORITHMS

    return list(ALGORITHMS)


def ukur_satu(algoritma: str, label: str, ukuran: int, ulangi: int) -> Baris:
    data = buat_data(ukuran)
    cipher = _cipher(algoritma)
    hash_asli = sha256_hex(data)

    waktu_enkripsi: list[float] = []
    waktu_dekripsi: list[float] = []
    ciphertext = b""

    for _ in range(ulangi):
        mulai = time.perf_counter()
        ciphertext, metadata = cipher.encrypt(data)
        waktu_enkripsi.append(time.perf_counter() - mulai)

        mulai = time.perf_counter()
        hasil = cipher.decrypt(ciphertext, metadata)
        waktu_dekripsi.append(time.perf_counter() - mulai)

        if sha256_hex(hasil) != hash_asli:
            raise RuntimeError(
                f"{algoritma} {label}: hasil dekripsi tidak identik dengan plaintext"
            )

    rata_enkripsi = statistics.fmean(waktu_enkripsi)
    rata_dekripsi = statistics.fmean(waktu_dekripsi)
    megabyte = ukuran / 1024**2

    return Baris(
        algoritma=algoritma,
        ukuran_label=label,
        ukuran_byte=ukuran,
        ulangi=ulangi,
        enkripsi_rata_ms=round(rata_enkripsi * 1000, 3),
        dekripsi_rata_ms=round(rata_dekripsi * 1000, 3),
        throughput_enkripsi_mb_s=round(megabyte / rata_enkripsi, 3),
        throughput_dekripsi_mb_s=round(megabyte / rata_dekripsi, 3),
        ciphertext_byte=len(ciphertext),
        overhead_persen=round((len(ciphertext) - ukuran) / ukuran * 100, 3),
        sha256_sama=True,
    )


def simpan(hasil: list[Baris], meta: dict, folder: Path) -> tuple[Path, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = folder / f"benchmark_{stamp}.csv"
    json_path = folder / f"benchmark_{stamp}.json"

    with csv_path.open("w", newline="", encoding="utf-8") as berkas:
        penulis = csv.DictWriter(berkas, fieldnames=list(asdict(hasil[0])))
        penulis.writeheader()
        penulis.writerows(asdict(baris) for baris in hasil)

    json_path.write_text(
        json.dumps(
            {"meta": meta, "hasil": [asdict(baris) for baris in hasil]},
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return csv_path, json_path


def cetak_tabel(hasil: list[Baris]) -> None:
    print(
        f"{'algoritma':<10} {'ukuran':>7} {'enc ms':>9} {'dec ms':>9} "
        f"{'enc MB/s':>9} {'dec MB/s':>9} {'cipher':>9} {'overhead':>9}"
    )
    for b in hasil:
        print(
            f"{b.algoritma:<10} {b.ukuran_label:>7} {b.enkripsi_rata_ms:>9.3f} "
            f"{b.dekripsi_rata_ms:>9.3f} {b.throughput_enkripsi_mb_s:>9.3f} "
            f"{b.throughput_dekripsi_mb_s:>9.3f} {b.ciphertext_byte:>9} "
            f"{b.overhead_persen:>8.3f}%"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--algoritma", help="dipisah koma; default semua dari ALGORITHMS")
    parser.add_argument("--ukuran", help="dipisah koma, mis. 1KB,100KB")
    parser.add_argument("--ulangi", type=int, default=3, help="pengulangan per kombinasi")
    parser.add_argument("--output", type=Path, default=HASIL_DIR)
    args = parser.parse_args(argv)

    if args.ulangi < 1:
        print("--ulangi minimal 1", file=sys.stderr)
        return 2

    try:
        semua_algoritma = _daftar_algoritma()
    except Exception as exc:  # modul kripto belum ada / belum lengkap
        print(f"Modul kripto belum siap: {exc!r}", file=sys.stderr)
        print("Lengkapi app/crypto/ (Anggota 2) lalu jalankan ulang.", file=sys.stderr)
        return 2

    algoritma = args.algoritma.split(",") if args.algoritma else semua_algoritma
    tidak_dikenal = [a for a in algoritma if a not in semua_algoritma]
    if tidak_dikenal:
        print(
            f"Algoritma tidak dikenal: {', '.join(tidak_dikenal)}. "
            f"Tersedia: {', '.join(semua_algoritma)}",
            file=sys.stderr,
        )
        return 2

    if args.ukuran:
        pilihan = args.ukuran.split(",")
        tidak_dikenal = [u for u in pilihan if u not in UKURAN_DEFAULT]
        if tidak_dikenal:
            print(
                f"Ukuran tidak dikenal: {', '.join(tidak_dikenal)}. "
                f"Tersedia: {', '.join(UKURAN_DEFAULT)}",
                file=sys.stderr,
            )
            return 2
        ukuran = {u: UKURAN_DEFAULT[u] for u in pilihan}
    else:
        ukuran = dict(UKURAN_DEFAULT)

    hasil: list[Baris] = []
    for nama in algoritma:
        for label, jumlah_byte in ukuran.items():
            print(f"mengukur {nama} {label} x{args.ulangi} ...", file=sys.stderr)
            try:
                hasil.append(ukur_satu(nama, label, jumlah_byte, args.ulangi))
            except Exception as exc:
                print(f"GAGAL {nama} {label}: {exc}", file=sys.stderr)
                return 1

    meta = {
        "waktu": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "prosesor": platform.processor() or "tidak diketahui",
        "seed": SEED,
        "ulangi": args.ulangi,
        "catatan": "Waktu algoritma in-memory; upload/jaringan tidak diukur.",
    }
    csv_path, json_path = simpan(hasil, meta, args.output)

    cetak_tabel(hasil)
    print(f"\nCSV : {csv_path}\nJSON: {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Anggota 4: benchmark waktu, throughput, ukuran ciphertext, dan integritas.

Mengukur primitive kriptografi in-memory (tanpa I/O dan tanpa jaringan), memakai
plaintext deterministik, lalu memverifikasi SHA-256 hasil dekripsi. Benchmark
berhenti dengan error bila ada satu hasil yang tidak identik, sehingga angka
yang dilaporkan tidak pernah berasal dari data rusak.

Jalankan dari root project:
    python benchmarks/benchmark.py
    python benchmarks/benchmark.py --algoritma AES-256-GCM --ulangi 5
    python benchmarks/benchmark.py --ukuran 1KB,100KB
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
from typing import Any, Protocol


class CipherModule(Protocol):
    ALGORITHM: str

    @staticmethod
    def encrypt(
        plaintext: bytes, key: bytes, *, aad: bytes = b""
    ) -> tuple[bytes, dict[str, Any]]: ...

    @staticmethod
    def decrypt(
        ciphertext: bytes, key: bytes, metadata: dict[str, Any], *, aad: bytes = b""
    ) -> bytes: ...

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SEED = 20261026
# Kunci dummy 32 byte khusus benchmark; bukan secret dan tidak dipakai aplikasi.
KEY_BENCHMARK = bytes(range(32))
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
    metadata_byte: int
    overhead_ciphertext_persen: float
    overhead_total_persen: float
    sha256_sama: bool


def buat_data(ukuran: int, seed: int = SEED) -> bytes:
    """Plaintext deterministik supaya hasil benchmark bisa direproduksi."""
    return random.Random(seed).randbytes(ukuran)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def daftar_algoritma() -> dict[str, CipherModule]:
    """Modul cipher yang tersedia, di-key dengan identifier ALGORITHM."""
    from app.crypto import aes, des, rc4

    return {modul.ALGORITHM: modul for modul in (aes, des, rc4)}


def ukur_satu(algoritma: str, label: str, ukuran: int, ulangi: int) -> Baris:
    data = buat_data(ukuran)
    cipher = daftar_algoritma()[algoritma]
    hash_asli = sha256_hex(data)

    waktu_enkripsi: list[float] = []
    waktu_dekripsi: list[float] = []
    ciphertext = b""
    metadata: dict = {}

    # Satu putaran pemanasan (tidak dicatat) supaya biaya inisialisasi library
    # tidak masuk ke rata-rata, terutama pada ukuran 1 KB.
    ciphertext, metadata = cipher.encrypt(data, KEY_BENCHMARK)
    cipher.decrypt(ciphertext, KEY_BENCHMARK, metadata)

    for _ in range(ulangi):
        mulai = time.perf_counter()
        ciphertext, metadata = cipher.encrypt(data, KEY_BENCHMARK)
        waktu_enkripsi.append(time.perf_counter() - mulai)

        mulai = time.perf_counter()
        hasil = cipher.decrypt(ciphertext, KEY_BENCHMARK, metadata)
        waktu_dekripsi.append(time.perf_counter() - mulai)

        if hasil != data or sha256_hex(hasil) != hash_asli:
            raise RuntimeError(
                f"{algoritma} {label}: hasil dekripsi tidak identik dengan plaintext"
            )

    rata_enkripsi = statistics.fmean(waktu_enkripsi)
    rata_dekripsi = statistics.fmean(waktu_dekripsi)
    megabyte = ukuran / 1024**2
    metadata_byte = len(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")
    )

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
        metadata_byte=metadata_byte,
        overhead_ciphertext_persen=round(
            (len(ciphertext) - ukuran) / ukuran * 100, 3
        ),
        overhead_total_persen=round(
            (len(ciphertext) + metadata_byte - ukuran) / ukuran * 100, 3
        ),
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
        f"{'algoritma':<20} {'ukuran':>7} {'enc ms':>9} {'dec ms':>9} "
        f"{'enc MB/s':>9} {'dec MB/s':>9} {'cipher B':>9} {'meta B':>7} "
        f"{'ovh c':>8} {'ovh tot':>8}"
    )
    for b in hasil:
        print(
            f"{b.algoritma:<20} {b.ukuran_label:>7} {b.enkripsi_rata_ms:>9.3f} "
            f"{b.dekripsi_rata_ms:>9.3f} {b.throughput_enkripsi_mb_s:>9.3f} "
            f"{b.throughput_dekripsi_mb_s:>9.3f} {b.ciphertext_byte:>9} "
            f"{b.metadata_byte:>7} {b.overhead_ciphertext_persen:>7.3f}% "
            f"{b.overhead_total_persen:>7.3f}%"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--algoritma", help="dipisah koma; default semua")
    parser.add_argument("--ukuran", help="dipisah koma, mis. 1KB,100KB")
    parser.add_argument("--ulangi", type=int, default=3, help="pengulangan per kombinasi")
    parser.add_argument("--output", type=Path, default=HASIL_DIR)
    args = parser.parse_args(argv)

    if args.ulangi < 1:
        print("--ulangi minimal 1", file=sys.stderr)
        return 2

    try:
        tersedia = daftar_algoritma()
    except Exception as exc:  # app/crypto belum lengkap atau dependensi hilang
        print(f"Modul kripto belum siap: {exc!r}", file=sys.stderr)
        print("Jalankan: pip install -r requirements.txt", file=sys.stderr)
        return 2

    algoritma = args.algoritma.split(",") if args.algoritma else list(tersedia)
    tidak_dikenal = [a for a in algoritma if a not in tersedia]
    if tidak_dikenal:
        print(
            f"Algoritma tidak dikenal: {', '.join(tidak_dikenal)}. "
            f"Tersedia: {', '.join(tersedia)}",
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
        "catatan": (
            "Waktu primitive kriptografi in-memory; I/O penyimpanan, upload, "
            "dan jaringan tidak diukur. AAD tidak dipakai (bukan jalur storage)."
        ),
    }
    csv_path, json_path = simpan(hasil, meta, args.output)

    cetak_tabel(hasil)
    print(f"\nCSV : {csv_path}\nJSON: {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

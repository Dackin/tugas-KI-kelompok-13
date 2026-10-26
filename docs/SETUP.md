# Setup dan menjalankan Secure RT

Panduan ini untuk anggota baru yang baru clone repository.

## Prasyarat

- Python 3.11 atau lebih baru (`python3 --version`)
- Git

## 1. Clone dan virtual environment

```bash
git clone <url-repo> tugas-KI-kelompok-13
cd tugas-KI-kelompok-13
python3 -m venv .venv
source .venv/bin/activate
```

## 2. Install dependensi

```bash
pip install -r requirements.txt
```

## 3. Konfigurasi `.env`

```bash
cp .env.example .env
```

Lalu isi dua nilai wajib di `.env`. Keduanya dibuat dengan perintah berbeda:

```bash
# SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# CRYPTO_MASTER_KEY_B64 (harus Base64 dari tepat 32 byte)
python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

| Variabel | Isi |
|---|---|
| `SECRET_KEY` | hasil perintah pertama, format hex 64 karakter |
| `CRYPTO_MASTER_KEY_B64` | hasil perintah kedua, format Base64 (dibaca `app/crypto/keys.py`) |
| `PRIVATE_STORAGE_DIR` | biarkan `private_storage` |
| `MAX_CONTENT_LENGTH_MB` | biarkan `50` |

`DATABASE_URL` sengaja dikomentari supaya memakai default SQLite di
`instance/secure_rt_dev.sqlite3`. Jangan diisi kosong (`DATABASE_URL=`) —
nilai kosong akan menimpa default dan membuat SQLAlchemy gagal.

**Jangan commit `.env`.** File itu sudah masuk `.gitignore`. Setiap anggota
punya `.env` sendiri dengan token sendiri.

## 4. Jalankan aplikasi

```bash
python run.py
```

Buka <http://127.0.0.1:5000>.

## 5. Menjalankan tes

Jalankan dari **root project**, dengan virtual environment aktif:

```bash
pytest -q                       # semua tes
pytest tests/test_auth.py -v    # satu file
pytest -k "dokumen" -v          # filter nama tes
```

`python -m pytest -q` juga boleh. Konfigurasi ada di `pytest.ini`
(`pythonpath = .`, `testpaths = tests`), jadi `import app` bekerja tanpa
menyetel `PYTHONPATH`.

**Jangan** menjalankan `python tests/conftest.py` — itu file fixture untuk
pytest, bukan program; menjalankannya langsung akan gagal dengan
`ModuleNotFoundError: No module named 'app'`.

Tes memakai database in-memory dan folder penyimpanan sementara
(`tests/conftest.py`), jadi tidak menyentuh `instance/` maupun
`private_storage/`.

## 6. Benchmark kriptografi

Setelah `app/crypto/` selesai:

```bash
python benchmarks/benchmark.py
python benchmarks/benchmark.py --algoritma AES-256-GCM --ukuran 1MB --ulangi 5
```

Hasil ditulis ke `benchmarks/results/benchmark_<timestamp>.csv` dan `.json`.
DES/RC4 memakai `pycryptodome` (bukan Python murni); pada mesin uji 10 MB DES
memakan ~0,28 detik per operasi. Gunakan `--ukuran 1KB,100KB` untuk percobaan
cepat.
Angka di `docs/HASIL_BENCHMARK.md` harus berasal dari file hasil ini, bukan
perkiraan.

## Troubleshooting

| Gejala | Sebab dan solusi |
|---|---|
| `ModuleNotFoundError: No module named 'flask'` | virtual environment belum aktif: `source .venv/bin/activate` |
| Database 0 byte dan tidak ada tabel | `app/models.py` belum di-import. Pastikan `create_app()` melakukan `from app import models` sebelum `db.create_all()` |
| Perubahan model tidak muncul | belum ada migrasi; hapus `instance/secure_rt_dev.sqlite3` lalu jalankan ulang (data dev hilang) |
| `.env` tidak terbaca | jalankan `python run.py` dari root project, bukan dari dalam `app/` |
| `RuntimeError: SECRET_KEY` | `.env` belum dibuat: `cp .env.example .env` |
| Port 5000 dipakai | `flask --app run run --port 5001` |

## Aturan data

- Gunakan data dummy. Jangan pakai KTP/KK asli.
- Jangan commit `.env`, kunci, database, atau isi `private_storage/`.
- `private_storage/` berada di luar `app/static/` sehingga tidak bisa diakses
  langsung lewat URL; akses hanya lewat route yang memeriksa login dan
  kepemilikan.

# Secure RT
Starter workspace untuk aplikasi layanan administrasi RT dengan autentikasi, pembatasan akses, penyimpanan dokumen terenkripsi, dan eksperimen AES/DES/RC4.

## Teknologi
Python 3.11+, Flask, Flask-SQLAlchemy, Flask-Login, python-dotenv, cryptography, pytest.

## Pembagian
1. **Rayyan Binar Ramadhan 5054251025 — Database & autentikasi:** `app/models.py`, `app/auth/routes.py`, `tests/test_auth.py`
2. **Rasya Gonawi 5054251032 — Kriptografi & penyimpanan:** `app/crypto/`, `tests/test_crypto.py`
3. **Raihan Nurhakim 5054251030 — Layanan RT & UI:** `app/tickets/`, `app/resident/`, `app/admin/`, `app/templates/`, `app/static/`
4. **Firdaus Mangkona 5054251003 — Integrasi, benchmark & pengujian:** `benchmarks/`, `tests/test_authorization.py`, `tests/test_storage.py`, dokumentasi hasil eksperimen.

## Fitur target
- Registrasi/login dan role `admin`/`warga`.
- Warga membuat tiket layanan dan mengunggah dokumen.
- Warga hanya melihat tiket/dokumen miliknya; admin memproses tiket.
- File dienkripsi sebelum disimpan ke `private_storage/`.
- Pengunduhan melewati autentikasi, pemeriksaan role, dan pemeriksaan kepemilikan.
- Benchmark mengukur waktu enkripsi/dekripsi, throughput, ukuran ciphertext, dan integritas.

## Menjalankan
1. Buat virtual environment.
2. `pip install -r requirements.txt`
3. Salin `.env.example` ke `.env`, lalu isi secret lokal.
4. `python run.py`

## Keamanan
Gunakan data dummy. Jangan commit `.env`, kunci, database berisi data asli, scan KTP/KK, atau dokumen warga. Simpan file di luar folder publik. Password di-hash, bukan dienkripsi. AES-GCM direkomendasikan untuk penggunaan nyata; DES dan RC4 hanya untuk eksperimen akademik dengan data dummy karena sudah tidak aman. ECB dilarang untuk mode block cipher. RC4 adalah stream cipher dan tidak memiliki mode block.

## Database target
`users`, `residents`, `tickets`, `ticket_messages`, `documents`, `audit_logs`.

## Benchmark
Gunakan file yang sama, lingkungan yang sama, dan pengulangan yang konsisten. Catat ukuran file, waktu, throughput, ukuran ciphertext termasuk overhead, serta hash SHA-256 sebelum/sesudah dekripsi. Jangan membuat hasil fiktif. Pisahkan waktu algoritma dari waktu upload/jaringan.

## Contoh commit
`feat: add resident and ticket models`
`feat: implement role-based authentication`
`feat: implement AES-GCM file encryption`
`feat: add resident ticket submission flow`
`test: block cross-resident document access`
`test: measure cipher speed and ciphertext size`
`docs: document benchmark methodology`

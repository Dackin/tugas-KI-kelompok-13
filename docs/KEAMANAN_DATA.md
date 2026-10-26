# Keamanan dan Klasifikasi Data

Dokumen ini menjelaskan data apa yang dianggap privat, dasar hukumnya, dan
bagaimana data dilindungi di aplikasi.

## 1. Dasar hukum

| Rujukan | Pokok |
|---|---|
| UU 27/2022 (UU PDP) Pasal 4–5 | Pembagian data pribadi umum dan spesifik |
| UU PDP Pasal 35 | Pengendali wajib menjamin keamanan data (teknis dan operasional) |
| UU PDP Pasal 46 | Pemberitahuan kegagalan perlindungan data maksimal 3×24 jam |
| GDPR Art. 4(1), 5(1)(f), 32 | Definisi data pribadi, prinsip integritas & kerahasiaan, keamanan pemrosesan |
| GDPR Art. 9, 33 | Kategori khusus dan notifikasi pelanggaran maksimal 72 jam |

## 2. Klasifikasi data

| Data | Klasifikasi | Dasar | Perlakuan di aplikasi |
|---|---|---|---|
| Username | identitas akun (umum) | UU PDP Pasal 4 | plaintext, diperlukan untuk login |
| Nama lengkap, alamat | data pribadi umum | UU PDP Pasal 4; GDPR Art. 4(1) | kolom database terenkripsi (AES-GCM) |
| NIK, nomor KK | data pribadi (identitas) | UU PDP Pasal 4 | kolom database terenkripsi (AES-GCM) |
| Deskripsi tiket, pesan | data pribadi (dapat memuat data sensitif) | UU PDP Pasal 35; GDPR Art. 5(1)(f) | kolom database terenkripsi |
| Catatan audit admin | catatan internal | UU PDP Pasal 35 | kolom database terenkripsi |
| Lampiran (KTP/KK/surat) | data pribadi spesifik / dokumen identitas | UU PDP Pasal 4–5; GDPR Art. 9 | ciphertext di `private_storage/` |
| Status tiket, jenis layanan, tanggal | metadata operasional | — | plaintext (dibutuhkan untuk filter) |
| Password | kredensial | — | hash scrypt (bukan enkripsi) |

Catatan: KTP/KK yang dipindai dapat memuat NIK, foto, dan data biometrik,
sehingga diperlakukan sebagai data pribadi spesifik. Aplikasi tidak menyimpan
NIK di dalam nama file; hanya nama logis di kolom `original_filename`.

## 3. Lapisan perlindungan

### 3.1 Lampiran file

- Disimpan di `private_storage/`, di luar `app/static/`, nama file UUID + `.bin`.
- Default AES-256-GCM. DES-CBC-HMAC-SHA256 dan RC4-HMAC-SHA256 tersedia untuk
  eksperimen akademik dan benchmark, bukan untuk data nyata.
- AAD mengikat `ticket_id`, `uploaded_by_user_id`, dan `original_filename`,
  sehingga ciphertext tidak bisa dipindah ke tiket atau pengguna lain.
- Tulis atomik, permission `0600`, path traversal ditolak saat dekripsi.
- Setiap download memeriksa login + kepemilikan di level query **sebelum**
  dekripsi; `CryptoError` dipetakan ke 400, bukan 500.

### 3.2 Kolom database

`app/crypto/fields.py` menyediakan `EncryptedText`, sebuah `TypeDecorator`
SQLAlchemy:

- Format: `enc:v1:<base64(nonce || ciphertext)>`, AES-256-GCM.
- Kunci diturunkan dari `CRYPTO_MASTER_KEY_B64` memakai HKDF-SHA256 dengan salt
  dan info terpisah dari kunci file, sehingga domain kunci berbeda.
- Nilai lama tanpa prefix `enc:v1:` dibaca apa adanya (kompatibilitas data
  pengembangan sebelum fitur ini aktif).
- Kolom yang memakai: `residents.full_name`, `residents.address`,
  `residents.nik`, `residents.family_card_number`, `tickets.description`,
  `ticket_messages.message`, `audit_logs.detail`.
- Tamper pada ciphertext menghasilkan `ValueError` saat dibaca, bukan data rusak
  yang dikembalikan diam-diam.

Konsekuensi yang disengaja:

- Kolom terenkripsi **tidak bisa** dipakai untuk `WHERE`/`ORDER BY`/`UNIQUE`
  karena nonce acak membuat ciphertext berbeda setiap penulisan. Pencarian
  pengguna memakai `users.username` yang tetap plaintext.
- Bila master key hilang atau diganti tanpa re-enkripsi, data lama tidak dapat
  dibaca. Belum ada `key_id`/key ring; rotasi kunci perlu proses re-enkripsi.

### 3.3 Otorisasi

- Warga hanya dapat membuka tiket dan lampiran miliknya (`resident_id` diambil
  dari `current_user`, bukan dari URL/form).
- Admin dapat memproses semua tiket; akses ini dicatat di `audit_logs`.
- Anonim diarahkan ke `/auth/login`; role salah mendapat 403.

## 4. Data dummy

`scripts/seed_dummy.py` membuat 30 kartu keluarga dummy: 30 akun warga
(`kk01`..`kk30`), 30 baris `Resident` dengan NIK + nomor KK (terenkripsi),
63 tiket dengan status bervariasi, dan 24 lampiran PDF valid. Semua isi dokumen
bertanda "DOKUMEN DUMMY".

```bash
python scripts/seed_dummy.py --reset --yes
python scripts/seed_dummy.py --jumlah-kk 10
```

Jangan pernah mengganti data dummy dengan data warga nyata untuk demonstrasi.

## 5. Keterbatasan yang masih terbuka

1. Belum ada rate limit/lockout login.
2. Belum ada rotasi kunci (`key_id`).
3. Belum ada pembersihan otomatis ciphertext yatim di luar alur upload.
4. `SECRET_KEY` masih punya fallback pengembangan bila `.env` kosong.
5. Belum ada notifikasi kebocoran (UU PDP Pasal 46 / GDPR Art. 33).

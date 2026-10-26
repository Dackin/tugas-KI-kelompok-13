# Panduan Integrasi Kriptografi untuk Anggota Lain

Dokumen ini menjelaskan cara modul Anggota 2 dipakai oleh route upload/download,
database, dan benchmark. AES-256-GCM wajib menjadi default aplikasi. DES dan RC4
hanya tersedia untuk eksperimen akademik dengan data dummy.

## 1. Lokasi data dan secret

| Data | Lokasi | Boleh masuk Git? |
|---|---|---|
| Master key | Environment server atau `.env` lokal | Tidak |
| Ciphertext | `private_storage/` | Tidak |
| Path, algoritma, metadata | Tabel `documents` | Ya untuk data dummy saja |
| Source code dan `.env.example` kosong | Repository | Ya |

Master key tidak dimiliki atau disimpan oleh user. Browser hanya mengirim file
asli melalui upload dan menerima file asli setelah server mengotorisasi serta
mendekripsinya.

`SECRET_KEY` Flask dan `CRYPTO_MASTER_KEY_B64` adalah dua secret yang berbeda.
Jangan menggunakan salah satunya sebagai pengganti yang lain.

## 2. Menyiapkan master key lokal

Salin `.env.example` menjadi `.env`, kemudian buat key acak 32 byte:

```powershell
python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Salin output hanya ke `.env`:

```dotenv
CRYPTO_MASTER_KEY_B64=HASIL_BASE64_DI_SINI
```

Jangan menaruh output tersebut di dokumentasi, chat publik, database, screenshot,
atau commit. Pada deployment nyata, gunakan secret manager/platform environment,
bukan file `.env` yang ikut didistribusikan.

Aplikasi memasukkan nilai mentah tersebut ke `app.config`. Route mengambil bytes
key tervalidasi secara lazy:

```python
from flask import current_app
from app.crypto import get_master_key

master_key = get_master_key(current_app.config)
```

Jika key hilang, Base64 rusak, atau hasilnya bukan 32 byte,
`KeyConfigurationError` dilempar dan operasi harus gagal tertutup. Jangan membuat
fallback key dalam source code.

## 3. Flow upload dan enkripsi

Urutan wajib:

1. Pastikan user sudah login.
2. Pastikan user berhak mengunggah ke tiket tersebut.
3. Validasi ukuran dan kebijakan tipe file.
4. Ambil master key dari konfigurasi server.
5. Bentuk context dokumen yang stabil.
6. Panggil `encrypt_file`; plaintext dienkripsi sebelum ditulis ke disk.
7. Simpan hasil `StoredFile` ke record `Document`.

Contoh bagian integrasi route:

```python
from flask import current_app
from app import db
from app.crypto import get_master_key
from app.crypto.storage import encrypt_file
from app.models import Document

uploaded = request.files["document"]
context = {
    "ticket_id": ticket.id,
    "uploaded_by_user_id": current_user.id,
    "original_filename": uploaded.filename,
}

stored = encrypt_file(
    uploaded.read(),
    storage_root=current_app.config["PRIVATE_STORAGE_DIR"],
    key=get_master_key(current_app.config),
    context=context,
    # Jika tidak diberikan, default-nya selalu AES-256-GCM.
)

document = Document(
    ticket_id=ticket.id,
    uploaded_by_user_id=current_user.id,
    original_filename=uploaded.filename,
    ciphertext_path=stored.ciphertext_path,
    algorithm=stored.algorithm,
    crypto_metadata_json=stored.crypto_metadata_json,
)
db.session.add(document)
db.session.commit()
```

Nama unggahan tidak pernah menjadi nama fisik. Storage menghasilkan nama UUID
acak berekstensi `.bin`. Jika commit database gagal setelah file berhasil ditulis,
integrasi harus menghapus ciphertext yatim secara aman atau memakai mekanisme
cleanup terjadwal.

Jangan menyediakan pilihan DES/RC4 pada form aplikasi biasa. Pemilihan algoritma
legacy hanya dilakukan oleh benchmark/eksperimen yang terkontrol.

## 4. Data yang disimpan

Pemetaan hasil enkripsi ke model saat ini:

```text
documents.original_filename     ← nama untuk download
documents.ciphertext_path       ← nama relatif UUID.bin
documents.algorithm             ← identifier algoritma
documents.crypto_metadata_json  ← nonce/IV/salt/tag, tanpa key
```

Metadata dan nonce/IV/salt tidak dianggap secret. Kerahasiaan bergantung pada
master key yang disimpan terpisah. Isi file tetap tidak dapat dibaca bila database
dan `private_storage` bocor tetapi master key tidak ikut bocor.

## 5. Flow GET, dekripsi, dan pengiriman file

Urutan wajib:

1. Pastikan user sudah login.
2. Cari `Document` dan tiket terkait.
3. Pastikan user adalah admin yang berwenang atau pemilik tiket.
4. Bentuk context persis seperti saat upload.
5. Ambil master key dari server.
6. Panggil `decrypt_file`; fungsi memvalidasi path dan autentikasi ciphertext.
7. Kirim plaintext hanya setelah dekripsi berhasil.

```python
from io import BytesIO
from flask import current_app, send_file
from app.crypto import CryptoError, get_master_key
from app.crypto.storage import decrypt_file

context = {
    "ticket_id": document.ticket_id,
    "uploaded_by_user_id": document.uploaded_by_user_id,
    "original_filename": document.original_filename,
}

plaintext = decrypt_file(
    ciphertext_path=document.ciphertext_path,
    storage_root=current_app.config["PRIVATE_STORAGE_DIR"],
    key=get_master_key(current_app.config),
    context=context,
    algorithm=document.algorithm,
    metadata=document.crypto_metadata_json,
)

return send_file(
    BytesIO(plaintext),
    as_attachment=True,
    download_name=document.original_filename,
    mimetype="application/octet-stream",
)
```

Gunakan attachment sebagai default. Jika file harus ditampilkan inline, whitelist
tipe aman seperti PDF/gambar raster. Jangan menampilkan HTML atau SVG unggahan
secara inline karena dapat menjalankan konten aktif di browser.

Tangani `CryptoError` sebagai kegagalan generik dan jangan mengirim detail apakah
key, tag, metadata, atau ciphertext yang salah. Log server juga tidak boleh berisi
master key atau plaintext.

## 6. Context/AAD tidak boleh berubah

Nilai berikut diautentikasi bersama file:

```python
{
    "ticket_id": int,
    "uploaded_by_user_id": int,
    "original_filename": str,
}
```

Perubahan salah satu nilai menyebabkan dekripsi gagal. Jika aplikasi perlu
mengubah nama file, desain migrasi/re-enkripsi terlebih dahulu; jangan langsung
mengedit `original_filename` pada database.

## 7. Batas perlindungan

- Kebocoran database memperlihatkan metadata bisnis seperti nama file dan ID,
  tetapi bukan isi dokumen.
- Kebocoran database dan ciphertext tetap tidak membuka isi tanpa master key.
- Kebocoran server beserta master key memungkinkan file didekripsi.
- Kolom nama, alamat, dan deskripsi tiket tidak dienkripsi oleh modul ini.
- DES dan RC4 tidak aman untuk penggunaan nyata walaupun dilengkapi HMAC.

Versi sekarang memakai satu master key dan belum memiliki `key_id`/key ring.
Mengganti key langsung akan membuat file lama tidak dapat didekripsi. Implementasi
rotasi harus menambahkan key version dan proses re-enkripsi sebelum key lama
dihapus.

## 8. Benchmark dan verifikasi

Benchmark harus memakai file, mesin, jumlah pengulangan, dan context yang sama.
Catat waktu enkripsi/dekripsi, throughput, ukuran ciphertext, panjang metadata,
dan total overhead. Selalu verifikasi:

```python
assert decrypted == original
assert sha256(decrypted).digest() == sha256(original).digest()
```

Jalankan tes correctness sebelum integrasi:

```powershell
python -m pytest tests/test_crypto.py tests/test_crypto_keys.py tests/test_storage.py -q
python -m pytest -q
```

## 9. Pembagian tanggung jawab

- Anggota 2 menjaga primitive, metadata, key loader, dan encrypted storage.
- Anggota 3 menghubungkan fungsi ke UI serta route upload/download.
- Anggota 4 menguji authorization lintas warga, integrasi, dan benchmark aktual.
- Route wajib melakukan authorization sebelum memanggil `decrypt_file`.

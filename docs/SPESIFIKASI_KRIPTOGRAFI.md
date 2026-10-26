# Spesifikasi Implementasi Kriptografi

## 1. Tujuan dan kondisi awal

Dokumen ini menjadi acuan implementasi anggota kriptografi untuk eksperimen AES,
DES, dan RC4, penyimpanan file terenkripsi, metadata, integritas, serta pengujian
kesamaan file hasil dekripsi.

Kondisi repository saat spesifikasi dibuat:

- `app/crypto/aes.py`, `des.py`, `rc4.py`, dan `storage.py` masih placeholder.
- `tests/test_crypto.py` dan `tests/test_storage.py` belum berisi test executable.
- Model `Document` sudah menyediakan `ciphertext_path`, `algorithm`, dan
  `crypto_metadata_json`.
- `instance/secure_rt_dev.sqlite3` berukuran 0 byte; belum ada data uji di dalamnya.
- Semua eksperimen harus menggunakan data dummy. Database, secret, dan dokumen
  pribadi tidak boleh di-commit.

## 2. Keputusan desain

| Algoritma | Konstruksi | Random value per file | Integritas | Status |
|---|---|---|---|---|
| AES | AES-256-GCM | nonce 12 byte | tag GCM 16 byte | Default aplikasi |
| DES | DES-CBC + PKCS#7 | IV 8 byte | HMAC-SHA256 | Akademik, tidak aman |
| RC4 | RC4 dengan kunci sesi unik | salt acak 16 byte | HMAC-SHA256 | Akademik, tidak aman |

ECB dilarang. RC4 tidak memiliki mode blok sehingga larangan ECB tidak berlaku,
tetapi reuse kunci/keystream tetap dilarang.

Catatan dependensi: gunakan AES-GCM, HKDF, dan HMAC dari `cryptography`. Karena
versi modern library tersebut tidak menjamin tersedianya single DES/ARC4, gunakan
`pycryptodome` untuk primitive DES dan ARC4 akademik serta tambahkan dependensinya
secara eksplisit. Jangan menyamarkan DES sebagai algoritma lain dan jangan menulis
primitive DES/RC4 sendiri.

## 3. Manajemen kunci

- Master key 32 byte berasal dari konfigurasi/environment dan tidak boleh masuk Git.
- AES menggunakan master key 32 byte secara langsung sebagai kunci AES-256.
- DES memakai salt acak 16 byte per file. HKDF-SHA256 menurunkan kunci DES 8 byte
  dan kunci HMAC 32 byte yang berbeda dari master key tersebut.
- RC4 memakai salt acak 16 byte per file. HKDF-SHA256 menurunkan kunci sesi RC4
  32 byte yang unik dan kunci HMAC 32 byte yang berbeda. Jangan simpan hasil
  turunan kunci di metadata.
- Pisahkan domain HKDF dengan `info` berbeda, misalnya
  `secure-rt/des/encryption`, `secure-rt/des/mac`, dan `secure-rt/rc4/mac`.
- Rotasi disiapkan melalui field `key_id`; metadata hanya menyimpan identifier,
  tidak menyimpan nilai kunci.

Untuk lingkup tugas minimal, penyimpanan dapat menerima key material dari pemanggil
atau konfigurasi test. Produksi tidak boleh memakai fallback key hard-coded.

## 4. Kontrak modul algoritma

Setiap `app/crypto/{aes,des,rc4}.py` menyediakan perilaku seragam:

```python
def encrypt(plaintext: bytes, key: bytes, *, aad: bytes = b"") -> tuple[bytes, dict]:
    """Mengembalikan ciphertext dan metadata JSON-safe."""

def decrypt(
    ciphertext: bytes,
    key: bytes,
    metadata: dict,
    *,
    aad: bytes = b"",
) -> bytes:
    """Memverifikasi integritas lalu mengembalikan plaintext."""
```

Validasi tipe dan panjang kunci/nonce/IV/tag dilakukan sebelum operasi kriptografi.
Semua nilai biner dalam metadata memakai Base64 standar secara konsisten. Dekoder
harus menolak Base64 tidak valid, field hilang, versi tidak didukung, dan ukuran
yang salah.

### Metadata minimum

Field umum:

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "key_id": "test-key-v1"
}
```

Tambahan per algoritma:

- AES: `nonce_b64`, `tag_b64` jika tag dipisahkan dari ciphertext.
- DES: `mode: "CBC"`, `salt_b64`, `iv_b64`, `padding: "PKCS7"`,
  `mac: "HMAC-SHA256"`, `tag_b64`, dan `insecure_academic_only: true`.
- RC4: `salt_b64`, `mac: "HMAC-SHA256"`, `tag_b64`, dan
  `insecure_academic_only: true`.

Representasi metadata yang ikut diautentikasi harus dikanonisasi secara stabil
(UTF-8, key terurut, separator tetap), tanpa field `tag_b64` itu sendiri.

### Integritas

- AES-GCM mengautentikasi ciphertext dan AAD melalui tag GCM.
- DES/RC4 menghitung HMAC atas domain separator + metadata kanonis + AAD +
  ciphertext. Tag diverifikasi sebelum unpadding atau pengembalian plaintext.
- Exception eksternal diseragamkan, misalnya `CryptoError("decryption failed")`;
  detail internal tidak ditampilkan kepada pengguna.

## 5. Kontrak penyimpanan file

`app/crypto/storage.py` bertanggung jawab untuk:

1. menerima bytes/file stream, algoritma, key/key provider, dan konteks dokumen;
2. membentuk AAD deterministik, misalnya versi skema, ID tiket, ID pengunggah, dan
   nama file logis;
3. mengenkripsi sebelum data ditulis ke disk;
4. membuat nama ciphertext acak (bukan nama unggahan pengguna);
5. menulis file sementara lalu melakukan atomic replace ke `private_storage/`;
6. mengembalikan path relatif, nama algoritma, dan metadata JSON;
7. saat membaca, memastikan resolved path tetap berada di storage root,
   memverifikasi autentikasi, lalu mengembalikan plaintext hanya jika valid.

Nama file asli disimpan sebagai metadata bisnis di database, bukan sebagai nama
file fisik. Jangan simpan plaintext sementara kecuali mutlak diperlukan. Bila ada
kegagalan, file sementara wajib dibersihkan.

Pemetaan ke model `Document`:

| Kolom | Isi |
|---|---|
| `ciphertext_path` | Path relatif ciphertext di private storage |
| `algorithm` | Identifier stabil: `AES-256-GCM`, `DES-CBC-HMAC-SHA256`, atau `RC4-HMAC-SHA256` |
| `crypto_metadata_json` | JSON metadata tervalidasi; tanpa key material |

## 6. Matriks pengujian

Jalankan seluruh kasus berikut untuk setiap algoritma:

| Kasus | Hasil yang diharapkan |
|---|---|
| Plaintext kosong | Round-trip identik |
| Data biner/non-UTF-8 | Round-trip identik |
| Ukuran di bawah, sama dengan, dan di atas block size | Round-trip identik |
| Plaintext sama dienkripsi dua kali | Ciphertext/nonce/IV berbeda |
| Kunci salah | Ditolak tanpa plaintext |
| Ciphertext berubah satu bit | Ditolak |
| Tag berubah satu bit | Ditolak |
| Metadata/AAD berubah | Ditolak |
| Metadata kurang/format Base64 rusak | Ditolak |

Kesamaan file wajib dibuktikan dengan dua pemeriksaan:

```python
assert decrypted == original
assert sha256(decrypted).digest() == sha256(original).digest()
```

Test penyimpanan juga memastikan file fisik tidak sama dengan plaintext, tidak
berada di folder publik, nama unggahan berbahaya tidak menyebabkan path traversal,
dan file parsial tidak tertinggal setelah kegagalan.

## 7. Kriteria selesai

- AES-GCM, DES-CBC, dan RC4 dapat round-trip seluruh data dummy pada matriks test.
- Tidak ada penggunaan ECB.
- AES-GCM menolak modifikasi melalui tag; DES dan RC4 menolak modifikasi melalui
  HMAC-SHA256 sebelum dekripsi.
- Nonce/IV/kunci sesi tidak dipakai ulang.
- File hasil dekripsi identik byte-per-byte dan SHA-256 dengan file asli.
- Seluruh metadata cukup untuk dekripsi tetapi tidak mengandung secret.
- `pytest` lulus dan hasil aktual dilaporkan tanpa rekayasa.
- Implementasi dan pengujian setiap algoritma berada pada commit terpisah seperti
  urutan yang ditentukan di `AGENTS.md`.

## 8. Perintah verifikasi

```powershell
python -m pytest tests/test_crypto.py -q
python -m pytest tests/test_storage.py -q
python -m pytest -q
```

Benchmark baru dijalankan setelah tes correctness dan integrity lulus. Gunakan
file serta jumlah pengulangan yang sama untuk tiap algoritma, dan pisahkan waktu
kriptografi dari waktu I/O atau jaringan.

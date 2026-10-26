# Pembagian tugas

## Anggota 1 — Database & autentikasi
File: `app/models.py`, `app/auth/routes.py`, `tests/test_auth.py`
Deliverable: pemetaan skema Access yang relevan, model data, registrasi/login/logout, password hashing, role, tes autentikasi.
Contoh commit: `feat: add resident and ticket models`; `feat: implement role-based authentication`; `test: cover login behavior`.

## Anggota 2 — Kriptografi & penyimpanan
File: `app/crypto/aes.py`, `des.py`, `rc4.py`, `storage.py`, `tests/test_crypto.py`
Deliverable: encrypt/decrypt, IV/nonce dan metadata, uji integritas, catatan keterbatasan DES/RC4.
Contoh commit: `feat: implement AES-GCM file encryption`; `test: verify decrypted file matches original`.

## Anggota 3 — Layanan RT & UI
File: `app/tickets/routes.py`, `app/resident/routes.py`, `app/admin/routes.py`, `app/templates/`, `app/static/`
Deliverable: dashboard, pengajuan tiket, upload lampiran, status/revisi, hasil surat, integrasi penyimpanan.
Contoh commit: `feat: add resident ticket submission form`; `feat: add admin ticket status workflow`.

## Anggota 4 — Integrasi, benchmark & pengujian
File: `benchmarks/benchmark.py`, `tests/test_authorization.py`, `tests/test_storage.py`, `README.md`
Deliverable: integrasi, uji akses lintas warga, uji download aman, benchmark aktual, dokumentasi setup dan metodologi.
Contoh commit: `test: block cross-resident document access`; `test: measure cipher speed and ciphertext size`; `docs: document benchmark methodology`.

## Tanggung jawab semua anggota
Commit perubahan sendiri secara rutin dan bermakna, review perubahan tim, tulis tes untuk fitur sendiri, dan jangan mengunggah data pribadi/secret ke GitHub.

## Kontrak teknis

Disepakati sebelum implementasi supaya pekerjaan bisa berjalan paralel.

### Environment variable (`.env`, contoh di `.env.example`)

| Nama | Dipakai | Keterangan |
|---|---|---|
| `SECRET_KEY` | Flask | kunci session |
| `CRYPTO_MASTER_KEY_B64` | `app/crypto/keys.py` | Base64 dari 32 byte acak |
| `PRIVATE_STORAGE_DIR` | storage | default `private_storage` |
| `MAX_CONTENT_LENGTH_MB` | upload | default 50 |
| `DATABASE_URL` | SQLAlchemy | dikomentari = pakai default `instance/secure_rt_dev.sqlite3` |

### Signature kripto

Semua modul cipher (`aes.py`, `des.py`, `rc4.py`) memakai bentuk seragam:

```python
def encrypt(plaintext: bytes, key: bytes, *, aad: bytes = b"") -> tuple[bytes, dict]
def decrypt(ciphertext: bytes, key: bytes, metadata: dict, *, aad: bytes = b"") -> bytes
```

Identifier algoritma (nilai kolom `Document.algorithm`):

| Modul | `ALGORITHM` |
|---|---|
| `aes.py` | `AES-256-GCM` (default aplikasi) |
| `des.py` | `DES-CBC-HMAC-SHA256` (akademik) |
| `rc4.py` | `RC4-HMAC-SHA256` (akademik) |

`app/crypto/storage.py`:

```python
def encrypt_file(plaintext, *, storage_root, key, context, algorithm="AES-256-GCM") -> StoredFile
def decrypt_file(*, ciphertext_path, storage_root, key, context, algorithm, metadata) -> bytes
```

`context` wajib berisi tepat tiga field dan ikut diautentikasi sebagai AAD:

```python
{"ticket_id": int, "uploaded_by_user_id": int, "original_filename": str}
```

`StoredFile` berisi `ciphertext_path`, `algorithm`, `crypto_metadata_json`.
Detail lengkap: `docs/INTEGRASI_KRIPTOGRAFI.md`.

### Aturan penyimpanan

- `Document.ciphertext_path` disimpan **relatif** terhadap `PRIVATE_STORAGE_DIR`.
- Nama file di disk memakai `uuid4`, bukan nama asli dari pengguna.
- Tulis atomik (file sementara + `os.replace`), permission `0600`.
- Tolak path yang keluar dari `PRIVATE_STORAGE_DIR` (`PathTraversalError`).
- `decrypt` wajib gagal, bukan mengembalikan data rusak, bila ciphertext diubah.

### Route

| Method | Path | Akses | Body |
|---|---|---|---|
| GET/POST | `/auth/register` | publik | `username`, `password` |
| GET/POST | `/auth/login` | publik | `username`, `password` |
| POST | `/auth/logout` | login | — |
| GET | `/resident/` | warga | — |
| GET/POST | `/tickets/baru` | warga | `service_type`, `description` |
| GET | `/tickets/<int:id>` | pemilik atau admin | — |
| POST | `/tickets/<int:id>/pesan` | pemilik atau admin | `message` |
| POST | `/tickets/<int:id>/dokumen` | pemilik | multipart `document` (algoritma tidak dipilih user, selalu `AES-256-GCM`) |
| GET | `/documents/<int:id>/download` | pemilik atau admin | — |
| GET | `/admin/tiket` | admin | — |
| POST | `/admin/tiket/<int:id>/status` | admin | `status` |

Denial akses: warga → resource warga lain = `403` atau `404`; warga → area admin = `403`;
anonim → redirect ke `/auth/login`. Pemeriksaan kepemilikan dilakukan **sebelum**
membaca file.

Pemetaan error: `CryptoError` (ciphertext rusak, path traversal, metadata tidak valid) → `400`.

### Helper autentikasi (sudah tersedia dari Anggota 1)

```python
from flask_login import current_user, login_required
from app.auth.utils import role_required, admin_required

current_user.is_admin     # bool
current_user.resident     # Resident milik user yang login
role_required("admin")    # 403 untuk role lain, redirect untuk anonim
```

Nama blueprint dan endpoint dipakai `default_dashboard_url()`:

| Blueprint | Endpoint wajib |
|---|---|
| `resident` | `resident.dashboard` |
| `admin` | `admin.dashboard` |
| `tickets` | `tickets.create`, `tickets.detail`, `tickets.upload`, `tickets.download` |

Tanpa endpoint itu, login tetap jatuh ke `/` (fallback), tetapi navigasi
pengguna jadi tidak jelas. Gunakan nama di atas.

Registrasi admin: `/auth/register` menerima field `admin_code`. Bila
`ADMIN_INVITE_CODE` tidak diset, semua pendaftaran menjadi `warga`.

### Audit log

`AuditLog` wajib ditulis minimal untuk: perubahan status tiket, upload dokumen,
dan download dokumen yang berhasil. Isi `action`, `resource_type`, `resource_id`,
dan `actor_user_id`.

### Status tiket

`Diajukan` → `Diproses` → `Selesai` atau `Ditolak`.

### Halaman wajib menampilkan `ticket.service_type`

Dashboard warga, detail tiket, dan antrean admin harus merender `service_type`,
karena `tests/test_authorization.py` memakai field itu sebagai penanda.

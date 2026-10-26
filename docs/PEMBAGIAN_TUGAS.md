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
| `CRYPTO_MASTER_KEY` | `app/crypto/keys.py` | hex 64 karakter, diturunkan via HKDF |
| `PRIVATE_STORAGE_DIR` | storage | default `private_storage` |
| `MAX_CONTENT_LENGTH_MB` | upload | default 50 |
| `DATABASE_URL` | SQLAlchemy | dikomentari = pakai default `instance/secure_rt_dev.sqlite3` |

### Signature kripto

Semua modul cipher (`aes.py`, `des.py`, `rc4.py`) wajib punya:

```python
def encrypt(data: bytes) -> tuple[bytes, dict]   # (ciphertext, metadata JSON-serializable)
def decrypt(blob: bytes, meta: dict) -> bytes    # raise bila integritas gagal
```

`app/crypto/__init__.py`:

```python
ALGORITHMS: dict[str, ModuleType]     # {"AES-GCM": aes, "DES-CBC": des, "RC4": rc4}
def get_cipher(nama: str) -> ModuleType
```

`app/crypto/storage.py`:

```python
def store_bytes(data: bytes, algorithm: str) -> StoredFile
def read_bytes(relative_path: str, metadata: dict) -> bytes
```

`StoredFile` berisi `relative_path`, `size_bytes`, `sha256_plaintext`, `algorithm`, `metadata`.

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
| POST | `/tickets/<int:id>/dokumen` | pemilik | multipart `file`, `algorithm` opsional |
| GET | `/documents/<int:id>/download` | pemilik atau admin | — |
| GET | `/admin/tiket` | admin | — |
| POST | `/admin/tiket/<int:id>/status` | admin | `status` |

Denial akses: warga → resource warga lain = `403` atau `404`; warga → area admin = `403`;
anonim → redirect ke `/auth/login`. Pemeriksaan kepemilikan dilakukan **sebelum**
membaca file.

Pemetaan error: `IntegrityError` (ciphertext rusak) → `400`; `PathTraversalError` → `400`.

### Status tiket

`Diajukan` → `Diproses` → `Selesai` atau `Ditolak`.

### Halaman wajib menampilkan `ticket.service_type`

Dashboard warga, detail tiket, dan antrean admin harus merender `service_type`,
karena `tests/test_authorization.py` memakai field itu sebagai penanda.

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

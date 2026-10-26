# Aturan Agen — Kriptografi dan Penyimpanan

Aturan ini berlaku untuk seluruh repository. Untuk pekerjaan pada `app/crypto/`,
`tests/test_crypto.py`, dan bagian kriptografi di `tests/test_storage.py`, ikuti
spesifikasi utama di `docs/SPESIFIKASI_KRIPTOGRAFI.md`.

## Batas pekerjaan

- Implementasikan AES, DES, dan RC4 hanya untuk eksperimen akademik dengan data
  dummy. AES-GCM adalah satu-satunya pilihan yang layak untuk penggunaan aplikasi.
- DES dan RC4 wajib diberi label `INSECURE/ACADEMIC ONLY` pada docstring dan
  metadata. Jangan menjadikannya algoritma default.
- Jangan membaca, membuat, atau commit data pribadi, kunci nyata, `.env`, hasil
  upload, maupun database berisi data warga.
- Jangan mengubah modul milik anggota lain kecuali diperlukan oleh kontrak
  integrasi. Jika perlu, buat perubahan sekecil mungkin dan jelaskan alasannya.

## Aturan keamanan wajib

- AES menggunakan AES-GCM dengan kunci 256 bit dan nonce acak 12 byte.
- DES menggunakan DES-CBC dengan IV acak 8 byte dan padding PKCS#7. ECB dilarang.
- RC4 adalah stream cipher dan tidak memiliki mode blok atau IV standar. Setiap
  enkripsi wajib memakai kunci sesi acak yang unik.
- DES-CBC dan RC4 wajib memakai encrypt-then-MAC HMAC-SHA256 dengan kunci enkripsi
  dan MAC terpisah yang diturunkan dari master key menggunakan salt unik dan HKDF.
  Verifikasi tag dilakukan sebelum dekripsi.
- Metadata yang diperlukan untuk dekripsi harus ikut diautentikasi. Encode nilai
  biner dalam Base64 dan jangan pernah menyimpan kunci di metadata/ciphertext.
- Gunakan pembanding tag constant-time dari library. Jangan membuat algoritma
  kriptografi primitif sendiri jika implementasi library yang sesuai tersedia.
- Semua kegagalan autentikasi, metadata tidak valid, algoritma tidak dikenal, dan
  ciphertext rusak harus menghasilkan exception publik yang seragam agar tidak
  menjadi oracle.
- File harus dienkripsi sebelum ditulis ke `private_storage/`. Tulis secara atomik,
  gunakan nama acak yang dibuat aplikasi, cegah path traversal, dan hapus file
  parsial jika operasi gagal.

## Kontrak implementasi

- Pertahankan API seragam `encrypt(plaintext, key, *, aad=b"")` dan
  `decrypt(ciphertext, key, metadata, *, aad=b"")` pada setiap modul algoritma.
- Hasil `encrypt` memisahkan `ciphertext` (bytes) dan `metadata` (dict JSON-safe).
- Metadata minimum mengikuti tabel dalam `docs/SPESIFIKASI_KRIPTOGRAFI.md`.
- Nilai AAD penyimpanan dibentuk secara deterministik dari konteks dokumen, bukan
  dari input JSON bebas. Jangan memasukkan path absolut atau secret ke metadata.
- Default penyimpanan adalah `AES-GCM`; pemilihan DES/RC4 harus eksplisit.

## Pengujian dan verifikasi

- Gunakan `pytest` dan data yang dibuat test di direktori sementara.
- Untuk setiap algoritma, uji round-trip file kosong, data biner, data non-UTF-8,
  dan file berukuran beberapa blok.
- Buktikan hasil dekripsi identik byte-per-byte dengan sumber dan cocokkan SHA-256.
- Uji nonce/IV/kunci sesi unik pada dua enkripsi plaintext yang sama.
- Uji perubahan satu byte pada ciphertext, tag, dan metadata; semuanya harus
  ditolak. Uji pula kunci salah dan AAD salah.
- Untuk AES/DES, tambahkan tes yang memastikan mode bukan ECB.
- Jangan menulis angka benchmark atau hasil pengujian fiktif. Jalankan perintahnya
  dan catat hanya hasil aktual.

## Disiplin commit

Jangan mencampur implementasi beberapa algoritma dalam satu commit. Setelah tes
terkait lulus, buat commit kecil dengan urutan yang disarankan:

1. `feat(crypto): implement AES-GCM file encryption`
2. `test(crypto): verify AES-GCM round trip and tamper detection`
3. `feat(crypto): implement academic DES-CBC encryption`
4. `test(crypto): verify DES-CBC round trip and integrity`
5. `feat(crypto): implement academic RC4 encryption`
6. `test(crypto): verify RC4 round trip and integrity`
7. `feat(crypto): add private encrypted file storage`
8. `test(crypto): verify stored file decrypts identically`

Sebelum setiap commit, periksa `git diff`, jalankan tes yang relevan, dan jangan
memasukkan perubahan milik anggota lain. Jangan amend, rebase, reset, atau push
tanpa instruksi eksplisit pengguna.

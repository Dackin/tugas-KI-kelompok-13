# Hasil Benchmark Kriptografi

Angka di bawah berasal dari eksekusi aktual `benchmarks/benchmark.py`, bukan
perkiraan. Data mentah: `benchmarks/results/benchmark_20261026_204435.csv`
dan `.json`.

## Metodologi

- Yang diukur: primitive kriptografi in-memory (`encrypt`/`decrypt` per modul).
  I/O penyimpanan, upload, dan jaringan **tidak** termasuk.
- Plaintext: byte deterministik dari `random.Random(20261026).randbytes(n)`,
  sehingga ukuran dan isi sama untuk setiap algoritma dan bisa direproduksi.
- Ukuran: 1 KB, 100 KB, 1 MB, 10 MB. Pengulangan: 3 per kombinasi; dilaporkan
  rata-rata (`statistics.fmean`). Satu putaran pemanasan dijalankan lebih dulu
  dan tidak dicatat, agar biaya inisialisasi library tidak masuk ke rata-rata.
- Kunci: 32 byte dummy khusus benchmark (bukan master key aplikasi, tidak dipakai
  runtime). AAD dikosongkan karena yang diukur primitive, bukan jalur storage.
- Integritas: setiap hasil dekripsi dibandingkan dengan plaintext asli
  (`bytes` sama) **dan** SHA-256. Bila satu saja berbeda, benchmark berhenti
  dengan error dan tidak menulis hasil.
- Overhead ciphertext = `(len(ciphertext) - n) / n`; overhead total menambahkan
  panjang metadata JSON (nonce/IV/salt/tag) yang ikut disimpan di database.

## Lingkungan

| Item | Nilai |
|---|---|
| CPU | AMD Ryzen 7 5825U |
| OS | Linux 7.1.13-200.fc44.x86_64 |
| Python | 3.14.7 |
| AES-GCM | `cryptography` 50.0.2 |
| DES / RC4 | `pycryptodome` 4.2.0 |

## Hasil

| Algoritma | Ukuran | Enc (ms) | Dec (ms) | Enc (MB/s) | Dec (MB/s) | Ciphertext (B) | Metadata (B) | Overhead cipher | Overhead total |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AES-256-GCM | 1 KB | 0,021 | 0,014 | 47,63 | 70,44 | 1.024 | 107 | 0,000% | 10,449% |
| AES-256-GCM | 100 KB | 0,051 | 0,038 | 1.902,26 | 2.584,32 | 102.400 | 107 | 0,000% | 0,104% |
| AES-256-GCM | 1 MB | 0,436 | 0,292 | 2.292,58 | 3.428,19 | 1.048.576 | 107 | 0,000% | 0,010% |
| AES-256-GCM | 10 MB | 6,169 | 5,041 | 1.621,07 | 1.983,90 | 10.485.760 | 107 | 0,001% | 0,001% |
| DES-CBC-HMAC-SHA256 | 1 KB | 0,075 | 0,078 | 13,00 | 12,59 | 1.032 | 267 | 0,781% | 26,855% |
| DES-CBC-HMAC-SHA256 | 100 KB | 2,784 | 2,660 | 35,08 | 36,72 | 102.408 | 267 | 0,008% | 0,269% |
| DES-CBC-HMAC-SHA256 | 1 MB | 28,046 | 27,233 | 35,66 | 36,72 | 1.048.584 | 267 | 0,001% | 0,026% |
| DES-CBC-HMAC-SHA256 | 10 MB | 282,730 | 273,639 | 35,37 | 36,54 | 10.485.768 | 267 | 0,000% | 0,003% |
| RC4-HMAC-SHA256 | 1 KB | 0,036 | 0,038 | 27,13 | 25,66 | 1.024 | 208 | 0,000% | 20,312% |
| RC4-HMAC-SHA256 | 100 KB | 0,355 | 0,329 | 275,28 | 296,54 | 102.400 | 208 | 0,000% | 0,203% |
| RC4-HMAC-SHA256 | 1 MB | 3,378 | 3,075 | 296,06 | 325,16 | 1.048.576 | 208 | 0,000% | 0,020% |
| RC4-HMAC-SHA256 | 10 MB | 34,326 | 31,477 | 291,33 | 317,69 | 10.485.760 | 208 | 0,000% | 0,002% |

## Pembacaan hasil

1. **AES-256-GCM paling cepat** — ~1.621 MB/s enkripsi pada 10 MB, sekitar
   46x DES dan 5,6x RC4. Karena itu AES-GCM menjadi default aplikasi.
2. **DES paling lambat** — ~35 MB/s dan stabil di semua ukuran. Wajar: blok
   8 byte dengan padding PKCS#7 dan HMAC tambahan; hanya untuk eksperimen
   akademik.
3. **RC4 di tengah** — ~291 MB/s, tetap tidak aman dan hanya untuk akademik.
4. **Overhead terbesar terjadi pada file kecil.** Untuk 1 KB, metadata tetap
   (107 B AES, 208 B RC4, 267 B DES) mendominasi: overhead total 10,4% / 20,3% /
   26,9%. Pada 10 MB overhead total ≤ 0,003%.
5. **Ciphertext AES identik panjangnya dengan plaintext** karena tag GCM (16 B)
   disimpan terpisah di metadata. DES membesar sampai kelipatan 8 byte
   (padding PKCS#7). RC4 tidak mengubah panjang.
6. **Throughput 1 KB lebih rendah dari 1 MB** (AES 47,63 vs 2.292,58 MB/s)
   karena biaya tetap per panggilan—pembuatan nonce/kunci sesi dan objek cipher—
   mendominasi data yang sangat kecil. Ini karakteristik nyata, bukan artefak.

## Batasan

- Satu mesin, tiga pengulangan; bukan benchmark statistik yang ketat.
- Implementasi DES/RC4 memakai `pycryptodome`, bukan implementasi Python murni,
  sehingga angka mencerminkan library tersebut.
- AAD tidak diukur; pada jalur storage AAD menambah data yang diautentikasi,
  tetapi tidak mengubah panjang ciphertext.
- Waktu I/O disk, serialisasi database, dan transfer jaringan tidak termasuk.
  Untuk latensi unggah nyata, ukur terpisah di level route.

## Cara mereproduksi

```bash
python benchmarks/benchmark.py
python benchmarks/benchmark.py --algoritma AES-256-GCM --ukuran 1MB --ulangi 5
```

Hasil baru ditulis ke `benchmarks/results/benchmark_<timestamp>.{csv,json}`.
Jangan mengedit angka di dokumen ini secara manual tanpa menjalankan ulang
benchmark.

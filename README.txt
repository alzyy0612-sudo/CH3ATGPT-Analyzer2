CH3ATGPT Analyzer — proyek Android dengan build online

Tidak perlu Android Studio di HP/komputer. APK dibuat oleh GitHub Actions.

LANGKAH:
1. Buat akun atau masuk ke GitHub.
2. Buat repository baru, misalnya CH3ATGPT-Analyzer.
3. Ekstrak ZIP ini. Unggah seluruh ISI folder ke repository (termasuk folder tersembunyi .github).
4. Buka tab Actions di repository dan aktifkan Actions bila diminta.
5. Jalankan workflow "Build APK" dengan tombol Run workflow, atau tunggu build berjalan setelah push.
6. Setelah selesai, buka hasil run workflow. Di bagian Artifacts unduh "CH3ATGPT-Analyzer-APK".
7. Ekstrak hasil unduhan ZIP, lalu instal app-debug.apk di Android. Izinkan instalasi dari sumber tersebut bila Android memintanya.

Catatan:
- APK debug untuk pengujian, bukan rilis Play Store.
- Proyek memerlukan koneksi internet ketika build online.
- Ini alat analisis statis dasar: membaca metadata ELF, SHA-256, dan string ASCII.
- Tidak menjalankan berkas yang dianalisis.
- Tidak dapat memecahkan enkripsi tanpa mengetahui algoritma dan kunci yang benar.

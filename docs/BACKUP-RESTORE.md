# Backup Restore

Saat migrasi schema lama ke multi-organization, aplikasi membuat backup database ke:

- `data/backups/`

Strategi saat ini:

- backup database SQLite sebelum migrasi besar
- database aktif tetap dipertahankan
- restore dilakukan dengan mengganti file database aktif menggunakan backup yang dipilih

# Database

Database utama: `SQLite`

Entitas utama:

- `organizations`
- `roles`
- `permissions`
- `role_permissions`
- `users`
- `agenda_entries`
- `tasks`
- `reminders`
- `notifications`
- `contacts`
- `letters`
- `dispositions`
- `documents`
- `contracts`
- `permits`
- `vendors`
- `assets`
- `meetings`
- `meeting_minutes`
- `audit_logs`
- `system_settings`

Prinsip relasi:

- setiap data penting memiliki `organization_id`
- setiap data yang dimonitor pusat tetap menyimpan organisasi pemilik asli
- audit trail terpisah dari tabel transaksi
- notification memakai `source_key` unik agar tidak duplikat

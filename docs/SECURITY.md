# Security

Keamanan yang sudah diterapkan:

- password hashing dengan Werkzeug
- session-based authentication
- route permission checks
- organization-based access control
- SQL parameterization
- audit log
- backup sebelum migrasi schema penting

Yang masih perlu dilanjutkan:

- CSRF protection terintegrasi form
- upload file validation
- MIME validation
- encrypted secret storage untuk email OAuth
- hardening session untuk deployment production

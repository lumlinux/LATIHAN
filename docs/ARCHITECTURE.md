# Architecture

AI SECRETARY menggunakan arsitektur monolith ringan berbasis Flask.

Komponen utama:

- `Flask app` untuk routing, rendering, auth session, dan workflow.
- `SQLite` sebagai relational database lokal.
- `Jinja templates` untuk dashboard, modul list, form, compliance, reports, dan audit.
- `RBAC + organization-based access` di service layer aplikasi.
- `Notification generation` berjalan saat halaman utama diakses.

Prinsip arsitektur:

- satu aplikasi
- satu database
- multi-organization
- pemilik data tetap pada unit asal
- PT melakukan monitoring tanpa mencampur ownership

# Authorization

Lapisan akses menggunakan dua prinsip:

1. Role-based access control
2. Organization-based access control

Role default:

- `OWNER / MANAGEMENT PT`
- `SEKRETARIS KANTOR PUSAT`
- `SEKRETARIS RS`
- `ADMIN IT`

Aturan inti:

- sekretaris RS hanya melihat dan mengubah data unit RS miliknya
- PT/Owner dapat memonitor data lintas RS sesuai permission
- PT tidak otomatis mengubah data milik RS
- Admin IT fokus pada akses teknis, bukan otomatis membaca isi dokumen rahasia

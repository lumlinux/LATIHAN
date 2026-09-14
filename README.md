# AI SECRETARY

AI SECRETARY adalah aplikasi sekretaris digital internal untuk `PT / Kantor Pusat`, `RS Bhakti Husada Cikarang`, dan `RS Bhakti Husada Purwakarta`.

Fokus aplikasi:

- digital secretary
- central administration
- document repository
- MOU / contract monitoring
- permit / license monitoring
- compliance & tembusan pusat
- task, reminder, meeting, dan audit trail
- AI secretary berbasis data aplikasi

## Stack

- Python 3
- Flask 3
- SQLite
- Jinja Templates
- CSS custom
- unittest + Flask test client

## Fitur Yang Sudah Aktif

- Authentication dengan session
- Role & Permission
- Multi-organization foundation
- Organization-based access control
- Dashboard lintas organisasi
- Agenda
- Calendar
- Task
- Reminder
- Notification center
- Contacts
- Incoming / Outgoing Letter
- Disposition
- Document Management
- Physical document upload ke storage lokal aman melalui backend
- Document detail page dengan preview, download, extracted text, resume, audit, dan version history
- Legacy attachment path compatibility melalui storage bridge
- Automatic text extraction untuk PDF, DOC, dan DOCX
- Automatic document resume untuk Bahasa Indonesia dan English
- Resume review workflow: regenerate, edit, approve, reject
- Secure backup arsip yang mencakup database dan file storage
- MOU & Contract
- License & Permit
- Vendor & Partner
- Asset Management
- Meeting
- Meeting Minutes
- Compliance dashboard
- Reports + export CSV
- Global search
- Audit log
- AI Secretary summary assistant

## Akun Default

- `owner / owner123`
- `sekretaris.pt / secretpt123`
- `sekretaris.cikarang / cikarang123`
- `sekretaris.purwakarta / purwakarta123`
- `admin.it / adminit123`
- `admin / admin123`

## Menjalankan Aplikasi

```powershell
.\.venv-1\Scripts\python.exe app.py
```

Komputer yang menjalankan aplikasi:

```text
http://127.0.0.1:5000
```

Akses dari komputer lain yang terhubung ke Wi-Fi/LAN yang sama:

```text
http://ALAMAT-IP-KOMPUTER-SERVER:5000
```

Contoh, jika alamat IP komputer server adalah `192.168.2.199`:

```text
http://192.168.2.199:5000
```

Untuk melihat alamat IP server:

```powershell
Get-NetIPAddress -AddressFamily IPv4
```

Jika Windows Firewall meminta izin saat pertama kali menjalankan aplikasi, izinkan akses pada jaringan `Private`. Kedua komputer harus berada pada jaringan yang sama. Jalankan aplikasi tetap pada komputer server, dan jangan menutup terminal yang menjalankannya.

## Menjalankan Test

```powershell
.\.venv-1\Scripts\python.exe -m unittest discover -s tests -v
```

## Struktur Penting

- `app.py`
- `services/document_processing.py`
- `templates/`
- `static/style.css`
- `data/ai_secretary.db`
- `data/backups/`
- `data/storage/`
- `tests/test_app.py`
- `docs/`

## Upload Dokumen

- Menu `Documents` sekarang memiliki tombol `Upload Document`.
- Upload juga bisa dimulai dari modul `Contracts`, `Permits`, `Letters`, `Tasks`, `Meetings`, `Vendors`, dan `Assets` melalui tombol `Add Document`.
- Format upload yang diizinkan: `PDF`, `DOC`, `DOCX`, `XLS`, `XLSX`, `PPT`, `PPTX`, `JPG`, `JPEG`, `PNG`, `ZIP`.
- File diakses ulang hanya lewat endpoint backend untuk preview/download, bukan direct path filesystem.

## Resume Dokumen

- Resume dibuat dari hasil ekstraksi teks dokumen, bukan dari nama file saja.
- Format minimal yang diproses untuk resume otomatis: `PDF`, `DOC`, `DOCX`.
- Status utama yang digunakan:
  - storage: `LEGACY_PATH`, `UPLOADED`, `MISSING`
  - extraction: `EXTRACTING_TEXT`, `TEXT_EXTRACTED`, `TEXT_EXTRACTION_UNAVAILABLE`, `FAILED`
  - summary: `GENERATING`, `READY_FOR_REVIEW`, `APPROVED`, `REJECTED`, `FAILED`

## Backup

- Halaman `Settings` sekarang menyediakan `Create Backup`.
- Arsip backup yang sudah dibuat dapat di-`Restore` kembali dari halaman `Settings` oleh user yang memiliki permission pengaturan.
- Arsip backup berisi database SQLite dan folder document storage agar metadata dan file fisik tetap sinkron saat dipindahkan.

## Catatan

- Integrasi email Gmail/Microsoft 365 belum diaktifkan di environment ini.
- OCR untuk file scan/image belum diaktifkan; file scan akan ditandai `TEXT_EXTRACTION_UNAVAILABLE` bila teks tidak terbaca.
- Sistem sudah mendukung konsep `Original Owner + Central Monitoring / Tembusan`.

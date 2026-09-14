import io
import shutil
import unittest
import zipfile
from pathlib import Path

from app import create_app, query_all, query_one


class AiSecretaryAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path("tests/.tmp")
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.temp_dir / "test.db"
        self.storage_root = self.temp_dir / "storage"
        self.backup_root = self.temp_dir / "backups"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": str(self.db_path),
                "STORAGE_ROOT": str(self.storage_root),
                "BACKUP_ROOT": str(self.backup_root),
                "LEGACY_STORAGE_ROOTS": [str(self.temp_dir)],
                "DOCUMENT_MAX_FILE_SIZE": 1024 * 1024,
                "MAX_CONTENT_LENGTH": 1024 * 1024,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def login(self, username="admin", password="admin123"):
        self.client.get("/logout", follow_redirects=True)
        return self.client.post("/login", data={"username": username, "password": password}, follow_redirects=True)

    def fetch_one(self, sql, params=()):
        with self.app.app_context():
            return query_one(sql, params)

    def fetch_all(self, sql, params=()):
        with self.app.app_context():
            return query_all(sql, params)

    def base_document_data(self, organization_id="1", title="Dokumen Uji", document_type="MOU", category="MOU"):
        return {
            "organization_id": organization_id,
            "title": title,
            "document_number": "DOC/001/2026",
            "document_type": document_type,
            "category": category,
            "department": "Legal",
            "document_date": "2026-09-14",
            "effective_date": "2026-09-14",
            "expiry_date": "2029-09-14",
            "status": "Active",
            "owner_id": "1",
            "pic_user_id": "1",
            "vendor_name": "Vendor ABC",
            "version": "v1.0",
            "tags": "mou,vendor",
            "confidentiality": "INTERNAL",
            "central_monitoring_required": "0",
            "central_status": "CREATED",
            "description": "Dokumen untuk pengujian.",
            "generate_summary": "1",
            "summary_language": "id",
            "allow_duplicate": "1",
        }

    def upload_document(self, filename, content, extra=None, follow_redirects=True):
        data = self.base_document_data()
        if extra:
            data.update(extra)
        data["document_file"] = (io.BytesIO(content), filename)
        return self.client.post("/documents/upload", data=data, content_type="multipart/form-data", follow_redirects=follow_redirects)

    def create_text_pdf(self, text: str) -> bytes:
        encoded = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        pdf = (
            "%PDF-1.4\n"
            "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >> endobj\n"
            f"4 0 obj << /Length 44 >> stream\nBT /F1 12 Tf 10 100 Td ({encoded}) Tj ET\nendstream endobj\n"
            "xref\n0 5\n0000000000 65535 f \n"
            "trailer << /Root 1 0 R /Size 5 >>\nstartxref\n0\n%%EOF"
        )
        return pdf.encode("latin1")

    def create_docx(self, text: str) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "word/document.xml",
                (
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                    f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
                ),
            )
        return stream.getvalue()

    def create_xlsx(self) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", "<Types></Types>")
        return stream.getvalue()

    def create_png(self) -> bytes:
        return b"\x89PNG\r\n\x1a\n" + b"\x00" * 64

    def create_doc(self, text: str) -> bytes:
        return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + text.encode("latin1", errors="ignore")

    def create_legacy_file(self, relative_path: str, content: bytes):
        path = self.temp_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_login_and_dashboard(self):
        response = self.login("owner", "owner123")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Dashboard", body)
        self.assertIn("Compliance Alerts", body)

    def test_admin_can_create_task(self):
        self.login("admin", "admin123")
        response = self.client.post(
            "/modules/tasks/new",
            data={
                "organization_id": "1",
                "title": "Prepare monthly report",
                "status": "TODO",
                "priority": "HIGH",
                "due_date": "2026-09-20T09:00",
                "assigned_to": "1",
                "related_type": "GENERAL",
                "description": "Compile KPI and executive summary.",
            },
            follow_redirects=True,
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Prepare monthly report", body)

    def test_rs_cikarang_cannot_see_purwakarta_contract(self):
        self.login("sekretaris.cikarang", "cikarang123")
        response = self.client.get("/modules/contracts")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Kerja Sama CT Scan", body)
        self.assertNotIn("Kontrak Laundry Medis", body)

    def test_owner_can_monitor_both_rs_contracts(self):
        self.login("owner", "owner123")
        response = self.client.get("/modules/contracts")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Kerja Sama CT Scan", body)
        self.assertIn("Kontrak Laundry Medis", body)

    def test_admin_it_cannot_open_document_repository(self):
        self.login("admin.it", "adminit123")
        response = self.client.get("/modules/documents")
        self.assertEqual(response.status_code, 403)

    def test_search_finds_asset_keyword(self):
        self.login("owner", "owner123")
        response = self.client.get("/search?q=CT+Scan")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("CT Scan", body)

    def test_settings_page_shows_company_and_letter_shortcuts(self):
        self.login("admin", "admin123")
        response = self.client.get("/settings")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Kelola Company Settings", body)
        self.assertIn("Kelola Kategori Surat", body)
        self.assertIn("Password Policy", body)

    def test_user_edit_rejects_mismatched_password_confirmation(self):
        self.login("admin", "admin123")
        user_row = self.fetch_one("SELECT * FROM users WHERE username = ?", ("sekretaris.cikarang",))
        previous_hash = user_row["password_hash"]
        response = self.client.post(
            f"/users/{user_row['id']}/edit",
            data={
                "full_name": user_row["full_name"],
                "email": user_row["email"],
                "phone": user_row["phone"] or "",
                "department": user_row["department"] or "",
                "position": user_row["position"] or "",
                "password": "PasswordBaru1!",
                "confirm_password": "PasswordBerbeda1!",
                "role_id": str(user_row["role_id"]),
                "organization_id": str(user_row["organization_id"]),
                "is_active": "on",
            },
            follow_redirects=True,
        )
        body = response.get_data(as_text=True)
        updated_row = self.fetch_one("SELECT * FROM users WHERE id = ?", (user_row["id"],))
        self.assertEqual(response.status_code, 200)
        self.assertIn("Password dan konfirmasi password harus sama.", body)
        self.assertEqual(updated_row["password_hash"], previous_hash)

    def test_company_settings_updates_date_and_month_format(self):
        self.login("admin", "admin123")
        response = self.client.post(
            "/settings/company",
            data={
                "company_name": "Bhakti Husada Group",
                "short_name": "Bhakti Husada",
                "company_code": "RSBH",
                "phone": "0210000000",
                "email": "admin@aisecretary.local",
                "website": "https://aisecretary.local",
                "city": "Jakarta",
                "province": "DKI Jakarta",
                "postal_code": "10110",
                "tax_number": "",
                "address": "Jl. Administrasi No. 1",
                "letter_number_format": "{NOMOR}/{KATEGORI}/{KODE_PERUSAHAAN}/{BULAN_ROMAWI}/{TAHUN}",
                "letter_prefix": "BH/",
                "date_format": "DD/MM/YYYY",
                "month_format": "NUMERIC",
                "active_year": "2026",
                "start_number": "5",
                "reset_policy": "MONTHLY",
                "use_organization_code_in_letters": "on",
                "official_name": "Direktur Utama",
                "official_position": "Direktur",
                "official_signature": "ttd",
                "password_min_length": "10",
                "password_expiry_days": "45",
                "password_require_uppercase": "on",
                "password_require_lowercase": "on",
                "password_require_digit": "on",
            },
            follow_redirects=True,
        )
        body = response.get_data(as_text=True)
        company = self.fetch_one("SELECT * FROM company_settings WHERE id = 1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Pengaturan perusahaan berhasil diperbarui.", body)
        self.assertEqual(company["date_format"], "DD/MM/YYYY")
        self.assertEqual(company["month_format"], "NUMERIC")
        self.assertEqual(company["letter_prefix"], "BH/")

    def test_pdf_upload_stores_file_and_generates_summary(self):
        self.login("admin", "admin123")
        response = self.upload_document(
            "mou-vendor.pdf",
            self.create_text_pdf("antara RS Bhakti Husada Cikarang dan Vendor ABC. Tujuan: kerja sama layanan. Rp 5000000. 14 September 2026."),
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Document Detail", body)
        self.assertIn("RESUME DOKUMEN", body)
        file_row = self.fetch_one("SELECT * FROM document_files WHERE original_filename = ?", ("mou-vendor.pdf",))
        summary_row = self.fetch_one("SELECT * FROM document_summaries WHERE document_id = ?", (file_row["document_id"],))
        self.assertIsNotNone(file_row)
        self.assertEqual(file_row["storage_status"], "UPLOADED")
        self.assertTrue((self.storage_root / file_row["storage_path"]).exists())
        self.assertEqual(summary_row["summary_status"], "READY_FOR_REVIEW")

    def test_docx_upload_supports_english_summary(self):
        self.login("admin", "admin123")
        response = self.upload_document(
            "agreement.docx",
            self.create_docx("between PT Alpha and PT Beta. Purpose: collaboration. Renewal: annual."),
            {"summary_language": "en"},
        )
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("DOCUMENT SUMMARY", body)
        summary_row = self.fetch_one("SELECT * FROM document_summaries WHERE language = 'en' ORDER BY id DESC LIMIT 1")
        self.assertEqual(summary_row["summary_status"], "READY_FOR_REVIEW")

    def test_xlsx_upload_marks_extraction_unavailable(self):
        self.login("admin", "admin123")
        response = self.upload_document(
            "report.xlsx",
            self.create_xlsx(),
            {"document_type": "ARCHIVE", "category": "Arsip"},
        )
        self.assertEqual(response.status_code, 200)
        file_row = self.fetch_one("SELECT * FROM document_files WHERE original_filename = ?", ("report.xlsx",))
        extraction_row = self.fetch_one("SELECT * FROM document_text_extractions WHERE document_file_id = ?", (file_row["id"],))
        summary_row = self.fetch_one("SELECT * FROM document_summaries WHERE document_file_id = ?", (file_row["id"],))
        self.assertEqual(file_row["storage_status"], "UPLOADED")
        self.assertEqual(extraction_row["extraction_status"], "TEXT_EXTRACTION_UNAVAILABLE")
        self.assertEqual(summary_row["summary_status"], "FAILED")

    def test_rejects_large_upload(self):
        self.login("admin", "admin123")
        self.app.config["DOCUMENT_MAX_FILE_SIZE"] = 128
        self.app.config["MAX_CONTENT_LENGTH"] = 128
        response = self.upload_document("big.pdf", self.create_text_pdf("A" * 400), follow_redirects=False)
        self.assertIn(response.status_code, {400, 413})

    def test_rejects_disallowed_extension(self):
        self.login("admin", "admin123")
        response = self.upload_document("danger.exe", b"MZP" * 20)
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Extension file tidak diizinkan", body)

    def test_sanitizes_dangerous_filename(self):
        self.login("admin", "admin123")
        self.upload_document("../kontrak-rahasia.pdf", self.create_text_pdf("antara A dan B."))
        file_row = self.fetch_one("SELECT * FROM document_files ORDER BY id DESC LIMIT 1")
        self.assertEqual(file_row["original_filename"], "kontrak-rahasia.pdf")
        self.assertNotIn("..", file_row["stored_filename"])

    def test_preview_and_download_uploaded_pdf(self):
        self.login("admin", "admin123")
        self.upload_document("preview.pdf", self.create_text_pdf("antara A dan B."))
        file_row = self.fetch_one("SELECT * FROM document_files WHERE original_filename = ?", ("preview.pdf",))
        download = self.client.get(f"/documents/files/{file_row['id']}/download")
        preview = self.client.get(f"/documents/files/{file_row['id']}/preview")
        self.assertEqual(download.status_code, 200)
        self.assertEqual(preview.status_code, 200)
        self.assertTrue(download.headers.get("Content-Disposition", "").startswith("attachment;"))
        self.assertIn("application/pdf", preview.headers.get("Content-Type", ""))
        download.close()
        preview.close()

    def test_versioning_restore_regenerate_and_review(self):
        self.login("admin", "admin123")
        self.upload_document("version-1.pdf", self.create_text_pdf("antara A dan B. Tujuan: versi pertama."))
        document_row = self.fetch_one("SELECT id FROM documents WHERE title = ? ORDER BY id DESC LIMIT 1", ("Dokumen Uji",))
        version_1 = self.fetch_one("SELECT * FROM document_files WHERE document_id = ? AND version_number = 1", (document_row["id"],))
        self.client.post(
            f"/documents/{document_row['id']}/versions/new",
            data={
                "document_file": (io.BytesIO(self.create_text_pdf("antara A dan B. Tujuan: versi kedua. Termination: yes.")), "version-2.pdf"),
                "generate_summary": "1",
                "summary_language": "id",
                "allow_duplicate": "1",
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        version_2 = self.fetch_one("SELECT * FROM document_files WHERE document_id = ? AND version_number = 2", (document_row["id"],))
        self.assertEqual(version_2["is_current"], 1)
        self.client.post(f"/documents/files/{version_1['id']}/restore", follow_redirects=True)
        restored = self.fetch_one("SELECT * FROM document_files WHERE id = ?", (version_1["id"],))
        self.assertEqual(restored["is_current"], 1)
        self.client.post(f"/documents/{document_row['id']}/summary/generate", data={"summary_language": "id"}, follow_redirects=True)
        summary_row = self.fetch_one("SELECT * FROM document_summaries WHERE document_id = ? AND is_current = 1", (document_row["id"],))
        self.client.post(
            f"/documents/summaries/{summary_row['id']}/review",
            data={"summary_text": "Resume final yang direview manual.", "review_notes": "Sudah dicek.", "next_status": "APPROVED"},
            follow_redirects=True,
        )
        updated_summary = self.fetch_one("SELECT * FROM document_summaries WHERE id = ?", (summary_row["id"],))
        self.assertEqual(updated_summary["summary_status"], "APPROVED")
        self.assertEqual(updated_summary["manually_edited"], 1)

    def test_legacy_file_can_generate_summary_and_missing_legacy_is_handled(self):
        self.create_legacy_file("docs/izin-rsckr.pdf", self.create_text_pdf("antara RSCKR dan Dinkes. Tujuan: izin operasional."))
        self.login("sekretaris.cikarang", "cikarang123")
        detail = self.client.get("/documents/1")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("LEGACY_PATH", detail.get_data(as_text=True))
        generate = self.client.post("/documents/1/summary/generate", data={"summary_language": "id"}, follow_redirects=True)
        self.assertEqual(generate.status_code, 200)
        self.assertIn("RESUME DOKUMEN", generate.get_data(as_text=True))
        self.login("owner", "owner123")
        missing_detail = self.client.get("/documents/2")
        self.assertEqual(missing_detail.status_code, 200)
        self.assertIn("MISSING", missing_detail.get_data(as_text=True))

    def test_rs_cikarang_cannot_download_purwakarta_document_but_owner_can(self):
        self.login("sekretaris.purwakarta", "purwakarta123")
        self.upload_document(
            "purwakarta.pdf",
            self.create_text_pdf("antara RS Purwakarta dan Vendor. Tujuan: kontrak."),
            {"organization_id": "3", "central_monitoring_required": "1", "central_status": "SENT TO HO"},
        )
        file_row = self.fetch_one("SELECT df.id FROM document_files df JOIN documents d ON d.id = df.document_id WHERE df.original_filename = ?", ("purwakarta.pdf",))
        self.login("sekretaris.cikarang", "cikarang123")
        forbidden = self.client.get(f"/documents/files/{file_row['id']}/download")
        self.assertEqual(forbidden.status_code, 403)
        self.login("owner", "owner123")
        allowed = self.client.get(f"/documents/files/{file_row['id']}/download")
        self.assertEqual(allowed.status_code, 200)
        allowed.close()

    def test_upload_from_contract_links_document_and_backup_includes_storage(self):
        self.login("sekretaris.cikarang", "cikarang123")
        response = self.client.post(
            "/documents/upload?related_type=CONTRACT&related_id=1",
            data={
                **self.base_document_data(organization_id="2", title="Lampiran Kontrak", category="Kontrak", document_type="CONTRACT"),
                "central_monitoring_required": "1",
                "central_status": "SENT TO HO",
                "document_file": (io.BytesIO(self.create_doc("antara RSCKR dan Vendor Medika. Tujuan: lampiran kontrak.")), "contract.doc"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        related = self.fetch_one("SELECT * FROM document_relations WHERE related_type = 'CONTRACT' AND related_id = 1 ORDER BY id DESC LIMIT 1")
        contract = self.fetch_one("SELECT file_document_id FROM contracts WHERE id = 1")
        file_row = self.fetch_one("SELECT * FROM document_files WHERE document_id = ? AND is_current = 1", (related["document_id"],))
        self.assertIsNotNone(related)
        self.assertEqual(contract["file_document_id"], related["document_id"])
        self.login("admin", "admin123")
        backup = self.client.post("/settings/backup/create", follow_redirects=True)
        self.assertEqual(backup.status_code, 200)
        archives = list(self.backup_root.glob("ai-secretary-backup-*.zip"))
        self.assertTrue(archives)
        with zipfile.ZipFile(archives[0]) as archive:
            names = archive.namelist()
        self.assertTrue(any(name.startswith("database/") for name in names))
        self.assertTrue(any(name.startswith("storage/") for name in names))
        stored_path = self.storage_root / file_row["storage_path"]
        self.assertTrue(stored_path.exists())
        stored_path.unlink()
        self.assertFalse(stored_path.exists())
        restore = self.client.post(f"/settings/backups/{archives[0].name}/restore", follow_redirects=True)
        self.assertEqual(restore.status_code, 200)
        self.assertTrue(stored_path.exists())


if __name__ == "__main__":
    unittest.main()

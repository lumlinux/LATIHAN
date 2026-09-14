from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {
    ".pdf": {"mime": {"application/pdf"}},
    ".doc": {"mime": {"application/msword", "application/octet-stream"}},
    ".docx": {"mime": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"}},
    ".xls": {"mime": {"application/vnd.ms-excel", "application/octet-stream"}},
    ".xlsx": {"mime": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"}},
    ".ppt": {"mime": {"application/vnd.ms-powerpoint", "application/octet-stream"}},
    ".pptx": {"mime": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip"}},
    ".jpg": {"mime": {"image/jpeg"}},
    ".jpeg": {"mime": {"image/jpeg"}},
    ".png": {"mime": {"image/png"}},
    ".zip": {"mime": {"application/zip", "application/x-zip-compressed"}},
}

PREVIEWABLE_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}
TEXT_EXTRACTABLE_EXTENSIONS = {".pdf", ".doc", ".docx"}


class DocumentProcessingError(Exception):
    pass


@dataclass
class SavedFile:
    original_filename: str
    stored_filename: str
    storage_relative_path: str
    mime_type: str
    extension: str
    file_size: int
    checksum: str
    storage_provider: str
    storage_status: str


class LocalStorageService:
    def __init__(self, storage_root: Path, max_file_size: int) -> None:
        self.storage_root = storage_root
        self.max_file_size = max_file_size
        self.storage_root.mkdir(parents=True, exist_ok=True)

    def save_upload(self, upload: FileStorage, organization_code: str, document_id: int, version_number: int) -> SavedFile:
        original_filename = sanitize_filename(upload.filename or "")
        if not original_filename:
            raise DocumentProcessingError("Nama file tidak valid.")

        extension = Path(original_filename).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            raise DocumentProcessingError("Extension file tidak diizinkan.")

        data = upload.stream.read()
        file_size = len(data)
        if file_size == 0:
            raise DocumentProcessingError("File kosong tidak dapat di-upload.")
        if file_size > self.max_file_size:
            raise DocumentProcessingError("File terlalu besar.")

        sniffed_mime = sniff_mime_type(original_filename, data)
        allowed_mimes = ALLOWED_EXTENSIONS[extension]["mime"]
        if sniffed_mime not in allowed_mimes:
            raise DocumentProcessingError("MIME type file tidak sesuai dengan extension yang diizinkan.")

        checksum = hashlib.sha256(data).hexdigest()
        stored_filename = f"{document_id}_v{version_number}_{uuid.uuid4().hex}{extension}"
        relative_dir = Path("documents") / organization_code / f"doc_{document_id}"
        absolute_dir = self.storage_root / relative_dir
        absolute_dir.mkdir(parents=True, exist_ok=True)
        absolute_path = absolute_dir / stored_filename
        absolute_path.write_bytes(data)

        return SavedFile(
            original_filename=original_filename,
            stored_filename=stored_filename,
            storage_relative_path=str(relative_dir / stored_filename),
            mime_type=sniffed_mime,
            extension=extension,
            file_size=file_size,
            checksum=checksum,
            storage_provider="LOCAL",
            storage_status="UPLOADED",
        )

    def resolve_path(self, storage_relative_path: str) -> Path:
        candidate = (self.storage_root / storage_relative_path).resolve()
        root = self.storage_root.resolve()
        if not str(candidate).startswith(str(root)):
            raise DocumentProcessingError("Path storage tidak valid.")
        return candidate

    def exists(self, storage_relative_path: str) -> bool:
        try:
            return self.resolve_path(storage_relative_path).exists()
        except DocumentProcessingError:
            return False

    def delete(self, storage_relative_path: str) -> None:
        try:
            target = self.resolve_path(storage_relative_path)
        except DocumentProcessingError:
            return
        if target.exists():
            target.unlink()


class TextExtractionService:
    def extract(self, file_path: Path, extension: str, language: str = "id") -> dict[str, Any]:
        extension = extension.lower()
        if extension not in TEXT_EXTRACTABLE_EXTENSIONS:
            return {
                "status": "TEXT_EXTRACTION_UNAVAILABLE",
                "method": "unsupported-format",
                "text": "",
                "error": "Format belum didukung untuk ekstraksi teks otomatis.",
                "language": language,
            }

        if extension == ".pdf":
            text = extract_text_from_pdf(file_path.read_bytes())
            if not text.strip():
                return {
                    "status": "TEXT_EXTRACTION_UNAVAILABLE",
                    "method": "pdf-no-text",
                    "text": "",
                    "error": "PDF tidak memiliki teks yang dapat diekstrak atau memerlukan OCR.",
                    "language": language,
                }
            return {"status": "TEXT_EXTRACTED", "method": "pdf-basic-parser", "text": text, "error": "", "language": language}

        if extension == ".docx":
            try:
                text = extract_text_from_docx(file_path)
            except (KeyError, zipfile.BadZipFile, ElementTree.ParseError):
                text = ""
            if not text.strip():
                return {
                    "status": "FAILED",
                    "method": "docx-parser",
                    "text": "",
                    "error": "DOCX tidak dapat diproses.",
                    "language": language,
                }
            return {"status": "TEXT_EXTRACTED", "method": "docx-xml-parser", "text": text, "error": "", "language": language}

        text = extract_text_from_legacy_doc(file_path.read_bytes())
        if not text.strip():
            return {
                "status": "TEXT_EXTRACTION_UNAVAILABLE",
                "method": "doc-binary-strings",
                "text": "",
                "error": "DOC tidak memiliki teks yang dapat diproses secara aman.",
                "language": language,
            }
        return {"status": "TEXT_EXTRACTED", "method": "doc-binary-strings", "text": text, "error": "", "language": language}


class SummaryService:
    def summarize(self, *, title: str, category: str, document_type: str, text: str, language: str = "id") -> dict[str, Any]:
        normalized = normalize_whitespace(text)
        lines = [line.strip() for line in normalized.splitlines() if line.strip()]
        sections = {
            "title": title or (lines[0] if lines else "Tidak ditemukan dalam dokumen."),
            "category": category or document_type or "Umum",
            "summary": summarize_text(lines, language),
            "parties": find_parties(normalized, language),
            "purpose": find_section_value(normalized, ["tujuan", "purpose"], language),
            "scope": find_section_value(normalized, ["ruang lingkup", "scope"], language),
            "important_dates": find_dates(normalized, language),
            "contract_value": find_money(normalized, language),
            "duration": find_duration(normalized, language),
            "obligations": find_section_value(normalized, ["kewajiban", "obligation"], language),
            "benefits": find_section_value(normalized, ["hak", "benefit"], language),
            "risks": find_risks(normalized, language),
            "termination": find_section_value(normalized, ["terminasi", "termination"], language),
            "payment": find_section_value(normalized, ["pembayaran", "payment"], language),
            "renewal": find_section_value(normalized, ["perpanjangan", "renewal"], language),
            "action_items": find_action_items(normalized, language),
            "missing_information": find_missing_information(normalized, language),
        }
        refs = build_source_references(normalized, sections)
        summary_text = render_summary(sections, refs, language)
        return {
            "status": "READY_FOR_REVIEW",
            "summary_text": summary_text,
            "structured_data": json.dumps(sections, ensure_ascii=False, indent=2),
            "source_references": json.dumps(refs, ensure_ascii=False, indent=2),
            "language": language,
        }


def sanitize_filename(filename: str) -> str:
    cleaned = secure_filename(filename.strip())
    if not cleaned or cleaned in {".", ".."}:
        return ""
    return cleaned


def sniff_mime_type(filename: str, data: bytes) -> str:
    extension = Path(filename).suffix.lower()
    if data.startswith(b"%PDF"):
        return "application/pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"PK\x03\x04"):
        if extension == ".docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if extension == ".xlsx":
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        if extension == ".pptx":
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        return "application/zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if extension == ".doc":
            return "application/msword"
        if extension == ".xls":
            return "application/vnd.ms-excel"
        if extension == ".ppt":
            return "application/vnd.ms-powerpoint"
        return "application/octet-stream"
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def extract_text_from_pdf(data: bytes) -> str:
    decoded = data.decode("latin1", errors="ignore")
    candidates = re.findall(r"\(([^)]{2,500})\)\s*Tj", decoded)
    candidates.extend(" ".join(re.findall(r"\(([^)]{1,300})\)", item)) for item in re.findall(r"\[(.*?)\]\s*TJ", decoded, flags=re.S))
    if not candidates:
        candidates = re.findall(r"\(([^)]{4,400})\)", decoded)
    cleaned = [decode_pdf_string(item) for item in candidates]
    return normalize_whitespace("\n".join(cleaned))


def decode_pdf_string(value: str) -> str:
    value = value.replace("\\(", "(").replace("\\)", ")").replace("\\n", "\n").replace("\\r", " ").replace("\\t", " ")
    return value


def extract_text_from_docx(file_path: Path) -> str:
    with zipfile.ZipFile(file_path) as archive:
        xml_bytes = archive.read("word/document.xml")
    root = ElementTree.fromstring(xml_bytes)
    texts = []
    for element in root.iter():
        if element.tag.endswith("}t") and element.text:
            texts.append(element.text)
        elif element.tag.endswith("}tab"):
            texts.append("\t")
        elif element.tag.endswith("}br"):
            texts.append("\n")
        elif element.tag.endswith("}p"):
            texts.append("\n")
    return normalize_whitespace("".join(texts))


def extract_text_from_legacy_doc(data: bytes) -> str:
    ascii_parts = re.findall(rb"[A-Za-z0-9][A-Za-z0-9\s,\.\-:/]{8,}", data)
    utf16_parts = re.findall(rb"(?:[\x20-\x7e]\x00){8,}", data)
    decoded = [part.decode("latin1", errors="ignore") for part in ascii_parts[:200]]
    decoded.extend(part.decode("utf-16le", errors="ignore") for part in utf16_parts[:200])
    return normalize_whitespace("\n".join(decoded))


def normalize_whitespace(text: str) -> str:
    text = text.replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def summarize_text(lines: list[str], language: str) -> str:
    if not lines:
        return "Tidak ditemukan dalam dokumen." if language == "id" else "Not found in document."
    body = [line for line in lines if len(line) > 20][:3]
    if not body:
        body = lines[:2]
    return " ".join(body)


def find_parties(text: str, language: str) -> list[str]:
    parties = []
    patterns = [
        r"antara\s+(.+?)\s+dan\s+(.+?)(?:\.|\n)",
        r"between\s+(.+?)\s+and\s+(.+?)(?:\.|\n)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I | re.S)
        if match:
            parties.extend([clean_reference(match.group(1)), clean_reference(match.group(2))])
            break
    if not parties:
        label = "Tidak ditemukan dalam dokumen." if language == "id" else "Not found in document."
        return [label]
    return [party for party in parties if party]


def find_section_value(text: str, labels: list[str], language: str) -> str:
    for label in labels:
        match = re.search(rf"{re.escape(label)}\s*[:\-]?\s*(.+?)(?=\n[A-Z][^\n]{{0,40}}[:\-]|\n[a-zA-Z ]{{3,30}}[:\-]|\Z)", text, flags=re.I | re.S)
        if match:
            return clean_reference(match.group(1))
    return "Tidak ditemukan dalam dokumen." if language == "id" else "Not found in document."


def find_dates(text: str, language: str) -> list[str]:
    patterns = re.findall(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}\s+[A-Za-z]+\s+\d{4}\b", text)
    if not patterns:
        return ["Tidak ditemukan dalam dokumen." if language == "id" else "Not found in document."]
    return patterns[:6]


def find_money(text: str, language: str) -> str:
    match = re.search(r"(Rp\.?\s?[\d\.,]+|IDR\s?[\d\.,]+|USD\s?[\d\.,]+)", text, flags=re.I)
    if match:
        return match.group(1)
    return "Tidak ditemukan dalam dokumen." if language == "id" else "Not found in document."


def find_duration(text: str, language: str) -> str:
    match = re.search(r"(\d+\s+(hari|bulan|tahun)|\d+\s+(day|month|year)s?)", text, flags=re.I)
    if match:
        return match.group(1)
    return "Perlu verifikasi manual." if language == "id" else "Manual verification required."


def find_risks(text: str, language: str) -> str:
    notes = []
    for keyword in ["terminasi", "termination", "denda", "penalty", "renewal", "perpanjangan", "pembayaran", "payment"]:
        if re.search(keyword, text, flags=re.I):
            notes.append(f"Perlu verifikasi bagian {keyword}.")
    return " ".join(notes[:4]) if notes else "Tidak ditemukan dalam dokumen."


def find_action_items(text: str, language: str) -> list[str]:
    items = []
    if re.search(r"berakhir|expired|expiry|jatuh tempo", text, flags=re.I):
        items.append("Buat reminder sebelum masa berlaku berakhir." if language == "id" else "Create reminder before expiry.")
    if re.search(r"terminasi|termination", text, flags=re.I):
        items.append("Review klausul terminasi." if language == "id" else "Review termination clause.")
    if re.search(r"perpanjangan|renewal", text, flags=re.I):
        items.append("Konfirmasi mekanisme perpanjangan." if language == "id" else "Confirm renewal mechanism.")
    if not items:
        items.append("Perlu verifikasi manual." if language == "id" else "Manual verification required.")
    return items


def find_missing_information(text: str, language: str) -> list[str]:
    checks = {
        "Nilai kontrak": r"(Rp\.?\s?[\d\.,]+|IDR\s?[\d\.,]+|USD\s?[\d\.,]+)",
        "Klausul terminasi": r"terminasi|termination",
        "Klausul pembayaran": r"pembayaran|payment",
        "Klausul perpanjangan": r"perpanjangan|renewal",
    }
    missing = [label if re.search(pattern, text, flags=re.I) is None else None for label, pattern in checks.items()]
    result = [item for item in missing if item]
    if result:
        return result
    return ["Tidak ditemukan kebutuhan tambahan." if language == "id" else "No additional gaps found."]


def build_source_references(text: str, sections: dict[str, Any]) -> dict[str, str]:
    lines = [line for line in text.splitlines() if line.strip()]
    refs: dict[str, str] = {}
    for key, value in sections.items():
        lookup = ""
        if isinstance(value, list) and value:
            lookup = str(value[0])
        elif isinstance(value, str):
            lookup = value
        if not lookup or "Tidak ditemukan" in lookup or "Not found" in lookup or "Perlu verifikasi" in lookup:
            refs[key] = "Perlu verifikasi manual."
            continue
        refs[key] = find_line_reference(lines, lookup)
    return refs


def find_line_reference(lines: list[str], lookup: str) -> str:
    probe = clean_reference(lookup).lower()[:50]
    for index, line in enumerate(lines, start=1):
        if probe and probe in line.lower():
            return f"Baris {index}"
    return "Teks hasil ekstraksi"


def render_summary(sections: dict[str, Any], references: dict[str, str], language: str) -> str:
    disclaimer = (
        "Resume dibuat secara otomatis berdasarkan teks dokumen yang berhasil diproses. Resume bukan pengganti dokumen asli dan tetap memerlukan verifikasi manual."
        if language == "id"
        else "This summary is automatically generated from extracted document text. It does not replace the original document and still requires manual verification."
    )
    parts = [
        "RESUME DOKUMEN" if language == "id" else "DOCUMENT SUMMARY",
        "",
        f"Judul: {sections['title']}" if language == "id" else f"Title: {sections['title']}",
        f"Kategori: {sections['category']}" if language == "id" else f"Category: {sections['category']}",
        "",
        f"Ringkasan: {sections['summary']}" if language == "id" else f"Summary: {sections['summary']}",
        format_list_section("Pihak yang Terlibat", sections["parties"], language),
        format_value_section("Tujuan Dokumen", sections["purpose"], references["purpose"], language),
        format_value_section("Ruang Lingkup", sections["scope"], references["scope"], language),
        format_list_section("Tanggal Penting", sections["important_dates"], language),
        format_value_section("Nilai Kontrak", sections["contract_value"], references["contract_value"], language),
        format_value_section("Durasi / Masa Berlaku", sections["duration"], references["duration"], language),
        format_value_section("Kewajiban Utama", sections["obligations"], references["obligations"], language),
        format_value_section("Hak / Benefit Utama", sections["benefits"], references["benefits"], language),
        format_value_section("Risiko / Catatan Penting", sections["risks"], references["risks"], language),
        format_value_section("Klausul Terminasi", sections["termination"], references["termination"], language),
        format_value_section("Klausul Pembayaran", sections["payment"], references["payment"], language),
        format_value_section("Klausul Perpanjangan", sections["renewal"], references["renewal"], language),
        format_list_section("Action Item", sections["action_items"], language),
        format_list_section("Informasi yang Belum Ditemukan", sections["missing_information"], language),
        "",
        disclaimer,
    ]
    return "\n".join(part for part in parts if part is not None)


def format_list_section(title: str, values: list[str], language: str) -> str:
    if not values:
        values = ["Tidak ditemukan dalam dokumen." if language == "id" else "Not found in document."]
    rendered = "\n".join(f"- {clean_reference(item)}" for item in values)
    return f"{title}:\n{rendered}"


def format_value_section(title: str, value: str, reference: str, language: str) -> str:
    clean = clean_reference(value)
    return f"{title}:\n{clean}\nSumber: {reference}"


def clean_reference(value: str) -> str:
    value = normalize_whitespace(value)
    value = re.sub(r"\s{2,}", " ", value)
    return value.strip(" -:\n\t")

from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import zipfile
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from services.document_processing import (
    ALLOWED_EXTENSIONS,
    PREVIEWABLE_EXTENSIONS,
    DocumentProcessingError,
    LocalStorageService,
    SummaryService,
    TextExtractionService,
    sniff_mime_type,
    sanitize_filename,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BACKUP_DIR = DATA_DIR / "backups"
STORAGE_DIR = DATA_DIR / "storage"
DEFAULT_DATABASE = DATA_DIR / "ai_secretary.db"

ORGANIZATIONS = [
    {"code": "PT", "name": "PT / Kantor Pusat", "kind": "HEAD_OFFICE", "parent_code": None, "is_central": 1},
    {"code": "RSCKR", "name": "RS Bhakti Husada Cikarang", "kind": "HOSPITAL", "parent_code": "PT", "is_central": 0},
    {"code": "RSPWK", "name": "RS Bhakti Husada Purwakarta", "kind": "HOSPITAL", "parent_code": "PT", "is_central": 0},
]

ROLE_DESCRIPTIONS = {
    "OWNER / MANAGEMENT PT": "Monitoring seluruh organisasi sesuai hak akses pusat tanpa otomatis mengubah data cabang.",
    "SEKRETARIS KANTOR PUSAT": "Mengelola administrasi PT dan memantau tembusan serta compliance dari RS.",
    "SEKRETARIS RS": "Mengelola seluruh administrasi unit RS masing-masing tanpa melihat unit RS lain.",
    "ADMIN IT": "Mengelola konfigurasi teknis, user, role, permission, audit, dan pengaturan sistem.",
    "Administrator": "Role kompatibilitas lama dengan akses penuh.",
    "Secretary": "Role kompatibilitas lama untuk sekretariat.",
    "Manager": "Role kompatibilitas lama untuk monitoring manajerial.",
    "User": "Role kompatibilitas lama untuk akses terbatas.",
}

PERMISSIONS = [
    ("dashboard.view", "Dashboard", "Melihat dashboard dan ringkasan organisasi."),
    ("users.manage", "Users", "Mengelola pengguna aplikasi."),
    ("roles.manage", "Roles", "Mengelola role dan permission."),
    ("settings.manage", "Settings", "Mengelola konfigurasi sistem."),
    ("audit.view", "Audit Log", "Melihat audit trail sistem."),
    ("search.global", "Global Search", "Melakukan pencarian lintas modul."),
    ("reports.view", "Reports", "Melihat dan mengekspor laporan."),
    ("compliance.view", "Compliance", "Melihat central monitoring dan compliance."),
    ("assistant.use", "AI Assistant", "Menggunakan AI Secretary."),
    ("notifications.view", "Notifications", "Melihat notifikasi."),
    ("agenda.view", "Agenda View", "Melihat agenda."),
    ("agenda.manage", "Agenda Manage", "Mengelola agenda."),
    ("calendar.view", "Calendar", "Melihat kalender."),
    ("tasks.view", "Task View", "Melihat task."),
    ("tasks.manage", "Task Manage", "Mengelola task."),
    ("reminders.view", "Reminder View", "Melihat reminder."),
    ("reminders.manage", "Reminder Manage", "Mengelola reminder."),
    ("contacts.view", "Contact View", "Melihat kontak."),
    ("contacts.manage", "Contact Manage", "Mengelola kontak."),
    ("incoming_letters.view", "Incoming Letter View", "Melihat surat masuk."),
    ("incoming_letters.manage", "Incoming Letter Manage", "Mengelola surat masuk."),
    ("outgoing_letters.view", "Outgoing Letter View", "Melihat surat keluar."),
    ("outgoing_letters.manage", "Outgoing Letter Manage", "Mengelola surat keluar."),
    ("dispositions.view", "Disposition View", "Melihat disposisi."),
    ("dispositions.manage", "Disposition Manage", "Mengelola disposisi."),
    ("documents.view", "Documents View", "Melihat dokumen."),
    ("documents.manage", "Documents Manage", "Mengelola dokumen."),
    ("contracts.view", "Contracts View", "Melihat MOU/kontrak."),
    ("contracts.manage", "Contracts Manage", "Mengelola MOU/kontrak."),
    ("permits.view", "Permits View", "Melihat perizinan/sertifikasi."),
    ("permits.manage", "Permits Manage", "Mengelola perizinan/sertifikasi."),
    ("vendors.view", "Vendors View", "Melihat vendor/partner."),
    ("vendors.manage", "Vendors Manage", "Mengelola vendor/partner."),
    ("assets.view", "Assets View", "Melihat asset."),
    ("assets.manage", "Assets Manage", "Mengelola asset."),
    ("meetings.view", "Meetings View", "Melihat meeting."),
    ("meetings.manage", "Meetings Manage", "Mengelola meeting."),
    ("meeting_minutes.view", "Minutes View", "Melihat minutes of meeting."),
    ("meeting_minutes.manage", "Minutes Manage", "Mengelola minutes of meeting."),
]

ROLE_PERMISSIONS = {
    "OWNER / MANAGEMENT PT": [
        "dashboard.view", "calendar.view", "tasks.view", "reminders.view", "notifications.view", "contacts.view",
        "incoming_letters.view", "outgoing_letters.view", "dispositions.view", "documents.view", "contracts.view",
        "permits.view", "vendors.view", "assets.view", "meetings.view", "meeting_minutes.view", "search.global",
        "compliance.view", "reports.view", "assistant.use", "agenda.view",
    ],
    "SEKRETARIS KANTOR PUSAT": [
        "dashboard.view", "agenda.view", "agenda.manage", "calendar.view", "tasks.view", "tasks.manage",
        "reminders.view", "reminders.manage", "notifications.view", "contacts.view", "contacts.manage",
        "incoming_letters.view", "incoming_letters.manage", "outgoing_letters.view", "outgoing_letters.manage",
        "dispositions.view", "dispositions.manage", "documents.view", "documents.manage", "contracts.view",
        "contracts.manage", "permits.view", "permits.manage", "vendors.view", "vendors.manage", "assets.view",
        "assets.manage", "meetings.view", "meetings.manage", "meeting_minutes.view", "meeting_minutes.manage",
        "search.global", "compliance.view", "reports.view", "assistant.use",
    ],
    "SEKRETARIS RS": [
        "dashboard.view", "agenda.view", "agenda.manage", "calendar.view", "tasks.view", "tasks.manage",
        "reminders.view", "reminders.manage", "notifications.view", "contacts.view", "contacts.manage",
        "incoming_letters.view", "incoming_letters.manage", "outgoing_letters.view", "outgoing_letters.manage",
        "dispositions.view", "dispositions.manage", "documents.view", "documents.manage", "contracts.view",
        "contracts.manage", "permits.view", "permits.manage", "vendors.view", "vendors.manage", "assets.view",
        "assets.manage", "meetings.view", "meetings.manage", "meeting_minutes.view", "meeting_minutes.manage",
        "search.global", "assistant.use",
    ],
    "ADMIN IT": ["dashboard.view", "users.manage", "roles.manage", "settings.manage", "audit.view", "notifications.view"],
    "Administrator": [code for code, _, _ in PERMISSIONS],
    "Secretary": [
        "dashboard.view", "agenda.view", "agenda.manage", "calendar.view", "tasks.view", "tasks.manage",
        "reminders.view", "reminders.manage", "notifications.view", "contacts.view", "contacts.manage",
        "incoming_letters.view", "incoming_letters.manage", "outgoing_letters.view", "outgoing_letters.manage",
        "dispositions.view", "dispositions.manage", "documents.view", "documents.manage", "contracts.view",
        "contracts.manage", "permits.view", "permits.manage", "vendors.view", "vendors.manage", "assets.view",
        "assets.manage", "meetings.view", "meetings.manage", "meeting_minutes.view", "meeting_minutes.manage",
        "search.global", "compliance.view", "assistant.use",
    ],
    "Manager": [
        "dashboard.view", "agenda.view", "calendar.view", "tasks.view", "tasks.manage", "reminders.view",
        "notifications.view", "contacts.view", "incoming_letters.view", "outgoing_letters.view", "dispositions.view",
        "documents.view", "contracts.view", "permits.view", "vendors.view", "assets.view", "meetings.view",
        "meeting_minutes.view", "search.global", "compliance.view", "assistant.use", "reports.view",
    ],
    "User": [
        "dashboard.view", "agenda.view", "agenda.manage", "calendar.view", "tasks.view", "reminders.view",
        "reminders.manage", "notifications.view", "contacts.view", "documents.view", "meetings.view",
        "assistant.use", "search.global",
    ],
}

DEFAULT_USERS = [
    ("owner", "Owner Management PT", "owner@aisecretary.local", "owner123", "OWNER / MANAGEMENT PT", "PT"),
    ("sekretaris.pt", "Sekretaris Kantor Pusat", "sekretaris.pt@aisecretary.local", "secretpt123", "SEKRETARIS KANTOR PUSAT", "PT"),
    ("sekretaris.cikarang", "Sekretaris RS Cikarang", "sekretaris.cikarang@aisecretary.local", "cikarang123", "SEKRETARIS RS", "RSCKR"),
    ("sekretaris.purwakarta", "Sekretaris RS Purwakarta", "sekretaris.purwakarta@aisecretary.local", "purwakarta123", "SEKRETARIS RS", "RSPWK"),
    ("admin.it", "Administrator IT", "admin.it@aisecretary.local", "adminit123", "ADMIN IT", "PT"),
    ("admin", "Administrator", "admin@aisecretary.local", "admin123", "Administrator", "PT"),
]

NAV_ITEMS = [
    {"label": "Dashboard", "endpoint": "dashboard", "permission": "dashboard.view"},
    {"label": "AI Secretary", "endpoint": "assistant_page", "permission": "assistant.use"},
    {"label": "Global Search", "endpoint": "search_page", "permission": "search.global"},
    {"label": "Agenda", "endpoint": "module_list", "permission": "agenda.view", "module": "agenda"},
    {"label": "Calendar", "endpoint": "calendar_view", "permission": "calendar.view"},
    {"label": "Tasks", "endpoint": "module_list", "permission": "tasks.view", "module": "tasks"},
    {"label": "Reminder", "endpoint": "module_list", "permission": "reminders.view", "module": "reminders"},
    {"label": "Contacts", "endpoint": "module_list", "permission": "contacts.view", "module": "contacts"},
    {"label": "Incoming Letters", "endpoint": "module_list", "permission": "incoming_letters.view", "module": "incoming_letters"},
    {"label": "Outgoing Letters", "endpoint": "module_list", "permission": "outgoing_letters.view", "module": "outgoing_letters"},
    {"label": "Dispositions", "endpoint": "module_list", "permission": "dispositions.view", "module": "dispositions"},
    {"label": "Documents", "endpoint": "module_list", "permission": "documents.view", "module": "documents"},
    {"label": "MOU & Contracts", "endpoint": "module_list", "permission": "contracts.view", "module": "contracts"},
    {"label": "Permits", "endpoint": "module_list", "permission": "permits.view", "module": "permits"},
    {"label": "Vendors", "endpoint": "module_list", "permission": "vendors.view", "module": "vendors"},
    {"label": "Assets", "endpoint": "module_list", "permission": "assets.view", "module": "assets"},
    {"label": "Meetings", "endpoint": "module_list", "permission": "meetings.view", "module": "meetings"},
    {"label": "Meeting Minutes", "endpoint": "module_list", "permission": "meeting_minutes.view", "module": "meeting_minutes"},
    {"label": "Notifications", "endpoint": "notifications_page", "permission": "notifications.view"},
    {"label": "Compliance", "endpoint": "compliance_page", "permission": "compliance.view"},
    {"label": "Reports", "endpoint": "reports_page", "permission": "reports.view"},
    {"label": "Audit Log", "endpoint": "audit_logs_page", "permission": "audit.view"},
    {"label": "User Management", "endpoint": "users_page", "permission": "users.manage"},
    {"label": "Letter Categories", "endpoint": "letter_categories_page", "permission": "settings.manage"},
    {"label": "Company Settings", "endpoint": "company_settings_page", "permission": "settings.manage"},
    {"label": "Role & Permission", "endpoint": "roles_page", "permission": "roles.manage"},
    {"label": "Settings", "endpoint": "settings_page", "permission": "settings.manage"},
]

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    parent_id INTEGER,
    is_central INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_code TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_code),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_code) REFERENCES permissions(code) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    department TEXT,
    position TEXT,
    password_hash TEXT NOT NULL,
    role_id INTEGER NOT NULL,
    organization_id INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS agenda_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    start_at TEXT NOT NULL,
    end_at TEXT NOT NULL,
    location TEXT,
    owner_id INTEGER,
    classification TEXT DEFAULT 'INTERNAL',
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    due_date TEXT,
    assigned_to INTEGER,
    related_type TEXT,
    related_id INTEGER,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    title TEXT NOT NULL,
    message TEXT,
    remind_at TEXT NOT NULL,
    status TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    related_type TEXT,
    related_id INTEGER,
    days_remaining INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    organization_id INTEGER,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    kind TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    link TEXT,
    source_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, source_key),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    full_name TEXT NOT NULL,
    company TEXT,
    position TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    notes TEXT,
    visibility TEXT NOT NULL,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    target_organization_id INTEGER,
    direction TEXT NOT NULL,
    letter_category_id INTEGER,
    letter_number TEXT NOT NULL,
    is_number_final INTEGER NOT NULL DEFAULT 0,
    subject TEXT NOT NULL,
    correspondent TEXT NOT NULL,
    letter_date TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    summary TEXT,
    follow_up TEXT,
    template_name TEXT,
    body TEXT,
    signer TEXT,
    attachment_path TEXT,
    is_tembusan_required INTEGER NOT NULL DEFAULT 0,
    central_status TEXT,
    classification TEXT DEFAULT 'INTERNAL',
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (target_organization_id) REFERENCES organizations(id),
    FOREIGN KEY (letter_category_id) REFERENCES letter_categories(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_letters_unique_number
ON letters(letter_number)
WHERE letter_number IS NOT NULL AND TRIM(letter_number) != '';

CREATE TABLE IF NOT EXISTS letter_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    number_format TEXT,
    start_number INTEGER NOT NULL DEFAULT 1,
    reset_policy TEXT NOT NULL DEFAULT 'YEARLY',
    is_active INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS letter_number_sequences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL,
    organization_id INTEGER NOT NULL,
    period_key TEXT NOT NULL,
    current_number INTEGER NOT NULL,
    last_generated_number TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(category_id, organization_id, period_key),
    FOREIGN KEY (category_id) REFERENCES letter_categories(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS company_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    company_name TEXT,
    short_name TEXT,
    company_code TEXT,
    address TEXT,
    city TEXT,
    province TEXT,
    postal_code TEXT,
    phone TEXT,
    email TEXT,
    website TEXT,
    tax_number TEXT,
    logo_storage_path TEXT,
    letter_number_format TEXT,
    letter_prefix TEXT,
    date_format TEXT,
    month_format TEXT,
    active_year TEXT,
    start_number INTEGER NOT NULL DEFAULT 1,
    reset_policy TEXT NOT NULL DEFAULT 'YEARLY',
    official_signature TEXT,
    official_name TEXT,
    official_position TEXT,
    use_organization_code_in_letters INTEGER NOT NULL DEFAULT 1,
    password_min_length INTEGER NOT NULL DEFAULT 8,
    password_require_uppercase INTEGER NOT NULL DEFAULT 1,
    password_require_lowercase INTEGER NOT NULL DEFAULT 1,
    password_require_digit INTEGER NOT NULL DEFAULT 1,
    password_require_special INTEGER NOT NULL DEFAULT 0,
    password_expiry_days INTEGER NOT NULL DEFAULT 90,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dispositions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    letter_id INTEGER NOT NULL,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    instruction TEXT NOT NULL,
    due_date TEXT,
    status TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (letter_id) REFERENCES letters(id),
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    title TEXT NOT NULL,
    document_number TEXT,
    document_type TEXT NOT NULL,
    category TEXT NOT NULL,
    department TEXT,
    document_date TEXT,
    effective_date TEXT,
    expiry_date TEXT,
    status TEXT,
    file_path TEXT,
    description TEXT,
    owner_id INTEGER,
    pic_user_id INTEGER,
    vendor_name TEXT,
    tags TEXT,
    version TEXT,
    confidentiality TEXT DEFAULT 'INTERNAL',
    central_monitoring_required INTEGER NOT NULL DEFAULT 0,
    central_status TEXT,
    original_document_id INTEGER,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (pic_user_id) REFERENCES users(id),
    FOREIGN KEY (original_document_id) REFERENCES documents(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS document_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    version_number INTEGER NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    extension TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    checksum TEXT,
    storage_provider TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    storage_status TEXT NOT NULL,
    is_previewable INTEGER NOT NULL DEFAULT 0,
    is_current INTEGER NOT NULL DEFAULT 1,
    uploaded_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(document_id, version_number),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS document_text_extractions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_file_id INTEGER NOT NULL UNIQUE,
    extraction_status TEXT NOT NULL,
    extracted_text TEXT,
    extraction_method TEXT,
    language TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (document_file_id) REFERENCES document_files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS document_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    document_file_id INTEGER NOT NULL,
    version_number INTEGER NOT NULL,
    revision_number INTEGER NOT NULL DEFAULT 1,
    summary_status TEXT NOT NULL,
    language TEXT NOT NULL,
    summary_text TEXT,
    structured_data TEXT,
    source_references TEXT,
    review_notes TEXT,
    generated_by INTEGER,
    reviewed_by INTEGER,
    generated_at TEXT,
    reviewed_at TEXT,
    manually_edited INTEGER NOT NULL DEFAULT 0,
    is_current INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (document_file_id) REFERENCES document_files(id) ON DELETE CASCADE,
    FOREIGN KEY (generated_by) REFERENCES users(id),
    FOREIGN KEY (reviewed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS document_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    related_type TEXT NOT NULL,
    related_id INTEGER NOT NULL,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    UNIQUE(document_id, related_type, related_id),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    contract_number TEXT NOT NULL,
    title TEXT NOT NULL,
    kind TEXT NOT NULL,
    partner_name TEXT,
    vendor_name TEXT,
    start_date TEXT,
    end_date TEXT,
    contract_value TEXT,
    pic_user_id INTEGER,
    status TEXT NOT NULL,
    renewal_status TEXT,
    notes TEXT,
    file_document_id INTEGER,
    central_monitoring_required INTEGER NOT NULL DEFAULT 0,
    central_status TEXT,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (pic_user_id) REFERENCES users(id),
    FOREIGN KEY (file_document_id) REFERENCES documents(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS permits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    permit_name TEXT NOT NULL,
    permit_number TEXT NOT NULL,
    permit_type TEXT NOT NULL,
    issuer TEXT,
    issue_date TEXT,
    effective_date TEXT,
    expiry_date TEXT,
    pic_user_id INTEGER,
    status TEXT NOT NULL,
    renewal_status TEXT,
    notes TEXT,
    file_document_id INTEGER,
    central_monitoring_required INTEGER NOT NULL DEFAULT 0,
    central_status TEXT,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (pic_user_id) REFERENCES users(id),
    FOREIGN KEY (file_document_id) REFERENCES documents(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    name TEXT NOT NULL,
    company TEXT,
    contact_person TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    category TEXT,
    compliance_status TEXT,
    notes TEXT,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    asset_code TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT,
    location TEXT,
    vendor_name TEXT,
    purchase_date TEXT,
    warranty_expiry TEXT,
    maintenance_due TEXT,
    status TEXT NOT NULL,
    notes TEXT,
    created_by INTEGER NOT NULL,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    title TEXT NOT NULL,
    agenda TEXT,
    start_at TEXT NOT NULL,
    end_at TEXT NOT NULL,
    location TEXT,
    organizer_id INTEGER NOT NULL,
    participants TEXT,
    attachment_path TEXT,
    status TEXT NOT NULL,
    notes TEXT,
    created_by INTEGER,
    updated_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (organizer_id) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS meeting_minutes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    meeting_id INTEGER NOT NULL,
    discussion TEXT NOT NULL,
    decisions TEXT,
    action_items TEXT,
    recorded_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (meeting_id) REFERENCES meetings(id),
    FOREIGN KEY (recorded_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    organization_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    entity_label TEXT,
    ip_address TEXT,
    before_data TEXT,
    after_data TEXT,
    details TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);

CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

MODULES = {
    "agenda": {
        "title": "Agenda",
        "singular": "Agenda Item",
        "permission_view": "agenda.view",
        "permission_manage": "agenda.manage",
        "table": "agenda_entries",
        "alias": "a",
        "base_query": """
            SELECT a.id, a.organization_id, org.name AS organization_name, a.title, a.category, a.description,
                   a.start_at, a.end_at, a.location, a.owner_id, owner.full_name AS owner_name,
                   a.classification, a.created_by, a.updated_at
            FROM agenda_entries a
            LEFT JOIN organizations org ON org.id = a.organization_id
            LEFT JOIN users owner ON owner.id = a.owner_id
        """,
        "columns": [("organization_name", "Organization"), ("title", "Title"), ("category", "Category"), ("start_at", "Start"), ("end_at", "End"), ("location", "Location"), ("owner_name", "Owner")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "title", "label": "Title", "type": "text", "required": True},
            {"name": "category", "label": "Category", "type": "select", "options": ["Board", "Operational", "Appointment", "Deadline"], "required": True},
            {"name": "start_at", "label": "Start", "type": "datetime-local", "required": True},
            {"name": "end_at", "label": "End", "type": "datetime-local", "required": True},
            {"name": "location", "label": "Location", "type": "text"},
            {"name": "owner_id", "label": "Owner", "type": "select", "options_source": "users", "required": True},
            {"name": "classification", "label": "Classification", "type": "select", "options": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"], "required": True},
            {"name": "description", "label": "Description", "type": "textarea"},
        ],
    },
    "tasks": {
        "title": "Task Management",
        "singular": "Task",
        "permission_view": "tasks.view",
        "permission_manage": "tasks.manage",
        "table": "tasks",
        "alias": "t",
        "base_query": """
            SELECT t.id, t.organization_id, org.name AS organization_name, t.title, t.description, t.status,
                   t.priority, t.due_date, t.related_type, t.related_id, t.assigned_to,
                   assignee.full_name AS assigned_name
            FROM tasks t
            LEFT JOIN organizations org ON org.id = t.organization_id
            LEFT JOIN users assignee ON assignee.id = t.assigned_to
        """,
        "columns": [("organization_name", "Organization"), ("title", "Title"), ("status", "Status"), ("priority", "Priority"), ("due_date", "Deadline"), ("assigned_name", "PIC")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "title", "label": "Task Title", "type": "text", "required": True},
            {"name": "status", "label": "Status", "type": "select", "options": ["TODO", "IN PROGRESS", "WAITING", "DONE", "CANCELLED"], "required": True},
            {"name": "priority", "label": "Priority", "type": "select", "options": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "required": True},
            {"name": "due_date", "label": "Deadline", "type": "datetime-local"},
            {"name": "assigned_to", "label": "PIC", "type": "select", "options_source": "users"},
            {"name": "related_type", "label": "Related Type", "type": "select", "options": ["GENERAL", "DOCUMENT", "EMAIL", "CONTRACT", "PERMIT", "VENDOR", "ASSET", "MEETING"]},
            {"name": "description", "label": "Description", "type": "textarea"},
        ],
    },
    "reminders": {
        "title": "Reminder",
        "singular": "Reminder",
        "permission_view": "reminders.view",
        "permission_manage": "reminders.manage",
        "table": "reminders",
        "alias": "r",
        "base_query": """
            SELECT r.id, r.organization_id, org.name AS organization_name, r.title, r.message, r.remind_at,
                   r.status, r.related_type, r.related_id, r.days_remaining, r.user_id,
                   owner.full_name AS user_name
            FROM reminders r
            LEFT JOIN organizations org ON org.id = r.organization_id
            LEFT JOIN users owner ON owner.id = r.user_id
        """,
        "columns": [("organization_name", "Organization"), ("title", "Title"), ("remind_at", "Remind At"), ("status", "Status"), ("related_type", "Related"), ("user_name", "Owner")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "title", "label": "Reminder Title", "type": "text", "required": True},
            {"name": "remind_at", "label": "Remind At", "type": "datetime-local", "required": True},
            {"name": "status", "label": "Status", "type": "select", "options": ["Scheduled", "Sent", "Completed"], "required": True},
            {"name": "user_id", "label": "Owner", "type": "select", "options_source": "users", "required": True},
            {"name": "related_type", "label": "Related Module", "type": "select", "options": ["GENERAL", "TASK", "MEETING", "LETTER", "DOCUMENT", "CONTRACT", "PERMIT"]},
            {"name": "message", "label": "Message", "type": "textarea"},
        ],
    },
    "contacts": {
        "title": "Contact Management",
        "singular": "Contact",
        "permission_view": "contacts.view",
        "permission_manage": "contacts.manage",
        "table": "contacts",
        "alias": "c",
        "base_query": """
            SELECT c.id, c.organization_id, org.name AS organization_name, c.full_name, c.company, c.position,
                   c.email, c.phone, c.address, c.notes, c.visibility
            FROM contacts c
            LEFT JOIN organizations org ON org.id = c.organization_id
        """,
        "columns": [("organization_name", "Organization"), ("full_name", "Full Name"), ("company", "Company"), ("position", "Position"), ("phone", "Phone"), ("visibility", "Visibility")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "full_name", "label": "Full Name", "type": "text", "required": True},
            {"name": "company", "label": "Company", "type": "text"},
            {"name": "position", "label": "Position", "type": "text"},
            {"name": "email", "label": "Email", "type": "email"},
            {"name": "phone", "label": "Phone", "type": "text"},
            {"name": "address", "label": "Address", "type": "textarea"},
            {"name": "visibility", "label": "Visibility", "type": "select", "options": ["Private", "Shared"], "required": True},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "incoming_letters": {
        "title": "Incoming Letter",
        "singular": "Incoming Letter",
        "permission_view": "incoming_letters.view",
        "permission_manage": "incoming_letters.manage",
        "table": "letters",
        "alias": "l",
        "fixed_values": {"direction": "incoming"},
        "base_query": """
            SELECT l.id, l.organization_id, org.name AS organization_name, target.name AS target_organization_name,
                   l.direction, l.letter_number, l.subject, l.correspondent, l.letter_date, l.status,
                   l.priority, l.summary, l.follow_up, l.template_name, l.signer, l.attachment_path,
                   l.letter_category_id, lc.code AS letter_category_code, lc.name AS letter_category_name,
                   l.is_tembusan_required, l.central_status, l.classification
            FROM letters l
            LEFT JOIN organizations org ON org.id = l.organization_id
            LEFT JOIN organizations target ON target.id = l.target_organization_id
            LEFT JOIN letter_categories lc ON lc.id = l.letter_category_id
            WHERE l.direction = 'incoming'
        """,
        "columns": [("organization_name", "Origin"), ("letter_category_code", "Category"), ("letter_number", "Letter No."), ("subject", "Subject"), ("correspondent", "Sender"), ("letter_date", "Date"), ("central_status", "Tembusan Status")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "target_organization_id", "label": "Target Organization", "type": "select", "options_source": "organizations"},
            {"name": "letter_category_id", "label": "Letter Category", "type": "select", "options_source": "letter_categories", "required": True},
            {"name": "letter_number", "label": "Letter Number", "type": "text", "readonly": True, "help_text": "Nomor otomatis dibuat oleh sistem saat surat final."},
            {"name": "subject", "label": "Subject", "type": "text", "required": True},
            {"name": "correspondent", "label": "Sender", "type": "text", "required": True},
            {"name": "letter_date", "label": "Letter Date", "type": "date", "required": True},
            {"name": "status", "label": "Status", "type": "select", "options": ["Received", "Reviewed", "On Process", "Cancelled", "Archived"], "required": True},
            {"name": "priority", "label": "Priority", "type": "select", "options": ["Low", "Medium", "High"], "required": True},
            {"name": "is_tembusan_required", "label": "Tembusan to PT", "type": "select", "options": ["0", "1"], "required": True},
            {"name": "central_status", "label": "Central Status", "type": "select", "options": ["CREATED", "SENT TO HO", "RECEIVED BY HO", "REVIEWED", "MONITORED", "ARCHIVED"], "required": True},
            {"name": "classification", "label": "Classification", "type": "select", "options": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"], "required": True},
            {"name": "summary", "label": "Summary", "type": "textarea"},
            {"name": "follow_up", "label": "Follow Up", "type": "textarea"},
        ],
    },
    "outgoing_letters": {
        "title": "Outgoing Letter",
        "singular": "Outgoing Letter",
        "permission_view": "outgoing_letters.view",
        "permission_manage": "outgoing_letters.manage",
        "table": "letters",
        "alias": "l",
        "fixed_values": {"direction": "outgoing"},
        "base_query": """
            SELECT l.id, l.organization_id, org.name AS organization_name, target.name AS target_organization_name,
                   l.direction, l.letter_number, l.subject, l.correspondent, l.letter_date, l.status,
                   l.priority, l.summary, l.follow_up, l.template_name, l.signer, l.attachment_path,
                   l.letter_category_id, lc.code AS letter_category_code, lc.name AS letter_category_name,
                   l.is_tembusan_required, l.central_status, l.classification
            FROM letters l
            LEFT JOIN organizations org ON org.id = l.organization_id
            LEFT JOIN organizations target ON target.id = l.target_organization_id
            LEFT JOIN letter_categories lc ON lc.id = l.letter_category_id
            WHERE l.direction = 'outgoing'
        """,
        "columns": [("organization_name", "Origin"), ("letter_category_code", "Category"), ("letter_number", "Letter No."), ("subject", "Subject"), ("correspondent", "Recipient"), ("letter_date", "Date"), ("status", "Status")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "target_organization_id", "label": "Target Organization", "type": "select", "options_source": "organizations"},
            {"name": "letter_category_id", "label": "Letter Category", "type": "select", "options_source": "letter_categories", "required": True},
            {"name": "letter_number", "label": "Letter Number", "type": "text", "readonly": True, "help_text": "Draft belum memakai nomor final. Nomor akan dibuat saat status bukan Draft."},
            {"name": "subject", "label": "Subject", "type": "text", "required": True},
            {"name": "correspondent", "label": "Recipient", "type": "text", "required": True},
            {"name": "letter_date", "label": "Letter Date", "type": "date", "required": True},
            {"name": "status", "label": "Status", "type": "select", "options": ["Draft", "Approval", "Issued", "Sent", "Cancelled", "Archived"], "required": True},
            {"name": "priority", "label": "Priority", "type": "select", "options": ["Low", "Medium", "High"], "required": True},
            {"name": "template_name", "label": "Template", "type": "text"},
            {"name": "signer", "label": "Signer", "type": "text"},
            {"name": "summary", "label": "Summary", "type": "textarea"},
            {"name": "follow_up", "label": "Follow Up", "type": "textarea"},
        ],
    },
    "dispositions": {
        "title": "Disposition",
        "singular": "Disposition",
        "permission_view": "dispositions.view",
        "permission_manage": "dispositions.manage",
        "table": "dispositions",
        "alias": "d",
        "base_query": """
            SELECT d.id, d.organization_id, org.name AS organization_name, d.letter_id, d.from_user_id, d.to_user_id,
                   d.instruction, d.due_date, d.status, d.notes, l.letter_number,
                   sender.full_name AS from_name, receiver.full_name AS to_name
            FROM dispositions d
            LEFT JOIN organizations org ON org.id = d.organization_id
            LEFT JOIN letters l ON l.id = d.letter_id
            LEFT JOIN users sender ON sender.id = d.from_user_id
            LEFT JOIN users receiver ON receiver.id = d.to_user_id
        """,
        "columns": [("organization_name", "Organization"), ("letter_number", "Letter"), ("from_name", "From"), ("to_name", "To"), ("due_date", "Deadline"), ("status", "Status")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "letter_id", "label": "Related Letter", "type": "select", "options_source": "letters", "required": True},
            {"name": "from_user_id", "label": "From", "type": "select", "options_source": "users", "required": True},
            {"name": "to_user_id", "label": "To", "type": "select", "options_source": "users", "required": True},
            {"name": "due_date", "label": "Deadline", "type": "date"},
            {"name": "status", "label": "Status", "type": "select", "options": ["Open", "In Progress", "Completed"], "required": True},
            {"name": "instruction", "label": "Instruction", "type": "textarea", "required": True},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "documents": {
        "title": "Document Management",
        "singular": "Document",
        "permission_view": "documents.view",
        "permission_manage": "documents.manage",
        "table": "documents",
        "alias": "d",
        "base_query": """
            SELECT d.id, d.organization_id, org.name AS organization_name, d.title, d.document_number, d.document_type,
                   d.category, d.document_date, d.expiry_date, d.status, d.file_path, d.vendor_name,
                   d.confidentiality, d.central_monitoring_required, d.central_status, owner.full_name AS owner_name,
                   COALESCE(df.storage_status, CASE WHEN d.file_path IS NOT NULL AND d.file_path != '' THEN 'LEGACY_PATH' ELSE 'MISSING' END) AS storage_status,
                   ds.summary_status,
                   df.original_filename AS current_filename,
                   df.version_number AS current_version_number
            FROM documents d
            LEFT JOIN organizations org ON org.id = d.organization_id
            LEFT JOIN users owner ON owner.id = d.owner_id
            LEFT JOIN document_files df ON df.document_id = d.id AND df.is_current = 1
            LEFT JOIN document_summaries ds ON ds.document_id = d.id AND ds.is_current = 1
        """,
        "columns": [("organization_name", "Organization"), ("title", "Title"), ("document_type", "Type"), ("document_number", "Number"), ("storage_status", "Storage"), ("summary_status", "Resume"), ("expiry_date", "Expiry")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "title", "label": "Document Title", "type": "text", "required": True},
            {"name": "document_number", "label": "Document Number", "type": "text"},
            {"name": "document_type", "label": "Document Type", "type": "select", "options": ["MOU", "CONTRACT", "PERMIT", "CERTIFICATE", "LEGAL", "LETTER", "ARCHIVE"], "required": True},
            {"name": "category", "label": "Category", "type": "select", "options": ["Perizinan", "MOU", "Kontrak", "Surat", "Legal", "Sertifikat", "Arsip"], "required": True},
            {"name": "department", "label": "Department", "type": "text"},
            {"name": "document_date", "label": "Document Date", "type": "date"},
            {"name": "effective_date", "label": "Effective Date", "type": "date"},
            {"name": "expiry_date", "label": "Expiry Date", "type": "date"},
            {"name": "status", "label": "Status", "type": "select", "options": ["Draft", "Active", "Expiring", "Expired", "Archived"], "required": True},
            {"name": "file_path", "label": "File Path", "type": "text"},
            {"name": "owner_id", "label": "Owner", "type": "select", "options_source": "users"},
            {"name": "pic_user_id", "label": "PIC", "type": "select", "options_source": "users"},
            {"name": "vendor_name", "label": "Vendor / Partner", "type": "text"},
            {"name": "version", "label": "Version", "type": "text"},
            {"name": "tags", "label": "Tags", "type": "text"},
            {"name": "confidentiality", "label": "Confidentiality", "type": "select", "options": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"], "required": True},
            {"name": "central_monitoring_required", "label": "Central Monitoring", "type": "select", "options": ["0", "1"], "required": True},
            {"name": "central_status", "label": "Central Status", "type": "select", "options": ["CREATED", "SENT TO HO", "RECEIVED BY HO", "REVIEWED", "MONITORED", "ARCHIVED"], "required": True},
            {"name": "description", "label": "Description", "type": "textarea"},
        ],
    },
    "contracts": {
        "title": "MOU & Contract",
        "singular": "Contract",
        "permission_view": "contracts.view",
        "permission_manage": "contracts.manage",
        "table": "contracts",
        "alias": "c",
        "base_query": """
            SELECT c.id, c.organization_id, org.name AS organization_name, c.contract_number, c.title, c.kind,
                   c.partner_name, c.vendor_name, c.start_date, c.end_date, c.contract_value, c.status,
                   c.renewal_status, c.central_monitoring_required, c.central_status, pic.full_name AS pic_name
            FROM contracts c
            LEFT JOIN organizations org ON org.id = c.organization_id
            LEFT JOIN users pic ON pic.id = c.pic_user_id
        """,
        "columns": [("organization_name", "Organization"), ("contract_number", "Number"), ("title", "Title"), ("kind", "Kind"), ("end_date", "End Date"), ("status", "Status")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "contract_number", "label": "Contract Number", "type": "text", "required": True},
            {"name": "title", "label": "Title", "type": "text", "required": True},
            {"name": "kind", "label": "Kind", "type": "select", "options": ["MOU", "CONTRACT"], "required": True},
            {"name": "partner_name", "label": "Partner", "type": "text"},
            {"name": "vendor_name", "label": "Vendor", "type": "text"},
            {"name": "start_date", "label": "Start Date", "type": "date"},
            {"name": "end_date", "label": "End Date", "type": "date"},
            {"name": "contract_value", "label": "Contract Value", "type": "text"},
            {"name": "pic_user_id", "label": "PIC", "type": "select", "options_source": "users"},
            {"name": "status", "label": "Status", "type": "select", "options": ["DRAFT", "REVIEW", "APPROVAL", "ACTIVE", "EXPIRING", "EXPIRED", "RENEWAL", "TERMINATED", "ARCHIVED"], "required": True},
            {"name": "renewal_status", "label": "Renewal Status", "type": "select", "options": ["NONE", "PLANNED", "IN PROGRESS", "RENEWED"], "required": True},
            {"name": "central_monitoring_required", "label": "Central Monitoring", "type": "select", "options": ["0", "1"], "required": True},
            {"name": "central_status", "label": "Central Status", "type": "select", "options": ["CREATED", "SENT TO HO", "RECEIVED BY HO", "REVIEWED", "MONITORED", "ARCHIVED"], "required": True},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "permits": {
        "title": "License & Permit",
        "singular": "Permit",
        "permission_view": "permits.view",
        "permission_manage": "permits.manage",
        "table": "permits",
        "alias": "p",
        "base_query": """
            SELECT p.id, p.organization_id, org.name AS organization_name, p.permit_name, p.permit_number,
                   p.permit_type, p.issuer, p.issue_date, p.effective_date, p.expiry_date, p.status,
                   p.renewal_status, p.central_monitoring_required, p.central_status, pic.full_name AS pic_name
            FROM permits p
            LEFT JOIN organizations org ON org.id = p.organization_id
            LEFT JOIN users pic ON pic.id = p.pic_user_id
        """,
        "columns": [("organization_name", "Organization"), ("permit_name", "Permit"), ("permit_number", "Number"), ("permit_type", "Type"), ("expiry_date", "Expiry"), ("status", "Status")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "permit_name", "label": "Permit Name", "type": "text", "required": True},
            {"name": "permit_number", "label": "Permit Number", "type": "text", "required": True},
            {"name": "permit_type", "label": "Permit Type", "type": "select", "options": ["Operational", "Health", "Equipment", "Environmental", "Building", "Certificate", "Other"], "required": True},
            {"name": "issuer", "label": "Issuer", "type": "text"},
            {"name": "issue_date", "label": "Issue Date", "type": "date"},
            {"name": "effective_date", "label": "Effective Date", "type": "date"},
            {"name": "expiry_date", "label": "Expiry Date", "type": "date"},
            {"name": "pic_user_id", "label": "PIC", "type": "select", "options_source": "users"},
            {"name": "status", "label": "Status", "type": "select", "options": ["PROCESSING", "ISSUED", "REGISTERED", "EXPIRING", "EXPIRED", "RENEWAL"], "required": True},
            {"name": "renewal_status", "label": "Renewal Status", "type": "select", "options": ["NONE", "PLANNED", "IN PROGRESS", "RENEWED"], "required": True},
            {"name": "central_monitoring_required", "label": "Central Monitoring", "type": "select", "options": ["0", "1"], "required": True},
            {"name": "central_status", "label": "Central Status", "type": "select", "options": ["CREATED", "SENT TO HO", "RECEIVED BY HO", "REVIEWED", "MONITORED", "ARCHIVED"], "required": True},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "vendors": {
        "title": "Vendor & Partner",
        "singular": "Vendor",
        "permission_view": "vendors.view",
        "permission_manage": "vendors.manage",
        "table": "vendors",
        "alias": "v",
        "base_query": """
            SELECT v.id, v.organization_id, org.name AS organization_name, v.name, v.company, v.contact_person,
                   v.email, v.phone, v.address, v.category, v.compliance_status, v.notes
            FROM vendors v
            LEFT JOIN organizations org ON org.id = v.organization_id
        """,
        "columns": [("organization_name", "Organization"), ("name", "Vendor"), ("company", "Company"), ("contact_person", "Contact"), ("category", "Category"), ("compliance_status", "Compliance")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "name", "label": "Vendor Name", "type": "text", "required": True},
            {"name": "company", "label": "Company", "type": "text"},
            {"name": "contact_person", "label": "Contact Person", "type": "text"},
            {"name": "email", "label": "Email", "type": "email"},
            {"name": "phone", "label": "Phone", "type": "text"},
            {"name": "address", "label": "Address", "type": "textarea"},
            {"name": "category", "label": "Category", "type": "select", "options": ["Medical", "Operational", "Legal", "IT", "General"], "required": True},
            {"name": "compliance_status", "label": "Compliance", "type": "select", "options": ["GOOD", "REVIEW", "CRITICAL"], "required": True},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "assets": {
        "title": "Asset Management",
        "singular": "Asset",
        "permission_view": "assets.view",
        "permission_manage": "assets.manage",
        "table": "assets",
        "alias": "a",
        "base_query": """
            SELECT a.id, a.organization_id, org.name AS organization_name, a.asset_code, a.name, a.category,
                   a.location, a.vendor_name, a.purchase_date, a.warranty_expiry, a.maintenance_due, a.status
            FROM assets a
            LEFT JOIN organizations org ON org.id = a.organization_id
        """,
        "columns": [("organization_name", "Organization"), ("asset_code", "Asset Code"), ("name", "Name"), ("category", "Category"), ("warranty_expiry", "Warranty"), ("maintenance_due", "Maintenance Due")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "asset_code", "label": "Asset Code", "type": "text", "required": True},
            {"name": "name", "label": "Asset Name", "type": "text", "required": True},
            {"name": "category", "label": "Category", "type": "select", "options": ["Medical", "IT", "Office", "Vehicle", "General"], "required": True},
            {"name": "location", "label": "Location", "type": "text"},
            {"name": "vendor_name", "label": "Vendor", "type": "text"},
            {"name": "purchase_date", "label": "Purchase Date", "type": "date"},
            {"name": "warranty_expiry", "label": "Warranty Expiry", "type": "date"},
            {"name": "maintenance_due", "label": "Maintenance Due", "type": "date"},
            {"name": "status", "label": "Status", "type": "select", "options": ["ACTIVE", "MAINTENANCE", "DAMAGED", "RETIRED"], "required": True},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "meetings": {
        "title": "Meeting",
        "singular": "Meeting",
        "permission_view": "meetings.view",
        "permission_manage": "meetings.manage",
        "table": "meetings",
        "alias": "m",
        "base_query": """
            SELECT m.id, m.organization_id, org.name AS organization_name, m.title, m.agenda, m.start_at, m.end_at,
                   m.location, m.participants, m.attachment_path, m.status, m.notes,
                   organizer.full_name AS organizer_name
            FROM meetings m
            LEFT JOIN organizations org ON org.id = m.organization_id
            LEFT JOIN users organizer ON organizer.id = m.organizer_id
        """,
        "columns": [("organization_name", "Organization"), ("title", "Title"), ("start_at", "Start"), ("end_at", "End"), ("location", "Location"), ("organizer_name", "Organizer")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "title", "label": "Meeting Title", "type": "text", "required": True},
            {"name": "start_at", "label": "Start", "type": "datetime-local", "required": True},
            {"name": "end_at", "label": "End", "type": "datetime-local", "required": True},
            {"name": "location", "label": "Location", "type": "text"},
            {"name": "organizer_id", "label": "Organizer", "type": "select", "options_source": "users", "required": True},
            {"name": "status", "label": "Status", "type": "select", "options": ["Scheduled", "Running", "Completed", "Cancelled"], "required": True},
            {"name": "participants", "label": "Participants", "type": "textarea"},
            {"name": "attachment_path", "label": "Attachment", "type": "text"},
            {"name": "agenda", "label": "Agenda", "type": "textarea"},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "meeting_minutes": {
        "title": "Meeting Minutes",
        "singular": "Meeting Minutes",
        "permission_view": "meeting_minutes.view",
        "permission_manage": "meeting_minutes.manage",
        "table": "meeting_minutes",
        "alias": "mm",
        "base_query": """
            SELECT mm.id, mm.organization_id, org.name AS organization_name, mm.meeting_id, mm.discussion,
                   mm.decisions, mm.action_items, meeting.title AS meeting_title,
                   recorder.full_name AS recorder_name
            FROM meeting_minutes mm
            LEFT JOIN organizations org ON org.id = mm.organization_id
            LEFT JOIN meetings meeting ON meeting.id = mm.meeting_id
            LEFT JOIN users recorder ON recorder.id = mm.recorded_by
        """,
        "columns": [("organization_name", "Organization"), ("meeting_title", "Meeting"), ("recorder_name", "Recorded By"), ("discussion", "Discussion"), ("decisions", "Decisions")],
        "fields": [
            {"name": "organization_id", "label": "Organization", "type": "select", "options_source": "organizations", "required": True},
            {"name": "meeting_id", "label": "Meeting", "type": "select", "options_source": "meetings", "required": True},
            {"name": "recorded_by", "label": "Recorded By", "type": "select", "options_source": "users", "required": True},
            {"name": "discussion", "label": "Discussion", "type": "textarea", "required": True},
            {"name": "decisions", "label": "Decisions", "type": "textarea"},
            {"name": "action_items", "label": "Action Items", "type": "textarea"},
        ],
    },
}

MONITORED_MODULES = {"documents", "contracts", "permits"}
EXPIRY_MODULES = {
    "documents": ("expiry_date", "Document"),
    "contracts": ("end_date", "Contract"),
    "permits": ("expiry_date", "Permit"),
    "assets": ("warranty_expiry", "Asset Warranty"),
}

RELATED_UPLOAD_TARGETS = {
    "CONTRACT": {"module": "contracts", "label_field": "title", "fk_column": "file_document_id"},
    "PERMIT": {"module": "permits", "label_field": "permit_name", "fk_column": "file_document_id"},
    "INCOMING_LETTER": {"module": "incoming_letters", "label_field": "subject"},
    "OUTGOING_LETTER": {"module": "outgoing_letters", "label_field": "subject"},
    "TASK": {"module": "tasks", "label_field": "title"},
    "MEETING": {"module": "meetings", "label_field": "title"},
    "VENDOR": {"module": "vendors", "label_field": "name"},
    "ASSET": {"module": "assets", "label_field": "name"},
}


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="ai-secretary-dev-secret",
        DATABASE=str(DEFAULT_DATABASE),
        BACKUP_ROOT=str(BACKUP_DIR),
        STORAGE_ROOT=str(STORAGE_DIR),
        LEGACY_STORAGE_ROOTS=[str(BASE_DIR), str(DATA_DIR)],
        DOCUMENT_MAX_FILE_SIZE=50 * 1024 * 1024,
        MAX_CONTENT_LENGTH=50 * 1024 * 1024,
        ENABLE_DOCUMENT_VERSIONING=True,
        ENABLE_TEXT_EXTRACTION=True,
        ENABLE_AUTOMATIC_SUMMARY=True,
        DEFAULT_SUMMARY_LANGUAGE="id",
    )
    if test_config:
        app.config.update(test_config)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Path(app.config["BACKUP_ROOT"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["STORAGE_ROOT"]).mkdir(parents=True, exist_ok=True)

    @app.template_filter("datetime_label")
    def datetime_label(value: Any) -> str:
        return format_datetime(value)

    @app.template_filter("date_label")
    def date_label(value: Any) -> str:
        return format_date(value)

    @app.template_filter("truncate_text")
    def truncate_text(value: Any, limit: int = 80) -> str:
        if value is None or value == "":
            return "-"
        text = str(value)
        return text if len(text) <= limit else f"{text[:limit].rstrip()}..."

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        user = getattr(g, "current_user", None)
        return {
            "app_name": "AI SECRETARY",
            "current_user": user,
            "has_permission": lambda code: user_has_permission(user, code),
            "nav_items": build_navigation(user),
        }

    @app.before_request
    def load_current_user() -> None:
        user_id = session.get("user_id")
        g.current_user = get_user_with_permissions(user_id) if user_id else None
        if g.current_user and g.current_user.get("must_change_password"):
            allowed = {"change_password", "logout", "static"}
            if request.endpoint not in allowed:
                return redirect(url_for("change_password", forced=1))

    @app.teardown_appcontext
    def close_db(exception: Exception | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.errorhandler(400)
    def bad_request(error: Exception):
        return render_template("error.html", title="Permintaan Tidak Valid", message="Data yang dikirim belum lengkap atau tidak sesuai aturan."), 400

    @app.errorhandler(403)
    def forbidden(error: Exception):
        return render_template("error.html", title="Akses Ditolak", message="Anda tidak memiliki permission untuk halaman atau data ini."), 403

    @app.errorhandler(404)
    def missing(error: Exception):
        return render_template("error.html", title="Halaman Tidak Ditemukan", message="Halaman yang Anda cari tidak tersedia."), 404

    @app.errorhandler(413)
    def payload_too_large(error: Exception):
        return render_template("error.html", title="File Terlalu Besar", message="Ukuran file melebihi batas upload yang diizinkan."), 413

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.current_user else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.current_user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = query_one(
                """
                SELECT u.id, u.username, u.full_name, u.email, u.password_hash, u.is_active, u.must_change_password,
                       u.created_at, u.updated_at, u.last_login_at, r.name AS role_name
                FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = ?
                """,
                (username,),
            )
            if not user or not user["is_active"] or not check_password_hash(user["password_hash"], password):
                flash("Username atau password tidak valid.", "error")
            else:
                if is_password_expired(user):
                    flash("Password Anda sudah kedaluwarsa. Silakan ubah password terlebih dahulu.", "error")
                session.clear()
                session["user_id"] = user["id"]
                execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_ts(), user["id"]))
                log_audit(user["id"], None, "LOGIN", "session", user["id"], user["username"], "User login.")
                flash(f"Selamat datang, {user['full_name']}.", "success")
                if user.get("must_change_password") or is_password_expired(user):
                    return redirect(url_for("change_password", forced=1))
                return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        if g.current_user:
            log_audit(g.current_user["id"], g.current_user["organization_id"], "LOGOUT", "session", g.current_user["id"], g.current_user["username"], "User logout.")
        session.clear()
        flash("Sesi berhasil diakhiri.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    @permission_required("dashboard.view")
    def dashboard():
        refresh_notifications()
        selected_org = request.args.get("organization", "").strip()
        return render_template("dashboard.html", **build_dashboard(g.current_user, selected_org), organization_filter=selected_org, filter_options=visible_organizations(g.current_user))

    @app.route("/calendar")
    @login_required
    @permission_required("calendar.view")
    def calendar_view():
        agenda_rows = get_accessible_rows("agenda", g.current_user)
        meeting_rows = get_accessible_rows("meetings", g.current_user)
        buckets: dict[str, list[dict[str, str]]] = {}
        for row in agenda_rows:
            buckets.setdefault((row["start_at"] or "")[:10], []).append({"label": row["title"], "kind": "Agenda", "time": format_time_only(row["start_at"])})
        for row in meeting_rows:
            buckets.setdefault((row["start_at"] or "")[:10], []).append({"label": row["title"], "kind": "Meeting", "time": format_time_only(row["start_at"])})
        days = []
        for offset in range(30):
            current = date.today() + timedelta(days=offset)
            key = current.isoformat()
            entries = buckets.get(key, [])
            days.append({"date": current, "entries": entries, "count": len(entries)})
        timeline = sorted(
            [*[{"when": row["start_at"], "title": row["title"], "kind": "Agenda", "location": row.get("location")} for row in agenda_rows], *[{"when": row["start_at"], "title": row["title"], "kind": "Meeting", "location": row.get("location")} for row in meeting_rows]],
            key=lambda item: item["when"] or "9999",
        )[:12]
        return render_template("calendar.html", days=days, timeline=timeline)

    @app.route("/search")
    @login_required
    @permission_required("search.global")
    def search_page():
        query_text = request.args.get("q", "").strip()
        return render_template("search.html", query_text=query_text, results=perform_search(query_text, g.current_user) if query_text else [])

    @app.route("/compliance")
    @login_required
    @permission_required("compliance.view")
    def compliance_page():
        return render_template("compliance.html", **build_compliance_dashboard(g.current_user))

    @app.route("/reports")
    @login_required
    @permission_required("reports.view")
    def reports_page():
        return render_template("reports.html", **build_report_rows(g.current_user))

    @app.route("/reports/export.csv")
    @login_required
    @permission_required("reports.view")
    def reports_export():
        report = build_report_rows(g.current_user)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["module", "organization", "label", "status", "date", "urgency"])
        for row in report["expiry_rows"]:
            writer.writerow([row["module"], row["organization_name"], row["label"], row["status"], row["expiry_date"], row["urgency"]])
        return Response(buffer.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=ai-secretary-expiry-report.csv"})

    @app.route("/audit-logs")
    @login_required
    @permission_required("audit.view")
    def audit_logs_page():
        logs = query_all(
            """
            SELECT a.id, a.action, a.entity_type, a.entity_id, a.entity_label, a.details, a.created_at,
                   u.full_name AS user_name, org.name AS organization_name
            FROM audit_logs a
            LEFT JOIN users u ON u.id = a.user_id
            LEFT JOIN organizations org ON org.id = a.organization_id
            ORDER BY a.id DESC LIMIT 300
            """
        )
        return render_template("audit_logs.html", logs=logs)

    @app.route("/settings")
    @login_required
    @permission_required("settings.manage")
    def settings_page():
        return render_template(
            "settings.html",
            organizations=query_all("SELECT id, code, name, kind, is_central FROM organizations ORDER BY id"),
            reminder_schedule=["90 hari", "60 hari", "30 hari", "14 hari", "7 hari", "1 hari", "Hari H", "Setelah expired"],
            settings_rows=query_all("SELECT key, value, updated_at FROM system_settings ORDER BY key"),
            backup_rows=list_backup_archives(),
            company_settings=get_company_settings(),
            letter_category_count=query_one("SELECT COUNT(*) AS total FROM letter_categories")["total"],
        )

    @app.route("/settings/letter-categories")
    @login_required
    @permission_required("settings.manage")
    def letter_categories_page():
        query_text = request.args.get("q", "").strip().lower()
        status_filter = request.args.get("status", "").strip().lower()
        rows = query_all("SELECT * FROM letter_categories ORDER BY is_active DESC, name ASC")
        if query_text:
            rows = [row for row in rows if query_text in f"{row['code']} {row['name']} {row.get('description') or ''}".lower()]
        if status_filter in {"active", "inactive"}:
            rows = [row for row in rows if bool(row["is_active"]) == (status_filter == "active")]
        return render_template("letter_categories.html", rows=rows, query_text=query_text, status_filter=status_filter)

    @app.route("/settings/letter-categories/new", methods=["GET", "POST"])
    @login_required
    @permission_required("settings.manage")
    def letter_category_create():
        if request.method == "POST":
            if save_letter_category(None, request.form):
                flash("Kategori surat berhasil ditambahkan.", "success")
                return redirect(url_for("letter_categories_page"))
        return render_template("letter_category_form.html", title="Tambah Kategori Surat", row=None)

    @app.route("/settings/letter-categories/<int:category_id>/edit", methods=["GET", "POST"])
    @login_required
    @permission_required("settings.manage")
    def letter_category_edit(category_id: int):
        row = query_one("SELECT * FROM letter_categories WHERE id = ?", (category_id,))
        if not row:
            abort(404)
        if request.method == "POST":
            if save_letter_category(category_id, request.form):
                flash("Kategori surat berhasil diperbarui.", "success")
                return redirect(url_for("letter_categories_page"))
        return render_template("letter_category_form.html", title="Edit Kategori Surat", row=row)

    @app.post("/settings/letter-categories/<int:category_id>/toggle")
    @login_required
    @permission_required("settings.manage")
    def letter_category_toggle(category_id: int):
        row = query_one("SELECT * FROM letter_categories WHERE id = ?", (category_id,))
        if not row:
            abort(404)
        next_status = 0 if row["is_active"] else 1
        execute("UPDATE letter_categories SET is_active = ?, updated_at = ? WHERE id = ?", (next_status, now_ts(), category_id))
        log_audit(g.current_user["id"], g.current_user["organization_id"], "UPDATE", "letter_category", category_id, row["code"], f"Status kategori surat menjadi {'ACTIVE' if next_status else 'INACTIVE'}.")
        flash("Status kategori surat berhasil diperbarui.", "success")
        return redirect(url_for("letter_categories_page"))

    @app.post("/settings/letter-categories/<int:category_id>/delete")
    @login_required
    @permission_required("settings.manage")
    def letter_category_delete(category_id: int):
        row = query_one("SELECT * FROM letter_categories WHERE id = ?", (category_id,))
        if not row:
            abort(404)
        usage = query_one("SELECT COUNT(*) AS total FROM letters WHERE letter_category_id = ?", (category_id,))
        if usage["total"]:
            flash("Kategori surat tidak dapat dihapus karena sudah digunakan.", "error")
        else:
            execute("DELETE FROM letter_categories WHERE id = ?", (category_id,))
            log_audit(g.current_user["id"], g.current_user["organization_id"], "DELETE", "letter_category", category_id, row["code"], "Kategori surat dihapus.")
            flash("Kategori surat berhasil dihapus.", "success")
        return redirect(url_for("letter_categories_page"))

    @app.route("/settings/company", methods=["GET", "POST"])
    @login_required
    @permission_required("settings.manage")
    def company_settings_page():
        company = get_company_settings()
        if request.method == "POST":
            try:
                if save_company_settings(request.form, request.files.get("logo_file"), company):
                    flash("Pengaturan perusahaan berhasil diperbarui.", "success")
                    return redirect(url_for("company_settings_page"))
            except DocumentProcessingError as exc:
                flash(str(exc), "error")
            company = get_company_settings()
        return render_template("company_settings.html", company=company)

    @app.route("/settings/company/logo")
    @login_required
    @permission_required("settings.manage")
    def company_logo_preview():
        company = get_company_settings()
        logo_path = resolve_company_logo_path(company.get("logo_storage_path"))
        if not logo_path or not logo_path.exists():
            abort(404)
        return send_file(logo_path, as_attachment=False, download_name=logo_path.name)

    @app.post("/settings/company/logo/delete")
    @login_required
    @permission_required("settings.manage")
    def company_logo_delete():
        company = get_company_settings()
        delete_company_logo(company.get("logo_storage_path"))
        execute("UPDATE company_settings SET logo_storage_path = NULL, updated_at = ? WHERE id = 1", (now_ts(),))
        log_audit(g.current_user["id"], g.current_user["organization_id"], "DELETE", "company_logo", 1, "company-logo", "Logo perusahaan dihapus.")
        flash("Logo perusahaan berhasil dihapus.", "success")
        return redirect(url_for("company_settings_page"))

    @app.route("/users")
    @login_required
    @permission_required("users.manage")
    def users_page():
        query_text = request.args.get("q", "").strip().lower()
        status_filter = request.args.get("status", "").strip()
        users = query_all(
            """
            SELECT u.id, u.username, u.full_name, u.email, u.phone, u.department, u.position, u.is_active,
                   u.must_change_password, u.last_login_at, r.name AS role_name, org.name AS organization_name
            FROM users u
            JOIN roles r ON r.id = u.role_id
            LEFT JOIN organizations org ON org.id = u.organization_id
            ORDER BY org.name, u.full_name
            """
        )
        if query_text:
            users = [
                row
                for row in users
                if query_text in " ".join(
                    [
                        str(row.get("full_name") or ""),
                        str(row.get("username") or ""),
                        str(row.get("email") or ""),
                        str(row.get("organization_name") or ""),
                        str(row.get("department") or ""),
                        str(row.get("position") or ""),
                    ]
                ).lower()
            ]
        if status_filter in {"active", "inactive"}:
            users = [row for row in users if bool(row["is_active"]) == (status_filter == "active")]
        return render_template("users.html", users=users, query_text=query_text, status_filter=status_filter)

    @app.route("/users/new", methods=["GET", "POST"])
    @login_required
    @permission_required("users.manage")
    def user_create():
        roles = query_all("SELECT id, name FROM roles ORDER BY name")
        organizations = query_all("SELECT id, name FROM organizations ORDER BY id")
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            department = request.form.get("department", "").strip()
            position = request.form.get("position", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            role_id = request.form.get("role_id", "")
            organization_id = request.form.get("organization_id", "")
            is_active = 1 if request.form.get("is_active", "on") == "on" else 0
            if not all([full_name, username, email, password, confirm_password, role_id, organization_id]):
                flash("Semua field wajib diisi.", "error")
            elif password != confirm_password:
                flash("Password dan konfirmasi password harus sama.", "error")
            else:
                error = validate_password_policy(password, username=username, email=email)
                if error:
                    flash(error, "error")
                    return render_template("user_form.html", title="Tambah User", roles=roles, organizations=organizations, user_row=None)
                try:
                    execute(
                        "INSERT INTO users (username, full_name, email, phone, department, position, password_hash, role_id, organization_id, is_active, must_change_password, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                        (username, full_name, email, phone, department, position, generate_password_hash(password), role_id, organization_id, is_active, now_ts(), now_ts()),
                    )
                    log_audit(g.current_user["id"], g.current_user["organization_id"], "CREATE", "user", None, username, f"User {username} ditambahkan.", after_data=json.dumps({"username": username, "email": email, "role_id": role_id}))
                    flash("User berhasil ditambahkan.", "success")
                    return redirect(url_for("users_page"))
                except sqlite3.IntegrityError:
                    flash("Username atau email sudah digunakan.", "error")
        return render_template("user_form.html", title="Tambah User", roles=roles, organizations=organizations, user_row=None)

    @app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
    @login_required
    @permission_required("users.manage")
    def user_edit(user_id: int):
        roles = query_all("SELECT id, name FROM roles ORDER BY name")
        organizations = query_all("SELECT id, name FROM organizations ORDER BY id")
        user_row = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not user_row:
            abort(404)
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            department = request.form.get("department", "").strip()
            position = request.form.get("position", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            role_id = request.form.get("role_id", "")
            organization_id = request.form.get("organization_id", "")
            is_active = 1 if request.form.get("is_active") == "on" else 0
            if not all([full_name, email, role_id, organization_id]):
                flash("Field wajib tidak boleh kosong.", "error")
            elif password and password != confirm_password:
                flash("Password dan konfirmasi password harus sama.", "error")
            else:
                try:
                    before_payload = json.dumps({"full_name": user_row["full_name"], "email": user_row["email"], "role_id": user_row["role_id"], "is_active": user_row["is_active"]})
                    if password:
                        error = validate_password_policy(password, username=user_row["username"], email=email)
                        if error:
                            flash(error, "error")
                            return render_template("user_form.html", title="Edit User", roles=roles, organizations=organizations, user_row=user_row)
                        execute("UPDATE users SET full_name = ?, email = ?, phone = ?, department = ?, position = ?, password_hash = ?, role_id = ?, organization_id = ?, is_active = ?, must_change_password = 0, updated_at = ? WHERE id = ?", (full_name, email, phone, department, position, generate_password_hash(password), role_id, organization_id, is_active, now_ts(), user_id))
                    else:
                        execute("UPDATE users SET full_name = ?, email = ?, phone = ?, department = ?, position = ?, role_id = ?, organization_id = ?, is_active = ?, updated_at = ? WHERE id = ?", (full_name, email, phone, department, position, role_id, organization_id, is_active, now_ts(), user_id))
                    log_audit(g.current_user["id"], g.current_user["organization_id"], "UPDATE", "user", user_id, user_row["username"], f"User {user_row['username']} diperbarui.", before_data=before_payload, after_data=json.dumps({"full_name": full_name, "email": email, "role_id": role_id, "is_active": is_active}))
                    flash("User berhasil diperbarui.", "success")
                    return redirect(url_for("users_page"))
                except sqlite3.IntegrityError:
                    flash("Email sudah digunakan.", "error")
        return render_template("user_form.html", title="Edit User", roles=roles, organizations=organizations, user_row=user_row)

    @app.route("/users/<int:user_id>/reset-password", methods=["GET", "POST"])
    @login_required
    @permission_required("users.manage")
    def user_reset_password(user_id: int):
        user_row = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not user_row:
            abort(404)
        if request.method == "POST":
            new_password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            if not new_password or not confirm_password:
                flash("Password baru dan konfirmasi wajib diisi.", "error")
            elif new_password != confirm_password:
                flash("Password baru dan konfirmasi harus sama.", "error")
            else:
                error = validate_password_policy(new_password, username=user_row["username"], email=user_row["email"])
                if error:
                    flash(error, "error")
                else:
                    execute("UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = ? WHERE id = ?", (generate_password_hash(new_password), now_ts(), user_id))
                    log_audit(g.current_user["id"], g.current_user["organization_id"], "RESET_PASSWORD", "user", user_id, user_row["username"], "Password user direset dan wajib diganti saat login berikutnya.")
                    flash("Password user berhasil direset. User wajib mengganti password saat login berikutnya.", "success")
                    return redirect(url_for("users_page"))
        return render_template("reset_password.html", user_row=user_row)

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        forced = request.args.get("forced") == "1" or bool(g.current_user.get("must_change_password"))
        if request.method == "POST":
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            current = query_one("SELECT * FROM users WHERE id = ?", (g.current_user["id"],))
            if not current or not check_password_hash(current["password_hash"], old_password):
                flash("Password lama tidak benar.", "error")
            elif new_password != confirm_password:
                flash("Password baru dan konfirmasi harus sama.", "error")
            elif old_password == new_password:
                flash("Password baru tidak boleh sama dengan password lama.", "error")
            else:
                error = validate_password_policy(new_password, username=current["username"], email=current["email"])
                if error:
                    flash(error, "error")
                else:
                    execute("UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = ? WHERE id = ?", (generate_password_hash(new_password), now_ts(), current["id"]))
                    log_audit(current["id"], current["organization_id"], "CHANGE_PASSWORD", "user", current["id"], current["username"], "User mengubah password sendiri.")
                    flash("Password berhasil diubah.", "success")
                    return redirect(url_for("dashboard"))
        return render_template("change_password.html", forced=forced)

    @app.route("/roles")
    @login_required
    @permission_required("roles.manage")
    def roles_page():
        roles = query_all("SELECT * FROM roles ORDER BY name")
        permissions = query_all("SELECT * FROM permissions ORDER BY code")
        permission_map = {role["id"]: {row["permission_code"] for row in query_all("SELECT permission_code FROM role_permissions WHERE role_id = ?", (role["id"],))} for role in roles}
        return render_template("roles.html", roles=roles, permissions=permissions, permission_map=permission_map)

    @app.route("/roles/new", methods=["GET", "POST"])
    @login_required
    @permission_required("roles.manage")
    def role_create():
        permissions = query_all("SELECT * FROM permissions ORDER BY code")
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            selected = request.form.getlist("permissions")
            if not name or not description:
                flash("Nama dan deskripsi role wajib diisi.", "error")
            else:
                try:
                    role_id = execute("INSERT INTO roles (name, description) VALUES (?, ?)", (name, description), True)
                    for code in selected:
                        execute("INSERT INTO role_permissions (role_id, permission_code) VALUES (?, ?)", (role_id, code))
                    log_action("CREATE", "role", name, detail=f"Role {name} dibuat.")
                    flash("Role berhasil ditambahkan.", "success")
                    return redirect(url_for("roles_page"))
                except sqlite3.IntegrityError:
                    flash("Nama role sudah ada.", "error")
        return render_template("role_form.html", title="Tambah Role", role_row=None, permissions=permissions, selected_permissions=set())

    @app.route("/roles/<int:role_id>/edit", methods=["GET", "POST"])
    @login_required
    @permission_required("roles.manage")
    def role_edit(role_id: int):
        permissions = query_all("SELECT * FROM permissions ORDER BY code")
        role_row = query_one("SELECT * FROM roles WHERE id = ?", (role_id,))
        if not role_row:
            abort(404)
        selected_permissions = {row["permission_code"] for row in query_all("SELECT permission_code FROM role_permissions WHERE role_id = ?", (role_id,))}
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            selected_permissions = set(request.form.getlist("permissions"))
            if not name or not description:
                flash("Nama dan deskripsi role wajib diisi.", "error")
            else:
                try:
                    execute("UPDATE roles SET name = ?, description = ? WHERE id = ?", (name, description, role_id))
                    execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
                    for code in selected_permissions:
                        execute("INSERT INTO role_permissions (role_id, permission_code) VALUES (?, ?)", (role_id, code))
                    log_action("UPDATE", "role", name, detail=f"Role {name} diperbarui.")
                    flash("Role berhasil diperbarui.", "success")
                    return redirect(url_for("roles_page"))
                except sqlite3.IntegrityError:
                    flash("Nama role sudah dipakai.", "error")
        return render_template("role_form.html", title="Edit Role", role_row=role_row, permissions=permissions, selected_permissions=selected_permissions)

    @app.route("/notifications")
    @login_required
    @permission_required("notifications.view")
    def notifications_page():
        refresh_notifications()
        notifications = query_all("SELECT id, title, message, kind, is_read, link, created_at FROM notifications WHERE user_id = ? ORDER BY is_read ASC, created_at DESC", (g.current_user["id"],))
        return render_template("notifications.html", notifications=notifications)

    @app.post("/notifications/<int:notification_id>/read")
    @login_required
    @permission_required("notifications.view")
    def mark_notification_read(notification_id: int):
        execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (notification_id, g.current_user["id"]))
        log_action("UPDATE", "notification", str(notification_id), detail="Notification marked as read.")
        flash("Notifikasi ditandai telah dibaca.", "success")
        return redirect(url_for("notifications_page"))

    @app.route("/assistant", methods=["GET", "POST"])
    @login_required
    @permission_required("assistant.use")
    def assistant_page():
        answer = None
        prompt = ""
        if request.method == "POST":
            prompt = request.form.get("prompt", "").strip()
            answer = build_assistant_response(prompt, g.current_user)
        return render_template("assistant.html", answer=answer, prompt=prompt)

    @app.route("/documents/upload", methods=["GET", "POST"])
    @login_required
    @permission_required("documents.manage")
    def document_upload():
        related_type = normalize_related_type(request.values.get("related_type", ""))
        related_id = parse_int(request.values.get("related_id"))
        related_context = get_related_upload_context(related_type, related_id, g.current_user)
        form_values = collect_document_upload_values(request.form, g.current_user, related_context)
        if request.method == "POST":
            upload = request.files.get("document_file")
            if not upload or not (upload.filename or "").strip():
                flash("File wajib dipilih sebelum upload.", "error")
                return render_template(
                    "document_upload.html",
                    title="Upload Document",
                    document_row=None,
                    fields=prepare_fields(MODULES["documents"], g.current_user, None),
                    form_values=form_values,
                    related_context=related_context,
                    allowed_extensions=", ".join(sorted(ALLOWED_EXTENSIONS)),
                )

            created_id = save_module("documents", None, request.form, g.current_user)
            if not created_id:
                return render_template(
                    "document_upload.html",
                    title="Upload Document",
                    document_row=None,
                    fields=prepare_fields(MODULES["documents"], g.current_user, None),
                    form_values=form_values,
                    related_context=related_context,
                    allowed_extensions=", ".join(sorted(ALLOWED_EXTENSIONS)),
                )

            document_row = get_document_or_404(int(created_id), manage=True)
            try:
                file_row = attach_uploaded_file(
                    document_row,
                    upload,
                    g.current_user,
                    generate_summary=request.form.get("generate_summary", "1") == "1",
                    summary_language=request.form.get("summary_language", app.config["DEFAULT_SUMMARY_LANGUAGE"]),
                    allow_duplicate=request.form.get("allow_duplicate") == "1",
                )
                if related_context:
                    link_document_to_related(document_row["id"], related_context["type"], related_context["id"], g.current_user)
            except DocumentProcessingError as exc:
                execute("DELETE FROM document_relations WHERE document_id = ?", (document_row["id"],))
                execute("DELETE FROM document_summaries WHERE document_id = ?", (document_row["id"],))
                execute("DELETE FROM document_files WHERE document_id = ?", (document_row["id"],))
                execute("DELETE FROM documents WHERE id = ?", (document_row["id"],))
                flash(str(exc), "error")
                return render_template(
                    "document_upload.html",
                    title="Upload Document",
                    document_row=None,
                    fields=prepare_fields(MODULES["documents"], g.current_user, None),
                    form_values=form_values,
                    related_context=related_context,
                    allowed_extensions=", ".join(sorted(ALLOWED_EXTENSIONS)),
                )

            flash(
                f"Upload berhasil. Document ID {document_row['id']} tersimpan dengan status {file_row['storage_status']}.",
                "success",
            )
            return redirect(url_for("document_detail", document_id=document_row["id"]))

        return render_template(
            "document_upload.html",
            title="Upload Document",
            document_row=None,
            fields=prepare_fields(MODULES["documents"], g.current_user, None),
            form_values=form_values,
            related_context=related_context,
            allowed_extensions=", ".join(sorted(ALLOWED_EXTENSIONS)),
        )

    @app.route("/documents/<int:document_id>")
    @login_required
    @permission_required("documents.view")
    def document_detail(document_id: int):
        document_row = get_document_or_404(document_id)
        return render_template(
            "document_detail.html",
            document=document_row,
            current_file=get_current_document_file(document_id),
            document_files=get_document_files(document_id),
            current_summary=get_current_document_summary(document_id),
            summary_history=get_document_summary_history(document_id),
            current_extraction=get_current_document_extraction(document_id),
            related_items=get_document_related_items(document_id),
            audit_rows=get_document_audit_rows(document_id),
            can_manage=user_has_permission(g.current_user, "documents.manage") and can_manage_record("documents", document_row, g.current_user),
        )

    @app.route("/documents/<int:document_id>/versions/new", methods=["GET", "POST"])
    @login_required
    @permission_required("documents.manage")
    def document_new_version(document_id: int):
        document_row = get_document_or_404(document_id, manage=True)
        if request.method == "POST":
            upload = request.files.get("document_file")
            if not upload or not (upload.filename or "").strip():
                flash("File versi baru wajib dipilih.", "error")
            else:
                try:
                    attach_uploaded_file(
                        document_row,
                        upload,
                        g.current_user,
                        generate_summary=request.form.get("generate_summary", "1") == "1",
                        summary_language=request.form.get("summary_language", app.config["DEFAULT_SUMMARY_LANGUAGE"]),
                        allow_duplicate=request.form.get("allow_duplicate") == "1",
                    )
                    flash("Versi dokumen baru berhasil di-upload.", "success")
                    return redirect(url_for("document_detail", document_id=document_id))
                except DocumentProcessingError as exc:
                    flash(str(exc), "error")
        return render_template(
            "document_upload.html",
            title=f"Upload Version - {document_row['title']}",
            document_row=document_row,
            fields=prepare_fields(MODULES["documents"], g.current_user, document_row),
            form_values=collect_document_upload_values(request.form, g.current_user, None, document_row),
            related_context=None,
            allowed_extensions=", ".join(sorted(ALLOWED_EXTENSIONS)),
        )

    @app.post("/documents/<int:document_id>/summary/generate")
    @login_required
    @permission_required("documents.manage")
    def document_generate_summary(document_id: int):
        document_row = get_document_or_404(document_id, manage=True)
        current_file = get_current_document_file(document_id)
        if not current_file:
            flash("Dokumen belum memiliki file aktif.", "error")
            return redirect(url_for("document_detail", document_id=document_id))
        summary_language = request.form.get("summary_language", app.config["DEFAULT_SUMMARY_LANGUAGE"])
        try:
            generate_summary_for_file(document_row, current_file, g.current_user, summary_language, regenerate=True)
            flash("Resume berhasil dibuat ulang.", "success")
        except DocumentProcessingError as exc:
            flash(str(exc), "error")
        return redirect(url_for("document_detail", document_id=document_id))

    @app.post("/documents/files/<int:file_id>/restore")
    @login_required
    @permission_required("documents.manage")
    def document_restore_version(file_id: int):
        file_row = get_document_file_or_404(file_id, manage=True)
        restore_document_version(file_row["document_id"], file_row["id"], g.current_user)
        flash("Versi dokumen berhasil dipulihkan menjadi versi aktif.", "success")
        return redirect(url_for("document_detail", document_id=file_row["document_id"]))

    @app.route("/documents/files/<int:file_id>/download")
    @login_required
    @permission_required("documents.view")
    def document_file_download(file_id: int):
        file_row = get_document_file_or_404(file_id)
        log_action("DOWNLOAD", "document_file", file_row["original_filename"], file_row["organization_id"], "Download original document.")
        return build_document_file_response(file_row, as_attachment=True)

    @app.route("/documents/files/<int:file_id>/preview")
    @login_required
    @permission_required("documents.view")
    def document_file_preview(file_id: int):
        file_row = get_document_file_or_404(file_id)
        if file_row["extension"] not in PREVIEWABLE_EXTENSIONS:
            flash("Preview tidak tersedia untuk format file ini.", "error")
            return redirect(url_for("document_detail", document_id=file_row["document_id"]))
        log_action("PREVIEW", "document_file", file_row["original_filename"], file_row["organization_id"], "Preview original document.")
        return build_document_file_response(file_row, as_attachment=False)

    @app.route("/documents/extractions/<int:file_id>/download")
    @login_required
    @permission_required("documents.view")
    def document_extraction_download(file_id: int):
        file_row = get_document_file_or_404(file_id)
        extraction = get_extraction_for_file(file_id)
        if not extraction or not extraction.get("extracted_text"):
            flash("Teks hasil ekstraksi belum tersedia.", "error")
            return redirect(url_for("document_detail", document_id=file_row["document_id"]))
        log_action("DOWNLOAD", "document_extraction", file_row["original_filename"], file_row["organization_id"], "Download extracted text.")
        return send_file(
            io.BytesIO(extraction["extracted_text"].encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name=f"document-{file_row['document_id']}-v{file_row['version_number']}-extracted.txt",
        )

    @app.route("/documents/summaries/<int:summary_id>/download")
    @login_required
    @permission_required("documents.view")
    def document_summary_download(summary_id: int):
        summary_row = get_document_summary_or_404(summary_id)
        log_action("DOWNLOAD", "document_summary", str(summary_row["document_id"]), summary_row["organization_id"], "Download document summary.")
        return send_file(
            io.BytesIO((summary_row.get("summary_text") or "").encode("utf-8")),
            mimetype="text/plain; charset=utf-8",
            as_attachment=True,
            download_name=f"document-{summary_row['document_id']}-v{summary_row['version_number']}-summary.txt",
        )

    @app.post("/documents/summaries/<int:summary_id>/review")
    @login_required
    @permission_required("documents.manage")
    def document_summary_review(summary_id: int):
        summary_row = get_document_summary_or_404(summary_id, manage=True)
        next_status = request.form.get("next_status", "REVIEWED").strip().upper()
        summary_text = request.form.get("summary_text", "").strip()
        review_notes = request.form.get("review_notes", "").strip()
        update_document_summary(summary_row, g.current_user, summary_text, review_notes, next_status)
        flash("Resume dokumen berhasil diperbarui.", "success")
        return redirect(url_for("document_detail", document_id=summary_row["document_id"]))

    @app.post("/settings/backup/create")
    @login_required
    @permission_required("settings.manage")
    def settings_backup_create():
        archive_name = create_backup_archive()
        flash(f"Backup berhasil dibuat: {archive_name.name}", "success")
        return redirect(url_for("settings_page"))

    @app.route("/settings/backups/<path:archive_name>/download")
    @login_required
    @permission_required("settings.manage")
    def settings_backup_download(archive_name: str):
        archive_path = Path(current_app().config["BACKUP_ROOT"]) / Path(archive_name).name
        if not archive_path.exists():
            abort(404)
        return send_file(archive_path, as_attachment=True, download_name=archive_path.name)

    @app.post("/settings/backups/<path:archive_name>/restore")
    @login_required
    @permission_required("settings.manage")
    def settings_backup_restore(archive_name: str):
        restore_backup_archive(archive_name)
        flash(f"Backup {Path(archive_name).name} berhasil direstore.", "success")
        return redirect(url_for("settings_page"))

    @app.route("/modules/<module>")
    @login_required
    def module_list(module: str):
        config = MODULES.get(module)
        if not config:
            abort(404)
        ensure_permission(config["permission_view"])
        return render_template("module_list.html", title=config["title"], module_key=module, config=config, rows=get_accessible_rows(module, g.current_user), can_manage=user_has_permission(g.current_user, config["permission_manage"]) and can_manage_any_org(g.current_user))

    @app.route("/modules/<module>/new", methods=["GET", "POST"])
    @login_required
    def module_create(module: str):
        config = MODULES.get(module)
        if not config:
            abort(404)
        ensure_permission(config["permission_manage"])
        if request.method == "POST" and save_module(module, None, request.form, g.current_user):
            flash(f"{config['singular']} berhasil ditambahkan.", "success")
            return redirect(url_for("module_list", module=module))
        return render_template("module_form.html", title=f"Tambah {config['singular']}", config=config, module_key=module, fields=prepare_fields(config, g.current_user, None), row={})

    @app.route("/modules/<module>/<int:record_id>/edit", methods=["GET", "POST"])
    @login_required
    def module_edit(module: str, record_id: int):
        config = MODULES.get(module)
        if not config:
            abort(404)
        ensure_permission(config["permission_manage"])
        row = get_module_record(module, record_id)
        if not row:
            abort(404)
        ensure_record_access(module, row, g.current_user)
        if request.method == "POST" and save_module(module, record_id, request.form, g.current_user):
            flash(f"{config['singular']} berhasil diperbarui.", "success")
            return redirect(url_for("module_list", module=module))
        return render_template("module_form.html", title=f"Edit {config['singular']}", config=config, module_key=module, fields=prepare_fields(config, g.current_user, row), row=row)

    with app.app_context():
        init_db()
    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database_path = Path(current_app().config["DATABASE"])
        database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def current_app() -> Flask:
    from flask import current_app as flask_current_app

    return flask_current_app


def query_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in get_db().execute(sql, params).fetchall()]


def query_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    row = get_db().execute(sql, params).fetchone()
    return dict(row) if row else None


def execute(sql: str, params: tuple[Any, ...] = (), return_lastrowid: bool = False) -> int | None:
    db = get_db()
    cursor = db.execute(sql, params)
    db.commit()
    return int(cursor.lastrowid) if return_lastrowid else None


def init_db() -> None:
    get_db().executescript(SCHEMA_SQL)
    get_db().commit()
    migrate_legacy_schema()
    seed_organizations()
    seed_roles_permissions()
    seed_default_users()
    ensure_default_settings()
    ensure_default_company_settings()
    seed_letter_categories()
    backfill_organization_defaults()
    seed_sample_data()
    sync_legacy_document_files()


def migrate_legacy_schema() -> None:
    database_path = Path(current_app().config["DATABASE"])
    if database_path.exists():
        try:
            users_columns = {row["name"] for row in query_all("PRAGMA table_info(users)")}
            if users_columns and "organization_id" not in users_columns:
                backup_name = Path(current_app().config["BACKUP_ROOT"]) / f"ai_secretary_pre_multi_org_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                if not backup_name.exists():
                    shutil.copy2(database_path, backup_name)
        except sqlite3.DatabaseError:
            pass

    ensure_column("users", "organization_id INTEGER")
    ensure_column("users", "updated_at TEXT")
    ensure_column("users", "phone TEXT")
    ensure_column("users", "department TEXT")
    ensure_column("users", "position TEXT")
    ensure_column("users", "must_change_password INTEGER NOT NULL DEFAULT 0")
    ensure_column("users", "last_login_at TEXT")
    ensure_column("agenda_entries", "organization_id INTEGER")
    ensure_column("agenda_entries", "classification TEXT DEFAULT 'INTERNAL'")
    ensure_column("agenda_entries", "updated_by INTEGER")
    ensure_column("tasks", "organization_id INTEGER")
    ensure_column("tasks", "related_type TEXT")
    ensure_column("tasks", "related_id INTEGER")
    ensure_column("tasks", "updated_by INTEGER")
    ensure_column("reminders", "organization_id INTEGER")
    ensure_column("reminders", "days_remaining INTEGER")
    ensure_column("notifications", "organization_id INTEGER")
    ensure_column("contacts", "organization_id INTEGER")
    ensure_column("contacts", "updated_by INTEGER")
    ensure_column("letters", "organization_id INTEGER")
    ensure_column("letters", "target_organization_id INTEGER")
    ensure_column("letters", "template_name TEXT")
    ensure_column("letters", "body TEXT")
    ensure_column("letters", "signer TEXT")
    ensure_column("letters", "attachment_path TEXT")
    ensure_column("letters", "letter_category_id INTEGER")
    ensure_column("letters", "is_number_final INTEGER NOT NULL DEFAULT 0")
    ensure_column("letters", "is_tembusan_required INTEGER NOT NULL DEFAULT 0")
    ensure_column("letters", "central_status TEXT")
    ensure_column("letters", "classification TEXT DEFAULT 'INTERNAL'")
    ensure_column("letters", "updated_by INTEGER")
    ensure_column("audit_logs", "ip_address TEXT")
    ensure_column("audit_logs", "before_data TEXT")
    ensure_column("audit_logs", "after_data TEXT")
    ensure_column("dispositions", "organization_id INTEGER")
    ensure_column("documents", "organization_id INTEGER")
    ensure_column("documents", "document_number TEXT")
    ensure_column("documents", "document_type TEXT DEFAULT 'ARCHIVE'")
    ensure_column("documents", "department TEXT")
    ensure_column("documents", "document_date TEXT")
    ensure_column("documents", "effective_date TEXT")
    ensure_column("documents", "expiry_date TEXT")
    ensure_column("documents", "pic_user_id INTEGER")
    ensure_column("documents", "status TEXT")
    ensure_column("documents", "vendor_name TEXT")
    ensure_column("documents", "confidentiality TEXT DEFAULT 'INTERNAL'")
    ensure_column("documents", "central_monitoring_required INTEGER NOT NULL DEFAULT 0")
    ensure_column("documents", "central_status TEXT")
    ensure_column("documents", "original_document_id INTEGER")
    ensure_column("documents", "created_by INTEGER")
    ensure_column("documents", "updated_by INTEGER")
    ensure_column("meetings", "organization_id INTEGER")
    ensure_column("meetings", "attachment_path TEXT")
    ensure_column("meetings", "created_by INTEGER")
    ensure_column("meetings", "updated_by INTEGER")
    ensure_column("meeting_minutes", "organization_id INTEGER")


def ensure_column(table: str, definition: str) -> None:
    existing = {row["name"] for row in query_all(f"PRAGMA table_info({table})")}
    name = definition.split()[0]
    if name not in existing:
        get_db().execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
        get_db().commit()


def seed_organizations() -> None:
    for org in ORGANIZATIONS:
        execute(
            "INSERT OR IGNORE INTO organizations (code, name, kind, parent_id, is_central, created_at, updated_at) VALUES (?, ?, ?, NULL, ?, ?, ?)",
            (org["code"], org["name"], org["kind"], org["is_central"], now_ts(), now_ts()),
        )
    org_map = {row["code"]: row["id"] for row in query_all("SELECT id, code FROM organizations")}
    for org in ORGANIZATIONS:
        if org["parent_code"]:
            execute("UPDATE organizations SET parent_id = ?, updated_at = ? WHERE code = ?", (org_map[org["parent_code"]], now_ts(), org["code"]))


def seed_roles_permissions() -> None:
    for code, name, description in PERMISSIONS:
        execute("INSERT OR IGNORE INTO permissions (code, name, description) VALUES (?, ?, ?)", (code, name, description))
    for role_name, description in ROLE_DESCRIPTIONS.items():
        execute("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", (role_name, description))
    role_map = {row["name"]: row["id"] for row in query_all("SELECT id, name FROM roles")}
    for role_name, permission_codes in ROLE_PERMISSIONS.items():
        for code in permission_codes:
            execute("INSERT OR IGNORE INTO role_permissions (role_id, permission_code) VALUES (?, ?)", (role_map[role_name], code))


def seed_default_users() -> None:
    roles = {row["name"]: row["id"] for row in query_all("SELECT id, name FROM roles")}
    orgs = {row["code"]: row["id"] for row in query_all("SELECT id, code FROM organizations")}
    for username, full_name, email, password, role_name, org_code in DEFAULT_USERS:
        if query_one("SELECT id FROM users WHERE username = ?", (username,)):
            continue
        execute(
            "INSERT INTO users (username, full_name, email, password_hash, role_id, organization_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (username, full_name, email, generate_password_hash(password), roles[role_name], orgs[org_code], now_ts(), now_ts()),
        )


def ensure_default_settings() -> None:
    defaults = {
        "app.default_classification": "INTERNAL",
        "reminder.schedule": "90,60,30,14,7,1,0,-1",
        "letter.numbering.pattern": "{org}/{year}/{sequence}",
        "email.integration.status": "NOT_CONFIGURED",
        "storage.provider": "LOCAL",
        "storage.root": str(STORAGE_DIR),
        "storage.max_file_size_mb": "50",
        "storage.allowed_extensions": ",".join(sorted(ALLOWED_EXTENSIONS)),
        "document.versioning.enabled": "1",
        "document.text_extraction.enabled": "1",
        "document.summary.enabled": "1",
        "document.summary.default_language": "id",
        "document.ocr.provider": "NOT_CONFIGURED",
        "document.summary.provider": "HEURISTIC_LOCAL",
        "password.min_length": "8",
        "password.require_uppercase": "1",
        "password.require_lowercase": "1",
        "password.require_digit": "1",
        "password.require_special": "0",
        "password.expiry_days": "90",
    }
    for key, value in defaults.items():
        execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)", (key, value, now_ts()))


def ensure_default_company_settings() -> None:
    execute(
        """
        INSERT OR IGNORE INTO company_settings (
            id, company_name, short_name, company_code, address, city, province, postal_code, phone, email, website, tax_number,
            logo_storage_path, letter_number_format, letter_prefix, date_format, month_format, active_year, start_number, reset_policy,
            official_signature, official_name, official_position, use_organization_code_in_letters,
            password_min_length, password_require_uppercase, password_require_lowercase, password_require_digit,
            password_require_special, password_expiry_days, created_at, updated_at
        ) VALUES (
            1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            "Bhakti Husada Group",
            "Bhakti Husada",
            "RSBH",
            "Jl. Administrasi No. 1",
            "Jakarta",
            "DKI Jakarta",
            "10110",
            "0210000000",
            "admin@aisecretary.local",
            "https://aisecretary.local",
            "",
            "{NOMOR}/{KATEGORI}/{KODE_PERUSAHAAN}/{BULAN_ROMAWI}/{TAHUN}",
            "",
            "DD MMM YYYY",
            "ROMAN",
            str(date.today().year),
            1,
            "YEARLY",
            "",
            "Direktur Utama",
            "Direktur",
            1,
            8,
            1,
            1,
            1,
            0,
            90,
            now_ts(),
            now_ts(),
        ),
    )


def seed_letter_categories() -> None:
    samples = [
        ("SK", "Surat Keputusan"),
        ("SU", "Surat Undangan"),
        ("SM", "Surat Masuk"),
        ("SKL", "Surat Keluar"),
        ("SP", "Surat Permohonan"),
        ("ST", "Surat Tugas"),
        ("ND", "Nota Dinas"),
    ]
    default_format = "{NOMOR}/{KATEGORI}/{KODE_PERUSAHAAN}/{BULAN_ROMAWI}/{TAHUN}"
    for code, name in samples:
        execute(
            """
            INSERT OR IGNORE INTO letter_categories (
                code, name, number_format, start_number, reset_policy, is_active, description, created_at, updated_at
            ) VALUES (?, ?, ?, 1, 'YEARLY', 1, '', ?, ?)
            """,
            (code, name, default_format, now_ts(), now_ts()),
        )


def backfill_organization_defaults() -> None:
    pt_org = query_one("SELECT id FROM organizations WHERE code = 'PT'")
    if not pt_org:
        return
    pt_id = pt_org["id"]
    for table in ["users", "agenda_entries", "tasks", "reminders", "contacts", "letters", "dispositions", "documents", "meetings", "meeting_minutes"]:
        if "organization_id" in {row["name"] for row in query_all(f"PRAGMA table_info({table})")}:
            execute(f"UPDATE {table} SET organization_id = ? WHERE organization_id IS NULL", (pt_id,))
    if "created_by" in {row["name"] for row in query_all("PRAGMA table_info(documents)")}: 
        execute("UPDATE documents SET created_by = COALESCE(created_by, owner_id, 1) WHERE created_by IS NULL")
    if "updated_by" in {row["name"] for row in query_all("PRAGMA table_info(documents)")}: 
        execute("UPDATE documents SET updated_by = COALESCE(updated_by, created_by, owner_id, 1) WHERE updated_by IS NULL")
    if "created_by" in {row["name"] for row in query_all("PRAGMA table_info(meetings)")}: 
        execute("UPDATE meetings SET created_by = COALESCE(created_by, organizer_id, 1) WHERE created_by IS NULL")
    if "updated_by" in {row["name"] for row in query_all("PRAGMA table_info(meetings)")}: 
        execute("UPDATE meetings SET updated_by = COALESCE(updated_by, created_by, organizer_id, 1) WHERE updated_by IS NULL")


def seed_sample_data() -> None:
    if query_one("SELECT id FROM contracts LIMIT 1"):
        return
    orgs = {row["code"]: row["id"] for row in query_all("SELECT id, code FROM organizations")}
    users = {row["username"]: row["id"] for row in query_all("SELECT id, username FROM users")}
    now = datetime.now().replace(second=0, microsecond=0)
    execute("INSERT INTO vendors (organization_id, name, company, contact_person, email, phone, address, category, compliance_status, notes, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSCKR"], "Vendor Medika", "PT Vendor Medika", "Ratna Vendor", "vendor@medika.local", "081200001", "Bekasi", "Medical", "GOOD", "Vendor alat medis utama.", users["sekretaris.cikarang"], users["sekretaris.cikarang"], now_ts(), now_ts()))
    execute("INSERT INTO documents (organization_id, title, document_number, document_type, category, department, document_date, effective_date, expiry_date, status, file_path, description, owner_id, pic_user_id, vendor_name, tags, version, confidentiality, central_monitoring_required, central_status, original_document_id, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSCKR"], "Izin Operasional RS Cikarang", "DOC-RSCKR-001", "PERMIT", "Perizinan", "Legal", date.today().isoformat(), date.today().isoformat(), (date.today() + timedelta(days=25)).isoformat(), "Active", "docs/izin-rsckr.pdf", "Dokumen izin operasional utama.", users["sekretaris.cikarang"], users["sekretaris.cikarang"], "Dinas Kesehatan", "izin,operasional", "v1.0", "CONFIDENTIAL", 1, "SENT TO HO", None, users["sekretaris.cikarang"], users["sekretaris.cikarang"], now_ts(), now_ts()))
    execute("INSERT INTO documents (organization_id, title, document_number, document_type, category, department, document_date, effective_date, expiry_date, status, file_path, description, owner_id, pic_user_id, vendor_name, tags, version, confidentiality, central_monitoring_required, central_status, original_document_id, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSPWK"], "Sertifikat Lingkungan RS Purwakarta", "DOC-RSPWK-002", "CERTIFICATE", "Sertifikat", "HSE", date.today().isoformat(), date.today().isoformat(), (date.today() + timedelta(days=70)).isoformat(), "Active", "docs/sertifikat-rspwk.pdf", "Sertifikat lingkungan aktif.", users["sekretaris.purwakarta"], users["sekretaris.purwakarta"], "Pemda", "sertifikat,lingkungan", "v1.1", "INTERNAL", 1, "RECEIVED BY HO", None, users["sekretaris.purwakarta"], users["sekretaris.purwakarta"], now_ts(), now_ts()))
    execute("INSERT INTO contracts (organization_id, contract_number, title, kind, partner_name, vendor_name, start_date, end_date, contract_value, pic_user_id, status, renewal_status, notes, file_document_id, central_monitoring_required, central_status, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSCKR"], "MOU-CKR-2026-001", "Kerja Sama CT Scan", "MOU", "PT Diagnostika", "Vendor Medika", date.today().isoformat(), (date.today() + timedelta(days=18)).isoformat(), "250000000", users["sekretaris.cikarang"], "EXPIRING", "PLANNED", "Perlu pembahasan renewal.", 1, 1, "MONITORED", users["sekretaris.cikarang"], users["sekretaris.cikarang"], now_ts(), now_ts()))
    execute("INSERT INTO contracts (organization_id, contract_number, title, kind, partner_name, vendor_name, start_date, end_date, contract_value, pic_user_id, status, renewal_status, notes, file_document_id, central_monitoring_required, central_status, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSPWK"], "CTR-PWK-2026-003", "Kontrak Laundry Medis", "CONTRACT", "PT Bersih Sehat", "PT Bersih Sehat", date.today().isoformat(), (date.today() - timedelta(days=3)).isoformat(), "90000000", users["sekretaris.purwakarta"], "EXPIRED", "NONE", "Belum diperpanjang.", 2, 1, "SENT TO HO", users["sekretaris.purwakarta"], users["sekretaris.purwakarta"], now_ts(), now_ts()))
    execute("INSERT INTO permits (organization_id, permit_name, permit_number, permit_type, issuer, issue_date, effective_date, expiry_date, pic_user_id, status, renewal_status, notes, file_document_id, central_monitoring_required, central_status, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSCKR"], "Izin Operasional Utama", "IZN-CKR-001", "Operational", "Dinas Kesehatan", date.today().isoformat(), date.today().isoformat(), (date.today() + timedelta(days=7)).isoformat(), users["sekretaris.cikarang"], "EXPIRING", "IN PROGRESS", "Perpanjangan sedang diproses.", 1, 1, "REVIEWED", users["sekretaris.cikarang"], users["sekretaris.cikarang"], now_ts(), now_ts()))
    execute("INSERT INTO permits (organization_id, permit_name, permit_number, permit_type, issuer, issue_date, effective_date, expiry_date, pic_user_id, status, renewal_status, notes, file_document_id, central_monitoring_required, central_status, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSPWK"], "Sertifikat Instalasi", "IZN-PWK-010", "Certificate", "Kementerian", date.today().isoformat(), date.today().isoformat(), (date.today() + timedelta(days=95)).isoformat(), users["sekretaris.purwakarta"], "REGISTERED", "NONE", "Masih aman.", 2, 1, "MONITORED", users["sekretaris.purwakarta"], users["sekretaris.purwakarta"], now_ts(), now_ts()))
    execute("INSERT INTO assets (organization_id, asset_code, name, category, location, vendor_name, purchase_date, warranty_expiry, maintenance_due, status, notes, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSCKR"], "AST-CT-001", "CT Scan 64 Slice", "Medical", "Radiologi", "Vendor Medika", date.today().isoformat(), (date.today() + timedelta(days=45)).isoformat(), (date.today() + timedelta(days=20)).isoformat(), "ACTIVE", "Perlu monitoring warranty.", users["sekretaris.cikarang"], users["sekretaris.cikarang"], now_ts(), now_ts()))
    execute("INSERT INTO letters (organization_id, target_organization_id, direction, letter_number, subject, correspondent, letter_date, status, priority, summary, follow_up, template_name, body, signer, attachment_path, is_tembusan_required, central_status, classification, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSCKR"], orgs["PT"], "incoming", "SM-RSCKR-001", "Undangan review kerja sama", "PT Diagnostika", date.today().isoformat(), "Received", "High", "Undangan review MOU CT Scan.", "Perlu disposisi ke Owner.", "", "", "", "", 1, "SENT TO HO", "CONFIDENTIAL", users["sekretaris.cikarang"], users["sekretaris.cikarang"], now_ts(), now_ts()))
    execute("INSERT INTO agenda_entries (organization_id, title, category, description, start_at, end_at, location, owner_id, classification, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["PT"], "Executive Compliance Review", "Board", "Review tembusan dan dokumen yang akan expired.", dt_value(now + timedelta(days=1, hours=2)), dt_value(now + timedelta(days=1, hours=3)), "Ruang Rapat Pusat", users["owner"], "CONFIDENTIAL", users["sekretaris.pt"], users["sekretaris.pt"], now_ts(), now_ts()))
    execute("INSERT INTO tasks (organization_id, title, description, status, priority, due_date, assigned_to, related_type, related_id, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["RSCKR"], "Renewal MOU CT Scan", "Koordinasikan draft perpanjangan dengan vendor dan PT.", "IN PROGRESS", "CRITICAL", dt_value(now + timedelta(days=5)), users["sekretaris.cikarang"], "CONTRACT", 1, users["sekretaris.cikarang"], users["sekretaris.cikarang"], now_ts(), now_ts()))
    execute("INSERT INTO reminders (organization_id, title, message, remind_at, status, user_id, related_type, related_id, days_remaining, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["PT"], "Review permit RS Cikarang", "Permit utama akan expired dalam 7 hari.", dt_value(now + timedelta(days=1)), "Scheduled", users["sekretaris.pt"], "PERMIT", 1, 7, now_ts(), now_ts()))
    execute("INSERT INTO contacts (organization_id, full_name, company, position, email, phone, address, notes, visibility, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["PT"], "Ratna Wulandari", "PT Diagnostika", "Corporate Secretary", "ratna@diagnostika.local", "081211112222", "Jakarta", "PIC untuk MOU CT Scan.", "Shared", users["sekretaris.pt"], users["sekretaris.pt"], now_ts(), now_ts()))
    execute("INSERT INTO meetings (organization_id, title, agenda, start_at, end_at, location, organizer_id, participants, attachment_path, status, notes, created_by, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (orgs["PT"], "Rapat Tinjau Tembusan RS", "Membahas dokumen RS yang belum ditembuskan dan yang akan expired.", dt_value(now + timedelta(days=2, hours=1)), dt_value(now + timedelta(days=2, hours=2)), "Board Room", users["sekretaris.pt"], "owner, sekretaris.pt, sekretaris.cikarang, sekretaris.purwakarta", "", "Scheduled", "Bahas compliance mingguan.", users["sekretaris.pt"], users["sekretaris.pt"], now_ts(), now_ts()))
    execute("INSERT INTO meeting_minutes (organization_id, meeting_id, discussion, decisions, action_items, recorded_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (orgs["PT"], 1, "Pembahasan monitoring expiry dan kelengkapan tembusan.", "PT akan menindaklanjuti kontrak expired RS Purwakarta.", "Sekretaris RS Purwakarta menyiapkan rencana renewal.", users["sekretaris.pt"], now_ts(), now_ts()))


def get_user_with_permissions(user_id: int | None) -> dict[str, Any] | None:
    if not user_id:
        return None
    user = query_one(
        """
        SELECT u.id, u.username, u.full_name, u.email, u.phone, u.department, u.position, u.is_active,
               u.organization_id, u.must_change_password, u.last_login_at, u.created_at, u.updated_at,
               r.id AS role_id, r.name AS role_name,
               org.name AS organization_name, org.code AS organization_code, org.kind AS organization_kind, org.is_central
        FROM users u
        JOIN roles r ON r.id = u.role_id
        LEFT JOIN organizations org ON org.id = u.organization_id
        WHERE u.id = ?
        """,
        (user_id,),
    )
    if not user:
        return None
    user["permissions"] = {row["permission_code"] for row in query_all("SELECT permission_code FROM role_permissions WHERE role_id = ?", (user["role_id"],))}
    return user


def build_navigation(user: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not user:
        return []
    items = []
    for item in NAV_ITEMS:
        if user_has_permission(user, item["permission"]):
            kwargs = {"module": item["module"]} if "module" in item else {}
            items.append({**item, "url": url_for(item["endpoint"], **kwargs)})
    return items


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.current_user:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def permission_required(code: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            ensure_permission(code)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def ensure_permission(code: str) -> None:
    if not user_has_permission(g.current_user, code):
        abort(403)


def user_has_permission(user: dict[str, Any] | None, code: str) -> bool:
    return bool(user and user.get("is_active") and code in user.get("permissions", set()))


def is_superuser(user: dict[str, Any]) -> bool:
    return user["role_name"] == "Administrator"


def is_owner(user: dict[str, Any]) -> bool:
    return user["role_name"] in {"OWNER / MANAGEMENT PT", "Manager"}


def is_hq_secretary(user: dict[str, Any]) -> bool:
    return user["role_name"] in {"SEKRETARIS KANTOR PUSAT", "Secretary"}


def is_rs_secretary(user: dict[str, Any]) -> bool:
    return user["role_name"] in {"SEKRETARIS RS", "User"}


def is_admin_it(user: dict[str, Any]) -> bool:
    return user["role_name"] == "ADMIN IT"


def can_manage_any_org(user: dict[str, Any]) -> bool:
    return not is_admin_it(user)


def visible_organizations(user: dict[str, Any]) -> list[dict[str, Any]]:
    if is_superuser(user) or is_owner(user) or is_hq_secretary(user):
        return query_all("SELECT id, name FROM organizations ORDER BY id")
    return query_all("SELECT id, name FROM organizations WHERE id = ?", (user["organization_id"],))


def permitted_organization_ids(user: dict[str, Any], module: str, for_manage: bool = False) -> set[int]:
    if is_superuser(user):
        return {row["id"] for row in query_all("SELECT id FROM organizations")}
    if is_admin_it(user):
        return set()
    if not for_manage and (is_owner(user) or is_hq_secretary(user)):
        if is_owner(user):
            return {row["id"] for row in query_all("SELECT id FROM organizations")}
        if module in MONITORED_MODULES or module in {"incoming_letters", "outgoing_letters"}:
            return {row["id"] for row in query_all("SELECT id FROM organizations")}
    return {user["organization_id"]}


def can_access_row(module: str, row: dict[str, Any], user: dict[str, Any]) -> bool:
    if is_superuser(user):
        return True
    if is_admin_it(user):
        return False
    row_org_id = row.get("organization_id")
    if row_org_id == user["organization_id"]:
        return True
    if is_owner(user):
        return True
    if is_hq_secretary(user):
        if module in MONITORED_MODULES and int(row.get("central_monitoring_required") or 0) == 1:
            return True
        if module in {"incoming_letters", "outgoing_letters"} and int(row.get("is_tembusan_required") or 0) == 1:
            return True
    return False


def can_manage_record(module: str, row: dict[str, Any], user: dict[str, Any]) -> bool:
    if is_superuser(user):
        return True
    if is_admin_it(user):
        return False
    return row.get("organization_id") == user["organization_id"]


def ensure_record_access(module: str, row: dict[str, Any], user: dict[str, Any]) -> None:
    if not can_access_row(module, row, user) or not can_manage_record(module, row, user):
        abort(403)


def get_accessible_rows(module: str, user: dict[str, Any]) -> list[dict[str, Any]]:
    config = MODULES[module]
    rows = query_all(f"{config['base_query']} ORDER BY {config['alias']}.id DESC")
    return [row for row in rows if can_access_row(module, row, user)]


def get_module_record(module: str, record_id: int) -> dict[str, Any] | None:
    config = MODULES[module]
    suffix = f" AND {config['alias']}.id = ?" if "WHERE" in config["base_query"].upper() else f" WHERE {config['alias']}.id = ?"
    return query_one(f"{config['base_query']}{suffix}", (record_id,))


def prepare_fields(config: dict[str, Any], user: dict[str, Any], row: dict[str, Any] | None) -> list[dict[str, Any]]:
    fields = []
    for field in config["fields"]:
        if row and row.get(field["name"]) is not None:
            value = str(row.get(field["name"]))
        elif field["name"] == "organization_id":
            value = str(user["organization_id"])
        elif field["name"] in {"owner_id", "pic_user_id", "user_id", "organizer_id", "recorded_by", "from_user_id"}:
            value = str(user["id"])
        elif field["name"] == "target_organization_id" and is_rs_secretary(user):
            pt = query_one("SELECT id FROM organizations WHERE code = 'PT'")
            value = str(pt["id"]) if pt else ""
        elif field["name"] == "central_monitoring_required":
            value = "1" if is_rs_secretary(user) else "0"
        elif field["name"] == "is_tembusan_required":
            value = "1" if is_rs_secretary(user) else "0"
        elif field["name"] == "central_status":
            value = "SENT TO HO" if is_rs_secretary(user) else "CREATED"
        elif field["name"] == "classification":
            value = "INTERNAL"
        elif field["name"] == "confidentiality":
            value = "INTERNAL"
        elif field["name"] == "letter_number":
            value = ""
        elif field["name"] == "renewal_status":
            value = "NONE"
        elif field["name"] == "status":
            value = field.get("options", [""])[0]
        else:
            value = ""
        fields.append({**field, "value": value, "options": resolve_field_options(field, user)})
    return fields


def resolve_field_options(field: dict[str, Any], user: dict[str, Any]) -> list[dict[str, str]]:
    if "options" in field:
        return [{"value": str(option), "label": str(option)} for option in field["options"]]
    if field.get("options_source") == "organizations":
        return [{"value": str(row["id"]), "label": row["name"]} for row in visible_organizations(user)]
    if field.get("options_source") == "users":
        rows = query_all("SELECT u.id, u.full_name, org.name AS organization_name, u.organization_id FROM users u LEFT JOIN organizations org ON org.id = u.organization_id WHERE u.is_active = 1 ORDER BY org.id, u.full_name")
        allowed = permitted_organization_ids(user, "agenda")
        return [{"value": str(row["id"]), "label": f"{row['full_name']} ({row['organization_name']})"} for row in rows if row["organization_id"] in allowed]
    if field.get("options_source") == "letter_categories":
        rows = query_all("SELECT id, code, name, is_active FROM letter_categories ORDER BY is_active DESC, name")
        return [{"value": str(row["id"]), "label": f"{row['code']} - {row['name']}"} for row in rows if row["is_active"]]
    if field.get("options_source") == "letters":
        rows = get_accessible_rows("incoming_letters", user) + get_accessible_rows("outgoing_letters", user)
        return [{"value": str(row["id"]), "label": f"{row['letter_number']} - {row['subject']}"} for row in rows]
    if field.get("options_source") == "meetings":
        return [{"value": str(row["id"]), "label": f"{row['title']} ({format_datetime(row['start_at'])})"} for row in get_accessible_rows("meetings", user)]
    return []


def save_module(module: str, record_id: int | None, form_data, user: dict[str, Any]) -> int | bool:
    config = MODULES[module]
    existing = get_module_record(module, record_id) if record_id else None
    if existing and not can_manage_record(module, existing, user):
        abort(403)
    values: dict[str, Any] = {}
    for field in config["fields"]:
        raw_value = form_data.get(field["name"], "").strip()
        if field.get("required") and raw_value == "":
            flash(f"Field {field['label']} wajib diisi.", "error")
            return False
        values[field["name"]] = normalize_field_value(field["type"], raw_value)
    organization_id = int(values.get("organization_id") or (existing.get("organization_id") if existing else user["organization_id"]))
    if organization_id not in permitted_organization_ids(user, module, for_manage=True):
        flash("Anda tidak boleh menyimpan data untuk organization tersebut.", "error")
        return False
    values["organization_id"] = organization_id
    if module in MONITORED_MODULES and organization_id != query_one("SELECT id FROM organizations WHERE code = 'PT'")["id"]:
        values["central_monitoring_required"] = int(values.get("central_monitoring_required") or 0)
        if values["central_monitoring_required"] == 1 and not values.get("central_status"):
            values["central_status"] = "SENT TO HO"
    if module in {"incoming_letters", "outgoing_letters"}:
        values["is_tembusan_required"] = int(values.get("is_tembusan_required") or 0)
        if values["is_tembusan_required"] == 1 and not values.get("central_status"):
            values["central_status"] = "SENT TO HO"
        if not prepare_letter_numbering(values, existing, user):
            return False
    values.update(config.get("fixed_values", {}))
    stamp_common_values(module, values, existing, user)
    if record_id:
        assignments = ", ".join(f"{column} = ?" for column in values)
        execute(f"UPDATE {config['table']} SET {assignments} WHERE id = ?", (*values.values(), record_id))
        log_action("UPDATE", module, str(record_id), organization_id, f"{config['singular']} diperbarui.")
        return True

    columns = ", ".join(values.keys())
    placeholders = ", ".join("?" for _ in values)
    created_id = execute(f"INSERT INTO {config['table']} ({columns}) VALUES ({placeholders})", tuple(values.values()), True)
    log_action("CREATE", module, str(created_id), organization_id, f"{config['singular']} dibuat.")
    return int(created_id or 0)


def stamp_common_values(module: str, values: dict[str, Any], existing: dict[str, Any] | None, user: dict[str, Any]) -> None:
    values["updated_at"] = now_ts()
    if "updated_by" in table_columns(MODULES[module]["table"]):
        values["updated_by"] = user["id"]
    if not existing:
        values["created_at"] = now_ts()
        if "created_by" in table_columns(MODULES[module]["table"]):
            values["created_by"] = user["id"]
    elif "created_by" in table_columns(MODULES[module]["table"]):
        values["created_by"] = existing.get("created_by", user["id"])


def table_columns(table: str) -> set[str]:
    return {row["name"] for row in query_all(f"PRAGMA table_info({table})")}


def normalize_field_value(field_type: str, value: str) -> Any:
    if value == "":
        return None
    if field_type == "select" and value.isdigit():
        return int(value)
    return value


def parse_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def get_company_settings() -> dict[str, Any]:
    row = query_one("SELECT * FROM company_settings WHERE id = 1")
    return row or {
        "company_name": "",
        "short_name": "",
        "company_code": "ORG",
        "letter_number_format": "{NOMOR}/{KATEGORI}/{KODE_PERUSAHAAN}/{BULAN_ROMAWI}/{TAHUN}",
        "reset_policy": "YEARLY",
        "start_number": 1,
        "use_organization_code_in_letters": 1,
        "password_min_length": 8,
        "password_require_uppercase": 1,
        "password_require_lowercase": 1,
        "password_require_digit": 1,
        "password_require_special": 0,
        "password_expiry_days": 90,
    }


def get_password_policy() -> dict[str, Any]:
    company = get_company_settings()
    return {
        "min_length": int(company.get("password_min_length") or 8),
        "require_uppercase": int(company.get("password_require_uppercase") or 0),
        "require_lowercase": int(company.get("password_require_lowercase") or 0),
        "require_digit": int(company.get("password_require_digit") or 0),
        "require_special": int(company.get("password_require_special") or 0),
        "expiry_days": int(company.get("password_expiry_days") or 90),
    }


def validate_password_policy(password: str, *, username: str = "", email: str = "") -> str | None:
    policy = get_password_policy()
    if len(password) < policy["min_length"]:
        return f"Password minimal {policy['min_length']} karakter."
    if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
        return "Password wajib mengandung huruf besar."
    if policy["require_lowercase"] and not re.search(r"[a-z]", password):
        return "Password wajib mengandung huruf kecil."
    if policy["require_digit"] and not re.search(r"\d", password):
        return "Password wajib mengandung angka."
    if policy["require_special"] and not re.search(r"[^A-Za-z0-9]", password):
        return "Password wajib mengandung karakter khusus."
    lowered = password.lower()
    if username and username.lower() in lowered:
        return "Password tidak boleh mengandung username."
    if email and email.split("@")[0].lower() in lowered:
        return "Password tidak boleh mengandung bagian email."
    return None


def is_password_expired(user: dict[str, Any]) -> bool:
    expiry_days = get_password_policy()["expiry_days"]
    if expiry_days <= 0:
        return False
    reference = user.get("updated_at") or user.get("created_at") or user.get("last_login_at")
    if not reference:
        return False
    try:
        changed_at = datetime.fromisoformat(str(reference))
    except ValueError:
        return False
    return (datetime.now() - changed_at).days >= expiry_days


def password_days_remaining(user: dict[str, Any]) -> int | None:
    expiry_days = get_password_policy()["expiry_days"]
    if expiry_days <= 0:
        return None
    reference = user.get("updated_at") or user.get("created_at") or user.get("last_login_at")
    if not reference:
        return None
    try:
        changed_at = datetime.fromisoformat(str(reference))
    except ValueError:
        return None
    return max(0, expiry_days - (datetime.now() - changed_at).days)


def prepare_letter_numbering(values: dict[str, Any], existing: dict[str, Any] | None, user: dict[str, Any]) -> bool:
    category_id = parse_int(values.get("letter_category_id"))
    if not category_id:
        flash("Kategori surat wajib dipilih.", "error")
        return False
    category = query_one("SELECT * FROM letter_categories WHERE id = ?", (category_id,))
    if not category:
        flash("Kategori surat tidak ditemukan.", "error")
        return False
    if not category["is_active"] and not (existing and existing.get("letter_category_id") == category_id):
        flash("Kategori surat nonaktif tidak dapat digunakan.", "error")
        return False

    status = str(values.get("status") or "").strip()
    current_number = (existing or {}).get("letter_number") or ""
    current_is_final = int((existing or {}).get("is_number_final") or 0)
    values["letter_number"] = current_number
    values["is_number_final"] = current_is_final

    if status == "Draft":
        values["letter_number"] = current_number if current_is_final else ""
        values["is_number_final"] = current_is_final
        return ensure_letter_number_unique(values["letter_number"], existing["id"] if existing else None)

    if current_is_final and current_number:
        return ensure_letter_number_unique(current_number, existing["id"] if existing else None)

    generated = reserve_letter_number(
        organization_id=int(values["organization_id"]),
        category_id=category_id,
        letter_date=str(values.get("letter_date") or date.today().isoformat()),
    )
    values["letter_number"] = generated
    values["is_number_final"] = 1
    if status == "Cancelled":
        values["is_number_final"] = 1
    return ensure_letter_number_unique(generated, existing["id"] if existing else None)


def ensure_letter_number_unique(letter_number: str, current_id: int | None) -> bool:
    if not letter_number.strip():
        return True
    sql = "SELECT id FROM letters WHERE letter_number = ?"
    params: tuple[Any, ...] = (letter_number,)
    if current_id:
        sql += " AND id != ?"
        params = (letter_number, current_id)
    if query_one(sql, params):
        flash("Nomor surat sudah digunakan.", "error")
        return False
    return True


def reserve_letter_number(*, organization_id: int, category_id: int, letter_date: str) -> str:
    category = query_one("SELECT * FROM letter_categories WHERE id = ?", (category_id,))
    organization = query_one("SELECT * FROM organizations WHERE id = ?", (organization_id,))
    company = get_company_settings()
    if not category or not organization:
        raise DocumentProcessingError("Data kategori surat atau organisasi tidak ditemukan.")
    target_date = safe_date(letter_date) or date.today()
    reset_policy = category.get("reset_policy") or company.get("reset_policy") or "YEARLY"
    period_key = build_letter_period_key(target_date, reset_policy)
    sequence_row = query_one(
        "SELECT * FROM letter_number_sequences WHERE category_id = ? AND organization_id = ? AND period_key = ?",
        (category_id, organization_id, period_key),
    )
    start_number = int(category.get("start_number") or company.get("start_number") or 1)
    next_number = start_number if not sequence_row else int(sequence_row["current_number"]) + 1
    letter_number = render_letter_number(next_number, category, organization, company, target_date)
    if sequence_row:
        execute(
            "UPDATE letter_number_sequences SET current_number = ?, last_generated_number = ?, updated_at = ? WHERE id = ?",
            (next_number, letter_number, now_ts(), sequence_row["id"]),
        )
    else:
        execute(
            "INSERT INTO letter_number_sequences (category_id, organization_id, period_key, current_number, last_generated_number, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (category_id, organization_id, period_key, next_number, letter_number, now_ts()),
        )
    return letter_number


def build_letter_period_key(target_date: date, reset_policy: str) -> str:
    policy = (reset_policy or "YEARLY").upper()
    if policy == "MONTHLY":
        return f"{target_date.year}-{target_date.month:02d}"
    if policy == "NEVER":
        return "GLOBAL"
    return str(target_date.year)


def render_letter_number(sequence_number: int, category: dict[str, Any], organization: dict[str, Any], company: dict[str, Any], target_date: date) -> str:
    format_pattern = category.get("number_format") or company.get("letter_number_format") or "{NOMOR}/{KATEGORI}/{KODE_PERUSAHAAN}/{BULAN_ROMAWI}/{TAHUN}"
    company_code = organization["code"] if int(company.get("use_organization_code_in_letters") or 1) else (company.get("company_code") or organization["code"])
    tokens = {
        "{NOMOR}": f"{sequence_number:03d}",
        "{KATEGORI}": category["code"],
        "{KODE_PERUSAHAAN}": company_code,
        "{BULAN_ROMAWI}": to_roman_month(target_date.month),
        "{BULAN}": f"{target_date.month:02d}",
        "{TAHUN}": str(target_date.year),
    }
    output = format_pattern
    for token, value in tokens.items():
        output = output.replace(token, value)
    prefix = str(company.get("letter_prefix") or "").strip()
    return f"{prefix}{output}" if prefix else output


def to_roman_month(month: int) -> str:
    numerals = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"]
    return numerals[max(1, min(month, 12)) - 1]


def safe_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def save_letter_category(category_id: int | None, form_data) -> bool:
    code = form_data.get("code", "").strip().upper()
    name = form_data.get("name", "").strip()
    number_format = form_data.get("number_format", "").strip() or "{NOMOR}/{KATEGORI}/{KODE_PERUSAHAAN}/{BULAN_ROMAWI}/{TAHUN}"
    start_number = parse_int(form_data.get("start_number")) or 1
    reset_policy = form_data.get("reset_policy", "YEARLY").strip().upper()
    is_active = 1 if form_data.get("is_active", "on") == "on" else 0
    description = form_data.get("description", "").strip()
    if not code or not name:
        flash("Kode dan nama kategori wajib diisi.", "error")
        return False
    if not re.fullmatch(r"[A-Z0-9]{2,10}", code):
        flash("Kode kategori hanya boleh huruf/angka 2-10 karakter.", "error")
        return False
    if any(token not in {"{NOMOR}", "{KATEGORI}", "{KODE_PERUSAHAAN}", "{BULAN_ROMAWI}", "{BULAN}", "{TAHUN}"} for token in re.findall(r"\{[A-Z_]+\}", number_format)):
        flash("Format nomor surat mengandung token yang tidak didukung.", "error")
        return False
    params = (code, name, number_format, start_number, reset_policy, is_active, description, now_ts())
    try:
        if category_id:
            before_payload = query_one("SELECT * FROM letter_categories WHERE id = ?", (category_id,))
            execute(
                "UPDATE letter_categories SET code = ?, name = ?, number_format = ?, start_number = ?, reset_policy = ?, is_active = ?, description = ?, updated_at = ? WHERE id = ?",
                (*params, category_id),
            )
            log_audit(g.current_user["id"], g.current_user["organization_id"], "UPDATE", "letter_category", category_id, code, "Kategori surat diperbarui.", before_data=json.dumps(before_payload), after_data=json.dumps({"code": code, "name": name, "reset_policy": reset_policy}))
            return True
        new_id = execute(
            "INSERT INTO letter_categories (code, name, number_format, start_number, reset_policy, is_active, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (code, name, number_format, start_number, reset_policy, is_active, description, now_ts(), now_ts()),
            True,
        )
        log_audit(g.current_user["id"], g.current_user["organization_id"], "CREATE", "letter_category", new_id, code, "Kategori surat ditambahkan.", after_data=json.dumps({"code": code, "name": name}))
        return True
    except sqlite3.IntegrityError:
        flash("Kode kategori atau nama kategori sudah digunakan.", "error")
        return False


def save_company_settings(form_data, logo_upload, current_settings: dict[str, Any]) -> bool:
    company_name = form_data.get("company_name", "").strip()
    short_name = form_data.get("short_name", "").strip()
    company_code = form_data.get("company_code", "").strip().upper()
    address = form_data.get("address", "").strip()
    city = form_data.get("city", "").strip()
    province = form_data.get("province", "").strip()
    postal_code = form_data.get("postal_code", "").strip()
    phone = form_data.get("phone", "").strip()
    email = form_data.get("email", "").strip()
    website = form_data.get("website", "").strip()
    tax_number = form_data.get("tax_number", "").strip()
    letter_number_format = form_data.get("letter_number_format", "").strip()
    letter_prefix = form_data.get("letter_prefix", "").strip()
    date_format = form_data.get("date_format", "").strip() or str(current_settings.get("date_format") or "DD MMM YYYY")
    month_format = form_data.get("month_format", "").strip() or str(current_settings.get("month_format") or "ROMAN")
    active_year = form_data.get("active_year", "").strip() or str(current_settings.get("active_year") or date.today().year)
    start_number = parse_int(form_data.get("start_number")) or 1
    reset_policy = form_data.get("reset_policy", "YEARLY").strip().upper()
    official_signature = form_data.get("official_signature", "").strip()
    official_name = form_data.get("official_name", "").strip()
    official_position = form_data.get("official_position", "").strip()
    use_org_code = 1 if form_data.get("use_organization_code_in_letters") == "on" else 0
    min_length = parse_int(form_data.get("password_min_length")) or 8
    require_upper = 1 if form_data.get("password_require_uppercase") == "on" else 0
    require_lower = 1 if form_data.get("password_require_lowercase") == "on" else 0
    require_digit = 1 if form_data.get("password_require_digit") == "on" else 0
    require_special = 1 if form_data.get("password_require_special") == "on" else 0
    expiry_days = parse_int(form_data.get("password_expiry_days")) or 90

    if not company_name or not company_code or not letter_number_format:
        flash("Nama perusahaan, kode perusahaan, dan format nomor surat wajib diisi.", "error")
        return False
    if any(token not in {"{NOMOR}", "{KATEGORI}", "{KODE_PERUSAHAAN}", "{BULAN_ROMAWI}", "{BULAN}", "{TAHUN}"} for token in re.findall(r"\{[A-Z_]+\}", letter_number_format)):
        flash("Format nomor surat mengandung token yang tidak didukung.", "error")
        return False

    logo_storage_path = current_settings.get("logo_storage_path")
    if logo_upload and (logo_upload.filename or "").strip():
        saved_logo = save_company_logo(logo_upload)
        if logo_storage_path and logo_storage_path != saved_logo:
            delete_company_logo(logo_storage_path)
        logo_storage_path = saved_logo

    before_payload = json.dumps(current_settings, default=str)
    execute(
        """
        UPDATE company_settings
        SET company_name = ?, short_name = ?, company_code = ?, address = ?, city = ?, province = ?, postal_code = ?, phone = ?, email = ?, website = ?, tax_number = ?,
            logo_storage_path = ?, letter_number_format = ?, letter_prefix = ?, date_format = ?, month_format = ?, active_year = ?, start_number = ?, reset_policy = ?,
            official_signature = ?, official_name = ?, official_position = ?, use_organization_code_in_letters = ?,
            password_min_length = ?, password_require_uppercase = ?, password_require_lowercase = ?, password_require_digit = ?, password_require_special = ?, password_expiry_days = ?, updated_at = ?
        WHERE id = 1
        """,
        (
            company_name, short_name, company_code, address, city, province, postal_code, phone, email, website, tax_number,
            logo_storage_path, letter_number_format, letter_prefix, date_format, month_format, active_year, start_number, reset_policy,
            official_signature, official_name, official_position, use_org_code,
            min_length, require_upper, require_lower, require_digit, require_special, expiry_days, now_ts(),
        ),
    )
    log_audit(g.current_user["id"], g.current_user["organization_id"], "UPDATE", "company_settings", 1, company_name, "Pengaturan perusahaan diperbarui.", before_data=before_payload, after_data=json.dumps({"company_code": company_code, "reset_policy": reset_policy, "password_min_length": min_length}))
    return True


def save_company_logo(upload) -> str:
    filename = sanitize_filename(upload.filename or "")
    extension = Path(filename).suffix.lower()
    if extension not in {".png", ".jpg", ".jpeg"}:
        raise DocumentProcessingError("Logo hanya boleh berformat PNG atau JPG.")
    data = upload.stream.read()
    if len(data) == 0:
        raise DocumentProcessingError("File logo kosong.")
    mime_type = sniff_mime_type(filename, data)
    if mime_type not in {"image/png", "image/jpeg"}:
        raise DocumentProcessingError("Format logo tidak valid.")
    branding_root = Path(current_app().config["STORAGE_ROOT"]) / "branding"
    branding_root.mkdir(parents=True, exist_ok=True)
    target = branding_root / f"company-logo{extension}"
    target.write_bytes(data)
    return str(Path("branding") / target.name)


def resolve_company_logo_path(storage_path: str | None) -> Path | None:
    if not storage_path:
        return None
    path = (Path(current_app().config["STORAGE_ROOT"]) / storage_path).resolve()
    root = Path(current_app().config["STORAGE_ROOT"]).resolve()
    if str(path).startswith(str(root)):
        return path
    return None


def delete_company_logo(storage_path: str | None) -> None:
    path = resolve_company_logo_path(storage_path)
    if path and path.exists():
        path.unlink()


def storage_service() -> LocalStorageService:
    return LocalStorageService(Path(current_app().config["STORAGE_ROOT"]), int(current_app().config["DOCUMENT_MAX_FILE_SIZE"]))


def text_extraction_service() -> TextExtractionService:
    return TextExtractionService()


def summary_service() -> SummaryService:
    return SummaryService()


def normalize_related_type(value: str) -> str:
    return value.strip().upper()


def collect_document_upload_values(
    form_data,
    user: dict[str, Any],
    related_context: dict[str, Any] | None,
    document_row: dict[str, Any] | None = None,
) -> dict[str, str]:
    values: dict[str, str] = {}
    fields = prepare_fields(MODULES["documents"], user, document_row)
    for field in fields:
        if field["name"] == "file_path":
            continue
        default = field["value"]
        if document_row and field["name"] in {"title", "document_number", "document_type", "category", "department", "document_date", "effective_date", "expiry_date", "status", "owner_id", "pic_user_id", "vendor_name", "tags", "version", "confidentiality", "central_monitoring_required", "central_status", "description", "organization_id"}:
            default = str(document_row.get(field["name"]) or default or "")
        values[field["name"]] = form_data.get(field["name"], default or "")
    if related_context:
        values["organization_id"] = values.get("organization_id") or str(related_context["organization_id"])
        if not values.get("title"):
            values["title"] = related_context["item_label"]
    values["generate_summary"] = form_data.get("generate_summary", "1")
    values["summary_language"] = form_data.get("summary_language", current_app().config["DEFAULT_SUMMARY_LANGUAGE"])
    values["allow_duplicate"] = form_data.get("allow_duplicate", "0")
    return values


def get_related_upload_context(related_type: str, related_id: int | None, user: dict[str, Any]) -> dict[str, Any] | None:
    if not related_type or related_id is None or related_type not in RELATED_UPLOAD_TARGETS:
        return None
    config = RELATED_UPLOAD_TARGETS[related_type]
    row = get_module_record(config["module"], related_id)
    if not row or not can_manage_record(config["module"], row, user):
        abort(403)
    label_field = config["label_field"]
    return {
        "type": related_type,
        "id": related_id,
        "module": config["module"],
        "organization_id": row["organization_id"],
        "item_label": row.get(label_field) or f"{config['module']} #{related_id}",
    }


def get_document_or_404(document_id: int, manage: bool = False) -> dict[str, Any]:
    row = get_module_record("documents", document_id)
    if not row:
        abort(404)
    if manage:
        ensure_record_access("documents", row, g.current_user)
    elif not can_access_row("documents", row, g.current_user):
        abort(403)
    return row


def get_document_files(document_id: int) -> list[dict[str, Any]]:
    rows = query_all(
        """
        SELECT df.*, d.organization_id, d.title
        FROM document_files df
        JOIN documents d ON d.id = df.document_id
        WHERE df.document_id = ?
        ORDER BY df.version_number DESC, df.id DESC
        """,
        (document_id,),
    )
    for row in rows:
        refresh_document_file_status(row)
    return rows


def get_current_document_file(document_id: int) -> dict[str, Any] | None:
    row = query_one(
        """
        SELECT df.*, d.organization_id, d.title
        FROM document_files df
        JOIN documents d ON d.id = df.document_id
        WHERE df.document_id = ? AND df.is_current = 1
        ORDER BY df.version_number DESC, df.id DESC
        LIMIT 1
        """,
        (document_id,),
    )
    if not row:
        row = query_one(
            """
            SELECT df.*, d.organization_id, d.title
            FROM document_files df
            JOIN documents d ON d.id = df.document_id
            WHERE df.document_id = ?
            ORDER BY df.version_number DESC, df.id DESC
            LIMIT 1
            """,
            (document_id,),
        )
    if row:
        refresh_document_file_status(row)
    return row


def get_document_file_or_404(file_id: int, manage: bool = False) -> dict[str, Any]:
    row = query_one(
        """
        SELECT df.*, d.organization_id, d.title
        FROM document_files df
        JOIN documents d ON d.id = df.document_id
        WHERE df.id = ?
        """,
        (file_id,),
    )
    if not row:
        abort(404)
    document_row = get_document_or_404(row["document_id"], manage=manage)
    row["organization_id"] = document_row["organization_id"]
    row["title"] = document_row["title"]
    refresh_document_file_status(row)
    return row


def get_extraction_for_file(file_id: int) -> dict[str, Any] | None:
    return query_one("SELECT * FROM document_text_extractions WHERE document_file_id = ?", (file_id,))


def get_current_document_extraction(document_id: int) -> dict[str, Any] | None:
    current_file = get_current_document_file(document_id)
    if not current_file:
        return None
    return get_extraction_for_file(current_file["id"])


def get_current_document_summary(document_id: int) -> dict[str, Any] | None:
    row = query_one(
        """
        SELECT ds.*, d.organization_id, d.title
        FROM document_summaries ds
        JOIN documents d ON d.id = ds.document_id
        WHERE ds.document_id = ? AND ds.is_current = 1
        ORDER BY ds.version_number DESC, ds.revision_number DESC, ds.id DESC
        LIMIT 1
        """,
        (document_id,),
    )
    if row:
        row["structured"] = parse_json_payload(row.get("structured_data"))
        row["references"] = parse_json_payload(row.get("source_references"))
    return row


def get_document_summary_history(document_id: int) -> list[dict[str, Any]]:
    rows = query_all(
        """
        SELECT ds.*, d.organization_id, d.title
        FROM document_summaries ds
        JOIN documents d ON d.id = ds.document_id
        WHERE ds.document_id = ?
        ORDER BY ds.version_number DESC, ds.revision_number DESC, ds.id DESC
        """,
        (document_id,),
    )
    for row in rows:
        row["structured"] = parse_json_payload(row.get("structured_data"))
        row["references"] = parse_json_payload(row.get("source_references"))
    return rows


def get_document_summary_or_404(summary_id: int, manage: bool = False) -> dict[str, Any]:
    row = query_one(
        """
        SELECT ds.*, d.organization_id, d.title
        FROM document_summaries ds
        JOIN documents d ON d.id = ds.document_id
        WHERE ds.id = ?
        """,
        (summary_id,),
    )
    if not row:
        abort(404)
    get_document_or_404(row["document_id"], manage=manage)
    row["structured"] = parse_json_payload(row.get("structured_data"))
    row["references"] = parse_json_payload(row.get("source_references"))
    return row


def parse_json_payload(value: Any) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def list_backup_archives() -> list[dict[str, Any]]:
    backup_root = Path(current_app().config["BACKUP_ROOT"])
    backup_root.mkdir(parents=True, exist_ok=True)
    rows = []
    for path in sorted(backup_root.glob("ai-secretary-backup-*.zip"), reverse=True):
        rows.append({"name": path.name, "size_kb": max(1, round(path.stat().st_size / 1024)), "modified_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")})
    return rows


def create_backup_archive() -> Path:
    backup_root = Path(current_app().config["BACKUP_ROOT"])
    backup_root.mkdir(parents=True, exist_ok=True)
    archive_path = backup_root / f"ai-secretary-backup-{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    database_path = Path(current_app().config["DATABASE"])
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if database_path.exists():
            archive.write(database_path, arcname=f"database/{database_path.name}")
        for file_path in Path(current_app().config["STORAGE_ROOT"]).rglob("*"):
            if file_path.is_file():
                archive.write(file_path, arcname=str(Path("storage") / file_path.relative_to(Path(current_app().config["STORAGE_ROOT"]))))
    log_action("BACKUP_CREATE", "backup", archive_path.name, detail="Database dan document storage dibackup.")
    return archive_path


def restore_backup_archive(archive_name: str) -> None:
    archive_path = Path(current_app().config["BACKUP_ROOT"]) / Path(archive_name).name
    if not archive_path.exists():
        abort(404)

    db = g.pop("db", None)
    if db is not None:
        db.close()

    storage_root = Path(current_app().config["STORAGE_ROOT"])
    database_path = Path(current_app().config["DATABASE"])
    storage_root.mkdir(parents=True, exist_ok=True)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    database_payload = None
    storage_payloads: list[tuple[Path, bytes]] = []
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            member_path = Path(member.filename)
            if member.is_dir():
                continue
            if member_path.is_absolute() or ".." in member_path.parts:
                raise DocumentProcessingError("Arsip backup tidak valid.")
            data = archive.read(member)
            if member.filename.startswith("database/"):
                database_payload = data
            elif member.filename.startswith("storage/"):
                relative = Path(*member_path.parts[1:])
                storage_payloads.append((relative, data))

    if database_payload is None:
        raise DocumentProcessingError("File database tidak ditemukan dalam arsip backup.")

    purge_directory_contents(storage_root)
    for relative_path, data in storage_payloads:
        target = (storage_root / relative_path).resolve()
        if not str(target).startswith(str(storage_root.resolve())):
            raise DocumentProcessingError("Path storage pada backup tidak valid.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    database_path.write_bytes(database_payload)
    log_action("BACKUP_RESTORE", "backup", archive_path.name, detail="Database dan document storage berhasil direstore.")


def purge_directory_contents(root: Path) -> None:
    if not root.exists():
        return
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()


def sync_legacy_document_files() -> None:
    rows = query_all(
        """
        SELECT d.id, d.organization_id, d.file_path, d.version
        FROM documents d
        WHERE d.file_path IS NOT NULL AND TRIM(d.file_path) != ''
        """
    )
    for row in rows:
        existing = query_one("SELECT id FROM document_files WHERE document_id = ? AND storage_provider = 'LEGACY' AND storage_path = ?", (row["id"], row["file_path"]))
        if existing:
            continue
        version_number = max(1, parse_version_number(row.get("version")))
        for current in query_all("SELECT id FROM document_files WHERE document_id = ?", (row["id"],)):
            execute("UPDATE document_files SET is_current = 0, updated_at = ? WHERE id = ?", (now_ts(), current["id"]))
        path = Path(row["file_path"])
        execute(
            """
            INSERT INTO document_files (
                document_id, version_number, original_filename, stored_filename, mime_type, extension, file_size,
                checksum, storage_provider, storage_path, storage_status, is_previewable, is_current, uploaded_by,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?)
            """,
            (
                row["id"],
                version_number,
                path.name or row["file_path"],
                path.name or row["file_path"],
                sniff_mime_type(path.name or row["file_path"], b""),
                path.suffix.lower(),
                0,
                None,
                "LEGACY",
                row["file_path"],
                "LEGACY_PATH",
                1 if path.suffix.lower() in PREVIEWABLE_EXTENSIONS else 0,
                now_ts(),
                now_ts(),
            ),
        )


def parse_version_number(value: Any) -> int:
    if value is None:
        return 1
    match = re.search(r"(\d+)", str(value))
    return int(match.group(1)) if match else 1


def next_document_version(document_id: int) -> int:
    row = query_one("SELECT MAX(version_number) AS max_version FROM document_files WHERE document_id = ?", (document_id,))
    return int(row["max_version"] or 0) + 1


def resolve_legacy_document_path(raw_path: str) -> Path | None:
    if not raw_path:
        return None
    candidate = Path(raw_path)
    allowed_roots = [Path(item).resolve() for item in current_app().config.get("LEGACY_STORAGE_ROOTS", [])]
    if candidate.is_absolute():
        resolved = candidate.resolve()
        return resolved if any(str(resolved).startswith(str(root)) for root in allowed_roots) else None
    for root in allowed_roots:
        resolved = (root / candidate).resolve()
        if str(resolved).startswith(str(root)) and resolved.exists():
            return resolved
    if allowed_roots:
        fallback = (allowed_roots[0] / candidate).resolve()
        if str(fallback).startswith(str(allowed_roots[0])):
            return fallback
    return None


def resolve_document_file_path(file_row: dict[str, Any]) -> Path | None:
    if file_row["storage_provider"] == "LOCAL":
        try:
            return storage_service().resolve_path(file_row["storage_path"])
        except DocumentProcessingError:
            return None
    if file_row["storage_provider"] == "LEGACY":
        return resolve_legacy_document_path(file_row["storage_path"])
    return None


def refresh_document_file_status(file_row: dict[str, Any]) -> None:
    resolved = resolve_document_file_path(file_row)
    should_exist = file_row["storage_status"] in {"UPLOADED", "LEGACY_PATH", "MIGRATED", "MISSING"}
    if not should_exist:
        return
    exists = bool(resolved and resolved.exists())
    next_status = file_row["storage_status"]
    if file_row["storage_provider"] == "LEGACY":
        next_status = "LEGACY_PATH" if exists else "MISSING"
    elif file_row["storage_provider"] == "LOCAL":
        next_status = "UPLOADED" if exists else "MISSING"
    if next_status != file_row["storage_status"]:
        execute("UPDATE document_files SET storage_status = ?, updated_at = ? WHERE id = ?", (next_status, now_ts(), file_row["id"]))
        file_row["storage_status"] = next_status


def find_duplicate_file(checksum: str, organization_id: int, document_id: int) -> dict[str, Any] | None:
    return query_one(
        """
        SELECT df.id, df.document_id, df.original_filename, df.version_number, d.title
        FROM document_files df
        JOIN documents d ON d.id = df.document_id
        WHERE df.checksum = ? AND d.organization_id = ? AND df.document_id != ?
        ORDER BY df.id DESC
        LIMIT 1
        """,
        (checksum, organization_id, document_id),
    )


def attach_uploaded_file(
    document_row: dict[str, Any],
    upload,
    user: dict[str, Any],
    *,
    generate_summary: bool,
    summary_language: str,
    allow_duplicate: bool,
) -> dict[str, Any]:
    version_number = next_document_version(document_row["id"])
    saved = storage_service().save_upload(upload, get_organization_code(document_row["organization_id"]), document_row["id"], version_number)
    duplicate = find_duplicate_file(saved.checksum, document_row["organization_id"], document_row["id"])
    if duplicate and not allow_duplicate:
        storage_service().delete(saved.storage_relative_path)
        raise DocumentProcessingError(
            f"File dengan isi yang sama sudah tersedia pada dokumen {duplicate['title']} versi {duplicate['version_number']}. Centang opsi upload duplikat bila tetap ingin menyimpan."
        )

    execute("UPDATE document_files SET is_current = 0, updated_at = ? WHERE document_id = ?", (now_ts(), document_row["id"]))
    file_id = execute(
        """
        INSERT INTO document_files (
            document_id, version_number, original_filename, stored_filename, mime_type, extension, file_size,
            checksum, storage_provider, storage_path, storage_status, is_previewable, is_current, uploaded_by,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """,
        (
            document_row["id"],
            version_number,
            saved.original_filename,
            saved.stored_filename,
            saved.mime_type,
            saved.extension,
            saved.file_size,
            saved.checksum,
            saved.storage_provider,
            saved.storage_relative_path,
            saved.storage_status,
            1 if saved.extension in PREVIEWABLE_EXTENSIONS else 0,
            user["id"],
            now_ts(),
            now_ts(),
        ),
        True,
    )
    execute("UPDATE documents SET version = ?, updated_at = ?, updated_by = ? WHERE id = ?", (f"v{version_number}.0", now_ts(), user["id"], document_row["id"]))
    file_row = get_document_file_or_404(int(file_id), manage=True)
    if generate_summary:
        process_document_file(document_row, file_row, user, summary_language)
    else:
        ensure_extraction_record(file_row["id"], current_app().config["DEFAULT_SUMMARY_LANGUAGE"], "PENDING", "")
    action = "NEW_VERSION" if version_number > 1 else "UPLOAD"
    log_audit(
        user["id"],
        document_row["organization_id"],
        action,
        "document_file",
        document_row["id"],
        document_row["title"],
        f"File {saved.original_filename} disimpan sebagai versi {version_number} dengan storage {saved.storage_provider}.",
    )
    return file_row


def ensure_extraction_record(file_id: int, language: str, status: str, error_message: str, text: str = "", method: str = "") -> None:
    existing = get_extraction_for_file(file_id)
    if existing:
        execute(
            """
            UPDATE document_text_extractions
            SET extraction_status = ?, extracted_text = ?, extraction_method = ?, language = ?, error_message = ?, updated_at = ?
            WHERE document_file_id = ?
            """,
            (status, text, method, language, error_message, now_ts(), file_id),
        )
    else:
        execute(
            """
            INSERT INTO document_text_extractions (
                document_file_id, extraction_status, extracted_text, extraction_method, language, error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (file_id, status, text, method, language, error_message, now_ts(), now_ts()),
        )


def process_document_file(document_row: dict[str, Any], file_row: dict[str, Any], user: dict[str, Any], summary_language: str) -> None:
    extraction = extract_document_text(document_row, file_row, summary_language, user)
    if extraction["extraction_status"] != "TEXT_EXTRACTED":
        create_failed_summary(document_row, file_row, user, summary_language, extraction.get("error_message") or "Teks dokumen tidak dapat diekstrak.")
        return
    if current_app().config.get("ENABLE_AUTOMATIC_SUMMARY", True):
        generate_summary_for_file(document_row, file_row, user, summary_language, regenerate=False)


def extract_document_text(document_row: dict[str, Any], file_row: dict[str, Any], language: str, user: dict[str, Any]) -> dict[str, Any]:
    ensure_extraction_record(file_row["id"], language, "EXTRACTING_TEXT", "")
    path = resolve_document_file_path(file_row)
    if not path or not path.exists():
        execute("UPDATE document_files SET storage_status = 'MISSING', updated_at = ? WHERE id = ?", (now_ts(), file_row["id"]))
        ensure_extraction_record(file_row["id"], language, "FAILED", "File tidak ditemukan pada storage.")
        result = get_extraction_for_file(file_row["id"]) or {}
        log_audit(user["id"], document_row["organization_id"], "TEXT_EXTRACTION", "document_extraction", document_row["id"], document_row["title"], "File tidak ditemukan pada storage.")
        return result

    if not current_app().config.get("ENABLE_TEXT_EXTRACTION", True):
        ensure_extraction_record(file_row["id"], language, "TEXT_EXTRACTION_UNAVAILABLE", "Fitur ekstraksi teks dinonaktifkan.")
        return get_extraction_for_file(file_row["id"]) or {}

    result = text_extraction_service().extract(path, file_row["extension"], language)
    ensure_extraction_record(
        file_row["id"],
        result["language"],
        result["status"],
        result.get("error", ""),
        result.get("text", ""),
        result.get("method", ""),
    )
    log_audit(
        user["id"],
        document_row["organization_id"],
        "TEXT_EXTRACTION",
        "document_extraction",
        document_row["id"],
        document_row["title"],
        f"Status ekstraksi: {result['status']} | Metode: {result.get('method', '-')}",
    )
    return get_extraction_for_file(file_row["id"]) or {}


def create_failed_summary(document_row: dict[str, Any], file_row: dict[str, Any], user: dict[str, Any], language: str, reason: str) -> None:
    revision_number = next_summary_revision(document_row["id"], file_row["id"], language)
    execute("UPDATE document_summaries SET is_current = 0, updated_at = ? WHERE document_id = ?", (now_ts(), document_row["id"]))
    execute(
        """
        INSERT INTO document_summaries (
            document_id, document_file_id, version_number, revision_number, summary_status, language,
            summary_text, structured_data, source_references, review_notes, generated_by, reviewed_by,
            generated_at, reviewed_at, manually_edited, is_current, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'FAILED', ?, ?, ?, ?, ?, ?, NULL, ?, NULL, 0, 1, ?, ?)
        """,
        (
            document_row["id"],
            file_row["id"],
            file_row["version_number"],
            revision_number,
            language,
            "",
            "{}",
            "{}",
            reason,
            user["id"],
            now_ts(),
            now_ts(),
            now_ts(),
        ),
    )
    log_audit(user["id"], document_row["organization_id"], "RESUME_GENERATED", "document_summary", document_row["id"], document_row["title"], f"Resume gagal dibuat: {reason}")


def next_summary_revision(document_id: int, file_id: int, language: str) -> int:
    row = query_one(
        """
        SELECT MAX(revision_number) AS max_revision
        FROM document_summaries
        WHERE document_id = ? AND document_file_id = ? AND language = ?
        """,
        (document_id, file_id, language),
    )
    return int(row["max_revision"] or 0) + 1


def generate_summary_for_file(
    document_row: dict[str, Any],
    file_row: dict[str, Any],
    user: dict[str, Any],
    language: str,
    *,
    regenerate: bool,
) -> None:
    extraction = get_extraction_for_file(file_row["id"])
    if not extraction or extraction.get("extraction_status") != "TEXT_EXTRACTED":
        extraction = extract_document_text(document_row, file_row, language, user)
    if extraction.get("extraction_status") != "TEXT_EXTRACTED" or not extraction.get("extracted_text"):
        create_failed_summary(document_row, file_row, user, language, extraction.get("error_message") or "Teks dokumen tidak dapat diekstrak.")
        raise DocumentProcessingError(extraction.get("error_message") or "Teks dokumen tidak dapat diekstrak.")

    revision_number = next_summary_revision(document_row["id"], file_row["id"], language)
    execute("UPDATE document_summaries SET is_current = 0, updated_at = ? WHERE document_id = ?", (now_ts(), document_row["id"]))
    summary_id = execute(
        """
        INSERT INTO document_summaries (
            document_id, document_file_id, version_number, revision_number, summary_status, language,
            summary_text, structured_data, source_references, review_notes, generated_by, reviewed_by,
            generated_at, reviewed_at, manually_edited, is_current, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'GENERATING', ?, '', '{}', '{}', '', ?, NULL, ?, NULL, 0, 1, ?, ?)
        """,
        (
            document_row["id"],
            file_row["id"],
            file_row["version_number"],
            revision_number,
            language,
            user["id"],
            now_ts(),
            now_ts(),
            now_ts(),
        ),
        True,
    )
    result = summary_service().summarize(
        title=document_row.get("title") or file_row["original_filename"],
        category=document_row.get("category") or "",
        document_type=document_row.get("document_type") or "",
        text=extraction.get("extracted_text", ""),
        language=language,
    )
    execute(
        """
        UPDATE document_summaries
        SET summary_status = ?, summary_text = ?, structured_data = ?, source_references = ?,
            generated_at = ?, updated_at = ?, review_notes = ?
        WHERE id = ?
        """,
        (
            result["status"],
            result["summary_text"],
            result["structured_data"],
            result["source_references"],
            now_ts(),
            now_ts(),
            "Dibuat ulang otomatis." if regenerate else "Dibuat otomatis saat upload.",
            summary_id,
        ),
    )
    log_audit(
        user["id"],
        document_row["organization_id"],
        "RESUME_REGENERATED" if regenerate else "RESUME_GENERATED",
        "document_summary",
        document_row["id"],
        document_row["title"],
        f"Resume versi file {file_row['version_number']} dibuat dengan bahasa {language}.",
    )


def update_document_summary(summary_row: dict[str, Any], user: dict[str, Any], summary_text: str, review_notes: str, next_status: str) -> None:
    allowed_statuses = {"DRAFT", "READY_FOR_REVIEW", "REVIEWED", "APPROVED", "REJECTED"}
    target_status = next_status if next_status in allowed_statuses else "REVIEWED"
    manually_edited = 1 if summary_text and summary_text != (summary_row.get("summary_text") or "") else int(summary_row.get("manually_edited") or 0)
    execute(
        """
        UPDATE document_summaries
        SET summary_text = ?, review_notes = ?, summary_status = ?, reviewed_by = ?, reviewed_at = ?, manually_edited = ?, updated_at = ?
        WHERE id = ?
        """,
        (summary_text or summary_row.get("summary_text") or "", review_notes, target_status, user["id"], now_ts(), manually_edited, now_ts(), summary_row["id"]),
    )
    if manually_edited:
        log_audit(user["id"], summary_row["organization_id"], "RESUME_EDITED", "document_summary", summary_row["document_id"], summary_row["title"], "Resume diedit manual.")
    action = {
        "REVIEWED": "RESUME_VIEWED",
        "APPROVED": "RESUME_APPROVED",
        "REJECTED": "RESUME_REJECTED",
        "DRAFT": "RESUME_EDITED",
        "READY_FOR_REVIEW": "RESUME_EDITED",
    }[target_status]
    log_audit(user["id"], summary_row["organization_id"], action, "document_summary", summary_row["document_id"], summary_row["title"], f"Status resume menjadi {target_status}.")


def restore_document_version(document_id: int, file_id: int, user: dict[str, Any]) -> None:
    file_row = get_document_file_or_404(file_id, manage=True)
    execute("UPDATE document_files SET is_current = 0, updated_at = ? WHERE document_id = ?", (now_ts(), document_id))
    execute("UPDATE document_files SET is_current = 1, updated_at = ? WHERE id = ?", (now_ts(), file_id))
    execute("UPDATE document_summaries SET is_current = 0, updated_at = ? WHERE document_id = ?", (now_ts(), document_id))
    summary_row = query_one(
        """
        SELECT id
        FROM document_summaries
        WHERE document_id = ? AND document_file_id = ?
        ORDER BY revision_number DESC, id DESC
        LIMIT 1
        """,
        (document_id, file_id),
    )
    if summary_row:
        execute("UPDATE document_summaries SET is_current = 1, updated_at = ? WHERE id = ?", (now_ts(), summary_row["id"]))
    execute("UPDATE documents SET version = ?, updated_at = ?, updated_by = ? WHERE id = ?", (f"v{file_row['version_number']}.0", now_ts(), user["id"], document_id))
    log_audit(user["id"], file_row["organization_id"], "RESTORE_VERSION", "document_file", document_id, file_row["title"], f"Versi aktif dipulihkan ke v{file_row['version_number']}.")


def get_document_related_items(document_id: int) -> list[dict[str, Any]]:
    items = []
    relation_rows = query_all("SELECT related_type, related_id FROM document_relations WHERE document_id = ? ORDER BY id DESC", (document_id,))
    direct_targets = [("contracts", "CONTRACT"), ("permits", "PERMIT")]
    for module, rel_type in direct_targets:
        for row in query_all(f"SELECT id FROM {MODULES[module]['table']} WHERE file_document_id = ?", (document_id,)):
            relation_rows.append({"related_type": rel_type, "related_id": row["id"]})
    seen = set()
    for relation in relation_rows:
        related_type = relation["related_type"]
        config = RELATED_UPLOAD_TARGETS.get(related_type)
        if not config:
            continue
        key = (related_type, relation["related_id"])
        if key in seen:
            continue
        seen.add(key)
        row = get_module_record(config["module"], relation["related_id"])
        if not row or not can_access_row(config["module"], row, g.current_user):
            continue
        label = row.get(config["label_field"]) or f"{config['module']} #{relation['related_id']}"
        target_url = url_for("module_edit", module=config["module"], record_id=row["id"]) if user_has_permission(g.current_user, MODULES[config["module"]]["permission_manage"]) and can_manage_record(config["module"], row, g.current_user) else url_for("module_list", module=config["module"])
        items.append({"module_label": config["module"].replace("_", " ").title(), "item_label": label, "url": target_url})
    return items


def link_document_to_related(document_id: int, related_type: str, related_id: int, user: dict[str, Any]) -> None:
    execute(
        "INSERT OR IGNORE INTO document_relations (document_id, related_type, related_id, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
        (document_id, related_type, related_id, user["id"], now_ts()),
    )
    config = RELATED_UPLOAD_TARGETS.get(related_type)
    if config and config.get("fk_column"):
        execute(
            f"UPDATE {MODULES[config['module']]['table']} SET {config['fk_column']} = ?, updated_at = ? WHERE id = ?",
            (document_id, now_ts(), related_id),
        )


def get_document_audit_rows(document_id: int) -> list[dict[str, Any]]:
    return query_all(
        """
        SELECT a.action, a.details, a.created_at, u.full_name AS user_name
        FROM audit_logs a
        LEFT JOIN users u ON u.id = a.user_id
        WHERE a.entity_id = ?
        ORDER BY a.id DESC
        LIMIT 20
        """,
        (document_id,),
    )


def build_document_file_response(file_row: dict[str, Any], *, as_attachment: bool):
    path = resolve_document_file_path(file_row)
    if not path or not path.exists():
        execute("UPDATE document_files SET storage_status = 'MISSING', updated_at = ? WHERE id = ?", (now_ts(), file_row["id"]))
        abort(404)
    return send_file(path, mimetype=file_row["mime_type"], as_attachment=as_attachment, download_name=file_row["original_filename"])


def get_organization_code(organization_id: int) -> str:
    row = query_one("SELECT code FROM organizations WHERE id = ?", (organization_id,))
    return row["code"] if row else "ORG"


def build_dashboard(user: dict[str, Any], selected_org: str = "") -> dict[str, Any]:
    org_filter = int(selected_org) if selected_org.isdigit() else None

    def filter_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [row for row in rows if not org_filter or row.get("organization_id") == org_filter]

    documents = filter_rows(get_accessible_rows("documents", user))
    contracts = filter_rows(get_accessible_rows("contracts", user))
    permits = filter_rows(get_accessible_rows("permits", user))
    assets = filter_rows(get_accessible_rows("assets", user))
    tasks = filter_rows(get_accessible_rows("tasks", user))
    reminders = filter_rows(get_accessible_rows("reminders", user))
    meetings = filter_rows(get_accessible_rows("meetings", user))
    letters = filter_rows(get_accessible_rows("incoming_letters", user)) + filter_rows(get_accessible_rows("outgoing_letters", user))
    notifications = query_all("SELECT id, title, message, kind, is_read, link, created_at FROM notifications WHERE user_id = ? ORDER BY is_read ASC, created_at DESC LIMIT 6", (user["id"],))
    compliance_alerts = build_expiry_rows(documents, contracts, permits, assets)[:8]
    overdue_tasks = [row for row in tasks if compute_days_remaining(row.get("due_date")) is not None and compute_days_remaining(row.get("due_date")) < 0 and row.get("status") != "DONE"]
    return {
        "report_cards": [
            {"label": "Open Tasks", "value": sum(1 for row in tasks if row.get("status") not in {"DONE", "CANCELLED"}), "accent": "amber"},
            {"label": "Documents", "value": len(documents), "accent": "blue"},
            {"label": "MOU / Contracts", "value": len(contracts), "accent": "rose"},
            {"label": "Permits", "value": len(permits), "accent": "green"},
            {"label": "Central Tembusan", "value": sum(1 for row in documents if int(row.get("central_monitoring_required") or 0) == 1), "accent": "purple"},
            {"label": "Unread Alerts", "value": sum(1 for row in notifications if not row["is_read"]), "accent": "slate"},
        ],
        "open_tasks": [row for row in tasks if row.get("status") not in {"DONE", "CANCELLED"}][:6],
        "due_reminders": sorted(reminders, key=lambda row: row.get("remind_at") or "9999")[:6],
        "pending_letters": letters[:6],
        "next_meetings": sorted(meetings, key=lambda row: row.get("start_at") or "9999")[:6],
        "dispositions": filter_rows(get_accessible_rows("dispositions", user))[:6],
        "notifications": notifications,
        "compliance_alerts": compliance_alerts,
        "overdue_tasks": overdue_tasks[:6],
    }


def build_expiry_rows(document_rows: list[dict[str, Any]], contract_rows: list[dict[str, Any]], permit_rows: list[dict[str, Any]], asset_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in document_rows:
        add_expiry_row(rows, "Document", row.get("organization_name"), row.get("title"), row.get("status"), row.get("expiry_date"))
    for row in contract_rows:
        add_expiry_row(rows, "Contract", row.get("organization_name"), row.get("title"), row.get("status"), row.get("end_date"))
    for row in permit_rows:
        add_expiry_row(rows, "Permit", row.get("organization_name"), row.get("permit_name"), row.get("status"), row.get("expiry_date"))
    for row in asset_rows:
        add_expiry_row(rows, "Asset", row.get("organization_name"), row.get("name"), row.get("status"), row.get("warranty_expiry"))
    rows.sort(key=lambda item: item["sort_key"])
    return rows


def add_expiry_row(target: list[dict[str, Any]], module: str, organization_name: str | None, label: str | None, status: str | None, expiry_date: str | None) -> None:
    days = compute_days_remaining(expiry_date)
    if days is None:
        return
    target.append({"module": module, "organization_name": organization_name or "-", "label": label or "-", "status": status or "-", "expiry_date": format_date(expiry_date), "days_remaining": days, "urgency": expiry_level(days), "sort_key": days})


def build_compliance_dashboard(user: dict[str, Any]) -> dict[str, Any]:
    if not (is_superuser(user) or is_owner(user) or is_hq_secretary(user)):
        abort(403)
    documents = get_accessible_rows("documents", user)
    contracts = get_accessible_rows("contracts", user)
    permits = get_accessible_rows("permits", user)
    hospitals = query_all("SELECT id, name FROM organizations WHERE kind = 'HOSPITAL' ORDER BY id")
    summary_rows = []
    for org in hospitals:
        org_docs = [row for row in documents if row["organization_id"] == org["id"]]
        org_contracts = [row for row in contracts if row["organization_id"] == org["id"]]
        org_permits = [row for row in permits if row["organization_id"] == org["id"]]
        summary_rows.append({
            "organization_name": org["name"],
            "documents_total": len(org_docs),
            "documents_tembusan": sum(1 for row in org_docs if int(row.get("central_monitoring_required") or 0) == 1),
            "contracts_total": len(org_contracts),
            "contracts_tembusan": sum(1 for row in org_contracts if int(row.get("central_monitoring_required") or 0) == 1),
            "permits_total": len(org_permits),
            "permits_tembusan": sum(1 for row in org_permits if int(row.get("central_monitoring_required") or 0) == 1),
        })
    pending_review = [row for row in documents if row.get("central_status") in {"CREATED", "SENT TO HO", "RECEIVED BY HO"}][:10]
    return {"summary_rows": summary_rows, "pending_review": pending_review, "expiring_items": build_expiry_rows(documents, contracts, permits, get_accessible_rows("assets", user))[:15]}


def build_report_rows(user: dict[str, Any]) -> dict[str, Any]:
    expiry_rows = build_expiry_rows(get_accessible_rows("documents", user), get_accessible_rows("contracts", user), get_accessible_rows("permits", user), get_accessible_rows("assets", user))
    return {
        "counts": {
            "documents": len(get_accessible_rows("documents", user)),
            "contracts": len(get_accessible_rows("contracts", user)),
            "permits": len(get_accessible_rows("permits", user)),
            "assets": len(get_accessible_rows("assets", user)),
            "expired": sum(1 for row in expiry_rows if row["days_remaining"] < 0),
            "critical": sum(1 for row in expiry_rows if 0 <= row["days_remaining"] <= 7),
        },
        "expiry_rows": expiry_rows[:50],
    }


def perform_search(query_text: str, user: dict[str, Any]) -> list[dict[str, Any]]:
    lookup = query_text.lower()
    sources = [
        ("documents", "Documents", lambda row: f"{row.get('title','')} {row.get('document_number','')} {row.get('vendor_name','')} {row.get('category','')}"),
        ("contracts", "Contracts", lambda row: f"{row.get('title','')} {row.get('contract_number','')} {row.get('partner_name','')} {row.get('vendor_name','')}"),
        ("permits", "Permits", lambda row: f"{row.get('permit_name','')} {row.get('permit_number','')} {row.get('issuer','')}"),
        ("vendors", "Vendors", lambda row: f"{row.get('name','')} {row.get('company','')} {row.get('category','')}"),
        ("assets", "Assets", lambda row: f"{row.get('asset_code','')} {row.get('name','')} {row.get('vendor_name','')}"),
        ("tasks", "Tasks", lambda row: f"{row.get('title','')} {row.get('description','')} {row.get('related_type','')}"),
        ("meetings", "Meetings", lambda row: f"{row.get('title','')} {row.get('agenda','')} {row.get('participants','')}"),
        ("incoming_letters", "Incoming Letters", lambda row: f"{row.get('letter_number','')} {row.get('subject','')} {row.get('correspondent','')}"),
        ("outgoing_letters", "Outgoing Letters", lambda row: f"{row.get('letter_number','')} {row.get('subject','')} {row.get('correspondent','')}"),
    ]
    results = []
    for module, label, builder in sources:
        for row in get_accessible_rows(module, user):
            haystack = builder(row).lower()
            if lookup in haystack:
                target_url = url_for("module_edit", module=module, record_id=row["id"]) if user_has_permission(user, MODULES[module]["permission_manage"]) and can_manage_record(module, row, user) else url_for("module_list", module=module)
                results.append({"module": label, "organization_name": row.get("organization_name", "-"), "title": row.get("title") or row.get("permit_name") or row.get("name") or row.get("subject") or row.get("letter_number"), "subtitle": builder(row), "url": target_url})
    return results[:100]


def refresh_notifications() -> None:
    user = g.current_user
    if not user:
        return
    for row in get_accessible_rows("tasks", user):
        days = compute_days_remaining(row.get("due_date"))
        if days is not None and row.get("status") not in {"DONE", "CANCELLED"} and days <= 7:
            upsert_notification(user["id"], user["organization_id"], f"Task deadline: {row['title']}", f"Task jatuh tempo {format_datetime(row['due_date'])} ({expiry_level(days)}).", "task", f"/modules/tasks/{row['id']}/edit", f"task:{row['id']}:{expiry_level(days)}")
    for module, (date_field, label) in EXPIRY_MODULES.items():
        for row in get_accessible_rows(module, user):
            days = compute_days_remaining(row.get(date_field))
            if days is None:
                continue
            band = expiry_level(days)
            if band in {"SAFE", "LOW"}:
                continue
            item_label = row.get("title") or row.get("permit_name") or row.get("name") or row.get("asset_code")
            target = f"/modules/{module}/{row['id']}/edit" if user_has_permission(user, MODULES[module]["permission_manage"]) and can_manage_record(module, row, user) else f"/modules/{module}"
            upsert_notification(user["id"], user["organization_id"], f"{label} {band}: {item_label}", f"{item_label} untuk {row.get('organization_name', '-')} berstatus {band} dengan sisa {days} hari.", "expiry", target, f"{module}:{row['id']}:{band}")
    for row in get_accessible_rows("documents", user):
        if int(row.get("central_monitoring_required") or 0) == 1 and row.get("central_status") in {"CREATED", "SENT TO HO", "RECEIVED BY HO"}:
            upsert_notification(user["id"], user["organization_id"], f"Tembusan baru: {row['title']}", f"Dokumen {row['title']} dari {row.get('organization_name', '-')} menunggu review pusat.", "compliance", "/compliance", f"tembusan:document:{row['id']}")
    if is_password_expired(user):
        upsert_notification(user["id"], user["organization_id"], "Password expired", "Password Anda sudah kedaluwarsa dan harus segera diganti.", "security", "/change-password?forced=1", f"password:expired:{user['id']}")
    else:
        password_age = password_days_remaining(user)
        if password_age is not None and password_age <= 7:
            upsert_notification(user["id"], user["organization_id"], "Password segera kedaluwarsa", f"Password Anda akan kedaluwarsa dalam {password_age} hari.", "security", "/change-password", f"password:warning:{user['id']}:{password_age}")


def upsert_notification(user_id: int, organization_id: int | None, title: str, message: str, kind: str, link: str, source_key: str) -> None:
    execute(
        """
        INSERT INTO notifications (user_id, organization_id, title, message, kind, is_read, link, source_key, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
        ON CONFLICT(user_id, source_key)
        DO UPDATE SET title = excluded.title, message = excluded.message, kind = excluded.kind, link = excluded.link
        """,
        (user_id, organization_id, title, message, kind, link, source_key, now_ts()),
    )


def build_assistant_response(prompt: str, user: dict[str, Any]) -> str:
    if not prompt:
        return "Tulis pertanyaan agar AI Secretary dapat merangkum dokumen, kontrak, permit, task, atau monitoring organisasi."
    text = prompt.lower()
    contracts = get_accessible_rows("contracts", user)
    permits = get_accessible_rows("permits", user)
    tasks = get_accessible_rows("tasks", user)
    documents = get_accessible_rows("documents", user)
    letters = get_accessible_rows("incoming_letters", user) + get_accessible_rows("outgoing_letters", user)
    org_name = None
    if "cikarang" in text:
        org_name = "RS Bhakti Husada Cikarang"
    elif "purwakarta" in text:
        org_name = "RS Bhakti Husada Purwakarta"
    elif "pt" in text or "pusat" in text:
        org_name = "PT / Kantor Pusat"
    if org_name:
        contracts = [row for row in contracts if row.get("organization_name") == org_name]
        permits = [row for row in permits if row.get("organization_name") == org_name]
        tasks = [row for row in tasks if row.get("organization_name") == org_name]
        documents = [row for row in documents if row.get("organization_name") == org_name]
        letters = [row for row in letters if row.get("organization_name") == org_name]
    lines = ["Ringkasan kerja dari AI Secretary:"]
    if "izin" in text or "permit" in text:
        rows = [row for row in permits if is_expiring_this_month(row.get("expiry_date")) or ("30 hari" in text and within_days(row.get("expiry_date"), 30))]
        if rows:
            lines.append("Permit yang perlu perhatian:")
            for row in rows[:5]:
                lines.append(f"- {row['permit_name']} | {row['organization_name']} | expired {format_date(row['expiry_date'])} | {expiry_level(compute_days_remaining(row['expiry_date']) or 999)}")
        else:
            lines.append("- Tidak ada permit yang cocok dengan kriteria.")
    elif "mou" in text or "kontrak" in text or "contract" in text:
        rows = [row for row in contracts if compute_days_remaining(row.get("end_date")) is not None and compute_days_remaining(row.get("end_date")) <= 30] if ("expired" in text or "habis" in text or "30 hari" in text) else contracts
        if rows:
            lines.append("Ringkasan MOU/Kontrak:")
            for row in rows[:5]:
                lines.append(f"- {row['contract_number']} | {row['title']} | {row['organization_name']} | {row['status']} | berakhir {format_date(row['end_date'])}")
        else:
            lines.append("- Tidak ada kontrak yang cocok.")
    elif "task" in text or "tugas" in text:
        lines.append("Task aktif:")
        active = [row for row in tasks if row.get("status") not in {"DONE", "CANCELLED"}]
        for row in active[:5]:
            lines.append(f"- {row['title']} | {row['organization_name']} | due {format_datetime(row.get('due_date'))}")
        if not active:
            lines.append("- Tidak ada task aktif.")
    elif "surat" in text:
        lines.append("Surat yang relevan:")
        for row in letters[:5]:
            lines.append(f"- {row['letter_number']} | {row['organization_name']} | {row['subject']} | {row['status']}")
        if not letters:
            lines.append("- Tidak ada surat yang dapat diakses.")
    elif "tembusan" in text or "compliance" in text:
        rows = [row for row in documents if int(row.get("central_monitoring_required") or 0) == 1 and row.get("central_status") != "ARCHIVED"]
        lines.append("Dokumen tembusan yang dimonitor PT:")
        for row in rows[:5]:
            lines.append(f"- {row['title']} | {row['organization_name']} | {row['central_status']}")
        if not rows:
            lines.append("- Tidak ada data tembusan aktif.")
    elif "email" in text:
        lines.append("- Integrasi email live belum dikonfigurasi di environment ini.")
        lines.append("- Fondasi data sekretariat sudah siap untuk dihubungkan ke Gmail atau Microsoft 365 secara OAuth.")
    else:
        lines.append(f"- Dokumen dapat diakses: {len(documents)}")
        lines.append(f"- Kontrak/MOU aktif: {len(contracts)}")
        lines.append(f"- Permit aktif: {len(permits)}")
        lines.append(f"- Task aktif: {sum(1 for row in tasks if row.get('status') not in {'DONE', 'CANCELLED'})}")
        lines.append(f"- Kontrak expiring <=30 hari: {sum(1 for row in contracts if within_days(row.get('end_date'), 30))}")
        lines.append(f"- Permit expiring <=30 hari: {sum(1 for row in permits if within_days(row.get('expiry_date'), 30))}")
        lines.append("Saran tindak lanjut: review item CRITICAL di dashboard compliance dan pastikan renewal task sudah dibuat.")
    return "\n".join(lines)


def compute_days_remaining(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return (date.fromisoformat(value[:10]) - date.today()).days
    except ValueError:
        return None


def expiry_level(days_remaining: int) -> str:
    if days_remaining < 0:
        return "EXPIRED"
    if days_remaining <= 7:
        return "CRITICAL"
    if days_remaining <= 30:
        return "HIGH"
    if days_remaining <= 60:
        return "MEDIUM"
    if days_remaining <= 90:
        return "LOW"
    return "SAFE"


def within_days(value: str | None, days: int) -> bool:
    remaining = compute_days_remaining(value)
    return remaining is not None and remaining <= days


def is_expiring_this_month(value: str | None) -> bool:
    if not value:
        return False
    try:
        target = date.fromisoformat(value[:10])
        today = date.today()
        return target.year == today.year and target.month == today.month
    except ValueError:
        return False


def log_action(action: str, entity_type: str, entity_label: str, organization_id: int | None = None, detail: str = "") -> None:
    if getattr(g, "current_user", None):
        log_audit(g.current_user["id"], organization_id or g.current_user.get("organization_id"), action, entity_type, None, entity_label, detail)


def current_request_ip() -> str | None:
    try:
        return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip() or None
    except RuntimeError:
        return None


def log_audit(
    user_id: int | None,
    organization_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None,
    entity_label: str | None,
    details: str,
    *,
    before_data: str | None = None,
    after_data: str | None = None,
    ip_address: str | None = None,
) -> None:
    execute(
        """
        INSERT INTO audit_logs (user_id, organization_id, action, entity_type, entity_id, entity_label, ip_address, before_data, after_data, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, organization_id, action, entity_type, entity_id, entity_label, ip_address or current_request_ip(), before_data, after_data, details, now_ts()),
    )


def now_ts() -> str:
    return datetime.now().isoformat(timespec="seconds")


def dt_value(value: datetime) -> str:
    return value.isoformat(timespec="minutes")


def format_datetime(value: Any) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(str(value)).strftime("%d %b %Y %H:%M")
    except ValueError:
        return str(value)


def format_date(value: Any) -> str:
    if not value:
        return "-"
    try:
        return date.fromisoformat(str(value)[:10]).strftime("%d %b %Y")
    except ValueError:
        return str(value)


def format_time_only(value: Any) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(str(value)).strftime("%H:%M")
    except ValueError:
        return str(value)


app = create_app()


if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        host=os.getenv("FLASK_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_PORT", "5000")),
    )

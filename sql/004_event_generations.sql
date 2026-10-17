-- Migration 004: secret generations for safe rotation + dual-sign window.
-- Applied idempotently by bridge_mcp/store.py::_apply_migrations (PRAGMA
-- user_version). This file documents the DDL; the code is authoritative.
ALTER TABLE event_subscriptions ADD COLUMN previous_secret_ref TEXT;
ALTER TABLE event_subscriptions ADD COLUMN previous_secret_sha256 TEXT;
ALTER TABLE event_subscriptions ADD COLUMN previous_expires_at TEXT;

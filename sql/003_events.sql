-- 003_events.sql — reference schema delta for native MCP Events
-- (bridge.ping isolated test scope). The crash-safe implementation lives in
-- store._apply_migrations(); this file is for human review.
--
-- The phase-0 event_subscriptions table tracked only callback URL + secret
-- ref. The ChatGPT MCP Events contract additionally requires: event name,
-- filter arguments, owner (authenticated principal), expiry
-- (refreshBefore), and a secret hash for change detection on refresh.

ALTER TABLE event_subscriptions ADD COLUMN event_name TEXT;
ALTER TABLE event_subscriptions ADD COLUMN arguments_json TEXT;
ALTER TABLE event_subscriptions ADD COLUMN owner TEXT;
ALTER TABLE event_subscriptions ADD COLUMN expires_at TEXT;
ALTER TABLE event_subscriptions ADD COLUMN secret_sha256 TEXT;

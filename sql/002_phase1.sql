-- Phase-1 migration: message-bound ack tokens + delivery leases.
-- Applied once via PRAGMA user_version (see store._apply_migrations).
-- ack_token_hash: sha256 hex of the bearer ack token issued by inbox_poll.
--   The plaintext token is NEVER stored; it is returned to the caller once.
-- lease_until: UTC ISO-8601; a polled-but-unacked message whose lease
--   expired is re-queued by the next inbox_poll (at-least-once delivery).
-- acks.disposition: 'processed' | 'rejected' as reported by the agent.
ALTER TABLE messages ADD COLUMN ack_token_hash TEXT;
ALTER TABLE messages ADD COLUMN lease_until TEXT;
ALTER TABLE acks ADD COLUMN disposition TEXT;

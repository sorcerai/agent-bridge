-- agent-bridge queue store schema (phase 0). WAL mode.
-- DB is the ONLY state. All access parameterized; hooks use .parameter set.
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS messages(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,   -- cursor unit
  message_id TEXT NOT NULL UNIQUE,
  direction TEXT NOT NULL CHECK(direction IN ('host_to_agent','agent_to_host')),
  sender TEXT NOT NULL,                    -- server-stamped, never caller input
  recipient TEXT NOT NULL,                 -- server-stamped
  correlation_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,           -- server-generated for admin enqueues
  payload_sha256 TEXT NOT NULL,            -- conflict detection
  created_at TEXT NOT NULL,                -- UTC ISO-8601
  type TEXT NOT NULL CHECK(type IN ('request','reply','result','ping','error')),
  payload_json TEXT NOT NULL,              -- <=16KB serialized, depth <=4
  taint TEXT NOT NULL DEFAULT 'untrusted',
  status TEXT NOT NULL CHECK(status IN
    ('queued','pending_agent_poll','awaiting_result','acked','expired','failed')),
  acked_at TEXT,
  delivered_at TEXT,
  last_error TEXT,                         -- enum class only, never raw
  expires_at TEXT NOT NULL,                -- 30-day TTL
  UNIQUE(direction, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_messages_dir_status_seq
  ON messages(direction, status, seq);

CREATE TABLE IF NOT EXISTS event_subscriptions(
  subscription_id TEXT PRIMARY KEY,
  callback_url TEXT NOT NULL,
  signing_secret_ref TEXT NOT NULL,        -- path to 0600 file, never the value
  status TEXT NOT NULL CHECK(status IN
    ('pending','pending_owner','active','disabled','failed')),
  created_at TEXT NOT NULL,
  verified_at TEXT,
  last_delivery_at TEXT,
  last_error TEXT                           -- enum class only
);

CREATE TABLE IF NOT EXISTS event_deliveries(
  event_id TEXT PRIMARY KEY,               -- evt_msg_<message_id>, stable across retries
  subscription_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  body_sha256 TEXT NOT NULL,               -- same body bytes every attempt
  status TEXT NOT NULL CHECK(status IN
    ('pending','sending','delivered','retry','failed')),
  lease_until TEXT,                        -- atomic claim by outbox hook
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_attempt_at TEXT,
  first_attempt_at TEXT,                    -- set on first claim; 24h retry budget anchor
  last_http_status INTEGER,
  last_error TEXT,                         -- enum class only
  FOREIGN KEY(subscription_id) REFERENCES event_subscriptions(subscription_id)
);
CREATE INDEX IF NOT EXISTS idx_deliveries_claim
  ON event_deliveries(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS acks(
  ack_id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  acked_at TEXT NOT NULL,
  delivery_token_hash TEXT NOT NULL,       -- token-bound acks
  FOREIGN KEY(message_id) REFERENCES messages(message_id)
);

-- Append-only telemetry. Declared in tool descriptions so readOnlyHint stays honest.
CREATE TABLE IF NOT EXISTS tool_calls(
  ts TEXT NOT NULL,
  tool TEXT NOT NULL,
  message_ids TEXT NOT NULL               -- JSON array, usually []
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_ts ON tool_calls(ts);

CREATE TABLE IF NOT EXISTS cursors(
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

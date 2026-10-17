"""SQLite access layer for the agent-bridge queue store.

All queries are parameterized. The DB is the ONLY state. Callers never build
SQL by string interpolation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from bridge_mcp import paths

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "sql", "001_init.sql")
# Reference only: the crash-safe implementation lives in
# _apply_migrations() below (P1-1). Kept for human review of the intended
# schema delta.
MIGRATION_002_PATH = os.path.join(os.path.dirname(__file__), "..", "sql", "002_phase1.sql")
DEFAULT_DB = paths.DEFAULT_DB
BUSY_TIMEOUT_MS = 5000
TTL_DAYS = 30

# Phase-1 hard caps (review P1-7 mitigations).
MAX_SENDS_PER_MIN = 10          # message_send: max agent->host enqueues / 60s
MAX_UNACKED_AGENT_TO_HOST = 50  # message_send refused past this unacked backlog
INBOX_POLL_LIMIT_MAX = 10       # inbox_poll limit ceiling
INBOX_POLL_LEASE_SECS = 600     # delivery lease before a polled message re-queues
TOOL_CALL_RETENTION_DAYS = 7    # audit retention (P2-4: bounded writes)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def connect(db_path: str = DEFAULT_DB) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)  # CREATE TABLE IF NOT EXISTS: idempotent
    return conn


def init_db(db_path: str = DEFAULT_DB) -> None:
    conn = connect(db_path)
    try:
        conn.commit()
    finally:
        conn.close()


def _ensure_schema(conn: sqlite3.Connection) -> None:
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = f.read()
    conn.executescript(schema)
    _apply_migrations(conn)


def _table_columns(conn: sqlite3.Connection, table: str) -> set:
    return {r[1] for r in
            conn.execute(f"PRAGMA table_info({table})").fetchall()}


SCHEMA_VERSION = 4


def _apply_migrations(conn: sqlite3.Connection) -> None:
    """Crash-safe migrations, tracked by PRAGMA user_version (P1-1).

    Each step is individually idempotent: columns are added only when
    missing (PRAGMA table_info), and user_version advances only after the
    step's work is verified present. A crash between ALTERs resumes
    cleanly instead of failing with "duplicate column name".
    Refuses to run on a DB from a newer schema version.
    """
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    if ver > SCHEMA_VERSION:
        raise RuntimeError(
            f"unsupported schema version {ver} (max {SCHEMA_VERSION})")
    if ver < 2:
        if "ack_token_hash" not in _table_columns(conn, "messages"):
            conn.execute("ALTER TABLE messages ADD COLUMN ack_token_hash TEXT")
        if "lease_until" not in _table_columns(conn, "messages"):
            conn.execute("ALTER TABLE messages ADD COLUMN lease_until TEXT")
        if "disposition" not in _table_columns(conn, "acks"):
            conn.execute("ALTER TABLE acks ADD COLUMN disposition TEXT")
        # Backfill: pre-phase-1 rows stuck in pending_agent_poll with
        # lease_until NULL would never redeliver (NULL < now is NULL in
        # SQL). Reset them to queued with an expired lease so the next
        # poll picks them up with a fresh token.
        conn.execute(
            "UPDATE messages SET status='queued', lease_until=?, "
            "ack_token_hash=NULL "
            "WHERE status='pending_agent_poll'",
            ("1970-01-01T00:00:00.000Z",))
        conn.commit()
        # Verify before advancing the version marker.
        if ({"ack_token_hash", "lease_until"}
                - _table_columns(conn, "messages")):
            raise RuntimeError("migration 002: messages columns missing")
        if "disposition" not in _table_columns(conn, "acks"):
            raise RuntimeError("migration 002: acks.disposition missing")
        conn.execute("PRAGMA user_version=2")
        conn.commit()
    if ver < 3:
        # Native MCP Events (bridge.ping test scope): the phase-0
        # event_subscriptions table only tracked callback+secret. The
        # events contract needs event name, filter arguments, owner,
        # expiry, and a secret hash for change detection.
        for col, ddl in (
                ("event_name", "TEXT"),
                ("arguments_json", "TEXT"),
                ("owner", "TEXT"),
                ("expires_at", "TEXT"),
                ("secret_sha256", "TEXT")):
            if col not in _table_columns(conn, "event_subscriptions"):
                conn.execute(
                    f"ALTER TABLE event_subscriptions ADD COLUMN {col} {ddl}")
        conn.commit()
        missing = ({"event_name", "arguments_json", "owner", "expires_at",
                    "secret_sha256"}
                   - _table_columns(conn, "event_subscriptions"))
        if missing:
            raise RuntimeError(f"migration 003: columns missing: {missing}")
        conn.execute("PRAGMA user_version=3")
        conn.commit()
    if ver < 4:
        # Secret generations for safe rotation + dual-signature window:
        # previous_secret_ref/sha256 keep the superseded generation so a
        # rotation does not break in-flight receivers; previous_expires_at
        # bounds the dual-sign window.
        for col, ddl in (
                ("previous_secret_ref", "TEXT"),
                ("previous_secret_sha256", "TEXT"),
                ("previous_expires_at", "TEXT")):
            if col not in _table_columns(conn, "event_subscriptions"):
                conn.execute(
                    f"ALTER TABLE event_subscriptions ADD COLUMN {col} {ddl}")
        conn.commit()
        missing = ({"previous_secret_ref", "previous_secret_sha256",
                    "previous_expires_at"}
                   - _table_columns(conn, "event_subscriptions"))
        if missing:
            raise RuntimeError(f"migration 004: columns missing: {missing}")
        conn.execute("PRAGMA user_version=4")
        conn.commit()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_payload(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class IdempotencyConflict(Exception):
    """Same (direction, idempotency_key) with a different payload hash."""

    def __init__(self, existing_message_id: str):
        super().__init__(f"idempotency conflict with {existing_message_id}")
        self.existing_message_id = existing_message_id


def enqueue(conn: sqlite3.Connection, *, direction: str, sender: str,
            recipient: str, correlation_id: str, idempotency_key: str,
            msg_type: str, payload: dict,
            status: str = "queued",
            check_caps: bool = False) -> dict:
    """Idempotent enqueue. Returns {message_id, idempotent_replay, created_at}.

    P1-2: the idempotency lookup happens FIRST — replays return the
    original row (original created_at) without consuming or checking caps,
    so a retry after response-loss succeeds even at the cap.
    P1-3: when check_caps is True, the caps check and the insert run in one
    BEGIN IMMEDIATE transaction, so concurrent writers cannot both pass the
    checks and overshoot the caps.
    """
    payload_json = canonical_payload(payload)
    digest = sha256_hex(payload_json.encode("utf-8"))
    now = utcnow()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=TTL_DAYS)
                  ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Open our own write transaction unless the caller already holds one
    # (e.g. a test mid-sequence); we only commit/rollback what we started.
    started = not conn.in_transaction
    if started:
        conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT message_id, payload_sha256, created_at FROM messages "
            "WHERE direction = ? AND idempotency_key = ?",
            (direction, idempotency_key)).fetchone()
        if row:
            if row["payload_sha256"] != digest:
                raise IdempotencyConflict(row["message_id"])
            if started:
                conn.rollback()
            return {"message_id": row["message_id"],
                    "idempotent_replay": True,
                    "created_at": row["created_at"]}

        if check_caps:
            _check_send_caps_locked(conn, now)

        message_id = "msg_" + uuid.uuid4().hex[:24]
        conn.execute(
            "INSERT INTO messages (message_id, direction, sender, recipient, "
            "correlation_id, idempotency_key, payload_sha256, created_at, type, "
            "payload_json, taint, status, expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (message_id, direction, sender, recipient, correlation_id,
             idempotency_key, digest, now, msg_type, payload_json,
             "untrusted", status, expires_at))
        if started:
            conn.commit()
        return {"message_id": message_id, "idempotent_replay": False,
                "created_at": now}
    except Exception:
        if started:
            conn.rollback()
        raise


def record_tool_call(conn: sqlite3.Connection, tool: str,
                     message_ids: list | None = None) -> None:
    conn.execute(
        "INSERT INTO tool_calls (ts, tool, message_ids) VALUES (?,?,?)",
        (utcnow(), tool, json.dumps(message_ids or [])))
    conn.commit()


def queue_health(conn: sqlite3.Connection) -> dict:
    def count(sql: str, args: tuple = ()) -> int:
        return conn.execute(sql, args).fetchone()[0]

    oldest = conn.execute(
        "SELECT MIN(created_at) FROM messages "
        "WHERE status IN ('queued','pending_agent_poll','awaiting_result')").fetchone()[0]
    age = None
    if oldest:
        age = max(0, int((datetime.now(timezone.utc) -
                          datetime.fromisoformat(oldest.replace("Z", "+00:00"))
                          ).total_seconds()))
    return {
        "host_to_agent_pending": count(
            "SELECT COUNT(*) FROM messages WHERE direction='host_to_agent' "
            "AND status IN ('queued','pending_agent_poll')"),
        "agent_to_host_unacked": count(
            "SELECT COUNT(*) FROM messages WHERE direction='agent_to_host' "
            "AND status IN ('queued','awaiting_result')"),
        "event_delivery_pending": count(
            "SELECT COUNT(*) FROM event_deliveries "
            "WHERE status IN ('pending','retry')"),
        "event_delivery_failed": count(
            "SELECT COUNT(*) FROM event_deliveries WHERE status='failed'"),
        "oldest_pending_age_secs": age,
    }


def expire_old(conn: sqlite3.Connection) -> int:
    """Move past-TTL rows to expired. Returns count."""
    cur = conn.execute(
        "UPDATE messages SET status='expired' "
        "WHERE status NOT IN ('acked','expired') AND expires_at < ?",
        (utcnow(),))
    conn.commit()
    return cur.rowcount


def get_message(conn: sqlite3.Connection, message_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM messages WHERE message_id = ?", (message_id,)).fetchone()
    return dict(row) if row else None


def active_subscription(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute(
        "SELECT * FROM event_subscriptions WHERE status='active' "
        "ORDER BY created_at DESC LIMIT 1").fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Native MCP Events (bridge.ping test scope)
# ---------------------------------------------------------------------------

def get_subscription(conn: sqlite3.Connection,
                     subscription_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM event_subscriptions WHERE subscription_id = ?",
        (subscription_id,)).fetchone()
    return dict(row) if row else None


def upsert_subscription(conn: sqlite3.Connection, *, subscription_id: str,
                        event_name: str, arguments_json: str,
                        callback_url: str, signing_secret_ref: str,
                        secret_sha256: str, owner: str, status: str,
                        verified_at: str | None,
                        expires_at: str | None,
                        previous_secret_ref: str | None = None,
                        previous_secret_sha256: str | None = None,
                        previous_expires_at: str | None = None) -> None:
    """Insert or replace a subscription row (deterministic ID: idempotent).

    previous_* carry the superseded secret generation for the bounded
    dual-signature window after a rotation.
    """
    conn.execute(
        "INSERT INTO event_subscriptions (subscription_id, callback_url, "
        "signing_secret_ref, status, created_at, verified_at, "
        "last_delivery_at, last_error, event_name, arguments_json, owner, "
        "expires_at, secret_sha256, previous_secret_ref, "
        "previous_secret_sha256, previous_expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(subscription_id) DO UPDATE SET "
        "callback_url=excluded.callback_url, "
        "signing_secret_ref=excluded.signing_secret_ref, status='active', "
        "verified_at=excluded.verified_at, last_error=NULL, "
        "event_name=excluded.event_name, "
        "arguments_json=excluded.arguments_json, owner=excluded.owner, "
        "expires_at=excluded.expires_at, secret_sha256=excluded.secret_sha256, "
        "previous_secret_ref=excluded.previous_secret_ref, "
        "previous_secret_sha256=excluded.previous_secret_sha256, "
        "previous_expires_at=excluded.previous_expires_at",
        (subscription_id, callback_url, signing_secret_ref, status,
         utcnow(), verified_at, None, None, event_name, arguments_json,
         owner, expires_at, secret_sha256, previous_secret_ref,
         previous_secret_sha256, previous_expires_at))
    conn.commit()


def clear_previous_generation(conn: sqlite3.Connection,
                              subscription_id: str) -> None:
    """Drop the dual-sign previous generation (after its window expires)."""
    conn.execute(
        "UPDATE event_subscriptions SET previous_secret_ref=NULL, "
        "previous_secret_sha256=NULL, previous_expires_at=NULL "
        "WHERE subscription_id = ?", (subscription_id,))
    conn.commit()


def disable_subscription(conn: sqlite3.Connection,
                         subscription_id: str) -> None:
    conn.execute(
        "UPDATE event_subscriptions SET status='disabled' "
        "WHERE subscription_id = ?", (subscription_id,))
    conn.commit()


def count_active_subscriptions(conn: sqlite3.Connection) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM event_subscriptions "
        "WHERE status='active'").fetchone()[0]


def record_delivery(conn: sqlite3.Connection, subscription_id: str) -> None:
    conn.execute(
        "UPDATE event_subscriptions SET last_delivery_at=? "
        "WHERE subscription_id = ?", (utcnow(), subscription_id))
    conn.commit()


# ---------------------------------------------------------------------------
# Phase 1: inbox_poll / inbox_ack / message_send support
# ---------------------------------------------------------------------------

class AckRejected(Exception):
    """inbox_ack refused. `reason` is a safe enum string for the caller."""

    def __init__(self, reason: str):
        super().__init__(f"ack rejected: {reason}")
        self.reason = reason


class RateLimited(Exception):
    """message_send refused: per-minute send cap hit."""


class QueueFull(Exception):
    """message_send refused: unacked backlog cap hit."""


def _ack_token_hash(token: str) -> str:
    return sha256_hex(token.encode("utf-8"))


def poll_inbox(conn: sqlite3.Connection, limit: int,
               lease_secs: int = INBOX_POLL_LEASE_SECS) -> list:
    """Deliver up to `limit` pending host_to_agent messages to the agent.

    Each returned message is leased (status pending_agent_poll) and bound
    to a fresh bearer ack_token. The token is returned in PLAINTEXT exactly
    once — only its sha256 is stored. Re-polling after lease expiry issues
    a NEW token (old token invalidated). Never logs tokens; the caller must
    not either.

    Returns a list of (message_row_dict, ack_token_plaintext) tuples.
    """
    now = utcnow()
    # Expire anything past TTL first; re-queue leases that lapsed.
    expire_old(conn)
    lease_cutoff = now
    conn.execute(
        "UPDATE messages SET status='queued', ack_token_hash=NULL, "
        "lease_until=NULL WHERE direction='host_to_agent' "
        "AND status='pending_agent_poll' AND lease_until < ?",
        (lease_cutoff,))
    rows = conn.execute(
        "SELECT * FROM messages WHERE direction='host_to_agent' "
        "AND status='queued' ORDER BY seq LIMIT ?",
        (limit,)).fetchall()
    lease_until = (datetime.now(timezone.utc) + timedelta(seconds=lease_secs)
                   ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    out = []
    for row in rows:
        token = "ack_" + secrets.token_urlsafe(32)
        conn.execute(
            "UPDATE messages SET status='pending_agent_poll', "
            "delivered_at=?, lease_until=?, ack_token_hash=? "
            "WHERE message_id=? AND status='queued'",
            (now, lease_until, _ack_token_hash(token), row["message_id"]))
        if conn.execute("SELECT changes()").fetchone()[0] == 1:
            out.append((dict(row), token))
    conn.commit()
    return out


def ack_message(conn: sqlite3.Connection, message_id: str, token: str,
                disposition: str = "processed",
                correlation_id: str | None = None) -> dict:
    """Acknowledge a leased host_to_agent message.

    Token must match the CURRENT ack_token_hash (constant-time compare).
    Acks are terminal and idempotent: re-acking an already-acked message
    with the same token is a no-op success. Anything else is AckRejected
    with a safe enum reason — never distinguishing "no such message" from
    "wrong token" in a way that aids probing.
    """
    row = get_message(conn, message_id)
    if row is None or row["direction"] != "host_to_agent":
        raise AckRejected("rejected")
    if correlation_id is not None and row["correlation_id"] != correlation_id:
        raise AckRejected("rejected")
    if not isinstance(token, str) or not token:
        raise AckRejected("rejected")
    presented = _ack_token_hash(token)
    stored = row.get("ack_token_hash") or ""
    match = hmac.compare_digest(presented, stored)
    if row["status"] == "acked":
        if not match:
            raise AckRejected("rejected")
        # P1-4: replay reports the STORED disposition, not the requested
        # one — the ack is terminal and the first disposition wins.
        prev = conn.execute(
            "SELECT disposition FROM acks WHERE message_id=? "
            "ORDER BY acked_at DESC LIMIT 1",
            (message_id,)).fetchone()
        stored_disp = (prev["disposition"] if prev and prev["disposition"]
                       else "processed")
        return {"message_id": message_id, "acked": True,
                "disposition": stored_disp, "idempotent_replay": True}
    if row["status"] != "pending_agent_poll" or not match:
        raise AckRejected("rejected")
    now = utcnow()
    conn.execute(
        "INSERT INTO acks (ack_id, message_id, acked_at, delivery_token_hash, "
        "disposition) VALUES (?,?,?,?,?)",
        ("ack_" + uuid.uuid4().hex[:24], message_id, now,
         presented, disposition))
    conn.execute(
        "UPDATE messages SET status='acked', acked_at=? WHERE message_id=?",
        (now, message_id))
    conn.commit()
    return {"message_id": message_id, "acked": True,
            "disposition": disposition, "idempotent_replay": False}


def check_send_caps(conn: sqlite3.Connection,
                    now: str | None = None) -> None:
    """Enforce message_send hard caps. Raises RateLimited / QueueFull.

    Standalone (non-atomic) version kept for tests and admin use; the
    production message_send path uses the atomic check inside enqueue().
    """
    _check_send_caps_locked(conn, now or utcnow())


def _check_send_caps_locked(conn: sqlite3.Connection, now: str) -> None:
    """Caps check to run inside an already-held write transaction."""
    try:
        minute_ago = (datetime.fromisoformat(now.replace("Z", "+00:00"))
                      - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        minute_ago = now
    recent = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE direction='agent_to_host' "
        "AND created_at >= ?", (minute_ago,)).fetchone()[0]
    if recent >= MAX_SENDS_PER_MIN:
        raise RateLimited(f"{MAX_SENDS_PER_MIN}/min cap")
    unacked = conn.execute(
        "SELECT COUNT(*) FROM messages WHERE direction='agent_to_host' "
        "AND status IN ('queued','awaiting_result')").fetchone()[0]
    if unacked >= MAX_UNACKED_AGENT_TO_HOST:
        raise QueueFull(f"{MAX_UNACKED_AGENT_TO_HOST} unacked cap")


def prune_tool_calls(conn: sqlite3.Connection,
                     days: int = TOOL_CALL_RETENTION_DAYS) -> int:
    """Delete audit rows older than `days`. Returns rows removed."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)
              ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    cur = conn.execute("DELETE FROM tool_calls WHERE ts < ?", (cutoff,))
    conn.commit()
    return cur.rowcount


def claim_delivery(conn: sqlite3.Connection, lease_secs: int = 120) -> dict | None:
    """Atomically claim one due delivery row. Returns the row or None.

    Due = pending/retry whose next_attempt_at has passed, OR a row left in
    'sending' whose lease expired (the worker crashed mid-attempt); the
    latter would otherwise be stranded forever.

    The returned dict also carries ``pre_claim``: the row's attempt
    bookkeeping (attempt_count, first_attempt_at, last_attempt_at) as it
    was before this claim, so a claim released without sending can be
    undone exactly (deliver._release_unattempted).
    """
    now = utcnow()
    lease_until = (datetime.now(timezone.utc) + timedelta(seconds=lease_secs)
                   ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if conn.in_transaction:
        conn.commit()
    # Select-then-update under one write lock: the pre-claim values read
    # here belong to exactly the row this claim updates.
    conn.execute("BEGIN IMMEDIATE")
    try:
        cand = conn.execute(
            "SELECT event_id, attempt_count, first_attempt_at, "
            "last_attempt_at FROM event_deliveries "
            "WHERE (status IN ('pending','retry') AND next_attempt_at <= ? "
            "AND (lease_until IS NULL OR lease_until < ?)) "
            "OR (status = 'sending' AND lease_until IS NOT NULL "
            "AND lease_until < ?) "
            "ORDER BY next_attempt_at LIMIT 1", (now, now, now)).fetchone()
        if cand is None:
            conn.rollback()
            return None
        conn.execute(
            "UPDATE event_deliveries SET status='sending', lease_until=?, "
            "attempt_count=attempt_count+1, last_attempt_at=?, "
            "first_attempt_at=COALESCE(first_attempt_at, ?) "
            "WHERE event_id = ?",
            (lease_until, now, now, cand["event_id"]))
        row = conn.execute(
            "SELECT * FROM event_deliveries WHERE event_id = ?",
            (cand["event_id"],)).fetchone()
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    out = dict(row)
    out["pre_claim"] = {"attempt_count": cand["attempt_count"],
                        "first_attempt_at": cand["first_attempt_at"],
                        "last_attempt_at": cand["last_attempt_at"]}
    return out

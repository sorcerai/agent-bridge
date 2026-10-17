#!/usr/bin/env python3
"""Non-AI event delivery worker for agent-bridge (phase 0 builds it,
phase 1 uses it once a subscription exists).

Reads ONE due event_deliveries row (atomic claim), signs the event body with
the subscription's secret (Standard Webhooks), and POSTs it via urllib.

Live-path note: nothing in this template enqueues event_deliveries rows,
so ``deliver_once`` is dormant. The module stays because bridge_mcp/events.py
(which performs native event delivery) imports its vetted primitives:
``public_ip_ok``, ``NoRedirect``, ``build_signature`` and
``load_signing_key``. The worker is kept aligned with events.py's safety
semantics so enabling a producer later does not reintroduce old defects:
- refuses while the bridge is frozen (checked before claiming AND again
  right before the POST; a refused row goes back to the queue unchanged);
- signs with the DECODED ``whsec_`` key (same loader as events.py), never
  the ASCII file contents;
- rows stranded in ``sending`` by a crash are reclaimed once their lease
  expires (store.claim_delivery).

Secret hygiene (P0-2/P0-3):
- The signing secret is read from the 0600 file referenced by
  event_subscriptions.signing_secret_ref. It NEVER appears in argv, env,
  logs, or error strings.
- `--dry-run` builds the headers and prints ONLY the header NAMES (never
  values) so the ps/log hygiene check can run without a live subscription.

Usage:
  deliver.py --once [--db PATH] [--dry-run]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bridge_mcp import paths, store  # noqa: E402

HTTP_TIMEOUT = 10
RETRY_DELAYS = [60, 300, 900, 3600]  # 1m, 5m, 15m, 1h, then hourly
MAX_AGE_SECS = 24 * 3600


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def next_attempt_delay(attempt_count: int) -> int:
    """Backoff 1m/5m/15m/1h then hourly, capped at 24h total."""
    if attempt_count <= len(RETRY_DELAYS):
        return RETRY_DELAYS[attempt_count - 1]
    return 3600


def public_ip_ok(host: str) -> bool:
    """Resolve host; accept only globally-routable addresses.

    Rejects private/loopback/link-local/CGNAT/multicast/reserved/
    unspecified. The explicit denylist is kept for readability; the
    ``not ip.is_global`` backstop is what actually catches ranges the
    denylist misses (notably 100.64.0.0/10 CGNAT, which ipaddress does
    NOT flag as private). Advisory when egress goes through an HTTP
    proxy — see events module docstring.
    """
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified
                or not ip.is_global):
            return False
    return True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirects not allowed (to {newurl})",
            headers, fp)


def build_signature(secret: bytes, event_id: str, ts: int, body: bytes) -> str:
    signed = f"{event_id}.{ts}.".encode("utf-8") + body
    digest = hmac.new(secret, signed, hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode("ascii")


def build_event_body(delivery: dict, message: dict) -> bytes:
    body = {
        "event_id": delivery["event_id"],
        "event_type": delivery["event_type"],
        "message_id": delivery["message_id"],
        "correlation_id": message.get("correlation_id"),
        "cursor_hint": message.get("seq"),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_secret(ref_path: str) -> bytes:
    """Read the signing secret from its 0600 file. Value never logged."""
    st = os.stat(ref_path)
    if st.st_mode & 0o077:
        raise PermissionError(f"secret file has unsafe permissions: {ref_path}")
    with open(ref_path, "rb") as f:
        return f.read().strip()


def load_signing_key(secret_ref: str) -> bytes:
    """Read a secret file and return the DECODED HMAC key bytes.

    The file holds the whsec_<base64> string; HMAC must use the decoded
    24-64 bytes, never the ASCII wrapper. Raises ValueError on any
    malformed content (PermissionError/OSError from read_secret).
    """
    raw = read_secret(secret_ref)  # bytes, stripped; never logged
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("secret file is not ASCII") from exc
    if not text.startswith("whsec_"):
        raise ValueError("secret file missing whsec_ prefix")
    try:
        key = base64.b64decode(text[len("whsec_"):], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("secret file is not valid base64") from exc
    if not 24 <= len(key) <= 64:
        raise ValueError("decoded secret not 24-64 bytes")
    return key


def bridge_frozen() -> bool:
    """Same freeze rule as events.bridge_frozen / the MCP server."""
    return os.path.exists(paths.frozen_path())


def _release_unattempted(conn, delivery: dict) -> None:
    """Put a claimed row back exactly as due, without spending an attempt.

    Restores the pre-claim attempt count AND attempt timestamps: a row
    refused (e.g. by a freeze) before any POST must not age toward the
    MAX_AGE_SECS retry budget as if it had been attempted.
    """
    pre = delivery.get("pre_claim")
    if pre is None:  # row not from claim_delivery: undo the count only
        conn.execute(
            "UPDATE event_deliveries SET status='retry', lease_until=NULL, "
            "attempt_count=MAX(attempt_count-1, 0) WHERE event_id = ?",
            (delivery["event_id"],))
    else:
        conn.execute(
            "UPDATE event_deliveries SET status='retry', lease_until=NULL, "
            "attempt_count=?, first_attempt_at=?, last_attempt_at=? "
            "WHERE event_id = ?",
            (pre["attempt_count"], pre["first_attempt_at"],
             pre["last_attempt_at"], delivery["event_id"]))
    conn.commit()


def deliver_once(conn, dry_run: bool = False) -> dict:
    """Claim one due delivery and attempt it. Returns an outcome dict with
    no secret material. Refuses (outcome "frozen") while the bridge is
    frozen."""
    if bridge_frozen():
        return {"outcome": "frozen", "reason": "bridge_frozen"}
    delivery = store.claim_delivery(conn)
    if not delivery:
        return {"outcome": "idle", "reason": "no due deliveries"}

    sub = conn.execute(
        "SELECT * FROM event_subscriptions WHERE subscription_id = ?",
        (delivery["subscription_id"],)).fetchone()
    if not sub or sub["status"] != "active":
        conn.execute(
            "UPDATE event_deliveries SET status='failed', "
            "last_error='subscription_inactive' WHERE event_id = ?",
            (delivery["event_id"],))
        conn.commit()
        return {"outcome": "failed", "reason": "subscription_inactive",
                "event_id": delivery["event_id"]}

    msg = store.get_message(conn, delivery["message_id"])
    if not msg:
        conn.execute(
            "UPDATE event_deliveries SET status='failed', "
            "last_error='message_missing' WHERE event_id = ?",
            (delivery["event_id"],))
        conn.commit()
        return {"outcome": "failed", "reason": "message_missing",
                "event_id": delivery["event_id"]}

    try:
        secret = load_signing_key(sub["signing_secret_ref"])
    except (OSError, PermissionError, ValueError) as exc:
        conn.execute(
            "UPDATE event_deliveries SET status='failed', last_error=? "
            "WHERE event_id = ?",
            (f"secret_unreadable:{type(exc).__name__}", delivery["event_id"]))
        conn.commit()
        return {"outcome": "failed", "reason": "secret_unreadable",
                "event_id": delivery["event_id"]}

    callback_url = sub["callback_url"]
    if not callback_url.startswith("https://"):
        outcome = _record_retry(conn, delivery, "callback_not_https")
        return {"outcome": outcome, "reason": "callback_not_https",
                "event_id": delivery["event_id"]}
    host = urllib.request.urlparse(callback_url).hostname or ""
    if not public_ip_ok(host):
        outcome = _record_retry(conn, delivery, "callback_ip_rejected")
        return {"outcome": outcome, "reason": "callback_ip_rejected",
                "event_id": delivery["event_id"]}

    body = build_event_body(delivery, msg)
    if store.sha256_hex(body) != delivery["body_sha256"]:
        conn.execute(
            "UPDATE event_deliveries SET status='failed', last_error='body_mismatch' "
            "WHERE event_id = ?", (delivery["event_id"],))
        conn.commit()
        return {"outcome": "failed", "reason": "body_mismatch",
                "event_id": delivery["event_id"]}

    ts = int(time.time())
    sig = build_signature(secret, delivery["event_id"], ts, body)
    # secret bytes no longer needed; drop the reference
    del secret
    headers = {
        "Content-Type": "application/json",
        "webhook-id": delivery["event_id"],
        "webhook-timestamp": str(ts),
        "webhook-signature": sig,
    }
    if dry_run:
        conn.execute(
            "UPDATE event_deliveries SET status='retry', lease_until=NULL, "
            "next_attempt_at=? WHERE event_id = ?",
            (utcnow(), delivery["event_id"]))
        conn.commit()
        return {"outcome": "dry_run", "event_id": delivery["event_id"],
                "header_names": sorted(headers.keys())}

    if bridge_frozen():
        # Frozen while this row was being prepared: send nothing.
        _release_unattempted(conn, delivery)
        return {"outcome": "frozen", "reason": "bridge_frozen",
                "event_id": delivery["event_id"]}
    req = urllib.request.Request(callback_url, data=body, headers=headers,
                                 method="POST")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:
            status = resp.getcode()
    except urllib.error.HTTPError as exc:
        status = exc.code
        outcome = _record_retry(conn, delivery, f"http_{status}", status)
        return {"outcome": outcome, "reason": f"http_{status}",
                "event_id": delivery["event_id"]}
    except Exception as exc:  # timeout, DNS, refused — enum class only
        outcome = _record_retry(conn, delivery, f"net_{type(exc).__name__}")
        return {"outcome": outcome, "reason": f"net_{type(exc).__name__}",
                "event_id": delivery["event_id"]}

    if 200 <= status < 300:
        conn.execute(
            "UPDATE event_deliveries SET status='delivered', lease_until=NULL, "
            "last_http_status=? WHERE event_id = ?",
            (status, delivery["event_id"]))
        conn.execute(
            "UPDATE event_subscriptions SET last_delivery_at=? "
            "WHERE subscription_id = ?",
            (utcnow(), delivery["subscription_id"]))
        conn.commit()
        return {"outcome": "delivered", "event_id": delivery["event_id"],
                "http_status": status}
    outcome = _record_retry(conn, delivery, f"http_{status}", status)
    return {"outcome": outcome, "reason": f"http_{status}",
            "event_id": delivery["event_id"]}


def _record_retry(conn, delivery: dict, error_class: str,
                  http_status: int | None = None) -> str:
    attempt = delivery["attempt_count"]
    created = delivery.get("first_attempt_at") or delivery["last_attempt_at"] or utcnow()
    try:
        age = (datetime.now(timezone.utc) -
               datetime.fromisoformat(created.replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        age = 0
    if age >= MAX_AGE_SECS:
        conn.execute(
            "UPDATE event_deliveries SET status='failed', lease_until=NULL, "
            "last_error='retry_budget_exhausted', last_http_status=? "
            "WHERE event_id = ?",
            (http_status, delivery["event_id"]))
        conn.commit()
        return "failed"
    delay = next_attempt_delay(attempt)
    nxt = (datetime.now(timezone.utc) + timedelta(seconds=delay)
           ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    conn.execute(
        "UPDATE event_deliveries SET status='retry', lease_until=NULL, "
        "next_attempt_at=?, last_error=?, last_http_status=? WHERE event_id = ?",
        (nxt, error_class, http_status, delivery["event_id"]))
    conn.commit()
    return "retry"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", required=True)
    ap.add_argument("--db", default=store.DEFAULT_DB)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    conn = store.connect(args.db)
    try:
        outcome = deliver_once(conn, dry_run=args.dry_run)
    finally:
        conn.close()
    # Outcome dict contains no secret material by construction.
    print(json.dumps(outcome))
    return 0 if outcome["outcome"] in ("idle", "delivered", "dry_run",
                                       "frozen") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Tool implementations for the phase-1 bridge server.

Phase 1 exposes four tools: bridge_status (health), inbox_poll (host->agent
delivery), inbox_ack (delivery acknowledgement), message_send (agent->host).

Security posture: this server performs no caller authentication of its
own. The poller (scripts/tunnel-poll.py) pins the private tools to one
x-openai-subject fingerprint BEFORE a command reaches this process, and
freezes the private tools on any other caller; the subject-watch hook
re-checks the poller log as defense in depth. Deploy it only behind that
gate, on a tunnel whose reachable callers you have verified. Every tool
call writes one audit row unless it is rejected for invalid arguments
(declared in descriptions; readOnlyHint=False).

Quarantine: every message body crossing the bridge is UNTRUSTED data, never
instructions. Bodies handed to the remote agent are wrapped in the taint
frame in the text content block; bodies handed to the host carry
taint="untrusted" explicitly.
"""
from __future__ import annotations

import json
import secrets

from . import manifest, schemas, store, taint

SERVER_VERSION = "0.3.0-events"

# Sender/recipient identities are SERVER-STAMPED, never caller input
# (review P1-7). The remote (ChatGPT) side is always "remote-agent"; the
# local side is always "host".
AGENT_SENDER = "remote-agent"
HOST_RECIPIENT = "host"

ACK_DISPOSITIONS = ("processed", "rejected")
SEND_MESSAGE_TYPES = ("reply", "request")


def _tool_result_text_blocks(summary: str, structured: dict) -> list:
    """content blocks: human summary + verbatim serialized JSON.

    Keeping the serialized JSON identical to structuredContent by
    construction (no hand-written divergence).
    """
    return [{"type": "text", "text": summary},
            {"type": "text", "text": json.dumps(structured)}]


def tool_bridge_status(conn, arguments: dict) -> dict:
    include_counts = arguments.get("include_counts", True)
    if not isinstance(include_counts, bool):
        raise schemas.ValidationError("include_counts must be boolean")
    health = store.queue_health(conn) if include_counts else {
        "host_to_agent_pending": None,
        "agent_to_host_unacked": None,
        "event_delivery_pending": None,
        "event_delivery_failed": None,
        "oldest_pending_age_secs": None,
    }
    return {
        "server_version": SERVER_VERSION,
        "time": store.utcnow(),
        # Random per-call nonce for caller attribution during the
        # access-boundary test: the tester reports the nonce they saw and
        # the operator joins it against the poller log. Not a secret.
        "probe_nonce": secrets.token_hex(8),
        "capabilities": {
            "tools": [t["name"] for t in manifest.PINNED_MANIFEST["tools"]],
            "events": {
                "available": True,
                "subscriptions_active": store.count_active_subscriptions(conn),
                # The scheduled inbox_poll fallback stays up alongside
                # events (events are an optional wake path only).
                "fallback_mode": True,
            },
        },
        "queue_health": health,
    }


def tool_inbox_poll(conn, arguments: dict) -> dict:
    """Deliver pending host_to_agent messages to the agent.

    Each message carries a one-time bearer ack_token (plaintext, returned
    exactly once). The token authorizes inbox_ack for that message_id ONLY.
    Tokens are never logged anywhere; only sha256 is stored.
    """
    limit = arguments.get("limit", 5)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise schemas.ValidationError("limit must be an integer")
    if not 1 <= limit <= store.INBOX_POLL_LIMIT_MAX:
        raise schemas.ValidationError(
            f"limit must be 1..{store.INBOX_POLL_LIMIT_MAX}")
    ack_mode = arguments.get("ack_mode", "explicit")
    if ack_mode != "explicit":
        raise schemas.ValidationError("ack_mode must be 'explicit'")

    delivered = store.poll_inbox(conn, limit)
    messages = []
    for row, token in delivered:
        messages.append({
            "message_id": row["message_id"],
            "seq": row["seq"],
            "sender": HOST_RECIPIENT,
            "recipient": AGENT_SENDER,
            "correlation_id": row["correlation_id"],
            "msg_type": row["type"],
            "taint": "untrusted",
            "payload": json.loads(row["payload_json"]),
            "ack_token": token,
            "expires_at": row["expires_at"],
        })
    return {
        "server_version": SERVER_VERSION,
        "time": store.utcnow(),
        "messages": messages,
        "queue_health": store.queue_health(conn),
    }


def inbox_poll_text(result: dict) -> str:
    """Human skim layer for inbox_poll. Every payload is wrapped in the
    quarantine frame so the model reading the text sees untrusted data as
    data, never instructions (P1-7)."""
    lines = ["inbox_poll: %d message(s)" % len(result.get("messages", []))]
    for m in result.get("messages", []):
        if not isinstance(m, dict):
            continue
        framed = taint.quarantine(
            json.dumps(m.get("payload", {}), separators=(",", ":")),
            str(m.get("sender", HOST_RECIPIENT)))
        lines.append(
            "message_id=%s seq=%s correlation_id=%s msg_type=%s\n%s\n"
            "ack_token: <issued separately in structured output — "
            "do not log or share it>" % (
                m.get("message_id"), m.get("seq"),
                m.get("correlation_id"), m.get("msg_type"), framed))
    return "\n".join(lines)


def tool_inbox_ack(conn, arguments: dict) -> dict:
    """Acknowledge a leased message. Token is bound to message_id;
    acks are terminal and idempotent."""
    message_id = arguments.get("message_id")
    schemas.check_id("message_id", message_id)
    token = arguments.get("ack_token")
    if not isinstance(token, str) or not token:
        raise schemas.ValidationError("ack_token must be a non-empty string")
    disposition = arguments.get("disposition", "processed")
    if disposition not in ACK_DISPOSITIONS:
        raise schemas.ValidationError(
            f"disposition must be one of {ACK_DISPOSITIONS}")
    correlation_id = arguments.get("correlation_id")
    if correlation_id is not None:
        schemas.check_id("correlation_id", correlation_id)
    return store.ack_message(conn, message_id, token, disposition,
                             correlation_id)


def tool_message_send(conn, arguments: dict) -> dict:
    """Enqueue an agent->host message. Direction and sender are FORCED
    server-side; the caller cannot choose them (P1-7)."""
    recipient = arguments.get("recipient")
    if recipient != HOST_RECIPIENT:
        raise schemas.ValidationError(
            f"recipient must be '{HOST_RECIPIENT}'")
    correlation_id = schemas.check_id("correlation_id",
                                      arguments.get("correlation_id"))
    idempotency_key = schemas.check_id("idempotency_key",
                                       arguments.get("idempotency_key"))
    msg_type = arguments.get("msg_type")
    if msg_type not in SEND_MESSAGE_TYPES:
        raise schemas.ValidationError(
            f"msg_type must be one of {SEND_MESSAGE_TYPES}")
    payload = schemas.check_payload(arguments.get("payload"))
    schemas.check_no_secrets(payload)
    # Atomic idempotent enqueue (P1-2, P1-3): the idempotency lookup runs
    # first inside one write transaction, so replays bypass the caps and
    # genuinely new rows check caps atomically with the insert.
    res = store.enqueue(
        conn, direction="agent_to_host", sender=AGENT_SENDER,
        recipient=HOST_RECIPIENT, correlation_id=correlation_id,
        idempotency_key=idempotency_key, msg_type=msg_type, payload=payload,
        check_caps=True)
    return {"message_id": res["message_id"],
            "idempotent_replay": res["idempotent_replay"],
            "created_at": res["created_at"]}

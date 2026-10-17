"""Input validation for agent-bridge MCP tools.

Server-side rules (plan §2.1/§3):
- correlation_id, idempotency_key: ^[A-Za-z0-9._:-]{1,128}$
- payload: <=16KB serialized, depth <=4
- `canary:` idempotency prefix reserved for the server
"""
from __future__ import annotations

import json
import re

ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_PAYLOAD_BYTES = 16 * 1024
MAX_PAYLOAD_DEPTH = 4
CANARY_PREFIX = "canary:"
DIRECTIONS = ("host_to_agent", "agent_to_host")
MESSAGE_TYPES = ("request", "reply", "result", "ping", "error")

# Credential-ish patterns refused at the host-side enqueue boundary (P1-11).
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{8,}"),
    re.compile(r"whsec_[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|bearer)\b\s*[:=]\s*\S{8,}"),
    re.compile(r"(?i)\bpassword\b\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


class ValidationError(Exception):
    pass


def check_id(name: str, value, allow_canary: bool = False) -> str:
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        raise ValidationError(f"{name} must match ^[A-Za-z0-9._:-]{{1,128}}$")
    if not allow_canary and value.startswith(CANARY_PREFIX):
        raise ValidationError(f"{name}: '{CANARY_PREFIX}' prefix is server-reserved")
    return value


def payload_depth(obj) -> int:
    """Conventional JSON depth: scalar=0, each container level adds 1."""
    if isinstance(obj, dict):
        if not obj:
            return 1
        return 1 + max(payload_depth(v) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return 1
        return 1 + max(payload_depth(v) for v in obj)
    return 0


def check_payload(payload) -> dict:
    if not isinstance(payload, dict):
        raise ValidationError("payload must be an object")
    serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise ValidationError(
            f"payload exceeds {MAX_PAYLOAD_BYTES} bytes serialized")
    if payload_depth(payload) > MAX_PAYLOAD_DEPTH:
        raise ValidationError(
            f"payload exceeds max depth {MAX_PAYLOAD_DEPTH}")
    return payload


def scan_for_secrets(text: str) -> str | None:
    """Return the name of the first matched secret pattern, else None."""
    for pat in SECRET_PATTERNS:
        if pat.search(text):
            return pat.pattern
    return None


def check_no_secrets(payload: dict) -> None:
    serialized = json.dumps(payload, ensure_ascii=True)
    hit = scan_for_secrets(serialized)
    if hit:
        raise ValidationError("payload looks like it contains credential material; refused")


def check_message_type(value) -> str:
    if value not in MESSAGE_TYPES:
        raise ValidationError(f"type must be one of {MESSAGE_TYPES}")
    return value

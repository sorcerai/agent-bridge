"""Quarantine framing for untrusted bridge content.

Every message-shaped payload that crosses the bridge is data, never
instructions. Bodies pulled by the host are wrapped so the quarantine is visible
at every read site.
"""
from __future__ import annotations


def quarantine(text: str, sender: str) -> str:
    """Wrap untrusted text in an explicit quarantine frame."""
    sender = str(sender).replace(">", "").replace("<", "")
    return f"<bridge_untrusted sender={sender}>\n{text}\n</bridge_untrusted>"


def envelope_for_read(message: dict) -> dict:
    """Shape a stored message row for host-side reads: taint is explicit."""
    return {
        "message_id": message["message_id"],
        "sender": message["sender"],
        "recipient": message["recipient"],
        "correlation_id": message["correlation_id"],
        "created_at": message["created_at"],
        "type": message["type"],
        "taint": "untrusted",
        "payload": message["payload_json"],
    }

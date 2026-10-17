#!/usr/bin/env python3
"""Phase-1 agent-bridge MCP server: stdio JSON-RPC 2.0, newline-delimited.

Exposes bridge_status, inbox_poll, inbox_ack, message_send. Events remain
disabled. Reads requests from stdin (one JSON object per line), writes
responses to stdout (one per line). All diagnostics go to stderr — stdout
is the wire and must stay clean.

Freeze gate: if the FROZEN marker exists ($BRIDGE_FROZEN_FILE, default
$BRIDGE_STATE_DIR/FROZEN; created by the poller's caller gate or the
subject-fingerprint watchdog on any unknown caller), the three private tools refuse with a
model-visible error while bridge_status keeps working. Unfreezing is
manual: rm the file and re-run the boundary check.

Startup gate: the served tools/list manifest must hash-match the pinned
manifest in manifest.py, or the server refuses to start.
"""
from __future__ import annotations

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bridge_mcp import (  # noqa: E402
    events, manifest, paths, schemas, store, taint, tools)

DB_PATH = paths.DEFAULT_DB
LOG_PATH = paths.MCP_LOG
FREEZE_PATH = paths.FREEZE_PATH

PROTOCOL_VERSION = "2025-06-18"
# Versions this server can speak. server/discover advertises these so tunnel
# clients (e.g. ChatGPT app creation) can negotiate before initialize.
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28"]


def log(msg: str) -> None:
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{store.utcnow()} {msg}\n")
    except OSError:
        pass


def err_response(req_id, code: int, message: str, data=None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _as_str(value) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _tool_names(value) -> list:
    if not isinstance(value, list):
        return []
    return [str(v)[:64] for v in value[:20]]


def _short(value, limit: int = 64) -> str:
    """Truncate caller-controlled values reflected into responses."""
    s = value if isinstance(value, str) else repr(value)
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _frozen() -> bool:
    """True when the boundary watchdog has frozen the private tools.

    The path is overridable via BRIDGE_FROZEN_FILE (tests point it at
    a temp file so the suite never observes production freeze state).
    """
    return os.path.exists(paths.frozen_path())


def _tool_error_result(text: str) -> dict:
    """Model-visible tool execution failure (result.isError), NOT a
    JSON-RPC protocol error — the model needs to read the message."""
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _capabilities() -> dict:
    """Single source of truth for advertised capabilities.

    initialize and server/discover MUST agree: both advertise tools and
    events. (P2-10: initialize used to advertise only tools.)
    """
    return {"tools": {}, "events": {}}


def _frozen_result(tool: str) -> dict:
    return _tool_error_result(
        f"tool '{tool}' is temporarily frozen: the bridge's caller-identity "
        "watchdog saw an unexpected caller fingerprint. Private messaging "
        "is suspended until the boundary is re-verified. bridge_status "
        "still works.")


def _status_text(result: dict) -> str:
    """Human-readable one-line-per-fact projection for the MCP `content` field.

    MCP's CallToolResult schema requires `content` (a list of content
    blocks); `structuredContent` alone is schema-invalid. Per the spec's
    structured-content guidance, the text block carries the serialized
    JSON too (see tools/call handler) — this summary is the human
    skim layer, not the source of truth.

    Projection rule: allowlisted public fields only, coerced to safe
    scalars. Never include raw exception text, SQL, file paths, env vars,
    request params, caller data, or payload bodies. No inference: values
    are printed as-is, never derived.
    """
    result = _as_dict(result)
    capabilities = _as_dict(result.get("capabilities"))
    events = _as_dict(capabilities.get("events"))
    queue = _as_dict(result.get("queue_health"))
    lines = [
        "agent-bridge %s @ %s" % (_as_str(result.get("server_version")),
                                   _as_str(result.get("time"))),
        "probe_nonce: %s" % _as_str(result.get("probe_nonce")),
        "tools: %s" % ", ".join(_tool_names(capabilities.get("tools"))),
        "events: available=%s fallback_mode=%s subscriptions_active=%s" % (
            _as_str(events.get("available")),
            _as_str(events.get("fallback_mode")),
            _as_str(events.get("subscriptions_active"))),
        "queue: host_to_agent_pending=%s agent_to_host_unacked=%s "
        "oldest_pending_age_secs=%s" % (
            _as_str(queue.get("host_to_agent_pending")),
            _as_str(queue.get("agent_to_host_unacked")),
            _as_str(queue.get("oldest_pending_age_secs"))),
    ]
    return "\n".join(lines)


def handle(request: dict, conn) -> dict | None:
    req_id = request.get("id")
    method = request.get("method")
    if method == "tools/call" and req_id is None:
        # P2-3: a notification-form tools/call would execute state-changing
        # code with no response channel — refuse to run it. (The poller
        # treats a None return as a notification ack.)
        log("refused notification-form tools/call")
        return None
    if method in ("events/subscribe", "events/unsubscribe") \
            and req_id is None:
        # P2-11: same rule for event mutations. A notification-form
        # subscribe/unsubscribe would mutate subscription state with no
        # request/response lifecycle — refuse, same as tools/call.
        log(f"refused notification-form {method}")
        return None
    raw_params = request.get("params")
    if raw_params is None:
        raw_params = {}
    if not isinstance(raw_params, dict):
        return err_response(req_id, -32602, "params must be an object")
    params = raw_params

    if method == "initialize":
        requested = params.get("protocolVersion")
        negotiated = requested if requested in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": negotiated,
            "capabilities": _capabilities(),
            "serverInfo": {"name": "agent-bridge", "version": tools.SERVER_VERSION},
        }}
    if method == "server/discover":
        # Tunnel-client discovery probe (SEP-2575). ChatGPT app creation
        # calls this INSTEAD of initialize; the client treats the result as
        # the InitializeResult. Must carry the full DiscoverResult shape
        # (resultType/capabilities/instructions), not just versions —
        # method-not-found or a bare version list breaks app creation.
        # The "events" capability advertises native MCP Events support;
        # ChatGPT surfaces events/list definitions on the plugin page
        # after a rescan.
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "resultType": "complete",
            "supportedVersions": SUPPORTED_VERSIONS,
            "capabilities": _capabilities(),
            "instructions": ("agent-bridge: queued messaging between a "
                             "local host agent and this agent. Tools: "
                             "bridge_status (health), inbox_poll (read "
                             "messages queued by the host), inbox_ack "
                             "(acknowledge), message_send (send to the "
                             "host). Events: bridge.ping (synthetic "
                             "connectivity probe)."),
        }}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "tools": manifest.PINNED_MANIFEST["tools"]}}
    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return err_response(req_id, -32602, "arguments must be an object")

        def _ok(result: dict, summary: str, message_ids=None) -> dict:
            # Audit write only after successful validation + execution.
            store.record_tool_call(conn, name, message_ids or [])
            return {"jsonrpc": "2.0", "id": req_id, "result": {
                # Per MCP structured-content guidance, the serialized JSON
                # rides along as a text block so every reader sees the same
                # facts; the summary is the skim layer.
                "content": [{"type": "text", "text": summary},
                            {"type": "text", "text": json.dumps(result)}],
                "structuredContent": result}}

        def _tool_fail(text: str) -> dict:
            # Model-visible failure: the caller needs the message, so this
            # is a result.isError, not a JSON-RPC protocol error. Audit it.
            store.record_tool_call(conn, name, [])
            return {"jsonrpc": "2.0", "id": req_id,
                    "result": _tool_error_result(text)}

        try:
            if name == "bridge_status":
                result = tools.tool_bridge_status(conn, arguments)
                return _ok(result, _status_text(result))
            if name in ("inbox_poll", "inbox_ack", "message_send"):
                if _frozen():
                    store.record_tool_call(conn, name, [])
                    return {"jsonrpc": "2.0", "id": req_id,
                            "result": _frozen_result(name)}
                if name == "inbox_poll":
                    result = tools.tool_inbox_poll(conn, arguments)
                    mids = [m["message_id"] for m in result["messages"]
                            if isinstance(m, dict)]
                    return _ok(result, tools.inbox_poll_text(result), mids)
                if name == "inbox_ack":
                    result = tools.tool_inbox_ack(conn, arguments)
                    text = ("inbox_ack: message_id=%s acked=%s "
                            "disposition=%s idempotent_replay=%s" % (
                                result["message_id"], result["acked"],
                                result["disposition"],
                                result["idempotent_replay"]))
                    return _ok(result, text, [result["message_id"]])
                result = tools.tool_message_send(conn, arguments)
                text = ("message_send: message_id=%s idempotent_replay=%s" % (
                    result["message_id"], result["idempotent_replay"]))
                return _ok(result, text, [result["message_id"]])
        except schemas.ValidationError as exc:
            return err_response(req_id, -32602, "invalid params",
                                {"error": str(exc)})
        except store.AckRejected as exc:
            return _tool_fail(f"inbox_ack rejected: {exc.reason}")
        except store.RateLimited:
            return _tool_fail(
                "message_send rate-limited: max "
                f"{store.MAX_SENDS_PER_MIN} sends/minute; retry shortly")
        except store.QueueFull:
            return _tool_fail(
                "message_send refused: unacked backlog at cap "
                f"({store.MAX_UNACKED_AGENT_TO_HOST}); wait for the host to "
                "catch up")
        except store.IdempotencyConflict as exc:
            return _tool_fail(
                "idempotency conflict: key already used with a different "
                f"payload (existing {exc.existing_message_id})")
        except Exception:  # never leak internals
            log("tools/call exception: " + traceback.format_exc(limit=3).replace("\n", " | "))
            return err_response(req_id, -32603, "internal error")
        return err_response(req_id, -32601, f"unknown tool: {_short(name)}")
    if method in ("events/list", "events/subscribe", "events/unsubscribe"):
        # Native MCP Events (bridge.ping isolated test scope). subscribe /
        # unsubscribe are private: the poller's synchronous caller gate
        # admits only the pinned tunnel caller (same as the private tools),
        # and the freeze file suspends them like the private tools.
        # events/list is open catalog metadata, like tools/list.
        try:
            if method == "events/list":
                result = events.events_list()
            elif method == "events/subscribe":
                if _frozen():
                    return err_response(
                        req_id, -32000, "events_frozen",
                        {"error": "events_frozen",
                         "message": "event subscriptions are temporarily "
                                    "frozen: the bridge's caller-identity "
                                    "watchdog saw an unexpected caller "
                                    "fingerprint."})
                result = events.handle_subscribe(conn, params)
            else:
                if _frozen():
                    return err_response(
                        req_id, -32000, "events_frozen",
                        {"error": "events_frozen",
                         "message": "event subscriptions are temporarily "
                                    "frozen: the bridge's caller-identity "
                                    "watchdog saw an unexpected caller "
                                    "fingerprint."})
                result = events.handle_unsubscribe(conn, params)
            store.record_tool_call(conn, method, [])
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except events.EventsError as exc:
            log(f"events {method} rejected: {exc.code}")
            return err_response(req_id, exc.code, str(exc), exc.data)
        except Exception:
            log("events exception: "
                + traceback.format_exc(limit=3).replace("\n", " | "))
            return err_response(req_id, -32603, "internal error")
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    return err_response(req_id, -32601,
                        f"method not found: {_short(method)}")


# Tools handle() can execute in this phase. main() asserts this set equals
# the pinned manifest's tool names, so wiring a tool in code without
# updating the manifest (or vice versa) refuses to start.
_ENABLED_TOOLS = ("bridge_status", "inbox_poll", "inbox_ack", "message_send")


def check_manifest_and_dispatch() -> dict:
    """Startup gates: pinned-manifest hash match AND dispatch-set match.

    Raises SystemExit on any drift. Separated from main() for testing.
    """
    served = {"tools": manifest.PINNED_MANIFEST["tools"]}
    manifest.verify_manifest(served)
    # Dispatch gate: the tools handle() can execute must equal the tools
    # the manifest advertises. Catches code wired without a manifest
    # update (the old gate compared the manifest to its own hash).
    manifest_names = {t["name"] for t in served["tools"]}
    if manifest_names != set(_ENABLED_TOOLS):
        raise SystemExit(
            f"manifest/dispatch mismatch: manifest={sorted(manifest_names)} "
            f"dispatch={sorted(_ENABLED_TOOLS)}; refusing to start")
    return served


def main() -> int:
    served = check_manifest_and_dispatch()

    conn = store.connect(DB_PATH)
    # P2-4: audit table is append-only — bound it with retention at startup.
    pruned = store.prune_tool_calls(conn)
    log(f"bridge-mcp start version={tools.SERVER_VERSION} db={DB_PATH} "
        f"pruned_tool_calls={pruned}")
    stdin = sys.stdin
    stdout = sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(err_response(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        try:
            response = handle(request, conn)
        except SystemExit:
            raise
        except Exception:
            log("handle exception: " + traceback.format_exc(limit=3).replace("\n", " | "))
            response = err_response(request.get("id"), -32603, "internal error")
        if response is not None:
            stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            stdout.flush()
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

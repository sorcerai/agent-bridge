#!/usr/bin/env python3
"""Tunnel poll loop for agent-bridge (host <-> remote ChatGPT agent).

Long-polls GET /v1/tunnels/{tunnel_id}/poll, dispatches queued JSON-RPC
commands to a persistent local MCP server child over stdio, and POSTs results
to /v1/tunnels/{tunnel_id}/response.

Wire semantics mirror the Go tunnel-client (pkg/controlplane):
- poll:        GET .../poll?limit=25&timeout_ms=30000
               204 = no commands; 200 = {"commands": [...]}
- command:     {"request_id","shard_token","command_type":"jsonrpc",
                "channel","created_at","headers","response_timeout",
                "jsonrpc": <raw JSON-RPC message>}
- response:    POST .../response
               {"request_id","channel","resp_json":<raw>,"resp_code":200,
                "resp_type":"jsonrpc_response"}
               + header X-Tunnel-Shard-Token: <shard_token> (required)
               200 = accepted; 404 = already fulfilled (also fine)
- backoff: 200ms -> 10s, factor 2, jitter; honor Retry-After
- redirects are rejected before auth material can leak elsewhere

Auth: `Authorization: Bearer $OPENAI_API_KEY`, attached only to https
requests whose host is in ALLOWED_HOSTS (redirects are rejected, so the
header can never follow a 3xx elsewhere). The key is read from the
environment at request time and is never logged; the MCP child is launched
through scripts/bridge-mcp.sh, which scrubs the environment (env -i), so the
child never inherits it.

Required configuration (the poller refuses to start without it):
- BRIDGE_TUNNEL_ID            your OpenAI Secure MCP Tunnel id
- OPENAI_API_KEY              credential for the tunnel control plane
Caller gate:
- BRIDGE_SUBJECT_FINGERPRINT  pinned x-openai-subject fingerprint (16 hex).
  UNSET = fail closed: every private call is rejected (without freezing)
  and its fingerprint is logged so the operator can capture and pin it.

Single-poller invariant: an OS advisory lock (fcntl.flock, LOCK_EX|LOCK_NB)
on the PID file, taken before the file is inspected or written and held for
the whole process lifetime. A second starter fails immediately; the lock
dies with the process, so a crashed poller never leaves a stale lock. The
PID is still written into the file for operators and the daemon hook.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import hmac
import json
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from queue import Queue, Empty
from urllib.parse import urlsplit

# Read once at import; validated by config_errors() before the poller runs.
TUNNEL_ID = os.environ.get("BRIDGE_TUNNEL_ID", "").strip()
TUNNEL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
BASE = "https://api.openai.com"
ALLOWED_HOSTS = ["api.openai.com"]
API_KEY_ENV = "OPENAI_API_KEY"
UA = "agent-bridge-poller/1.0.0"

# ---- Caller-identity gate (P0-2) ----
# Private tools are pinned to ONE caller: the x-openai-subject fingerprint
# the operator captured and configured. The poller enforces this
# SYNCHRONOUSLY at dispatch: a private tools/call whose x-openai-subject
# fingerprint is not the pinned baseline is rejected BEFORE the MCP child
# ever sees it, and FROZEN is created so the freeze persists until a human
# re-verifies the boundary. The shell watchdog remains as defense-in-depth,
# not as the primary gate. The fingerprint identifies the calling
# app/account principal as presented by the control plane, not a person.
# Unset baseline: fail closed (reject every private call, no freeze).
SUBJECT_BASELINE_FP = os.environ.get("BRIDGE_SUBJECT_FINGERPRINT",
                                     "").strip()
SUBJECT_FP_RE = re.compile(r"^[0-9a-f]{16}$")
PRIVATE_TOOLS = frozenset({"inbox_poll", "inbox_ack", "message_send"})
# Native MCP Events: subscribe/unsubscribe are private (same caller gate as
# the private tools). events/list stays open catalog metadata, like
# tools/list.
PRIVATE_EVENT_METHODS = frozenset({"events/subscribe", "events/unsubscribe"})


def gate_kind_for(method, params) -> tuple | None:
    """Pure gate decision for the synchronous caller gate (P0-2).

    Returns ("tool", name) or ("method", name) when the call is private
    (pinned to the baseline subject fingerprint), None when the method is
    open. Unit-testable without a Poller instance.

    Total function: arbitrary malformed JSON-RPC values (non-string
    methods, non-dict params, unhashable names) return None instead of
    raising — a malformed command must never kill the poller (P1-7).
    """
    if not isinstance(method, str):
        return None
    if method == "tools/call":
        name = params.get("name") if isinstance(params, dict) else None
        if isinstance(name, str) and name in PRIVATE_TOOLS:
            return ("tool", safe_tool_name(name))
    elif method in PRIVATE_EVENT_METHODS:
        return ("method", safe_method(method))
    return None
KNOWN_TOOLS = frozenset({"bridge_status"} | PRIVATE_TOOLS)
# Argument names declared in the pinned tool manifest
# (bridge_mcp/manifest.py inputSchema properties; a test keeps the two in
# sync). Only these names are ever logged; any other caller-supplied key
# collapses to a fixed "unknown:<count>" marker (review #8).
TOOL_ARG_NAMES = {
    "bridge_status": frozenset({"include_counts"}),
    "inbox_poll": frozenset({"limit", "ack_mode"}),
    "inbox_ack": frozenset({"message_id", "ack_token", "disposition",
                            "correlation_id"}),
    "message_send": frozenset({"recipient", "correlation_id",
                               "idempotency_key", "msg_type", "payload"}),
}
# Same defaults/overrides as bridge_mcp/paths.py (this script stays
# standalone and does not import the package).
STATE_DIR = os.environ.get("BRIDGE_STATE_DIR") or os.path.expanduser(
    "~/.local/state/agent-bridge")
FROZEN_FILE = os.path.join(STATE_DIR, "FROZEN")

# Log allowlists (P0-4): caller-controlled strings are NEVER logged
# verbatim. Unknown values collapse to fixed enums.
KNOWN_METHODS = frozenset({
    "initialize", "server/discover", "tools/list", "tools/call",
    "events/list", "events/subscribe", "events/unsubscribe",
    "notifications/initialized", "notifications/cancelled", "ping",
})
KNOWN_COMMAND_TYPES = frozenset({
    "jsonrpc", "oauth_discovery", "session_termination",
})
# Only these header names are fingerprinted into the log (values are
# hashed truncated SHA-256, never raw). Everything else is dropped.
LOGGABLE_HEADERS = ("x-openai-subject", "x-openai-session")

POLL_LIMIT = 25
POLL_TIMEOUT_MS = 30000          # service-side long-poll wait
POLL_GUARDRAIL_SECS = 5          # client deadline = wait + guardrail
BACKOFF_MIN = 0.2
BACKOFF_MAX = 10.0
RESPONSE_RETRY_STATUSES = {408, 429, 502, 503, 504}
RESPONSE_ATTEMPTS = 3
MCP_DISPATCH_TIMEOUT = 60

RUN_DIR = os.path.join(STATE_DIR, "run")
LOG_DIR = os.path.join(STATE_DIR, "logs")
PID_FILE = os.path.join(RUN_DIR, "tunnel-poll.pid")
HEARTBEAT_FILE = os.path.join(RUN_DIR, "tunnel-poll.heartbeat")
LOG_FILE = os.path.join(LOG_DIR, "tunnel-poll.log")
MCP_LAUNCHER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "bridge-mcp.sh")

RESPONSE_TIMEOUT_RE = re.compile(r"^([0-9]+)(ns|us|ms|s|m|h)$")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class PollerLog:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._f = open(path, "a", encoding="utf-8")
        self._lock = threading.Lock()

    def emit(self, level: str, event: str, **fields):
        # Never log: shard tokens, auth material, message/payload bodies.
        rec = {"ts": utcnow(), "level": level, "event": event}
        rec.update(fields)
        with self._lock:
            self._f.write(json.dumps(rec) + "\n")
            self._f.flush()

    def close(self):
        with self._lock:
            self._f.close()


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        # HTTP date
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
    except (ValueError, TypeError):
        return None


def backoff_delay(attempt: int) -> float:
    delay = min(BACKOFF_MAX, BACKOFF_MIN * (2 ** attempt))
    return delay * (0.5 + random.random() * 0.5)  # jitter


def parse_response_timeout(value) -> float | None:
    if not isinstance(value, str):
        return None
    m = RESPONSE_TIMEOUT_RE.match(value)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n * {"ns": 1e-9, "us": 1e-6, "ms": 1e-3, "s": 1,
                "m": 60, "h": 3600}[unit]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect rejected", headers, fp)


class MCPChild:
    """Persistent MCP server child over stdio (newline-delimited JSON-RPC)."""

    def __init__(self, log: PollerLog):
        self.log = log
        self._lock = threading.Lock()
        self._responses: dict = {}
        self._pending: set = set()  # ids with a live waiter (P1-6)
        self._cond = threading.Condition(self._lock)
        self.proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stopped = False

    def start(self):
        with self._lock:
            self._stopped = False
        self.proc = subprocess.Popen(
            ["bash", MCP_LAUNCHER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        # MCP initialize handshake
        resp = self.call({"jsonrpc": "2.0", "id": "init-1",
                          "method": "initialize",
                          "params": {"protocolVersion": "2025-06-18",
                                     "capabilities": {},
                                     "clientInfo": {"name": "agent-bridge-poller",
                                                    "version": "1.0.0"}}},
                         timeout=15)
        if resp is None or "error" in resp:
            raise RuntimeError(f"MCP initialize failed: {resp}")
        self.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.log.emit("info", "mcp_child_ready",
                      server=str(resp.get("result", {}).get("serverInfo", {}))[:120])

    def _read_loop(self):
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rid = msg.get("id")
                if rid is None:
                    continue
                with self._cond:
                    # P1-6: drop late responses — nobody is waiting for this
                    # id anymore, so retaining it would leak payload/token
                    # bytes in memory and grow without bound.
                    if rid not in self._pending:
                        continue
                    self._responses[rid] = msg
                    self._cond.notify_all()
        except (ValueError, OSError):
            pass
        finally:
            with self._cond:
                self._cond.notify_all()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def notify(self, msg: dict):
        with self._lock:
            if not self.alive():
                raise RuntimeError("mcp child not alive")
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()

    def call(self, msg: dict, timeout: float) -> dict | None:
        rid = msg.get("id")
        with self._lock:
            if not self.alive():
                raise RuntimeError("mcp child not alive")
            self._pending.add(rid)
            self._responses.pop(rid, None)
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
        try:
            deadline = time.time() + timeout
            while True:
                with self._cond:
                    if rid in self._responses:
                        break
                    remaining = deadline - time.time()
                    if remaining <= 0 or not self.alive():
                        break
                    self._cond.wait(timeout=min(remaining, 1.0))
        finally:
            # P1-6: unpend BEFORE popping, under the same lock the reader
            # uses, so a response arriving in this window is dropped rather
            # than retained. A response that arrives after the deadline is
            # dropped, never delivered to a later caller that happens to
            # reuse the same JSON-RPC id.
            with self._cond:
                self._pending.discard(rid)
                return self._responses.pop(rid, None)

    def stop(self):
        with self._lock:
            self._stopped = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.proc.kill()
                except OSError:
                    pass


def authed_request(url: str, method: str = "GET", data: bytes | None = None,
                   headers: dict | None = None) -> urllib.request.Request:
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": UA,
                                          "Accept": "application/json"})
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    # Host allowlist: the bearer key is attached only to https requests
    # for ALLOWED_HOSTS; anything else is refused before auth is added.
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise RuntimeError("refusing to attach credentials: host not allowlisted")
    key = os.environ.get(API_KEY_ENV, "")
    if not key:
        raise RuntimeError(f"{API_KEY_ENV} is not set")
    req.add_header("Authorization", f"Bearer {key}")
    return req


def config_errors() -> list:
    """Startup configuration check. Returns human-readable errors (never
    secret values); an empty list means the poller may start. An unset
    BRIDGE_SUBJECT_FINGERPRINT is NOT an error: the gate fails closed."""
    errors = []
    if not TUNNEL_ID:
        errors.append("BRIDGE_TUNNEL_ID is not set")
    elif not TUNNEL_ID_RE.match(TUNNEL_ID):
        errors.append("BRIDGE_TUNNEL_ID has unexpected characters "
                      "(expected [A-Za-z0-9_-]{1,128})")
    if not os.environ.get(API_KEY_ENV):
        errors.append(f"{API_KEY_ENV} is not set")
    if SUBJECT_BASELINE_FP and not SUBJECT_FP_RE.match(SUBJECT_BASELINE_FP):
        errors.append("BRIDGE_SUBJECT_FINGERPRINT must be 16 lowercase hex "
                      "chars (copy it from the poller log's header_fp)")
    return errors


def safe_request_id(value) -> str:
    s = str(value)
    return s[:128] if len(s) <= 128 else s[:125] + "..."


def safe_method(value) -> str:
    """Collapse caller-controlled method names to a fixed enum (P0-4)."""
    return value if isinstance(value, str) and value in KNOWN_METHODS \
        else "unknown_method"


def safe_command_type(value) -> str:
    return value if isinstance(value, str) and value in KNOWN_COMMAND_TYPES \
        else "unknown_command_type"


def safe_tool_name(value) -> str:
    """Collapse caller-controlled tool names to a fixed enum (P0-4)."""
    return value if isinstance(value, str) and value in KNOWN_TOOLS \
        else "unknown_tool"


def header_fingerprints(headers) -> dict:
    """Map allowlisted header name -> sha256(value)[:16].

    Only LOGGABLE_HEADERS are fingerprinted (names are safe to log; values
    never are). Header names are case-normalized; everything else is
    dropped, so attacker-controlled header names cannot reach the log
    (P0-4). Note: these are truncated SHA-256 fingerprints, not HMACs —
    they rely on OpenAI subject/session values being opaque and
    high-entropy (P2-2).
    """
    fp = {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            name = str(k).lower()
            if name not in LOGGABLE_HEADERS:
                continue
            digest = hashlib.sha256(
                str(v).encode("utf-8", "replace")).hexdigest()[:16]
            fp[name] = digest
    return fp


def subject_fingerprint(headers) -> str | None:
    """Fingerprint of the x-openai-subject header, or None if absent.

    Fail-closed helper for the dispatch-time caller gate (P0-2). This is
    deliberately a thin wrapper over header_fingerprints: the gate and
    the audit log MUST fingerprint the identical canonicalization of the
    value. They once diverged (the gate hashed the unwrapped raw string
    while the log hashed str(value)), so the pinned baseline could never
    match at gate time and the approved caller was rejected with
    subject_mismatch. Any fingerprint that is not the pinned baseline
    still fails the gate comparison, so missing/empty/duplicated
    subjects stay rejected via mismatch.
    """
    return header_fingerprints(headers).get("x-openai-subject")


# In-memory freeze flag (P1-8): freeze_private_tools sets this even if the
# FROZEN file cannot be created, so the poller keeps rejecting private
# calls. Loud failure is logged at the call site; the MCP child checks
# the file itself, so a file-creation failure still leaves the child
# unaware — documented in README (security model) as a residual.
_MEM_FROZEN = False


def _mem_frozen() -> bool:
    """True if the bridge is frozen (in-memory flag or FROZEN file)."""
    return _MEM_FROZEN or os.path.exists(
        os.environ.get("BRIDGE_FROZEN_FILE", FROZEN_FILE))


def freeze_private_tools() -> bool:
    """Create FROZEN atomically (O_CREAT|O_EXCL): private tools refuse
    while it exists; bridge_status keeps working. Unfreezing is manual.
    Honors BRIDGE_FROZEN_FILE like the server's freeze gate.

    Returns True when the bridge is (now) frozen. A False return means
    the file could not be created — the caller must log it loudly; the
    in-memory flag still gates this poller process.
    """
    global _MEM_FROZEN
    _MEM_FROZEN = True
    path = os.environ.get("BRIDGE_FROZEN_FILE", FROZEN_FILE)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    except OSError:
        return False
    return True


def tool_call_info(raw: dict) -> dict:
    """Safe attribution for tools/call: tool name + argument key names only.
    Never argument values, and never caller-controlled key text: only
    names declared in the manifest for that tool are logged; everything
    else is counted under a fixed "unknown:<n>" marker."""
    if raw.get("method") != "tools/call":
        return {}
    params = raw.get("params")
    if not isinstance(params, dict):
        return {}
    tool = safe_tool_name(params.get("name", ""))
    info = {"tool": tool}
    args = params.get("arguments")
    if isinstance(args, dict):
        allowed = TOOL_ARG_NAMES.get(tool, frozenset())
        known = sorted(k for k in args if isinstance(k, str) and k in allowed)
        unknown = len(args) - len(known)
        info["arg_keys"] = known + ([f"unknown:{unknown}"] if unknown else [])
    return info


def probe_nonce_of(resp) -> str | None:
    try:
        nonce = resp["result"]["structuredContent"].get("probe_nonce")
    except (KeyError, TypeError, AttributeError):
        return None
    return nonce if isinstance(nonce, str) else None


def message_ids_of(resp) -> list:
    """Allowlisted message-id attribution for phase-1 tools/call results.

    Extracts ONLY message_id strings (opaque, non-sensitive) from
    structuredContent: top-level message_id, and messages[].message_id.
    Never payload bodies, tokens, or idempotency keys.
    """
    try:
        sc = resp["result"]["structuredContent"]
    except (KeyError, TypeError, AttributeError):
        return []
    if not isinstance(sc, dict):
        return []
    ids = []
    mid = sc.get("message_id")
    if isinstance(mid, str):
        ids.append(mid[:64])
    msgs = sc.get("messages")
    if isinstance(msgs, list):
        for m in msgs[:16]:
            if isinstance(m, dict) and isinstance(m.get("message_id"), str):
                ids.append(m["message_id"][:64])
    return ids


class Poller:
    def __init__(self, log: PollerLog, max_polls: int | None = None):
        self.log = log
        self.max_polls = max_polls
        self.child = MCPChild(log)
        self._stop = threading.Event()
        self._opener = urllib.request.build_opener(NoRedirect)
        self._id_counter = 0  # unique internal JSON-RPC ids per dispatch
        self._pid_fd: int | None = None

    # ---- single-poller invariant ----
    def claim_pid(self):
        """Take the exclusive PID-file lock or refuse to start.

        The flock is acquired BEFORE the file is read or written, and the
        fd is kept open for the process lifetime (Python fds are
        non-inheritable, so the MCP child never holds it). If a previous
        holder unlinked the file between our open and our lock, we would
        hold a lock on an orphaned inode — so the locked fd must still be
        the file at PID_FILE, else retry.
        """
        os.makedirs(RUN_DIR, exist_ok=True)
        while True:
            fd = os.open(PID_FILE, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                holder = b""
                try:
                    holder = os.read(fd, 32)
                except OSError:
                    pass
                os.close(fd)
                if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN,
                                     errno.EACCES):
                    raise SystemExit(f"cannot lock PID file: {exc.strerror}")
                pid = holder.decode("ascii", "replace").strip()[:16] or "?"
                raise SystemExit(
                    f"another poller holds the PID lock (pid {pid}); "
                    "refusing to start")
            try:
                same = os.path.samestat(os.fstat(fd), os.stat(PID_FILE))
            except FileNotFoundError:
                same = False
            if same:
                break
            os.close(fd)  # raced with an exiting holder's unlink; retry
        previous = os.read(fd, 32).decode("ascii", "replace").strip()
        if previous and previous != str(os.getpid()):
            self.log.emit("warn", "stale_pidfile", pid=previous[:16])
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.fsync(fd)
        self._pid_fd = fd

    def release_pid(self):
        """Unlink the PID file, then drop the lock (in that order, so a new
        starter can never lock the inode we are about to remove)."""
        if self._pid_fd is None:
            return
        try:
            os.unlink(PID_FILE)
        except OSError:
            pass
        try:
            os.close(self._pid_fd)
        except OSError:
            pass
        self._pid_fd = None

    def heartbeat(self):
        try:
            with open(HEARTBEAT_FILE, "w") as f:
                f.write(str(int(time.time())))
        except OSError:
            pass

    # ---- poll cycle ----
    def poll_once(self, limit: int = POLL_LIMIT) -> list | None:
        """Returns command list, [] on 204/empty, None on transport failure."""
        url = (f"{BASE}/v1/tunnels/{TUNNEL_ID}/poll"
               f"?limit={limit}&timeout_ms={POLL_TIMEOUT_MS}")
        req = authed_request(url)
        deadline = POLL_TIMEOUT_MS / 1000 + POLL_GUARDRAIL_SECS
        try:
            with self._opener.open(req, timeout=deadline) as resp:
                if resp.status == 204:
                    return []
                body = resp.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            if exc.code == 204:
                return []
            raise
        try:
            envelope = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"poll body not JSON: {exc}")
        return envelope.get("commands", []) or []

    def post_response(self, request_id: str, shard_token: str, channel: str,
                      resp_json, resp_type: str = "jsonrpc_response") -> bool:
        """POST one response. True = accepted or already-fulfilled."""
        payload = {"request_id": request_id,
                   "resp_code": 200,
                   "resp_type": resp_type}
        if channel:
            payload["channel"] = channel
        if resp_json is not None:
            payload["resp_json"] = resp_json
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        attempt = 0
        while attempt < RESPONSE_ATTEMPTS:
            req = authed_request(
                f"{BASE}/v1/tunnels/{TUNNEL_ID}/response", method="POST",
                data=data,
                headers={"Content-Type": "application/json",
                         "X-Tunnel-Shard-Token": shard_token})
            try:
                with self._opener.open(req, timeout=30) as resp:
                    status = resp.status
            except urllib.error.HTTPError as exc:
                status = exc.code
                if status == 404:
                    self.log.emit("warn", "response_already_fulfilled",
                                  request_id=safe_request_id(request_id))
                    return True
                if status not in RESPONSE_RETRY_STATUSES or \
                        attempt == RESPONSE_ATTEMPTS - 1:
                    self.log.emit("error", "response_post_failed",
                                  request_id=safe_request_id(request_id),
                                  http_status=status)
                    return False
                retry_after = None
                try:
                    retry_after = parse_retry_after(exc.headers.get("Retry-After"))
                except Exception:
                    pass
                delay = retry_after if retry_after else backoff_delay(attempt)
                time.sleep(delay)
                attempt += 1
                continue
            except Exception as exc:
                if attempt == RESPONSE_ATTEMPTS - 1:
                    self.log.emit("error", "response_post_failed",
                                  request_id=safe_request_id(request_id),
                                  error_class=type(exc).__name__)
                    return False
                time.sleep(backoff_delay(attempt))
                attempt += 1
                continue
            if status == 200:
                return True
            if status == 404:
                return True
            self.log.emit("error", "response_post_failed",
                          request_id=safe_request_id(request_id),
                          http_status=status)
            return False
        return False

    def dispatch(self, cmd: dict):
        ctype = cmd.get("command_type", "")
        request_id = cmd.get("request_id", "")
        if ctype != "jsonrpc":
            # oauth_discovery / session_termination: not handled in phase 0.
            # Logged loudly (never silently dropped); the control plane will
            # time the command out on its side.
            self.log.emit("warn", "command_type_skipped",
                          command_type=safe_command_type(ctype),
                          request_id=safe_request_id(request_id))
            return
        shard_token = cmd.get("shard_token", "")
        if not shard_token or not request_id:
            self.log.emit("error", "command_missing_fields",
                          request_id=safe_request_id(request_id))
            return
        raw = cmd.get("jsonrpc")
        if not isinstance(raw, dict):
            self.log.emit("error", "command_bad_jsonrpc",
                          request_id=safe_request_id(request_id))
            return
        # Envelope attribution (P0-1): allowlisted header fingerprints
        # (never raw values), channel, and control-plane timestamp.
        # This is the only caller-distinguishing signal available.
        envelope = {
            "channel": str(cmd.get("channel", ""))[:64],
            "created_at": str(cmd.get("created_at", ""))[:32],
            "header_fp": header_fingerprints(cmd.get("headers")),
        }
        # the way back so a late response can never reach the wrong caller.
        timeout = parse_response_timeout(cmd.get("response_timeout")) \
            or MCP_DISPATCH_TIMEOUT
        # Floor: a "1ns"-style timeout is effectively zero; never dispatch
        # with less than 1s or the child can't do any work.
        timeout = min(max(timeout, 1.0), 300)
        # Id uniqueness (P1-1): one persistent child serves every caller and
        # ChatGPT sessions reuse small ids (1, 2, 3). Rewrite to an internal
        # unique id before writing to the child; restore the caller's id on
        # the way back so a late response can never reach the wrong caller.
        caller_id = raw.get("id")
        # ---- Synchronous caller gate (P0-2) ----
        # Private tools AND private event methods are pinned to the baseline
        # subject fingerprint. Missing, duplicated, malformed, or unknown
        # subjects are rejected BEFORE the MCP child ever sees the command
        # — the child never executes a private call from an unverified
        # caller. bridge_status, tools/list and events/list stay open
        # (discovery/attribution surface).
        try:
            _gate_kind = gate_kind_for(raw.get("method"), raw.get("params"))
        except Exception:
            # P1-7: a malformed command must never kill the poller. Fail
            # closed with a protocol error and keep polling.
            self.log.emit("error", "gate_decision_failed",
                          request_id=safe_request_id(request_id))
            resp = {"jsonrpc": "2.0", "id": caller_id,
                    "error": {"code": -32600,
                             "message": "invalid request"}}
            self.post_response(request_id, shard_token,
                               cmd.get("channel", ""), resp)
            return
        if _gate_kind is not None and not SUBJECT_BASELINE_FP:
            # Template bootstrap: no baseline pinned yet. Fail CLOSED —
            # reject every private call before the child sees it — but do
            # not freeze: with nothing pinned there is no "unexpected"
            # caller, only an unconfigured gate. The envelope's header_fp
            # is logged so the operator can capture and pin the
            # fingerprint of their own deliberate first call.
            _kind, _gated_name = _gate_kind
            self.log.emit(
                "error", "command_rejected_caller",
                request_id=safe_request_id(request_id),
                **{_kind: _gated_name},
                reason="subject_baseline_unset",
                **envelope)
            resp = {"jsonrpc": "2.0", "id": caller_id,
                    "error": {"code": -32001,
                              "message": "caller not authorized for "
                                         "private bridge methods"}}
            self.post_response(request_id, shard_token,
                               cmd.get("channel", ""), resp)
            return
        if _gate_kind is not None:
            _fp = subject_fingerprint(cmd.get("headers"))
            _ok_fp = _fp is not None and hmac.compare_digest(
                _fp, SUBJECT_BASELINE_FP)
            if _mem_frozen():
                # Freeze suspends private calls even for the pinned
                # caller (in-memory flag covers a failed freeze-file
                # write inside this process).
                _ok_fp = False
            if not _ok_fp:
                _freeze_ok = freeze_private_tools()
                _kind, _gated_name = _gate_kind
                if not _freeze_ok:
                    self.log.emit("error", "freeze_file_failed",
                                  request_id=safe_request_id(request_id))
                self.log.emit(
                    "error", "command_rejected_caller",
                    request_id=safe_request_id(request_id),
                    **{_kind: _gated_name},
                    reason=("missing_or_invalid_subject" if _fp is None
                            else "subject_mismatch"),
                    **envelope)
                resp = {"jsonrpc": "2.0", "id": caller_id,
                        "error": {"code": -32001,
                                  "message": "caller not authorized for "
                                             "private bridge methods"}}
                self.post_response(request_id, shard_token,
                                   cmd.get("channel", ""), resp)
                return
        child_msg = raw
        if caller_id is not None:
            self._id_counter += 1
            child_msg = dict(raw)
            child_msg["id"] = f"{request_id}#{self._id_counter}"
        try:
            if not self.child.alive():
                self.log.emit("warn", "mcp_child_dead_respawn")
                self.child.stop()
                self.child = MCPChild(self.log)
                self.child.start()
            resp = self.child.call(child_msg, timeout=timeout)
        except Exception as exc:
            self.log.emit("error", "mcp_dispatch_failed",
                          request_id=safe_request_id(request_id),
                          error_class=type(exc).__name__)
            resp = {"jsonrpc": "2.0", "id": caller_id,
                    "error": {"code": -32603, "message": "internal error"}}
        if isinstance(resp, dict) and child_msg is not raw:
            resp = dict(resp)
            resp["id"] = caller_id
        if resp is None:
            # child produced no response (notification or timeout)
            if caller_id is None:
                ok = self.post_response(request_id, shard_token,
                                        cmd.get("channel", ""), None,
                                        resp_type="jsonrpc_notify")
                self.log.emit("info" if ok else "error",
                              "command_dispatched",
                              request_id=safe_request_id(request_id),
                              posted=ok, method=safe_method(raw.get("method")),
                              is_error=False, **envelope)
            else:
                self.log.emit("error", "mcp_dispatch_timeout",
                              request_id=safe_request_id(request_id),
                              **envelope)
                resp = {"jsonrpc": "2.0", "id": caller_id,
                        "error": {"code": -32603, "message": "dispatch timeout"}}
                self.post_response(request_id, shard_token,
                                   cmd.get("channel", ""), resp)
            return
        ok = self.post_response(request_id, shard_token,
                                cmd.get("channel", ""), resp)
        fields = {"request_id": safe_request_id(request_id), "posted": ok,
                  "method": safe_method(raw.get("method")),
                  "is_error": isinstance(resp, dict) and "error" in resp,
                  **tool_call_info(raw), **envelope}
        nonce = probe_nonce_of(resp)
        if nonce:
            fields["probe_nonce"] = nonce
        mids = message_ids_of(resp)
        if mids:
            fields["message_ids"] = mids
        self.log.emit("info" if ok else "error", "command_dispatched",
                      **fields)

    def run(self):
        self.claim_pid()
        self.log.emit("info", "poller_start", tunnel_id=TUNNEL_ID,
                      pid=os.getpid())
        self.child.start()
        consecutive_errors = 0
        polls = 0
        try:
            while not self._stop.is_set():
                if self.max_polls is not None and polls >= self.max_polls:
                    break
                polls += 1
                self.heartbeat()
                try:
                    commands = self.poll_once()
                except urllib.error.HTTPError as exc:
                    status = exc.code
                    retry_after = None
                    try:
                        retry_after = parse_retry_after(
                            exc.headers.get("Retry-After"))
                    except Exception:
                        pass
                    delay = retry_after if retry_after is not None \
                        else backoff_delay(consecutive_errors)
                    consecutive_errors += 1
                    self.log.emit("warn", "poll_http_error",
                                  http_status=status,
                                  retry_in_s=round(delay, 2),
                                  consecutive_errors=consecutive_errors)
                    if self._stop.wait(delay):
                        break
                    continue
                except Exception as exc:
                    delay = backoff_delay(consecutive_errors)
                    consecutive_errors += 1
                    self.log.emit("warn", "poll_error",
                                  error_class=type(exc).__name__,
                                  retry_in_s=round(delay, 2),
                                  consecutive_errors=consecutive_errors)
                    if self._stop.wait(delay):
                        break
                    continue
                consecutive_errors = 0
                if commands:
                    self.log.emit("info", "poll_commands", count=len(commands))
                    for cmd in commands:
                        if self._stop.is_set():
                            break
                        if isinstance(cmd, dict):
                            self.dispatch(cmd)
                        else:
                            self.log.emit("warn", "command_not_object")
        finally:
            self.log.emit("info", "poller_stop")
            self.child.stop()
            self.release_pid()
            self.log.close()

    def request_stop(self):
        self._stop.set()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-polls", type=int, default=None,
                    help="stop after N poll cycles (testing)")
    args = ap.parse_args(argv)
    errors = config_errors()
    if errors:
        # Fail loudly before touching the network or the PID file.
        for err in errors:
            print(f"tunnel-poll: config error: {err}", file=sys.stderr)
        return 2
    log = PollerLog(LOG_FILE)
    if not SUBJECT_BASELINE_FP:
        log.emit("warn", "subject_baseline_unset",
                 detail="private methods will be rejected until "
                        "BRIDGE_SUBJECT_FINGERPRINT is pinned")
        print("tunnel-poll: WARNING BRIDGE_SUBJECT_FINGERPRINT unset; "
              "private methods are rejected (fail closed)", file=sys.stderr)
    poller = Poller(log, max_polls=args.max_polls)

    def on_term(signum, frame):
        poller.request_stop()

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    try:
        poller.run()
    except SystemExit as exc:
        log.emit("error", "poller_refused", reason=str(exc)[:200])
        log.close()
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

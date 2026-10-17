#!/usr/bin/env python3
"""Native MCP Events support for agent-bridge (isolated test scope).

Implements the ChatGPT MCP Events contract
(https://developers.openai.com/plugins/build/mcp-events) for ONE synthetic
event, ``bridge.ping``. Purpose: verify that the remote agent can hold a
real event subscription and be woken by it (an optional wake path).

Scope discipline:
- No changes to authentication, caller allowlists, workspace access, or the
  scheduled inbox_poll fallback. The poller's synchronous caller gate treats
  events/subscribe and events/unsubscribe as private (same as the private
  tools); events/list stays open like tools/list.
- Callback URLs and signing secrets are NEVER invented: they come only from
  ChatGPT inside an authorized events/subscribe call.
- Synthetic payloads carry no message bodies, secrets, or real tasks — only
  a random nonce, timestamps, and IDs. No instructions to the model.

Security notes:
- The signing secret is written to a 0600 file under the secrets dir and
  referenced by path; it never appears in argv, env, logs, or errors.
  Files are content-addressed generations (``<sub>.<gen>.secret``) and
  immutable once written: rotation stages the new generation, verifies it,
  then transactionally promotes it. A failed verification never touches
  the live generation. The superseded generation is retained for a short
  dual-signature window so in-flight receivers keep validating.
- The secret FILE holds the literal ``whsec_<base64>`` string ChatGPT
  supplied (single unambiguous format). Signing ALWAYS decodes it first:
  HMAC uses the decoded 24-64 bytes, never the ASCII ``whsec_`` wrapper.
- Callback verification: signed single-use challenge, 2xx + constant-time
  echo compare, cached per principal+URL for 24h. Failure -> JSON-RPC
  -32015 (CallbackEndpointError), nothing persisted.
- SSRF: https-only, hostname resolved at subscribe AND delivery time, every
  resolved address must be globally routable (private/loopback/link-local/
  CGNAT/multicast/reserved rejected), no redirects, callback response
  bodies capped at 64 KiB. A 10s wall-clock budget starts before DNS
  resolution and is enforced across connect and every body read (see
  http_post for exactly what is and is not preemptible).
  Caveat: when egress goes through an HTTP proxy, the proxy performs the
  final resolution; the local check is advisory defense-in-depth, not a
  guarantee (TOCTOU between check and connect also applies). Callback
  URLs are only safe when issued by the real platform. See README.
- Deterministic subscription IDs derive from (owner, callback URL, event
  name, canonical arguments). Owner is the constant AUTHORIZED_CALLER:
  the poller's synchronous gate guarantees only the pinned tunnel caller
  ever reaches subscribe, so no second principal can exist to collide.
- Delivery refuses while the bridge is frozen (boundary watchdog), unless
  the operator passes an explicit audited override. The freeze is
  re-checked before every retry attempt; an in-flight request cannot be
  recalled.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from bridge_mcp import paths, store
from bridge_mcp.deliver import (  # phase-0 worker's vetted primitives
    NoRedirect,
    build_signature,
    load_signing_key,
    public_ip_ok,
)

EVENT_NAME = "bridge.ping"

# The only principal that can ever reach events/subscribe: the poller's
# synchronous caller gate admits exactly the pinned x-openai-subject
# fingerprint and freezes on anything else. The subscription owner is
# therefore this constant, not a caller-supplied value.
AUTHORIZED_CALLER = "tunnel-authorized-caller"

SUBSCRIPTION_TTL_DEFAULT_SECS = 7 * 24 * 3600
SUBSCRIPTION_TTL_MAX_SECS = 30 * 24 * 3600
VERIFICATION_CACHE_SECS = 24 * 3600
HTTP_TIMEOUT_SECS = 10
MAX_EVENT_BYTES = 256 * 1024
MAX_CALLBACK_RESPONSE_BYTES = 64 * 1024
FIRE_MAX_ATTEMPTS = 3
FIRE_BACKOFF_SECS = [5, 60]
# Bounded dual-signature window after a secret rotation: the superseded
# generation stays valid this long so receivers mid-cutover keep
# validating. Deliveries during the window carry both signatures.
DUAL_SIGN_WINDOW_SECS = 3600
# Retry policy for synthetic delivery: only transient failures are
# retried. Permanent 4xx (other than the no-retry 410/413 pair) fail fast.
RETRYABLE_HTTP_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
TRANSIENT_ERROR_REASONS = frozenset({"timeout", "network_error",
                                     "deadline_exceeded"})

FREEZE_PATH = paths.FREEZE_PATH

SECRETS_DIR = paths.SECRETS_DIR


class EventsError(Exception):
    """JSON-RPC-mapped events failure. `code`/`data` go on the wire."""

    def __init__(self, code: int, message: str, data: dict | None = None):
        super().__init__(message)
        self.code = code
        self.data = data or {}


CALLBACK_ERROR = -32015  # CallbackEndpointError per the events doc


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _iso_plus(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Event catalog
# ---------------------------------------------------------------------------

EVENT_DEFINITIONS = [
    {
        "name": EVENT_NAME,
        "description": (
            "Synthetic connectivity probe for the agent-bridge wake-up "
            "test. Carries no message content, only a random nonce and "
            "timestamps. Emitted manually by the bridge operator."),
        "delivery": ["webhook"],
        "inputSchema": {
            "type": "object",
            "properties": {
                "label": {
                    "type": "string",
                    "description": "Optional operator label for the test run.",
                    "maxLength": 64,
                },
            },
            "additionalProperties": False,
        },
        "payloadSchema": {
            "type": "object",
            "properties": {
                "event_nonce": {"type": "string"},
                "emitted_at": {"type": "string"},
                "subscription_id": {"type": "string"},
                "label": {"type": "string",
                          "description": "Operator label for the test run."},
            },
            "required": ["event_nonce", "emitted_at", "subscription_id"],
            "additionalProperties": False,
        },
    },
]


def events_list() -> dict:
    return {"events": EVENT_DEFINITIONS}


# ---------------------------------------------------------------------------
# Subscription validation
# ---------------------------------------------------------------------------

def _validate_secret(secret) -> bytes:
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise EventsError(-32602, "invalid params",
                          {"reason": "secret must start with 'whsec_'"})
    raw = secret[len("whsec_"):]
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        raise EventsError(-32602, "invalid params",
                          {"reason": "secret is not valid base64"})
    if not 24 <= len(key) <= 64:
        raise EventsError(-32602, "invalid params",
                          {"reason": "secret must decode to 24-64 bytes"})
    return key


def _validate_callback_url(url) -> str:
    if not isinstance(url, str) or not url:
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery.url must be a string"})
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery.url does not parse"})
    if parts.scheme != "https":
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery.url must be https"})
    host = parts.hostname
    if not host:
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery.url has no hostname"})
    if parts.username or parts.password:
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery.url must not embed credentials"})
    # SSRF: resolve at subscribe time; every resolved address must be
    # public. (Advisory behind an egress proxy — see module
    # docstring.)
    if not public_ip_ok(host):
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery.url host does not resolve "
                                     "to a public address"})
    return url


def _validate_arguments(arguments) -> dict:
    if arguments is None:
        return {}
    if not isinstance(arguments, dict):
        raise EventsError(-32602, "invalid params",
                          {"reason": "arguments must be an object"})
    if set(arguments) - {"label"}:
        raise EventsError(-32602, "invalid params",
                          {"reason": "unknown argument keys"})
    label = arguments.get("label")
    if label is not None and (not isinstance(label, str)
                              or len(label) > 64):
        raise EventsError(-32602, "invalid params",
                          {"reason": "label must be a string <= 64 chars"})
    return {"label": label} if label is not None else {}


def subscription_id_for(callback_url: str, event_name: str,
                        arguments: dict) -> str:
    """Deterministic ID from (owner, callback URL, event name, arguments).

    Arguments are canonicalized (sorted keys) so key order never creates
    duplicate subscriptions.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)
    digest = hashlib.sha256(
        "|".join(["v1", AUTHORIZED_CALLER, callback_url, event_name,
                  canonical]).encode("utf-8")).hexdigest()
    return "sub_" + digest[:24]


# ---------------------------------------------------------------------------
# Secret generations
# ---------------------------------------------------------------------------
# The secret file holds the literal whsec_<base64> string ChatGPT supplied
# (one unambiguous format). Files are content-addressed generations:
# <sub_id>.<gen>.secret where gen = first 12 hex of sha256(whsec_string).
# Generations are IMMUTABLE once written and never overwritten in place,
# so a failed rotation can never clobber the live generation. Signing
# always decodes the file content to the raw 24-64 key bytes first —
# HMAC never uses the ASCII whsec_ wrapper.


def _secret_path(subscription_id: str, generation: str | None = None) -> str:
    safe = "".join(c for c in subscription_id
                   if c.isalnum() or c in ("-", "_"))[:64]
    if generation:
        gsafe = "".join(c for c in generation if c.isalnum())[:16]
        return os.path.join(SECRETS_DIR, f"{safe}.{gsafe}.secret")
    return os.path.join(SECRETS_DIR, safe + ".secret")


def _generation_for(secret_sha256: str) -> str:
    return secret_sha256[:12]


def write_secret_generation(subscription_id: str, secret_b64: str,
                            secret_sha256: str) -> str:
    """Atomically write one immutable secret generation (0600).

    Content-addressed: the same secret always maps to the same path, and
    an existing generation is never overwritten. Returns the path.
    """
    os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
    path = _secret_path(subscription_id, _generation_for(secret_sha256))
    if os.path.exists(path):
        return path  # identical generation already staged/live
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(secret_b64)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    return path


def _delete_file_quiet(path: str | None) -> None:
    if not path:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def delete_secret_generations(subscription_id: str,
                              *refs: str | None) -> None:
    """Delete the given generation files (unsubscribe / cleanup)."""
    for ref in refs:
        _delete_file_quiet(ref)
    # Legacy (pre-generation) single-file layout, if one ever exists.
    _delete_file_quiet(_secret_path(subscription_id))


# load_signing_key (imported from deliver.py, shared with the legacy worker)
# reads a secret file and returns the DECODED HMAC key bytes; HMAC never
# uses the ASCII whsec_ wrapper.


def bridge_frozen() -> bool:
    """True when the boundary watchdog froze the bridge (same rule as the
    MCP server's _frozen: BRIDGE_FROZEN_FILE override or the FROZEN
    file). Delivery refuses while frozen unless explicitly overridden."""
    return os.path.exists(paths.frozen_path())


# ---------------------------------------------------------------------------
# Webhook HTTP (SSRF-safe)
# ---------------------------------------------------------------------------

def _remaining(deadline: float) -> float:
    """Seconds left in the wall-clock budget; raises once it is spent."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise EventsError(CALLBACK_ERROR, "callback deadline exceeded",
                          {"reason": "deadline_exceeded"})
    return left


def _tighten_socket_timeout(fp, seconds: float) -> None:
    """Best effort: shrink the response socket's timeout to the remaining
    budget so the next blocking recv cannot outlive the deadline. Relies
    on http.client internals; silently skipped when they are absent (the
    after-read clock check in _read_capped still applies)."""
    try:
        fp.fp.raw._sock.settimeout(seconds)
    except Exception:  # noqa: BLE001 - optional hardening only
        pass


def _read_capped(fp, deadline: float) -> bytes:
    """Read at most MAX_CALLBACK_RESPONSE_BYTES+1, bounded by deadline.

    Callback responses are untrusted: an attacker-controlled endpoint must
    not be able to exhaust memory or drip-feed the single MCP child
    forever. The clock is checked before AND after every chunk; a chunk
    that lands past the deadline aborts the read (deadline_exceeded)
    rather than being accepted. ``read1`` is preferred so one call
    returns after a single socket recv instead of looping until the chunk
    size is filled. Returns the (possibly truncated) body; callers that
    need the full body treat truncation as a verification failure
    downstream.
    """
    chunks: list[bytes] = []
    total = 0
    limit = MAX_CALLBACK_RESPONSE_BYTES + 1
    reader = getattr(fp, "read1", None) or fp.read
    while total < limit:
        _tighten_socket_timeout(fp, _remaining(deadline))
        chunk = reader(min(16384, limit - total))
        _remaining(deadline)  # a chunk that arrived late is not accepted
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


class _DeadlineWatchdog:
    """Hard wall-clock bound on one delivery attempt.

    Armed as soon as the HTTP connection object exists; on expiry it
    shuts down every socket the attempt opened and closes the connection,
    so whatever receive is blocked at that moment (connect/TLS, response
    headers, body chunks, chunked trailers inside ``read1``) returns or
    raises. Clock checks between calls cannot do this: a single stdlib
    call may loop over many receives, each inside the socket timeout.
    Everything done from the timer thread swallows errors — the
    connection may be mid-connect or already closed.
    """

    def __init__(self) -> None:
        self.fired = False
        self._lock = threading.Lock()
        self._conn = None
        self._socks: list = []
        self._timer: threading.Timer | None = None

    def arm(self, conn, seconds: float) -> None:
        with self._lock:
            self._conn = conn
            self._timer = threading.Timer(seconds, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def attach(self, sock) -> None:
        """Track a socket; shut it down at once if the deadline passed."""
        with self._lock:
            self._socks.append(sock)
            fired = self.fired
        if fired:
            self._shutdown(sock)

    def cancel(self) -> None:
        with self._lock:
            timer = self._timer
        if timer is not None:
            timer.cancel()

    @staticmethod
    def _shutdown(sock) -> None:
        try:
            if isinstance(sock, ssl.SSLSocket):
                # Shut the fd down beneath the TLS layer; wakes a blocked
                # SSL read in the other thread without touching its state.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            else:
                sock.shutdown(socket.SHUT_RDWR)
        except Exception:  # noqa: BLE001 - closed/detached/not yet open
            pass

    def _fire(self) -> None:
        with self._lock:
            self.fired = True
            socks = list(self._socks)
            conn = self._conn
        for sock in socks:
            self._shutdown(sock)
        try:
            if conn is not None:
                conn.close()
        except Exception:  # noqa: BLE001 - mid-connect or already closed
            pass


class _WatchedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that reports every socket it opens to a watchdog.

    Replaces socket.create_connection, which would try each resolved
    address with the full timeout before handing a socket back: here each
    socket is attached BEFORE its connect, and each connect is capped at
    the budget still remaining.
    """

    def __init__(self, *args, watchdog: _DeadlineWatchdog, deadline: float,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self._watchdog = watchdog
        self._deadline = deadline
        self._create_connection = self._connect_bounded

    def _connect_bounded(self, address, timeout, source_address=None):
        host, port = address
        err: OSError | None = None
        for af, socktype, proto, _, sa in socket.getaddrinfo(
                host, port, 0, socket.SOCK_STREAM):
            left = _remaining(self._deadline)
            sock = socket.socket(af, socktype, proto)
            self._watchdog.attach(sock)
            try:
                sock.settimeout(left if timeout is None
                                else min(timeout, left))
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock
            except OSError as exc:
                err = exc
                sock.close()
        raise err or OSError("getaddrinfo returned no addresses")

    def connect(self):
        super().connect()
        self._watchdog.attach(self.sock)  # TLS socket the response reads


def _callback_ssl_context():
    """TLS context for callback requests. None = http.client's default
    (certificate and hostname verification on); tests substitute one."""
    return None


class _WatchedHTTPSHandler(urllib.request.HTTPSHandler):
    """Arms the deadline watchdog the moment the connection is created."""

    def __init__(self, watchdog: _DeadlineWatchdog, deadline: float):
        super().__init__(context=_callback_ssl_context())
        self._watchdog = watchdog
        self._deadline = deadline

    def https_open(self, req):
        def make_conn(*args, **kwargs):
            conn = _WatchedHTTPSConnection(*args, watchdog=self._watchdog,
                                           deadline=self._deadline, **kwargs)
            self._watchdog.arm(conn, _remaining(self._deadline))
            return conn

        return self.do_open(make_conn, req, context=self._context)


def _deadline_error() -> EventsError:
    return EventsError(CALLBACK_ERROR, "callback deadline exceeded",
                       {"reason": "deadline_exceeded"})


def http_post(url: str, body: bytes, headers: dict) -> tuple[bytes, int]:
    """POST with the documented callback protections.

    https-only, no redirects, response bodies capped at
    MAX_CALLBACK_RESPONSE_BYTES. One wall-clock budget of
    HTTP_TIMEOUT_SECS starts at entry, BEFORE the DNS/SSRF resolution:
    time spent in getaddrinfo is subtracted and the remainder is the
    socket timeout. From the moment the connection object exists a
    watchdog thread enforces that remainder as a hard limit: on expiry it
    shuts the sockets down and closes the connection, so any blocked
    receive (connect/TLS, headers, body chunks, chunked trailers) ends
    and the attempt fails as deadline_exceeded. The body read also
    re-checks the clock around every chunk. NOT preemptible: blocking
    getaddrinfo lookups — the SSRF check's (before the connection exists;
    its duration counts against the budget, so nothing is sent once it
    is spent) and the one inside connect (the watchdog fails the attempt
    as soon as it returns) — each bounded only by the system resolver's
    own timeouts. Hostname is re-resolved here (delivery
    time) and must be globally routable — advisory behind an egress
    proxy (see module docstring).
    """
    deadline = time.monotonic() + HTTP_TIMEOUT_SECS
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise EventsError(CALLBACK_ERROR, "callback not https",
                          {"reason": "callback_not_https"})
    host = parts.hostname or ""
    if not public_ip_ok(host):
        raise EventsError(CALLBACK_ERROR, "callback host rejected",
                          {"reason": "callback_ip_rejected"})
    if len(body) > MAX_EVENT_BYTES:
        raise EventsError(CALLBACK_ERROR, "event body exceeds 256 KiB",
                          {"reason": "body_too_large"})
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method="POST")
    watchdog = _DeadlineWatchdog()
    opener = urllib.request.build_opener(
        NoRedirect, _WatchedHTTPSHandler(watchdog, deadline))
    try:
        try:
            # Remaining budget after resolution (raises if DNS used it all).
            with opener.open(req, timeout=_remaining(deadline)) as resp:
                _remaining(deadline)  # headers arrived past the deadline
                data = _read_capped(resp, deadline)
                if watchdog.fired:
                    raise _deadline_error()
                return data, resp.getcode()
        except urllib.error.HTTPError as exc:
            # HTTPError still carries a status; read any body for the echo
            # check, then surface the status to the caller.
            try:
                data = _read_capped(exc, deadline)
            except Exception:
                data = b""
            if watchdog.fired:
                raise _deadline_error()
            return data, exc.code
    except EventsError:
        if watchdog.fired:
            raise _deadline_error()
        raise
    except Exception as exc:
        # Whatever the watchdog's close made the blocked call raise
        # (OSError, URLError, IncompleteRead, SSLError...) is the deadline.
        if watchdog.fired:
            raise _deadline_error()
        if isinstance(exc, (socket.timeout, TimeoutError)):
            raise EventsError(CALLBACK_ERROR, "callback request timed out",
                              {"reason": "timeout"})
        raise EventsError(CALLBACK_ERROR, "callback request failed",
                          {"reason": "network_error",
                           "error_class": type(exc).__name__})
    finally:
        watchdog.cancel()


def _signed_headers(keys: list[bytes], webhook_id: str, body: bytes,
                    subscription_id: str) -> dict:
    """Standard Webhooks headers. Timestamp AND signature are fresh per
    call — retries MUST rebuild headers (never reuse a stale pair).

    With >1 key (rotation dual-sign window), signatures are
    space-separated per the multi-signature format; receivers accept if
    any listed signature validates.
    """
    ts = int(time.time())
    sigs = " ".join(build_signature(k, webhook_id, ts, body) for k in keys)
    return {
        "Content-Type": "application/json",
        "webhook-id": webhook_id,
        "webhook-timestamp": str(ts),
        "webhook-signature": sigs,
        "X-MCP-Subscription-Id": subscription_id,
    }


# ---------------------------------------------------------------------------
# Callback verification (challenge)
# ---------------------------------------------------------------------------

def verify_callback(url: str, secret: bytes, subscription_id: str) -> None:
    """Signed single-use challenge; raises EventsError(-32015) on failure.

    Sends {"type":"verification","challenge":<random>} and requires a 2xx
    with the challenge echoed back (constant-time compare).
    """
    challenge = secrets.token_urlsafe(32)
    webhook_id = "msg_verification_" + secrets.token_hex(8)
    body = json.dumps({"type": "verification", "challenge": challenge},
                      separators=(",", ":")).encode("utf-8")
    headers = _signed_headers([secret], webhook_id, body, subscription_id)
    try:
        resp_body, status = http_post(url, body, headers)
    except EventsError:
        raise
    if not 200 <= status < 300:
        raise EventsError(CALLBACK_ERROR, "callback verification failed",
                          {"reason": "challenge_failed",
                           "http_status": status})
    try:
        echoed = json.loads(resp_body.decode("utf-8")).get("challenge")
    except Exception:
        echoed = None
    if not isinstance(echoed, str) or not hmac.compare_digest(
            echoed, challenge):
        raise EventsError(CALLBACK_ERROR, "callback verification failed",
                          {"reason": "challenge_failed"})
    # secret bytes no longer needed in this frame
    del secret


def _recently_verified(row: dict) -> bool:
    verified_at = row.get("verified_at")
    if not verified_at:
        return False
    try:
        ts = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return 0 <= age < VERIFICATION_CACHE_SECS


# ---------------------------------------------------------------------------
# events/subscribe / events/unsubscribe
# ---------------------------------------------------------------------------

def handle_subscribe(conn, params: dict) -> dict:
    if bridge_frozen():
        raise EventsError(-32000, "events_frozen",
                          {"error": "events_frozen"})
    if not isinstance(params, dict):
        raise EventsError(-32602, "invalid params",
                          {"reason": "params must be an object"})
    name = params.get("name")
    if name != EVENT_NAME:
        raise EventsError(-32602, "invalid params",
                          {"reason": f"unknown event: {name!r}"[:80]})
    arguments = _validate_arguments(params.get("arguments"))
    delivery = params.get("delivery")
    if not isinstance(delivery, dict):
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery must be an object"})
    if delivery.get("mode") != "webhook":
        raise EventsError(-32602, "invalid params",
                          {"reason": "only webhook delivery is supported"})
    callback_url = _validate_callback_url(delivery.get("url"))
    secret_key = _validate_secret(delivery.get("secret"))
    secret_b64 = delivery["secret"]  # whsec_ form, for the secret file

    if "ttlMs" not in params:
        # Omitted: server default lifetime.
        grant_secs: int | None = SUBSCRIPTION_TTL_DEFAULT_SECS
    elif params["ttlMs"] is None:
        # Explicit null: no expiration.
        grant_secs = None
    else:
        ttl_ms = params["ttlMs"]
        if not (isinstance(ttl_ms, int) and not isinstance(ttl_ms, bool)
                and ttl_ms >= 0):
            raise EventsError(-32602, "invalid params",
                              {"reason": "ttlMs must be a non-negative "
                                         "integer or null"})
        # Enforce a 60s minimum to prevent excessive refresh requests, and
        # never grant more than the server maximum.
        grant_secs = max(60, min(ttl_ms // 1000, SUBSCRIPTION_TTL_MAX_SECS))
    if grant_secs is None:
        refresh_before = None
        expires_at = None
    else:
        refresh_before = _iso_plus(grant_secs)
        expires_at = refresh_before

    sub_id = subscription_id_for(callback_url, name, arguments)
    secret_sha = hashlib.sha256(secret_b64.encode("ascii")).hexdigest()
    existing = store.get_subscription(conn, sub_id)

    secret_changed = existing is None or \
        existing.get("secret_sha256") != secret_sha
    url_changed = existing is None or \
        existing.get("callback_url") != callback_url
    need_verify = secret_changed or url_changed or \
        not (existing is not None and _recently_verified(existing))

    # STAGED rotation: the new secret goes to an immutable generation file
    # first. The live generation is never touched until verification
    # succeeds, so a failed challenge cannot destroy a working
    # subscription, and concurrent deliveries keep the old key.
    new_ref = write_secret_generation(sub_id, secret_b64, secret_sha)
    try:
        if need_verify:
            verify_callback(callback_url, secret_key, sub_id)
            verified_at = utcnow()
        else:
            verified_at = existing["verified_at"]
    except EventsError:
        # Failed verification destroys NOTHING: only the staged generation
        # is removed (and only if it isn't the live one).
        if existing is None or \
                existing.get("signing_secret_ref") != new_ref:
            _delete_file_quiet(new_ref)
        raise
    finally:
        del secret_key

    # Transactional promotion. The superseded generation enters the
    # bounded dual-signature window; any older generation is collected.
    prev_ref = prev_sha = prev_exp = None
    garbage: list[str | None] = []
    if existing is not None:
        if secret_changed:
            old_ref = existing.get("signing_secret_ref")
            if old_ref and old_ref != new_ref:
                prev_ref = old_ref
                prev_sha = existing.get("secret_sha256")
                prev_exp = _iso_plus(DUAL_SIGN_WINDOW_SECS)
            old_prev = existing.get("previous_secret_ref")
            if old_prev and old_prev not in (new_ref, prev_ref):
                garbage.append(old_prev)
        else:
            # Secret unchanged: carry the existing dual-sign window.
            prev_ref = existing.get("previous_secret_ref")
            prev_sha = existing.get("previous_secret_sha256")
            prev_exp = existing.get("previous_expires_at")

    store.upsert_subscription(
        conn, subscription_id=sub_id, event_name=name,
        arguments_json=json.dumps(arguments, sort_keys=True,
                                  separators=(",", ":")),
        callback_url=callback_url, signing_secret_ref=new_ref,
        secret_sha256=secret_sha, owner=AUTHORIZED_CALLER,
        status="active", verified_at=verified_at, expires_at=expires_at,
        previous_secret_ref=prev_ref,
        previous_secret_sha256=prev_sha,
        previous_expires_at=prev_exp)
    for ref in garbage:
        _delete_file_quiet(ref)
    return {"id": sub_id, "refreshBefore": refresh_before,
            "cursor": None, "truncated": False}


def handle_unsubscribe(conn, params: dict) -> dict:
    """Idempotent, authorized against the stored owner."""
    if not isinstance(params, dict):
        raise EventsError(-32602, "invalid params",
                          {"reason": "params must be an object"})
    name = params.get("name")
    arguments = _validate_arguments(params.get("arguments"))
    delivery = params.get("delivery") or {}
    if not isinstance(delivery, dict):
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery must be an object"})
    url = delivery.get("url")
    if not isinstance(url, str) or not url:
        raise EventsError(-32602, "invalid params",
                          {"reason": "delivery.url must be a string"})
    sub_id = subscription_id_for(url, name, arguments)
    row = store.get_subscription(conn, sub_id)
    if row is not None:
        if row.get("owner") != AUTHORIZED_CALLER:
            raise EventsError(-32602, "invalid params",
                              {"reason": "subscription owner mismatch"})
        store.disable_subscription(conn, sub_id)
        delete_secret_generations(sub_id, row.get("signing_secret_ref"),
                                  row.get("previous_secret_ref"))
    return {}


# ---------------------------------------------------------------------------
# Synthetic event emission (operator-triggered test fire)
# ---------------------------------------------------------------------------

def fire_synthetic_event(conn, subscription_id: str,
                         label: str | None = None,
                         allow_frozen: bool = False) -> dict:
    """Deliver ONE bridge.ping event to an active subscription.

    Returns {event_id, delivered, http_status, attempts, reason?}.
    Retry policy: transient failures (timeout/network/deadline, or HTTP
    408/429/5xx) get bounded backoff; permanent 4xx (incl. 410/413) fail
    fast with no retry. Timestamp+signature are rebuilt on EVERY attempt
    (never reused). While the bridge is frozen, delivery refuses unless
    the operator passes an explicit audited override; the freeze is
    re-checked before every attempt (so also after every backoff sleep)
    and aborts the remaining retries. An HTTP request already in flight
    when the freeze lands cannot be recalled.
    """
    if bridge_frozen() and not allow_frozen:
        return {"delivered": False, "reason": "bridge_frozen"}
    sub = store.get_subscription(conn, subscription_id)
    if sub is None or sub.get("status") != "active":
        return {"delivered": False, "reason": "subscription_not_active"}
    expires_at = sub.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) >= exp:
                store.disable_subscription(conn, subscription_id)
                return {"delivered": False, "reason": "subscription_expired"}
        except ValueError:
            pass
    try:
        # P0-1: the file holds the whsec_ string; HMAC needs the DECODED
        # bytes. load_signing_key enforces this (no raw-file fallback).
        # Fail fast here; per-attempt keys are rebuilt fresh below.
        load_signing_key(sub["signing_secret_ref"])
    except (OSError, PermissionError, ValueError) as exc:
        return {"delivered": False,
                "reason": f"secret_unreadable:{type(exc).__name__}"}
    # Dual-sign window: superseded generation still validates.
    prev_ref = sub.get("previous_secret_ref")
    prev_exp = sub.get("previous_expires_at")
    prev_live = False
    if prev_ref:
        try:
            pexp = datetime.fromisoformat(
                (prev_exp or "").replace("Z", "+00:00"))
            prev_live = datetime.now(timezone.utc) < pexp
        except ValueError:
            prev_live = False
        if prev_live:
            # Previous generation validated per attempt below (best
            # effort); nothing more to do here.
            pass
        else:
            # Window lapsed: collect the old generation file + row fields.
            _delete_file_quiet(prev_ref)
            store.clear_previous_generation(conn, subscription_id)

    event_id = "evt_" + secrets.token_hex(12)
    data = {"event_nonce": secrets.token_hex(16),
            "emitted_at": utcnow(),
            "subscription_id": subscription_id}
    if label:
        data["label"] = label[:64]
    event = {"eventId": event_id,
             "name": EVENT_NAME,
             "timestamp": utcnow(),
             "data": data,
             "cursor": None}
    body = json.dumps(event, separators=(",", ":")).encode("utf-8")

    attempts = 0
    delay_idx = 0
    while True:
        # Freeze is re-checked before EVERY outbound attempt, which also
        # covers the moment right after each backoff sleep: a freeze set
        # by another process mid-retry stops the remaining attempts. An
        # explicit override at creation (allow_frozen) still applies to
        # the whole call. A request already on the wire cannot be
        # recalled.
        if not allow_frozen and bridge_frozen():
            return {"event_id": event_id, "delivered": False,
                    "attempts": attempts, "reason": "bridge_frozen"}
        attempts += 1
        # Fresh timestamp + signature every attempt (P1-5).
        attempt_keys = [load_signing_key(sub["signing_secret_ref"])]
        if prev_live:
            try:
                attempt_keys.append(load_signing_key(prev_ref))
            except (OSError, PermissionError, ValueError):
                pass
        headers = _signed_headers(attempt_keys, event_id, body,
                                  subscription_id)
        try:
            _, status = http_post(sub["callback_url"], body, headers)
        except EventsError as exc:
            reason = (exc.data or {}).get("reason", "callback_error")
            if reason in TRANSIENT_ERROR_REASONS \
                    and delay_idx < len(FIRE_BACKOFF_SECS):
                time.sleep(FIRE_BACKOFF_SECS[delay_idx])
                delay_idx += 1
                continue
            return {"event_id": event_id, "delivered": False,
                    "attempts": attempts, "reason": reason}
        if 200 <= status < 300:
            store.record_delivery(conn, subscription_id)
            return {"event_id": event_id, "delivered": True,
                    "http_status": status, "attempts": attempts}
        if status in (410, 413):
            return {"event_id": event_id, "delivered": False,
                    "http_status": status, "attempts": attempts,
                    "reason": "no_retry_status"}
        if status in RETRYABLE_HTTP_STATUSES \
                and delay_idx < len(FIRE_BACKOFF_SECS):
            time.sleep(FIRE_BACKOFF_SECS[delay_idx])
            delay_idx += 1
            continue
        return {"event_id": event_id, "delivered": False,
                "http_status": status, "attempts": attempts,
                "reason": "retry_budget_exhausted" if status in
                RETRYABLE_HTTP_STATUSES else f"http_{status}"}

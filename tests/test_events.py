#!/usr/bin/env python3
"""Hermetic unit tests for native MCP Events (bridge.ping isolated test).

No network. Temp DBs only. The webhook HTTP layer and DNS checks are
monkeypatched; secret files go to a temp dir.

Run: python3 tests/test_events.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import importlib.util
import json
import os
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Hermetic: drop every inherited BRIDGE_* variable and FORCE test-owned
# state/db/log/hook/freeze paths before any bridge module is imported. No
# test may read, write or delete the operator's real freeze marker.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _hermetic  # noqa: E402,F401

from bridge_mcp import events, server, store  # noqa: E402

_POLL_PATH = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "scripts", "tunnel-poll.py")
_spec = importlib.util.spec_from_file_location("tunnel_poll", _POLL_PATH)
tunnel_poll = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tunnel_poll)


def make_conn():
    d = tempfile.mkdtemp(prefix="bridge-events-test-")
    return store.connect(os.path.join(d, "test.db"))


def make_secret(nbytes=32):
    return "whsec_" + base64.b64encode(os.urandom(nbytes)).decode("ascii")


class ChallengeServer:
    """Fake ChatGPT callback: echoes the verification challenge."""

    def __init__(self, fail=False, http_status=200):
        self.calls = 0
        self.fail = fail
        self.http_status = http_status
        self.last_headers = None
        self.last_url = None

    def __call__(self, url, body, headers):
        self.calls += 1
        self.last_url = url
        self.last_headers = dict(headers)
        payload = json.loads(body.decode("utf-8"))
        if payload.get("type") == "verification" and not self.fail:
            echo = {"challenge": payload["challenge"]}
        else:
            echo = {"challenge": "wrong"} if self.fail else {"ok": True}
        return json.dumps(echo).encode("utf-8"), self.http_status


class EventsTestBase(unittest.TestCase):
    def setUp(self):
        self.conn = make_conn()
        self._tmp = tempfile.mkdtemp(prefix="bridge-events-secrets-")
        self._old_secrets = events.SECRETS_DIR
        events.SECRETS_DIR = self._tmp
        # DNS/SSRF check passes by default; individual tests override.
        self._old_ipok = events.public_ip_ok
        events.public_ip_ok = lambda host: True
        self._old_http = events.http_post
        self._old_backoff = events.FIRE_BACKOFF_SECS
        events.FIRE_BACKOFF_SECS = [0, 0]

    def tearDown(self):
        events.SECRETS_DIR = self._old_secrets
        events.public_ip_ok = self._old_ipok
        events.http_post = self._old_http
        events.FIRE_BACKOFF_SECS = self._old_backoff
        self.conn.close()

    def subscribe_params(self, **kw):
        p = {"name": "bridge.ping",
             "arguments": {},
             "delivery": {"mode": "webhook",
                          "url": "https://events.example.com/cb/1",
                          "secret": make_secret()}}
        p.update(kw)
        return p

    def do_subscribe(self, srv=None, **kw):
        srv = srv if srv is not None else ChallengeServer()
        events.http_post = srv
        return events.handle_subscribe(self.conn, self.subscribe_params(**kw)), srv


class EventsListTest(EventsTestBase):
    def test_list_returns_bridge_ping_definition(self):
        result = events.events_list()
        self.assertEqual(len(result["events"]), 1)
        d = result["events"][0]
        self.assertEqual(d["name"], "bridge.ping")
        self.assertEqual(d["delivery"], ["webhook"])
        self.assertIn("description", d)
        for key in ("type", "properties", "additionalProperties"):
            self.assertIn(key, d["inputSchema"])
            self.assertIn(key, d["payloadSchema"])
        self.assertEqual(
            set(d["payloadSchema"]["required"]),
            {"event_nonce", "emitted_at", "subscription_id"})

    def test_server_routes_events_list(self):
        resp = server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "events/list",
             "params": {}}, self.conn)
        self.assertEqual(resp["result"]["events"][0]["name"], "bridge.ping")

    def test_discover_advertises_events_capability(self):
        resp = server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover",
             "params": {}}, self.conn)
        self.assertIn("events", resp["result"]["capabilities"])


class SubscribeValidationTest(EventsTestBase):
    def test_unknown_event_rejected(self):
        with self.assertRaises(events.EventsError) as cm:
            events.handle_subscribe(self.conn, self.subscribe_params(
                name="message.created"))
        self.assertEqual(cm.exception.code, -32602)

    def test_secret_must_have_whsec_prefix(self):
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                delivery={"mode": "webhook",
                          "url": "https://events.example.com/cb/1",
                          "secret": "not-a-whsec-secret"}))

    def test_secret_must_be_valid_base64(self):
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                delivery={"mode": "webhook",
                          "url": "https://events.example.com/cb/1",
                          "secret": "whsec_!!!notbase64!!!"}))

    def test_secret_byte_length_bounds(self):
        short = "whsec_" + base64.b64encode(b"x" * 16).decode("ascii")
        long = "whsec_" + base64.b64encode(b"x" * 65).decode("ascii")
        for bad in (short, long):
            with self.assertRaises(events.EventsError):
                events.handle_subscribe(self.conn, self.subscribe_params(
                    delivery={"mode": "webhook",
                              "url": "https://events.example.com/cb/1",
                              "secret": bad}))

    def test_callback_must_be_https(self):
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                delivery={"mode": "webhook",
                          "url": "http://events.example.com/cb/1",
                          "secret": make_secret()}))

    def test_callback_rejects_private_host(self):
        events.public_ip_ok = lambda host: False
        with self.assertRaises(events.EventsError) as cm:
            events.handle_subscribe(self.conn, self.subscribe_params())
        self.assertIn("public", str(cm.exception.data.get("reason", "")))

    def test_callback_rejects_userinfo(self):
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                delivery={"mode": "webhook",
                          "url": "https://user:pass@events.example.com/cb",
                          "secret": make_secret()}))

    def test_delivery_mode_must_be_webhook(self):
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                delivery={"mode": "polling",
                          "url": "https://events.example.com/cb/1",
                          "secret": make_secret()}))

    def test_arguments_schema_enforced(self):
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                arguments={"nope": 1}))
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                arguments={"label": "x" * 65}))

    def test_ttl_ms_must_be_non_negative_int(self):
        with self.assertRaises(events.EventsError):
            events.handle_subscribe(self.conn, self.subscribe_params(
                ttlMs="soon"))

    def test_verification_failure_returns_32015_and_persists_nothing(self):
        srv = ChallengeServer(fail=True)
        events.http_post = srv
        with self.assertRaises(events.EventsError) as cm:
            events.handle_subscribe(self.conn, self.subscribe_params())
        self.assertEqual(cm.exception.code, -32015)
        self.assertEqual(cm.exception.data.get("reason"), "challenge_failed")
        self.assertEqual(store.count_active_subscriptions(self.conn), 0)
        # Secret file removed on failure.
        self.assertEqual(os.listdir(self._tmp), [])


class SubscribeSuccessTest(EventsTestBase):
    def test_subscribe_returns_id_and_refresh_before(self):
        result, srv = self.do_subscribe()
        self.assertTrue(result["id"].startswith("sub_"))
        self.assertIsNotNone(result["refreshBefore"])
        self.assertIsNone(result["cursor"])
        self.assertFalse(result["truncated"])
        row = store.get_subscription(self.conn, result["id"])
        self.assertEqual(row["status"], "active")
        self.assertEqual(row["event_name"], "bridge.ping")
        self.assertEqual(row["owner"], events.AUTHORIZED_CALLER)
        self.assertIsNotNone(row["verified_at"])
        # Secret stored as 0600 file, never in the row.
        st = os.stat(row["signing_secret_ref"])
        self.assertEqual(st.st_mode & 0o777, 0o600)
        with open(row["signing_secret_ref"], encoding="ascii") as f:
            self.assertTrue(f.read().startswith("whsec_"))
        # Challenge was actually sent with the required headers.
        self.assertIn("webhook-signature", srv.last_headers)
        self.assertIn("X-MCP-Subscription-Id", srv.last_headers)
        self.assertEqual(srv.last_headers["X-MCP-Subscription-Id"],
                         result["id"])

    def test_deterministic_id_and_idempotent_resubscribe(self):
        r1, srv = self.do_subscribe()
        r2, _ = self.do_subscribe()
        self.assertEqual(r1["id"], r2["id"])
        self.assertEqual(store.count_active_subscriptions(self.conn), 1)
        # Second subscribe hit the verification cache: one challenge total.
        self.assertEqual(srv.calls, 1)

    def test_argument_key_order_does_not_duplicate(self):
        p1 = self.subscribe_params(arguments={"label": "a"})
        p2 = self.subscribe_params(
            arguments=dict([("label", "a")]))  # same content
        s1 = ChallengeServer()
        events.http_post = s1
        r1 = events.handle_subscribe(self.conn, p1)
        s2 = ChallengeServer()
        events.http_post = s2
        r2 = events.handle_subscribe(self.conn, p2)
        self.assertEqual(r1["id"], r2["id"])
        self.assertEqual(store.count_active_subscriptions(self.conn), 1)

    def test_different_arguments_different_id(self):
        r1, _ = self.do_subscribe(arguments={"label": "one"})
        r2, _ = self.do_subscribe(arguments={"label": "two"})
        self.assertNotEqual(r1["id"], r2["id"])

    def test_secret_rotation_reverifies(self):
        r1, srv = self.do_subscribe()
        params = self.subscribe_params()
        params["delivery"] = dict(params["delivery"])
        params["delivery"]["secret"] = make_secret()  # new secret, same URL
        events.http_post = srv
        events.handle_subscribe(self.conn, params)
        self.assertEqual(srv.calls, 2)  # re-challenged on secret change

    def test_ttl_ms_grants_bounded_lifetime(self):
        result, _ = self.do_subscribe(ttlMs=3_600_000)
        row = store.get_subscription(self.conn, result["id"])
        self.assertIsNotNone(row["expires_at"])
        self.assertEqual(result["refreshBefore"], row["expires_at"])

    def test_ttl_ms_null_grants_no_expiration(self):
        result, _ = self.do_subscribe(ttlMs=None)
        self.assertIsNone(result["refreshBefore"])
        row = store.get_subscription(self.conn, result["id"])
        self.assertIsNone(row["expires_at"])


class UnsubscribeTest(EventsTestBase):
    def _sub_id(self):
        result, _ = self.do_subscribe()
        return result["id"]

    def test_unsubscribe_disables_and_removes_secret(self):
        sub_id = self._sub_id()
        row = store.get_subscription(self.conn, sub_id)
        secret_path = row["signing_secret_ref"]
        self.assertTrue(os.path.exists(secret_path))
        result = events.handle_unsubscribe(
            self.conn, {"name": "bridge.ping", "arguments": {},
                        "delivery": {"mode": "webhook",
                                     "url": "https://events.example.com/cb/1"}})
        self.assertEqual(result, {})
        self.assertEqual(
            store.get_subscription(self.conn, sub_id)["status"], "disabled")
        self.assertFalse(os.path.exists(secret_path))
        self.assertEqual(store.count_active_subscriptions(self.conn), 0)

    def test_unsubscribe_idempotent_on_missing(self):
        result = events.handle_unsubscribe(
            self.conn, {"name": "bridge.ping", "arguments": {},
                        "delivery": {"mode": "webhook",
                                     "url": "https://events.example.com/none"}})
        self.assertEqual(result, {})

    def test_unsubscribe_owner_mismatch_rejected(self):
        sub_id = self._sub_id()
        self.conn.execute(
            "UPDATE event_subscriptions SET owner='someone-else' "
            "WHERE subscription_id=?", (sub_id,))
        self.conn.commit()
        with self.assertRaises(events.EventsError):
            events.handle_unsubscribe(
                self.conn, {"name": "bridge.ping", "arguments": {},
                            "delivery": {"mode": "webhook",
                                         "url": "https://events.example.com/cb/1"}})


class SignatureTest(unittest.TestCase):
    def test_standard_webhooks_vector(self):
        from bridge_mcp.deliver import build_signature
        secret = base64.b64decode("dGVzdHNlY3JldHRlc3RzZWNyZXR0ZXN0c2VjcmV0")
        sig = build_signature(secret, "msg_123", 1614265330, b'{"a":1}')
        self.assertTrue(sig.startswith("v1,"))
        expected = "v1," + base64.b64encode(hmac.new(
            secret, b"msg_123.1614265330." + b'{"a":1}',
            hashlib.sha256).digest()).decode("ascii")
        self.assertEqual(sig, expected)


class FireTest(EventsTestBase):
    def _active_sub(self):
        result, _ = self.do_subscribe()
        return result["id"]

    def test_fire_delivers_signed_event(self):
        sub_id = self._active_sub()
        srv = ChallengeServer()
        events.http_post = srv
        outcome = events.fire_synthetic_event(self.conn, sub_id,
                                              label="wake-test-1")
        self.assertTrue(outcome["delivered"])
        self.assertEqual(outcome["http_status"], 200)
        self.assertTrue(outcome["event_id"].startswith("evt_"))
        # Headers carry identity + signature, never the secret.
        self.assertEqual(srv.last_headers["X-MCP-Subscription-Id"], sub_id)
        self.assertEqual(srv.last_headers["webhook-id"], outcome["event_id"])
        self.assertTrue(
            srv.last_headers["webhook-signature"].startswith("v1,"))

    def test_fire_no_retry_on_410(self):
        sub_id = self._active_sub()
        srv = ChallengeServer(http_status=410)
        events.http_post = srv
        outcome = events.fire_synthetic_event(self.conn, sub_id)
        self.assertFalse(outcome["delivered"])
        self.assertEqual(outcome["http_status"], 410)
        self.assertEqual(outcome["attempts"], 1)
        self.assertEqual(srv.calls, 1)

    def test_fire_retries_transient_then_gives_up(self):
        sub_id = self._active_sub()
        srv = ChallengeServer(http_status=500)
        events.http_post = srv
        outcome = events.fire_synthetic_event(self.conn, sub_id)
        self.assertFalse(outcome["delivered"])
        self.assertEqual(outcome["attempts"], 3)
        self.assertEqual(outcome["reason"], "retry_budget_exhausted")

    def test_fire_refuses_inactive_subscription(self):
        outcome = events.fire_synthetic_event(self.conn, "sub_nope")
        self.assertFalse(outcome["delivered"])
        self.assertEqual(outcome["reason"], "subscription_not_active")


class MigrationV3Test(unittest.TestCase):
    def test_v2_db_gains_event_columns(self):
        d = tempfile.mkdtemp(prefix="bridge-events-mig-")
        path = os.path.join(d, "test.db")
        raw = __import__("sqlite3").connect(path)
        with open(os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "sql", "001_init.sql"),
                encoding="utf-8") as f:
            raw.executescript(f.read())
        raw.execute("PRAGMA user_version=2")
        raw.commit()
        raw.close()
        conn = store.connect(path)
        try:
            ver = conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(ver, store.SCHEMA_VERSION)
            cols = {r[1] for r in conn.execute(
                "PRAGMA table_info(event_subscriptions)")}
            self.assertTrue(
                {"event_name", "arguments_json", "owner", "expires_at",
                 "secret_sha256", "previous_secret_ref",
                 "previous_secret_sha256", "previous_expires_at"} <= cols,
                f"missing event columns: {cols}")
        finally:
            conn.close()


class PollerGateTest(unittest.TestCase):
    def test_private_event_methods_gated(self):
        for method in ("events/subscribe", "events/unsubscribe"):
            kind = tunnel_poll.gate_kind_for(method, {})
            self.assertEqual(kind, ("method", method))

    def test_events_list_open(self):
        self.assertIsNone(tunnel_poll.gate_kind_for("events/list", {}))

    def test_private_tools_still_gated(self):
        for tool in ("inbox_poll", "inbox_ack", "message_send"):
            kind = tunnel_poll.gate_kind_for(
                "tools/call", {"name": tool, "arguments": {}})
            self.assertEqual(kind, ("tool", tool))

    def test_open_methods_ungated(self):
        for method, params in (
                ("tools/call", {"name": "bridge_status"}),
                ("tools/list", {}),
                ("server/discover", {}),
                ("initialize", {}),
                ("ping", {})):
            self.assertIsNone(tunnel_poll.gate_kind_for(method, params))


class BridgeStatusEventsTest(EventsTestBase):
    def test_status_reports_events_available(self):
        from bridge_mcp import tools
        result = tools.tool_bridge_status(self.conn, {})
        ev = result["capabilities"]["events"]
        self.assertTrue(ev["available"])
        self.assertTrue(ev["fallback_mode"])
        self.assertEqual(ev["subscriptions_active"], 0)
        self._active_sub_via_server()

    def _active_sub_via_server(self):
        from bridge_mcp import tools
        self.do_subscribe()
        result = tools.tool_bridge_status(self.conn, {})
        self.assertEqual(
            result["capabilities"]["events"]["subscriptions_active"], 1)


def _sub_params(secret, url="https://events.example.test/cb"):
    return {"name": "bridge.ping", "arguments": {"label": "reg"},
            "delivery": {"mode": "webhook", "url": url, "secret": secret},
            "ttlMs": 3600000}


def _independent_sig(key: bytes, webhook_id: str, ts: str,
                     body: bytes) -> str:
    """Signature computed WITHOUT events.build_signature: the true
    cross-check for P0-1 (would fail if the raw whsec_ file bytes were
    used as the HMAC key)."""
    mac = hmac.new(key, webhook_id.encode() + b"." + ts.encode()
                   + b"." + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode("ascii")


class EventsReviewRegressionTest(EventsTestBase):
    """Regression tests for the gpt-6.1-sol review findings (2026-09-30).

    Each test targets one upheld finding: P0-1 (decoded signing key),
    P0-2 (staged rotation), P0-3 (CGNAT), P1-4 (bounded reads), P1-5
    (retry policy + fresh headers), P1-6 (dual-sign), P1-7 (malformed
    input), P1-8 (freeze), P1-9 (proxy sanitizer), P2-10/P2-11.
    """

    def _subscribe(self, secret=None, url="https://events.example.test/cb"):
        secret = secret or make_secret()
        events.http_post = ChallengeServer()
        try:
            sub = events.handle_subscribe(
                self.conn, _sub_params(secret, url))
        finally:
            events.http_post = self._old_http
        return sub, secret

    # -- P0-1: delivery signs with the DECODED key -------------------------
    def test_signature_uses_decoded_key(self):
        sub, secret = self._subscribe()
        captured = {}

        def cap(url, body, headers):
            captured.update(body=body, headers=dict(headers))
            return b'{"ok":true}', 200

        events.http_post = cap
        try:
            out = events.fire_synthetic_event(self.conn, sub["id"])
        finally:
            events.http_post = self._old_http
        self.assertTrue(out["delivered"], out)
        hdrs = captured["headers"]
        key = base64.b64decode(secret[len("whsec_"):])
        self.assertEqual(
            hdrs["webhook-signature"],
            _independent_sig(key, hdrs["webhook-id"],
                             hdrs["webhook-timestamp"], captured["body"]))

    # -- P0-2: failed rotation preserves the live subscription --------------
    def test_failed_rotation_preserves_live_secret(self):
        sub, secret = self._subscribe()
        row = store.get_subscription(self.conn, sub["id"])
        live_ref = row["signing_secret_ref"]
        self.assertTrue(os.path.exists(live_ref))
        with open(live_ref, encoding="ascii") as f:
            self.assertEqual(f.read(), secret)

        new_secret = make_secret()
        events.http_post = ChallengeServer(fail=True)  # challenge fails
        try:
            with self.assertRaises(events.EventsError):
                events.handle_subscribe(
                    self.conn, _sub_params(new_secret))
        finally:
            events.http_post = self._old_http

        # Live generation untouched; row still points at it; fire works.
        self.assertTrue(os.path.exists(live_ref))
        with open(live_ref, encoding="ascii") as f:
            self.assertEqual(f.read(), secret)
        row2 = store.get_subscription(self.conn, sub["id"])
        self.assertEqual(row2["signing_secret_ref"], live_ref)
        self.assertEqual(row2["status"], "active")
        self.assertIsNone(row2["previous_secret_ref"])
        # Only the live generation file remains in the secrets dir.
        files = os.listdir(self._tmp)
        self.assertEqual(files, [os.path.basename(live_ref)], files)

    # -- P1-6: dual-signature window after rotation -------------------------
    def test_rotation_dual_signs_both_generations(self):
        sub, secret_a = self._subscribe()
        secret_b = make_secret()
        events.http_post = ChallengeServer()
        try:
            sub2 = events.handle_subscribe(
                self.conn, _sub_params(secret_b))
        finally:
            events.http_post = self._old_http
        self.assertEqual(sub2["id"], sub["id"])
        row = store.get_subscription(self.conn, sub["id"])
        self.assertIsNotNone(row["previous_secret_ref"])
        self.assertNotEqual(row["previous_secret_ref"],
                            row["signing_secret_ref"])
        self.assertTrue(os.path.exists(row["previous_secret_ref"]))

        captured = {}

        def cap(url, body, headers):
            captured.update(body=body, headers=dict(headers))
            return b'{"ok":true}', 200

        events.http_post = cap
        try:
            out = events.fire_synthetic_event(self.conn, sub["id"])
        finally:
            events.http_post = self._old_http
        self.assertTrue(out["delivered"], out)
        sigs = captured["headers"]["webhook-signature"].split(" ")
        self.assertEqual(len(sigs), 2, sigs)
        hdrs = captured["headers"]
        key_b = base64.b64decode(secret_b[len("whsec_"):])
        key_a = base64.b64decode(secret_a[len("whsec_"):])
        expected = {
            _independent_sig(key_b, hdrs["webhook-id"],
                             hdrs["webhook-timestamp"], captured["body"]),
            _independent_sig(key_a, hdrs["webhook-id"],
                             hdrs["webhook-timestamp"], captured["body"]),
        }
        self.assertEqual(set(sigs), expected)

    def test_generations_are_immutable(self):
        secret = make_secret()
        sha = hashlib.sha256(secret.encode("ascii")).hexdigest()
        p1 = events.write_secret_generation("sub_x", secret, sha)
        p2 = events.write_secret_generation("sub_x", secret, sha)
        self.assertEqual(p1, p2)
        with open(p1, encoding="ascii") as f:
            self.assertEqual(f.read(), secret)
        p3 = events.write_secret_generation("sub_x", make_secret(),
                                            hashlib.sha256(b"z").hexdigest())
        self.assertNotEqual(p1, p3)

    # -- P0-3: CGNAT and friends rejected -----------------------------------
    def test_cgnat_and_special_ranges_rejected(self):
        from bridge_mcp import deliver

        def fake_gai(ip):
            return [(2, 1, 6, "", (ip, 443))]

        for bad in ("100.64.0.1", "100.127.255.255", "10.0.0.1",
                    "192.168.1.1", "127.0.0.1", "169.254.1.1",
                    "224.0.0.1", "0.0.0.0", "::1", "fc00::1",
                    "192.0.2.1", "198.18.0.1"):
            with mock.patch.object(
                    deliver.socket, "getaddrinfo",
                    side_effect=lambda h, p, type=None: fake_gai(bad)):
                self.assertFalse(deliver.public_ip_ok("x.test"), bad)
        with mock.patch.object(
                deliver.socket, "getaddrinfo",
                side_effect=lambda h, p, type=None: fake_gai("8.8.8.8")):
            self.assertTrue(deliver.public_ip_ok("x.test"))

    # -- P1-5: retry policy + fresh timestamp/signature per attempt ---------
    def _capture_fire(self, sub_id, script):
        """script: list of (body, status) or EventsError per attempt."""
        captured = []
        calls = {"n": 0}

        def fake(url, body, headers):
            captured.append(dict(headers))
            step = script[min(calls["n"], len(script) - 1)]
            calls["n"] += 1
            if isinstance(step, Exception):
                raise step
            return step

        events.http_post = fake
        try:
            out = events.fire_synthetic_event(self.conn, sub_id)
        finally:
            events.http_post = self._old_http
        return out, captured

    def test_retry_uses_fresh_timestamp_and_signature(self):
        sub, _ = self._subscribe()
        err = events.EventsError(-32015, "x", {"reason": "timeout"})
        ticks = iter([1700000000.0, 1700000001.0, 1700000002.0])
        with mock.patch.object(events.time, "time",
                               side_effect=lambda: next(ticks)):
            out, captured = self._capture_fire(
                sub["id"], [err, (b'{"ok":true}', 200)])
        self.assertTrue(out["delivered"], out)
        self.assertEqual(out["attempts"], 2)
        self.assertEqual(len(captured), 2)
        # Headers are rebuilt per attempt: distinct timestamps and
        # signatures bound to those timestamps.
        self.assertNotEqual(captured[0]["webhook-timestamp"],
                            captured[1]["webhook-timestamp"])
        self.assertNotEqual(captured[0]["webhook-signature"],
                            captured[1]["webhook-signature"])

    def test_no_retry_on_permanent_4xx(self):
        sub, _ = self._subscribe()
        for status in (400, 401, 403, 404):
            out, captured = self._capture_fire(
                sub["id"], [(b"{}", status)])
            self.assertFalse(out["delivered"])
            self.assertEqual(out["attempts"], 1, status)
            self.assertEqual(len(captured), 1, status)
            self.assertEqual(out["reason"], f"http_{status}", status)

    def test_no_retry_on_410_413(self):
        sub, _ = self._subscribe()
        for status in (410, 413):
            out, _ = self._capture_fire(sub["id"], [(b"{}", status)])
            self.assertFalse(out["delivered"])
            self.assertEqual(out["attempts"], 1, status)
            self.assertEqual(out["reason"], "no_retry_status", status)

    def test_retry_on_transient_then_success(self):
        sub, _ = self._subscribe()
        out, _ = self._capture_fire(
            sub["id"], [(b"{}", 503), (b"{}", 429), (b'{"ok":true}', 200)])
        self.assertTrue(out["delivered"], out)
        self.assertEqual(out["attempts"], 3)

    def test_transient_network_error_retried(self):
        sub, _ = self._subscribe()
        err = events.EventsError(-32015, "x", {"reason": "network_error"})
        out, _ = self._capture_fire(sub["id"], [err, (b'{"ok":true}', 200)])
        self.assertTrue(out["delivered"], out)
        self.assertEqual(out["attempts"], 2)

    # -- P1-4: bounded response reads ---------------------------------------
    def test_response_body_capped(self):
        class Big:
            def read(self, n):
                return b"x" * n

        data = events._read_capped(Big(), 9999999999.0)
        self.assertEqual(len(data), events.MAX_CALLBACK_RESPONSE_BYTES + 1)

    def test_read_deadline_enforced(self):
        class Slow:
            def read(self, n):
                return b"x" * n

        with self.assertRaises(events.EventsError) as ctx:
            events._read_capped(Slow(), 0.0)  # deadline already passed
        self.assertEqual(ctx.exception.data["reason"], "deadline_exceeded")

    # -- Review #2: wall-clock deadline covers DNS + every read --------------
    def _fake_clock(self, start=1000.0):
        clock = {"t": start}
        patcher = mock.patch.object(events.time, "monotonic",
                                    side_effect=lambda: clock["t"])
        patcher.start()
        self.addCleanup(patcher.stop)
        return clock

    def _fake_opener(self, opened):
        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b""

            def getcode(self):
                return 200

        class Opener:
            def open(self, req, timeout):
                opened.append(timeout)
                return Resp()

        return mock.patch.object(events.urllib.request, "build_opener",
                                 lambda *a: Opener())

    def test_late_chunk_past_deadline_rejected(self):
        clock = self._fake_clock(0.0)

        class Drip:
            def read(self, n):
                clock["t"] = 11.0      # a slow read crosses the deadline
                return b""             # ...and then reports EOF

        with self.assertRaises(events.EventsError) as ctx:
            events._read_capped(Drip(), 10.0)
        self.assertEqual(ctx.exception.data["reason"], "deadline_exceeded")

    def test_read1_preferred_over_filling_read(self):
        calls = []

        class Resp:
            def read(self, n):
                calls.append("read")
                return b""

            def read1(self, n):
                calls.append("read1")
                return b""

        events._read_capped(Resp(), 9999999999.0)
        self.assertEqual(calls, ["read1"])

    def test_dns_time_counts_against_budget(self):
        clock = self._fake_clock(1000.0)

        def slow_dns(host):
            clock["t"] += events.HTTP_TIMEOUT_SECS + 1
            return True

        events.public_ip_ok = slow_dns
        opened = []
        with self._fake_opener(opened):
            with self.assertRaises(events.EventsError) as ctx:
                events.http_post("https://events.example.test/cb", b"{}", {})
        self.assertEqual(ctx.exception.data["reason"], "deadline_exceeded")
        self.assertEqual(opened, [])   # nothing sent once the budget is spent

    def test_socket_timeout_is_remaining_budget(self):
        clock = self._fake_clock(1000.0)

        def dns_4s(host):
            clock["t"] += 4
            return True

        events.public_ip_ok = dns_4s
        opened = []
        with self._fake_opener(opened):
            body, status = events.http_post(
                "https://events.example.test/cb", b"{}", {})
        self.assertEqual(status, 200)
        self.assertEqual(len(opened), 1)
        self.assertAlmostEqual(opened[0], events.HTTP_TIMEOUT_SECS - 4)

    # -- Delta review #2: chunked trailers cannot outlive the deadline -------
    def test_watchdog_aborts_trailer_drip(self):
        """Real HTTPResponse over a fake socket: after the terminal 0-chunk
        the peer drips trailer lines forever, each well inside the socket
        timeout. read1() loops over them internally, so only the watchdog
        closing the connection can end the attempt."""
        budget, drip = 0.5, 0.05
        sentinel = 100              # ~5 s of trailers: proof of no bound
        trailers = []

        class Raw(io.RawIOBase):
            def __init__(self, sock):
                self.sock = sock
                self.pending = (b"HTTP/1.1 200 OK\r\n"
                                b"Transfer-Encoding: chunked\r\n\r\n"
                                b"2\r\nok\r\n0\r\n")

            def readable(self):
                return True

            def readinto(self, b):
                if not self.pending:
                    time.sleep(drip)   # one receive, inside socket timeout
                    if self.sock.shut:
                        raise OSError("connection closed by watchdog")
                    if len(trailers) >= sentinel:
                        raise RuntimeError("probe sentinel: never bounded")
                    trailers.append(1)
                    self.pending = b"X-Drip: %d\r\n" % len(trailers)
                elif self.sock.shut:
                    raise OSError("connection closed by watchdog")
                n = min(len(b), len(self.pending))
                b[:n] = self.pending[:n]
                self.pending = self.pending[n:]
                return n

        class FakeSock:
            shut = False

            def __init__(self, *a):
                pass

            def connect(self, addr):
                pass

            def setsockopt(self, *a):
                pass

            def settimeout(self, t):
                pass

            def sendall(self, data):
                pass

            def makefile(self, mode):
                return io.BufferedReader(Raw(self))

            def shutdown(self, how):
                self.shut = True

            def close(self):
                pass

        class PlainContext:            # TLS elided: the fake is plaintext
            def wrap_socket(self, sock, server_hostname=None):
                return sock

        with mock.patch.object(events, "HTTP_TIMEOUT_SECS", budget), \
                mock.patch.object(events, "_callback_ssl_context",
                                  lambda: PlainContext()), \
                mock.patch.object(events.socket, "getaddrinfo",
                                  lambda *a: [(2, 1, 6, "",
                                               ("192.0.2.1", 443))]), \
                mock.patch.object(events.socket, "socket", FakeSock):
            start = time.monotonic()
            with self.assertRaises(events.EventsError) as ctx:
                events.http_post("https://events.example.test/cb", b"{}", {})
            elapsed = time.monotonic() - start
        self.assertEqual(ctx.exception.data["reason"], "deadline_exceeded",
                         ctx.exception.data)
        self.assertLess(len(trailers), sentinel)
        self.assertLess(elapsed, budget + 1.0)

    def test_connect_across_addresses_bounded_by_deadline(self):
        """socket.create_connection would give every resolved address the
        full timeout; each connect must instead get only what is left."""
        budget = 0.5
        attempts = []

        class BlackholeSock:
            def __init__(self, *a):
                self.timeout = None

            def settimeout(self, t):
                self.timeout = t

            def connect(self, addr):
                attempts.append(addr)
                time.sleep(self.timeout)       # SYN never answered
                raise socket.timeout("timed out")

            def shutdown(self, how):
                pass

            def close(self):
                pass

        addrs = [(2, 1, 6, "", ("192.0.2.%d" % i, 443)) for i in (1, 2, 3)]
        with mock.patch.object(events, "HTTP_TIMEOUT_SECS", budget), \
                mock.patch.object(events.socket, "getaddrinfo",
                                  lambda *a: addrs), \
                mock.patch.object(events.socket, "socket", BlackholeSock):
            start = time.monotonic()
            with self.assertRaises(events.EventsError) as ctx:
                events.http_post("https://events.example.test/cb", b"{}", {})
            elapsed = time.monotonic() - start
        self.assertEqual(ctx.exception.data["reason"], "deadline_exceeded",
                         ctx.exception.data)
        self.assertLess(elapsed, budget + 0.5)
        self.assertLess(len(attempts), len(addrs))

    # -- Review #6: a freeze during backoff stops the remaining retries ----
    def _freeze_on_first_attempt(self, sub_id, allow_frozen=False):
        frozen = os.path.join(tempfile.mkdtemp(prefix="bridge-freeze-"),
                              "FROZEN")
        calls = []

        def fake(url, body, headers):
            calls.append(1)
            if len(calls) == 1:
                open(frozen, "w").close()   # another process freezes
                return b"{}", 503           # retryable
            return b'{"ok":true}', 200

        events.http_post = fake
        try:
            with mock.patch.dict(os.environ, {"BRIDGE_FROZEN_FILE": frozen}):
                out = events.fire_synthetic_event(
                    self.conn, sub_id, allow_frozen=allow_frozen)
        finally:
            events.http_post = self._old_http
        return out, calls

    def test_freeze_during_backoff_aborts_retries(self):
        sub, _ = self._subscribe()
        out, calls = self._freeze_on_first_attempt(sub["id"])
        self.assertEqual(len(calls), 1)         # no attempt while frozen
        self.assertFalse(out["delivered"])
        self.assertEqual(out["reason"], "bridge_frozen")
        self.assertEqual(out["attempts"], 1)

    def test_override_frozen_keeps_retrying(self):
        sub, _ = self._subscribe()
        out, calls = self._freeze_on_first_attempt(sub["id"],
                                                   allow_frozen=True)
        self.assertEqual(len(calls), 2)
        self.assertTrue(out["delivered"], out)

    # -- P1-7: malformed JSON-RPC never raises in the gate -------------------
    def test_gate_kind_for_malformed_inputs(self):
        for method, params in (
                (None, None), ([], {}), ({}, {}), ("tools/call", None),
                ("tools/call", {"name": []}), ("tools/call", {"name": {}}),
                ("tools/call", {"name": 123}), ("events/subscribe", None),
                (123, {"name": "inbox_poll"})):
            try:
                tunnel_poll.gate_kind_for(method, params)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"gate_kind_for({method!r}, ...) raised {exc!r}")

    # -- P1-8: freeze --------------------------------------------------------
    def test_fire_refused_when_frozen(self):
        sub, _ = self._subscribe()
        # Per-test marker: never the inherited/operator BRIDGE_FROZEN_FILE.
        frozen_path = os.path.join(
            tempfile.mkdtemp(prefix="bridge-fire-frozen-"), "FROZEN")
        patcher = mock.patch.dict(os.environ,
                                  {"BRIDGE_FROZEN_FILE": frozen_path})
        patcher.start()
        self.addCleanup(patcher.stop)
        with open(frozen_path, "w", encoding="ascii") as f:
            f.write("test\n")
        events.http_post = ChallengeServer()
        try:
            out = events.fire_synthetic_event(self.conn, sub["id"])
            self.assertFalse(out["delivered"])
            self.assertEqual(out["reason"], "bridge_frozen")
            # Explicit audited override still fires.
            out2 = events.fire_synthetic_event(
                self.conn, sub["id"], allow_frozen=True)
            self.assertTrue(out2["delivered"], out2)
            # Subscribe is also refused while frozen.
            with self.assertRaises(events.EventsError) as ctx:
                events.handle_subscribe(
                    self.conn, _sub_params(make_secret()))
            self.assertEqual(ctx.exception.code, -32000)
        finally:
            events.http_post = self._old_http

    # -- P1-9: proxy sanitizer -----------------------------------------------
    def test_proxy_sanitizer_strips_userinfo(self):
        from bridge_mcp import proxyenv
        env = {
            "https_proxy": "http://user:s3cret@example-egress-proxy:3128",
            "HTTPS_PROXY": "http://example-egress-proxy:3128",
            "no_proxy": "localhost,127.0.0.1",
            "PATH": "/usr/bin:/bin",
        }
        out = proxyenv.proxy_exports(env)
        for v in out.values():
            self.assertNotIn("s3cret", v)
            self.assertNotIn("user@", v)
        self.assertEqual(out["https_proxy"],
                         "http://example-egress-proxy:3128")
        self.assertEqual(out["no_proxy"], "localhost,127.0.0.1")
        self.assertNotIn("PATH", out)
        # Eval-safe round-trip: shell can eval the output and the values
        # come back intact.
        import shlex as _shlex
        text = proxyenv.shell_exports(env)
        parsed = {}
        for line in text.splitlines():
            k, v = line.split("=", 1)
            parsed[k] = _shlex.split(v)[0]
        self.assertEqual(parsed["https_proxy"],
                         "http://example-egress-proxy:3128")

    # -- P2-10: initialize advertises events ----------------------------------
    def test_initialize_advertises_events(self):
        resp = server.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18",
                        "capabilities": {}, "clientInfo": {}}},
            self.conn)
        caps = resp["result"]["capabilities"]
        self.assertIn("tools", caps)
        self.assertIn("events", caps)

    # -- P2-11: notification-form mutations refused ---------------------------
    def test_notification_form_subscribe_refused(self):
        secret = make_secret()
        for method in ("events/subscribe", "events/unsubscribe"):
            resp = server.handle(
                {"jsonrpc": "2.0", "method": method,
                 "params": {"name": "bridge.ping",
                            "delivery": {"mode": "webhook",
                                         "url": "https://x.test/cb",
                                         "secret": secret}}},
                self.conn)
            self.assertIsNone(resp, method)
        self.assertEqual(store.count_active_subscriptions(self.conn), 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)

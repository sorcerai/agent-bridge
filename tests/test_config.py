#!/usr/bin/env python3
"""Hermetic tests for template configuration: required env, fail-closed
caller gate, bearer-auth host allowlist, freeze semantics, and the admin
CLI's state-dir handling. No network. Temp dirs only.

Run: python3 tests/test_config.py
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Hermetic: drop every inherited BRIDGE_* variable and FORCE test-owned
# state/db/log/hook/freeze paths before any bridge module is imported. No
# test may read, write or delete the operator's real freeze marker.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _hermetic  # noqa: E402,F401

POLL_PATH = os.path.join(ROOT, "scripts", "tunnel-poll.py")
ADMIN = os.path.join(ROOT, "scripts", "bridge-admin.sh")

GOOD_ENV = {
    "BRIDGE_TUNNEL_ID": "tunnel_example0000",
    "OPENAI_API_KEY": "test-key-not-real",
}


def load_poller(env: dict | None = None, drop: tuple = ()):
    """Import tunnel-poll.py fresh under a patched environment (module
    constants are read at import time)."""
    patched = dict(os.environ)
    for k in ("BRIDGE_TUNNEL_ID", "OPENAI_API_KEY",
              "BRIDGE_SUBJECT_FINGERPRINT") + tuple(drop):
        patched.pop(k, None)
    patched.update(env or {})
    with mock.patch.dict(os.environ, patched, clear=True):
        spec = importlib.util.spec_from_file_location("tunnel_poll", POLL_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


class ConfigErrorsTest(unittest.TestCase):
    def test_tunnel_id_required(self):
        mod = load_poller({"OPENAI_API_KEY": "k"})
        self.assertIn("BRIDGE_TUNNEL_ID is not set", mod.config_errors())

    def test_tunnel_id_charset_enforced(self):
        mod = load_poller({**GOOD_ENV, "BRIDGE_TUNNEL_ID": "../../v1/x?y"})
        self.assertTrue(any("unexpected characters" in e
                            for e in mod.config_errors()))

    def test_api_key_required(self):
        mod = load_poller({"BRIDGE_TUNNEL_ID": "tunnel_x"})
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENAI_API_KEY", None)
            self.assertIn("OPENAI_API_KEY is not set", mod.config_errors())

    def test_malformed_fingerprint_refused(self):
        for bad in ("XYZ", "0123456789ABCDEF", "0123456789abcde",
                    "0123456789abcdef0"):
            mod = load_poller({**GOOD_ENV,
                               "BRIDGE_SUBJECT_FINGERPRINT": bad})
            with mock.patch.dict(os.environ, GOOD_ENV):
                self.assertTrue(
                    any("BRIDGE_SUBJECT_FINGERPRINT" in e
                        for e in mod.config_errors()), bad)

    def test_unset_fingerprint_is_not_a_startup_error(self):
        mod = load_poller(GOOD_ENV)
        with mock.patch.dict(os.environ, GOOD_ENV):
            self.assertEqual(mod.config_errors(), [])
        self.assertEqual(mod.SUBJECT_BASELINE_FP, "")

    def test_no_baked_in_deployment_values(self):
        mod = load_poller({})
        self.assertEqual(mod.TUNNEL_ID, "")
        self.assertEqual(mod.SUBJECT_BASELINE_FP, "")

    def test_main_refuses_without_config_and_writes_no_pidfile(self):
        state = tempfile.mkdtemp(prefix="bridge-main-")
        mod = load_poller({"BRIDGE_STATE_DIR": state})
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENAI_API_KEY", None)
            with mock.patch("sys.stderr", new=io.StringIO()):
                rc = mod.main([])
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(mod.PID_FILE))


class BearerAuthTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_poller(GOOD_ENV)

    def test_bearer_attached_for_allowlisted_host(self):
        with mock.patch.dict(os.environ, GOOD_ENV):
            req = self.mod.authed_request(
                "https://api.openai.com/v1/tunnels/tunnel_x/poll")
        self.assertEqual(req.get_header("Authorization"),
                         "Bearer test-key-not-real")
        self.assertEqual(req.get_header("User-agent"),
                         "agent-bridge-poller/1.0.0")

    def test_non_allowlisted_host_refused(self):
        with mock.patch.dict(os.environ, GOOD_ENV):
            for url in ("https://evil.example.com/v1/x",
                        "http://api.openai.com/v1/x",
                        "https://api.openai.com.evil.example/v1/x"):
                with self.assertRaises(RuntimeError, msg=url):
                    self.mod.authed_request(url)

    def test_missing_key_refused_at_request_time(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENAI_API_KEY", None)
            with self.assertRaises(RuntimeError):
                self.mod.authed_request("https://api.openai.com/v1/x")


class GateDispatchTest(unittest.TestCase):
    """Dispatch-level caller gate with a fake child and fake transport."""

    SUBJECT = ["subject-of-the-pinned-caller"]

    def make_poller(self, baseline: str | None):
        env = dict(GOOD_ENV)
        if baseline is not None:
            env["BRIDGE_SUBJECT_FINGERPRINT"] = baseline
        mod = load_poller(env)
        frozen = os.path.join(tempfile.mkdtemp(prefix="bridge-gate-"),
                              "FROZEN")
        patcher = mock.patch.dict(os.environ, {"BRIDGE_FROZEN_FILE": frozen})
        patcher.start()
        self.addCleanup(patcher.stop)
        log_events = []
        log = types.SimpleNamespace(
            emit=lambda level, event, **f: log_events.append((event, f)))
        poller = mod.Poller(log)
        child_calls = []

        class FakeChild:
            def alive(self):
                return True

            def call(self, msg, timeout):
                child_calls.append(msg)
                return {"jsonrpc": "2.0", "id": msg.get("id"),
                        "result": {"ok": True}}

        poller.child = FakeChild()
        posted = []
        poller.post_response = (
            lambda rid, tok, ch, resp, resp_type="jsonrpc_response":
            posted.append(resp) or True)
        return mod, poller, frozen, log_events, child_calls, posted

    def cmd(self, method="tools/call", params=None, subject=SUBJECT):
        headers = {"X-OpenAI-Subject": subject} if subject is not None else {}
        return {"command_type": "jsonrpc", "request_id": "req_1",
                "shard_token": "shard_x", "channel": "c",
                "headers": headers,
                "jsonrpc": {"jsonrpc": "2.0", "id": 7, "method": method,
                            "params": params if params is not None else
                            {"name": "inbox_poll", "arguments": {}}}}

    def pinned_fp(self, mod):
        return mod.header_fingerprints(
            {"x-openai-subject": self.SUBJECT})["x-openai-subject"]

    def test_unset_baseline_rejects_private_without_freeze(self):
        mod, poller, frozen, events, child, posted = self.make_poller(None)
        poller.dispatch(self.cmd())
        self.assertEqual(child, [])                      # child never saw it
        self.assertEqual(posted[0]["error"]["code"], -32001)
        self.assertEqual(posted[0]["id"], 7)
        self.assertFalse(os.path.exists(frozen))         # no freeze
        rejected = [f for e, f in events if e == "command_rejected_caller"]
        self.assertEqual(rejected[0]["reason"], "subject_baseline_unset")
        # The fingerprint is logged so the operator can capture it.
        self.assertEqual(rejected[0]["header_fp"]["x-openai-subject"],
                         self.pinned_fp(mod))

    def test_unset_baseline_rejects_private_event_methods(self):
        mod, poller, frozen, events, child, posted = self.make_poller(None)
        poller.dispatch(self.cmd(method="events/subscribe", params={}))
        self.assertEqual(child, [])
        self.assertEqual(posted[0]["error"]["code"], -32001)

    def test_unset_baseline_keeps_open_methods_open(self):
        mod, poller, frozen, events, child, posted = self.make_poller(None)
        poller.dispatch(self.cmd(method="tools/list", params={}))
        self.assertEqual(len(child), 1)
        self.assertIn("result", posted[0])

    def test_pinned_caller_dispatched(self):
        probe = load_poller(GOOD_ENV)
        mod, poller, frozen, events, child, posted = \
            self.make_poller(self.pinned_fp(probe))
        poller.dispatch(self.cmd())
        self.assertEqual(len(child), 1)
        self.assertEqual(posted[0]["id"], 7)             # caller id restored
        self.assertFalse(os.path.exists(frozen))

    def test_mismatch_rejects_and_freezes_then_blocks_pinned(self):
        probe = load_poller(GOOD_ENV)
        mod, poller, frozen, events, child, posted = \
            self.make_poller(self.pinned_fp(probe))
        poller.dispatch(self.cmd(subject=["someone-else"]))
        self.assertEqual(child, [])
        self.assertEqual(posted[-1]["error"]["code"], -32001)
        self.assertTrue(os.path.exists(frozen))
        rejected = [f for e, f in events if e == "command_rejected_caller"]
        self.assertEqual(rejected[-1]["reason"], "subject_mismatch")
        # Freeze persists: even the pinned caller is now refused.
        poller.dispatch(self.cmd())
        self.assertEqual(child, [])
        self.assertEqual(posted[-1]["error"]["code"], -32001)

    def test_missing_subject_rejected_and_frozen(self):
        probe = load_poller(GOOD_ENV)
        mod, poller, frozen, events, child, posted = \
            self.make_poller(self.pinned_fp(probe))
        poller.dispatch(self.cmd(subject=None))
        self.assertEqual(child, [])
        self.assertTrue(os.path.exists(frozen))
        rejected = [f for e, f in events if e == "command_rejected_caller"]
        self.assertEqual(rejected[-1]["reason"], "missing_or_invalid_subject")


class PidLockTest(unittest.TestCase):
    """Review #5: the PID file is an OS advisory lock, not check-then-write."""

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="bridge-pid-")
        self.mod = load_poller(dict(GOOD_ENV, BRIDGE_STATE_DIR=self.state))
        self.log = types.SimpleNamespace(emit=lambda *a, **k: None)

    def poller(self):
        p = self.mod.Poller(self.log)
        self.addCleanup(p.release_pid)
        return p

    def test_two_simultaneous_claims_exactly_one_wins(self):
        import threading
        barrier = threading.Barrier(2)
        results = []

        def claim(p):
            barrier.wait()
            try:
                p.claim_pid()
                results.append("won")
            except SystemExit as exc:
                results.append(str(exc))

        threads = [threading.Thread(target=claim, args=(self.poller(),))
                   for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(results.count("won"), 1, results)
        loser = [r for r in results if r != "won"][0]
        self.assertIn("another poller holds the PID lock", loser)
        with open(self.mod.PID_FILE) as f:
            self.assertEqual(f.read(), str(os.getpid()))  # still readable

    def test_second_process_refused_while_first_holds_lock(self):
        first = self.poller()
        first.claim_pid()
        code = ("import importlib.util, sys, types\n"
                f"spec = importlib.util.spec_from_file_location('tp', {POLL_PATH!r})\n"
                "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
                "p = m.Poller(types.SimpleNamespace(emit=lambda *a, **k: None))\n"
                "p.claim_pid()\n")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": self.state, "BRIDGE_STATE_DIR": self.state}
        r = subprocess.run([sys.executable, "-c", code], env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("another poller holds the PID lock", r.stderr)
        self.assertIn(str(os.getpid()), r.stderr)

    def test_release_allows_next_claim_and_stale_file_is_claimable(self):
        first = self.poller()
        first.claim_pid()
        first.release_pid()
        self.assertFalse(os.path.exists(self.mod.PID_FILE))
        with open(self.mod.PID_FILE, "w") as f:   # stale file, no lock
            f.write("999999")
        second = self.poller()
        second.claim_pid()
        with open(self.mod.PID_FILE) as f:
            self.assertEqual(f.read(), str(os.getpid()))


class ArgKeyLoggingTest(unittest.TestCase):
    """Review #8: only manifest-declared argument names reach the log."""

    def setUp(self):
        self.mod = load_poller(GOOD_ENV)

    def info(self, name, args):
        return self.mod.tool_call_info(
            {"method": "tools/call",
             "params": {"name": name, "arguments": args}})

    def test_unknown_keys_collapse_to_count(self):
        info = self.info("bridge_status",
                         {"include_counts": True, "FAKE_SECRET_IN_KEY": 1,
                          "sk-also-not-logged": 2})
        self.assertEqual(info["arg_keys"], ["include_counts", "unknown:2"])
        self.assertNotIn("FAKE_SECRET", json.dumps(info))

    def test_names_of_another_tool_are_unknown(self):
        info = self.info("inbox_poll", {"limit": 1, "payload": {}})
        self.assertEqual(info["arg_keys"], ["limit", "unknown:1"])

    def test_unknown_tool_logs_no_names(self):
        info = self.info("FAKE_TOOL_NAME", {"limit": 1})
        self.assertEqual(info, {"tool": "unknown_tool",
                                "arg_keys": ["unknown:1"]})

    def test_non_string_keys_counted(self):
        # JSON object keys are strings, but never trust the shape.
        info = self.info("inbox_poll", {1: "x", "limit": 2})
        self.assertEqual(info["arg_keys"], ["limit", "unknown:1"])

    def test_allowlist_matches_pinned_manifest(self):
        from bridge_mcp import manifest
        declared = {t["name"]: frozenset(t["inputSchema"]["properties"])
                    for t in manifest.PINNED_MANIFEST["tools"]}
        self.assertEqual(declared, dict(self.mod.TOOL_ARG_NAMES))


class PathsTest(unittest.TestCase):
    def test_defaults_under_agent_bridge_state(self):
        code = ("import json; from bridge_mcp import paths; print(json.dumps("
                "[paths.STATE_DIR, paths.DEFAULT_DB, paths.FREEZE_PATH, "
                "paths.SECRETS_DIR, paths.MCP_LOG]))")
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("BRIDGE_")}
        env["HOME"] = "/home/user"
        env["PYTHONPATH"] = ROOT
        out = json.loads(subprocess.check_output(
            [sys.executable, "-c", code], env=env, text=True))
        base = "/home/user/.local/state/agent-bridge"
        self.assertEqual(out, [base, base + "/bridge.db", base + "/FROZEN",
                               base + "/secrets",
                               base + "/logs/bridge-mcp.log"])

    def test_poller_and_package_agree_on_frozen_default(self):
        state = tempfile.mkdtemp(prefix="bridge-agree-")
        mod = load_poller({"BRIDGE_STATE_DIR": state})
        code = "from bridge_mcp import paths; print(paths.FREEZE_PATH)"
        env = _hermetic.clean_env(BRIDGE_STATE_DIR=state, PYTHONPATH=ROOT)
        out = subprocess.check_output([sys.executable, "-c", code],
                                      env=env, text=True).strip()
        self.assertEqual(out, mod.FROZEN_FILE)


FAKE_PW = "FAKE_PROXY_PASSWORD"
LAUNCHER = os.path.join(ROOT, "scripts", "bridge-mcp.sh")
# Stand-in for bridge_mcp/server.py: records the environment the launcher
# handed it (env -i scrubs everything else) and exits.
FAKE_SERVER = (
    "import json, os\n"
    "with open(os.path.join(os.environ['BRIDGE_STATE_DIR'], "
    "'child-env.json'), 'w') as f:\n"
    "    json.dump(dict(os.environ), f)\n")


class ProxySanitizerTest(unittest.TestCase):
    """P0: the sanitizer never returns a value it could not parse."""

    def test_scheme_less_credential_url_is_dropped(self):
        from bridge_mcp import proxyenv
        raw = f"fake-user:{FAKE_PW}@proxy.example:3128"
        self.assertIsNone(proxyenv.sanitize_proxy_url(raw))
        dropped = []
        out = proxyenv.proxy_exports({"https_proxy": raw}, dropped)
        self.assertEqual(out, {})
        self.assertEqual(dropped, ["https_proxy"])

    def test_malformed_inputs_are_dropped(self):
        from bridge_mcp import proxyenv
        for raw in (f"http://u:{FAKE_PW}@proxy.example:notaport",
                    f"http://u:{FAKE_PW}@proxy.example:99999",
                    f"http://u:{FAKE_PW}@",
                    f"http://u:{FAKE_PW}@[::1",
                    f"http://u:{FAKE_PW}@proxy.example:3128\nX=1",
                    f"http://proxy.example:3128/u:{FAKE_PW}@x",
                    "proxy.example:3128"):
            self.assertIsNone(proxyenv.sanitize_proxy_url(raw), raw)

    def test_valid_urls_keep_host_and_port_only(self):
        from bridge_mcp import proxyenv
        self.assertEqual(
            proxyenv.sanitize_proxy_url(f"http://u:{FAKE_PW}@proxy.example:3128"),
            "http://proxy.example:3128")
        self.assertEqual(
            proxyenv.sanitize_proxy_url(f"http://u:{FAKE_PW}@[2001:db8::1]:3128"),
            "http://[2001:db8::1]:3128")


class LauncherProxyTest(unittest.TestCase):
    """P0: launcher-level checks against a fake BRIDGE_HOME whose
    server.py dumps the child environment."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="bridge-launch-")
        self.state = os.path.join(self.home, "state")
        os.makedirs(self.state)
        pkg = os.path.join(self.home, "bridge_mcp")
        os.makedirs(pkg)
        open(os.path.join(pkg, "__init__.py"), "w").close()
        shutil.copy(os.path.join(ROOT, "bridge_mcp", "proxyenv.py"), pkg)
        with open(os.path.join(pkg, "server.py"), "w") as f:
            f.write(FAKE_SERVER)
        self.env_file = os.path.join(self.state, "child-env.json")

    def launch(self, **extra):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME": self.home, "BRIDGE_HOME": self.home,
               "BRIDGE_STATE_DIR": self.state,
               "BRIDGE_PYTHON": sys.executable, **extra}
        return subprocess.run(["bash", LAUNCHER], env=env,
                              capture_output=True, text=True, timeout=30)

    def child_env(self):
        with open(self.env_file) as f:
            return json.load(f)

    def assert_no_password(self, child):
        for k, v in child.items():
            self.assertNotIn(FAKE_PW, v, k)

    def test_scheme_less_credential_url_never_reaches_child(self):
        r = self.launch(https_proxy=f"fake-user:{FAKE_PW}@proxy.example:3128",
                        HTTP_PROXY=f"http://u:{FAKE_PW}@proxy.example:3128")
        self.assertEqual(r.returncode, 0, r.stderr)
        child = self.child_env()
        self.assertNotIn("https_proxy", child)
        self.assertEqual(child["HTTP_PROXY"], "http://proxy.example:3128")
        self.assert_no_password(child)
        self.assertIn("dropping unparseable proxy variable https_proxy",
                      r.stderr)
        self.assertNotIn(FAKE_PW, r.stderr)

    def test_bad_port_never_reaches_child(self):
        r = self.launch(
            https_proxy=f"http://fake-user:{FAKE_PW}@proxy.example:notaport")
        self.assertEqual(r.returncode, 0, r.stderr)
        child = self.child_env()
        self.assertNotIn("https_proxy", child)
        self.assert_no_password(child)

    def test_sanitizer_failure_aborts_launch(self):
        with open(os.path.join(self.home, "bridge_mcp", "proxyenv.py"),
                  "w") as f:
            f.write("raise ValueError('boom')\n")
        r = self.launch(
            https_proxy=f"http://fake-user:{FAKE_PW}@proxy.example:3128")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("proxy sanitizer failed", r.stderr)
        self.assertFalse(os.path.exists(self.env_file))  # child never ran
        self.assertNotIn(FAKE_PW, r.stdout + r.stderr)

    def test_unexpected_sanitizer_output_aborts_launch(self):
        with open(os.path.join(self.home, "bridge_mcp", "proxyenv.py"),
                  "w") as f:
            f.write("print('OPENAI_API_KEY=leak')\n")
        r = self.launch()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.env_file))

    def test_no_proxy_configured_launches_clean(self):
        r = self.launch()
        self.assertEqual(r.returncode, 0, r.stderr)
        child = self.child_env()
        self.assertFalse({k for k in child if "proxy" in k.lower()})


@unittest.skipUnless(shutil.which("sqlite3"), "sqlite3 CLI not installed")
class AdminCliTest(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="bridge-admin-")
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("BRIDGE_")}
        self.env.update(BRIDGE_STATE_DIR=self.state, BRIDGE_SLACK_PING="0")

    def admin(self, *args, check=True):
        return subprocess.run(["bash", ADMIN, *args], env=self.env,
                              capture_output=True, text=True, check=check)

    def test_init_works_on_fresh_state(self):
        r = self.admin("init")
        self.assertIn("journal_mode=wal", r.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.state, "bridge.db")))

    def test_enqueue_stamps_host_roles_in_configured_db(self):
        self.admin("init")
        r = self.admin("enqueue", "--type", "request", "--subject", "s",
                       "--body", "hello")
        mid = json.loads(r.stdout.splitlines()[0])["message_id"]
        rows = json.loads(self.admin("list").stdout)
        self.assertEqual(rows[0]["message_id"], mid)
        self.assertEqual(rows[0]["direction"], "host_to_agent")
        self.assertEqual(rows[0]["sender"], "host")
        self.assertEqual(rows[0]["recipient"], "remote-agent")

    def test_missing_db_refused_for_non_init(self):
        r = self.admin("list", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("db missing", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=1)

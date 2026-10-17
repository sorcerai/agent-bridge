#!/usr/bin/env python3
"""Run the hooks/ scripts standalone (built-in runtime stubs) against temp
state. Checks the stdout decision contract, BRIDGE_HOOK_RUNTIME override,
and the subject-watch freeze. No network.

Run: python3 tests/test_hooks.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _hermetic  # noqa: E402,F401  (forced test-owned BRIDGE_* paths)
HOOKS = os.path.join(ROOT, "hooks")


@unittest.skipUnless(shutil.which("sqlite3"), "sqlite3 CLI not installed")
class HookTestBase(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="bridge-hooks-")
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("BRIDGE_")}
        self.env["BRIDGE_STATE_DIR"] = self.state

    def run_hook(self, name, **extra_env):
        env = dict(self.env, **extra_env)
        r = subprocess.run(["bash", os.path.join(HOOKS, name)], env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, r.stdout)   # exactly one decision
        return json.loads(lines[0]), r

    def enqueue_agent_message(self):
        env = dict(self.env, PYTHONPATH=ROOT)
        code = ("from bridge_mcp import store; c = store.connect(); "
                "print(store.enqueue(c, direction='agent_to_host', "
                "sender='remote-agent', recipient='host', "
                "correlation_id='c1', idempotency_key='k1', "
                "msg_type='reply', payload={'text': 'hi'})['message_id'])")
        return subprocess.check_output([sys.executable, "-c", code],
                                       env=env, text=True).strip()


class NewMsgWatchTest(HookTestBase):
    def test_watermark_then_wake_with_ids_only(self):
        first, _ = self.run_hook("bridge-newmsg-watch.sh")
        self.assertEqual(first["decision"], "silent")
        self.assertIn("cursor initialized", first["reason"])
        time.sleep(0.01)
        mid = self.enqueue_agent_message()
        out, _ = self.run_hook("bridge-newmsg-watch.sh",
                               BRIDGE_WAKE_TARGET="chat-123")
        self.assertEqual(out["decision"], "wake")
        self.assertEqual(out["payload"], {"count": 1, "message_ids": mid})
        self.assertEqual(out["target"], "chat-123")
        self.assertNotIn("hi", json.dumps(out["payload"]))   # no bodies
        again, _ = self.run_hook("bridge-newmsg-watch.sh")
        self.assertEqual(again["decision"], "silent")       # fires once

    def test_external_runtime_is_sourced(self):
        rt = os.path.join(self.state, "runtime.sh")
        with open(rt, "w") as f:
            f.write('silent() { echo "CUSTOM:silent:$1"; exit 0; }\n'
                    'wake() { echo "CUSTOM:wake:$1"; exit 0; }\n'
                    'log() { :; }\n')
        r = subprocess.run(
            ["bash", os.path.join(HOOKS, "bridge-newmsg-watch.sh")],
            env=dict(self.env, BRIDGE_HOOK_RUNTIME=rt),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("CUSTOM:silent:"), r.stdout)


class InboxWatchTest(HookTestBase):
    def test_silent_when_nothing_stale(self):
        self.enqueue_agent_message()
        out, _ = self.run_hook("bridge-inbox-watch.sh")
        self.assertEqual(out["decision"], "silent")

    def test_wake_when_stale(self):
        mid = self.enqueue_agent_message()
        # The hook's cutoff has whole-second precision; let the clock tick
        # past created_at so a 0s window counts the message as stale.
        time.sleep(1.1)
        out, _ = self.run_hook("bridge-inbox-watch.sh",
                               BRIDGE_INBOX_STALE_SECS="0")
        self.assertEqual(out["decision"], "wake")
        self.assertIn(mid, out["payload"]["stale_message_ids"])


class OutboxWatchTest(HookTestBase):
    def test_silent_when_no_due_deliveries(self):
        self.enqueue_agent_message()  # creates the DB
        out, _ = self.run_hook("bridge-outbox-watch.sh")
        self.assertEqual(out, {"decision": "silent",
                               "reason": "no due event deliveries"})


class SubjectWatchTest(HookTestBase):
    FP = "0123456789abcdef"

    def write_log(self, *records):
        logs = os.path.join(self.state, "logs")
        os.makedirs(logs, exist_ok=True)
        with open(os.path.join(logs, "tunnel-poll.log"), "a") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

    def dispatched(self, fp, tool="inbox_poll"):
        return {"event": "command_dispatched", "method": "tools/call",
                "tool": tool, "header_fp": {"x-openai-subject": fp}}

    def test_matching_fingerprint_silent(self):
        self.write_log(self.dispatched(self.FP),
                       {"event": "command_dispatched", "method": "tools/list",
                        "header_fp": {}})
        out, _ = self.run_hook("bridge-subject-watch.sh",
                               BRIDGE_SUBJECT_FINGERPRINT=self.FP)
        self.assertEqual(out["decision"], "silent")
        self.assertFalse(os.path.exists(os.path.join(self.state, "FROZEN")))

    def test_unknown_fingerprint_freezes_and_wakes(self):
        self.write_log(self.dispatched("fedcba9876543210"))
        out, _ = self.run_hook("bridge-subject-watch.sh",
                               BRIDGE_SUBJECT_FINGERPRINT=self.FP)
        self.assertEqual(out["decision"], "wake")
        self.assertTrue(out["payload"]["frozen"])
        self.assertTrue(os.path.exists(os.path.join(self.state, "FROZEN")))

    def test_unset_baseline_fails_closed(self):
        self.write_log(self.dispatched(self.FP))
        out, r = self.run_hook("bridge-subject-watch.sh")
        self.assertEqual(out["decision"], "wake")
        self.assertTrue(os.path.exists(os.path.join(self.state, "FROZEN")))
        self.assertIn("BRIDGE_SUBJECT_FINGERPRINT unset", r.stderr)

    def test_dry_run_does_not_freeze(self):
        self.write_log(self.dispatched("fedcba9876543210"))
        out, _ = self.run_hook("bridge-subject-watch.sh",
                               BRIDGE_SUBJECT_FINGERPRINT=self.FP,
                               BRIDGE_HOOK_DRY_RUN="1")
        self.assertEqual(out["decision"], "wake")
        self.assertFalse(os.path.exists(os.path.join(self.state, "FROZEN")))


class SubjectWatchGateFreezeTest(HookTestBase):
    """Review #3/#4: gate-triggered freezes wake; dedupe never hides a new
    fingerprint or a new freeze; dry runs consume no state."""

    FP = SubjectWatchTest.FP
    OTHER = "fedcba9876543210"
    write_log = SubjectWatchTest.write_log
    dispatched = SubjectWatchTest.dispatched

    def rejected(self, fp, reason="subject_mismatch", tool="inbox_poll"):
        # Same shape as tunnel-poll.py's command_rejected_caller record.
        hfp = {"x-openai-subject": fp} if fp else {}
        return {"ts": "2026-10-17T00:00:00.000000Z", "level": "error",
                "event": "command_rejected_caller", "request_id": "req_1",
                "tool": tool, "reason": reason, "channel": "c",
                "created_at": "", "header_fp": hfp}

    @property
    def frozen(self):
        return os.path.join(self.state, "FROZEN")

    def watch(self, **env):
        return self.run_hook("bridge-subject-watch.sh",
                             BRIDGE_SUBJECT_FINGERPRINT=self.FP, **env)[0]

    def test_gate_rejection_wakes_even_when_already_frozen(self):
        open(self.frozen, "w").close()        # the poller already froze
        self.write_log(self.rejected(self.OTHER))
        out = self.watch()
        self.assertEqual(out["decision"], "wake")
        self.assertEqual(out["payload"]["rejected_caller_records"], 1)
        self.assertIn(self.OTHER, out["payload"]["unknown_subject_fps"])

    def test_missing_subject_rejection_wakes_and_freezes(self):
        self.write_log(self.rejected(None, "missing_or_invalid_subject"))
        out = self.watch()
        self.assertEqual(out["decision"], "wake")
        self.assertTrue(os.path.exists(self.frozen))

    def test_bootstrap_rejection_is_exempt(self):
        self.write_log(self.rejected(self.OTHER, "subject_baseline_unset"))
        out = self.watch()
        self.assertEqual(out["decision"], "silent")
        self.assertFalse(os.path.exists(self.frozen))

    def test_pinned_caller_refused_while_frozen_is_not_new(self):
        self.write_log(self.rejected(self.FP))
        out = self.watch()
        self.assertEqual(out["decision"], "silent")

    def test_freeze_file_failure_wakes_and_freezes(self):
        self.write_log({"event": "freeze_file_failed", "request_id": "r"})
        out = self.watch()
        self.assertEqual(out["decision"], "wake")
        self.assertEqual(out["payload"]["freeze_file_failed"], 1)
        self.assertTrue(os.path.exists(self.frozen))

    def test_dedupe_same_freeze_same_fp(self):
        self.write_log(self.rejected(self.OTHER))
        self.assertEqual(self.watch()["decision"], "wake")
        self.write_log(self.rejected(self.OTHER))
        out = self.watch()
        self.assertEqual(out["decision"], "silent")
        self.assertIn("dedupe", out["reason"])

    def test_dedupe_never_hides_new_fingerprint(self):
        self.write_log(self.rejected(self.OTHER))
        self.assertEqual(self.watch()["decision"], "wake")
        self.write_log(self.rejected("00000000000000aa"))
        out = self.watch()
        self.assertEqual(out["decision"], "wake")
        self.assertEqual(out["payload"]["new_subject_fps"],
                         "00000000000000aa")

    def test_dedupe_never_hides_new_freeze(self):
        self.write_log(self.rejected(self.OTHER))
        self.assertEqual(self.watch()["decision"], "wake")
        # Operator unfreezes; the same caller trips the gate again and the
        # poller re-creates FROZEN (a new freeze, same known fingerprint).
        os.unlink(self.frozen)
        open(self.frozen, "w").close()
        os.utime(self.frozen, (time.time() + 5, time.time() + 5))
        self.write_log(self.rejected(self.OTHER))
        self.assertEqual(self.watch()["decision"], "wake")

    def test_enforcement_independent_of_dedupe(self):
        self.write_log(self.dispatched(self.OTHER))
        self.assertEqual(self.watch()["decision"], "wake")
        os.unlink(self.frozen)            # unfrozen, fp already reported
        self.write_log(self.dispatched(self.OTHER))
        self.watch()
        self.assertTrue(os.path.exists(self.frozen))

    def test_dry_run_then_real_run_matches_real_run(self):
        self.write_log(self.dispatched(self.OTHER))
        dry = self.watch(BRIDGE_HOOK_DRY_RUN="1")
        self.assertEqual(dry["decision"], "wake")
        self.assertFalse(os.path.exists(os.path.join(self.state, "hooks")))
        self.assertFalse(os.path.exists(self.frozen))
        real = self.watch()
        self.assertEqual(real["decision"], "wake")
        self.assertTrue(os.path.exists(self.frozen))


class DryRunPurityTest(HookTestBase):
    """Review #4: BRIDGE_HOOK_DRY_RUN=1 writes no hook state at all."""

    def assert_no_hook_state(self):
        self.assertFalse(os.path.exists(os.path.join(self.state, "hooks")),
                         os.listdir(self.state))

    def test_newmsg_dry_run_does_not_init_cursor(self):
        self.enqueue_agent_message()
        out, _ = self.run_hook("bridge-newmsg-watch.sh",
                               BRIDGE_HOOK_DRY_RUN="1")
        self.assertIn("dry-run", out["reason"])
        self.assert_no_hook_state()

    def test_newmsg_dry_run_then_real_run(self):
        self.run_hook("bridge-newmsg-watch.sh")          # init cursor
        mid = self.enqueue_agent_message()
        dry, _ = self.run_hook("bridge-newmsg-watch.sh",
                               BRIDGE_HOOK_DRY_RUN="1")
        self.assertIn(mid, dry["reason"])
        real, _ = self.run_hook("bridge-newmsg-watch.sh")
        self.assertEqual(real["decision"], "wake")
        self.assertEqual(real["payload"]["message_ids"], mid)

    def test_inbox_dry_run_writes_nothing(self):
        self.enqueue_agent_message()
        time.sleep(1.1)
        out, _ = self.run_hook("bridge-inbox-watch.sh",
                               BRIDGE_INBOX_STALE_SECS="0",
                               BRIDGE_HOOK_DRY_RUN="1")
        self.assertEqual(out["decision"], "wake")
        self.assert_no_hook_state()

    def test_daemon_dry_run_writes_nothing(self):
        self.run_hook("bridge-daemon-watch.sh", BRIDGE_HOOK_DRY_RUN="1")
        self.assertEqual(os.listdir(self.state), [])

    def test_outbox_dry_run_writes_nothing(self):
        self.enqueue_agent_message()
        self.run_hook("bridge-outbox-watch.sh", BRIDGE_HOOK_DRY_RUN="1")
        self.assert_no_hook_state()


class NewMsgCursorTest(HookTestBase):
    """Review #7: the cursor is the monotonic seq of the rows returned."""

    def insert_raw(self, created_at):
        import sqlite3
        import uuid
        conn = sqlite3.connect(os.path.join(self.state, "bridge.db"))
        mid = "msg_" + uuid.uuid4().hex[:24]
        cols = [r[1] for r in conn.execute("PRAGMA table_info(messages)")]
        row = conn.execute("SELECT * FROM messages LIMIT 1").fetchone()
        rec = dict(zip(cols, row))
        rec.pop("seq")
        rec.update(message_id=mid, created_at=created_at,
                   idempotency_key="k-" + mid, status="queued")
        conn.execute(
            f"INSERT INTO messages ({','.join(rec)}) "
            f"VALUES ({','.join('?' * len(rec))})", list(rec.values()))
        conn.commit()
        conn.close()
        return mid

    def test_late_commit_with_older_timestamp_still_fires(self):
        # A row whose created_at predates the last wake (stamped before a
        # slow commit / clock step) but committed afterwards: a timestamp
        # watermark skips it forever; the seq cursor does not.
        self.enqueue_agent_message()
        self.run_hook("bridge-newmsg-watch.sh")          # init
        mid2 = self.insert_raw("2000-01-01T00:00:00.000000Z")
        out, _ = self.run_hook("bridge-newmsg-watch.sh")
        self.assertEqual(out["decision"], "wake")
        self.assertEqual(out["payload"]["message_ids"], mid2)

    def test_upgrade_from_timestamp_watermark_skips_nothing(self):
        # Rows announced under the old watermark (created_at <= wm) may
        # wake once more; rows it had not announced must never be skipped,
        # even when their seq is lower than an already-announced row's.
        hs = os.path.join(self.state, "hooks", "bridge-newmsg-watch")
        self.enqueue_agent_message()                     # creates the DB
        conn_rows = []
        for ts in ("2020-01-01T00:00:00.000000Z",       # announced
                   "2030-01-01T00:00:00.000000Z",       # unannounced
                   "2020-06-01T00:00:00.000000Z",       # announced, higher seq
                   "2031-01-01T00:00:00.000000Z"):      # unannounced
            conn_rows.append(self.insert_raw(ts))
        os.makedirs(hs)
        with open(os.path.join(hs, "watermark"), "w") as f:
            f.write("2027-01-01T00:00:00.000Z\n")
        out, _ = self.run_hook("bridge-newmsg-watch.sh")
        ids = out["payload"]["message_ids"].split()
        self.assertEqual(out["decision"], "wake")
        self.assertIn(conn_rows[1], ids)
        self.assertIn(conn_rows[3], ids)
        self.assertNotIn(conn_rows[0], ids)

    def test_cursor_is_max_seq_of_returned_rows(self):
        self.enqueue_agent_message()
        self.run_hook("bridge-newmsg-watch.sh")
        a = self.insert_raw("2030-01-01T00:00:00.000000Z")
        b = self.insert_raw("2030-01-01T00:00:01.000000Z")
        out, _ = self.run_hook("bridge-newmsg-watch.sh")
        self.assertEqual(out["payload"], {"count": 2,
                                          "message_ids": f"{a} {b}"})
        import sqlite3
        conn = sqlite3.connect(os.path.join(self.state, "bridge.db"))
        max_seq = conn.execute("SELECT MAX(seq) FROM messages").fetchone()[0]
        conn.close()
        with open(os.path.join(self.state, "hooks", "bridge-newmsg-watch",
                               "cursor_seq")) as f:
            self.assertEqual(int(f.read()), max_seq)
        again, _ = self.run_hook("bridge-newmsg-watch.sh")
        self.assertEqual(again["decision"], "silent")


class DaemonWatchTest(HookTestBase):
    def test_dry_run_reports_unhealthy_without_starting(self):
        out, _ = self.run_hook("bridge-daemon-watch.sh",
                               BRIDGE_HOOK_DRY_RUN="1")
        self.assertEqual(out["decision"], "silent")
        self.assertIn("dry-run", out["reason"])
        self.assertFalse(os.path.exists(
            os.path.join(self.state, "run", "tunnel-poll.pid")))


if __name__ == "__main__":
    unittest.main(verbosity=1)

#!/usr/bin/env python3
"""Review #9: the suite never touches the operator's configured state.

Runs the in-process test modules in a subprocess whose environment looks
like an operator shell that sourced a real .env (BRIDGE_STATE_DIR,
BRIDGE_DB, BRIDGE_FROZEN_FILE ... pointing at live paths, with the bridge
currently FROZEN). The suite must pass and leave those paths untouched.

Run: python3 tests/test_hermetic.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _hermetic  # noqa: E402


def snapshot(root: str) -> dict:
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            out[path] = (st.st_mtime_ns, st.st_size)
    return out


class OperatorEnvIsolationTest(unittest.TestCase):
    def test_forced_paths_are_test_owned(self):
        for key in ("BRIDGE_STATE_DIR", "BRIDGE_DB", "BRIDGE_MCP_LOG",
                    "BRIDGE_HOOK_STATE_DIR", "BRIDGE_FROZEN_FILE"):
            self.assertTrue(os.environ[key].startswith(_hermetic.ROOT), key)

    def test_suite_ignores_operator_freeze_marker_and_state(self):
        op = tempfile.mkdtemp(prefix="bridge-operator-")
        state = os.path.join(op, "state")
        os.makedirs(os.path.join(state, "logs"))
        marker = os.path.join(op, "FROZEN")
        with open(marker, "w") as f:
            f.write("operator freeze\n")
        before = snapshot(op)
        env = _hermetic.clean_env(
            BRIDGE_STATE_DIR=state,
            BRIDGE_DB=os.path.join(state, "bridge.db"),
            BRIDGE_MCP_LOG=os.path.join(state, "logs", "bridge-mcp.log"),
            BRIDGE_HOOK_STATE_DIR=os.path.join(state, "hooks"),
            BRIDGE_FROZEN_FILE=marker,
            BRIDGE_SUBJECT_FINGERPRINT="0123456789abcdef",
            BRIDGE_HOOK_DRY_RUN="1")
        r = subprocess.run(
            [sys.executable, "-m", "unittest", "test_events", "test_bridge",
             "test_config"],
            cwd=HERE, env=env, capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-4000:])
        self.assertTrue(os.path.exists(marker))
        self.assertEqual(snapshot(op), before)


if __name__ == "__main__":
    unittest.main(verbosity=1)

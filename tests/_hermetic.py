"""Test isolation: import this BEFORE any bridge module.

Every BRIDGE_* variable inherited from the operator's environment (for
example a sourced .env with a real BRIDGE_FROZEN_FILE) is removed, then
test-owned temp paths are FORCED (not setdefault) for state, db, logs,
hook state and the freeze marker. bridge_mcp.paths reads these at import
time, so this must run first. Runs once per process: a second test module
importing it gets the same paths the bridge modules already captured.

Subprocess tests should build their environment with ``clean_env()``.
"""
from __future__ import annotations

import os
import tempfile

ROOT = tempfile.mkdtemp(prefix="bridge-test-")
STATE_DIR = os.path.join(ROOT, "state")
FROZEN_FILE = os.path.join(ROOT, "frozen", "FROZEN")

for _key in [k for k in os.environ if k.startswith("BRIDGE_")]:
    del os.environ[_key]

os.makedirs(STATE_DIR)
os.makedirs(os.path.dirname(FROZEN_FILE))
os.environ.update({
    "BRIDGE_STATE_DIR": STATE_DIR,
    "BRIDGE_DB": os.path.join(STATE_DIR, "bridge.db"),
    "BRIDGE_MCP_LOG": os.path.join(STATE_DIR, "logs", "bridge-mcp.log"),
    "BRIDGE_HOOK_STATE_DIR": os.path.join(STATE_DIR, "hooks"),
    "BRIDGE_FROZEN_FILE": FROZEN_FILE,
})


def clean_env(**extra) -> dict:
    """os.environ without ANY BRIDGE_* variable, plus ``extra``."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRIDGE_")}
    env.update(extra)
    return env

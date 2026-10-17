"""Filesystem locations for agent-bridge state.

Single source of truth for the Python side. Every location is overridable
by environment variable; defaults live under ~/.local/state/agent-bridge/.
The shell scripts (scripts/, hooks/) apply the same defaults and the same
variable names, so poller, MCP child, admin CLI, and hooks always agree.

- BRIDGE_STATE_DIR    state root (db, logs, run/, secrets/, FROZEN)
- BRIDGE_DB           SQLite queue store (default: $BRIDGE_STATE_DIR/bridge.db)
- BRIDGE_MCP_LOG      MCP child diagnostics log
- BRIDGE_FROZEN_FILE  freeze marker (default: $BRIDGE_STATE_DIR/FROZEN);
                      read at call time, so tests can repoint it per-test
"""
from __future__ import annotations

import os

STATE_DIR = os.environ.get("BRIDGE_STATE_DIR") or os.path.expanduser(
    "~/.local/state/agent-bridge")
DEFAULT_DB = os.environ.get("BRIDGE_DB") or os.path.join(STATE_DIR, "bridge.db")
MCP_LOG = os.environ.get("BRIDGE_MCP_LOG") or os.path.join(
    STATE_DIR, "logs", "bridge-mcp.log")
FREEZE_PATH = os.path.join(STATE_DIR, "FROZEN")
SECRETS_DIR = os.path.join(STATE_DIR, "secrets")


def frozen_path() -> str:
    """Current freeze-marker path (BRIDGE_FROZEN_FILE override honored)."""
    return os.environ.get("BRIDGE_FROZEN_FILE", FREEZE_PATH)

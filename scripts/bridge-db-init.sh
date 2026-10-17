#!/usr/bin/env bash
# Initialize the agent-bridge SQLite store (WAL mode). Idempotent.
# Schema migrations beyond 001 are applied by bridge_mcp/store.py on first
# connect (PRAGMA user_version).
set -euo pipefail
umask 077

BRIDGE_HOME="${BRIDGE_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STATE_DIR="${BRIDGE_STATE_DIR:-$HOME/.local/state/agent-bridge}"
DB="${BRIDGE_DB:-$STATE_DIR/bridge.db}"
SCHEMA="$BRIDGE_HOME/sql/001_init.sql"

mkdir -p "$STATE_DIR/run" "$STATE_DIR/logs" "$STATE_DIR/secrets" "$(dirname "$DB")"
chmod 700 "$STATE_DIR" "$STATE_DIR/secrets"

command -v sqlite3 >/dev/null || { echo "bridge-db-init: sqlite3 missing" >&2; exit 1; }
[ -f "$SCHEMA" ] || { echo "bridge-db-init: schema missing: $SCHEMA" >&2; exit 1; }

sqlite3 "$DB" < "$SCHEMA"
# verify WAL actually on
mode=$(sqlite3 "$DB" "PRAGMA journal_mode;")
[ "$mode" = "wal" ] || { echo "bridge-db-init: WAL not enabled (got $mode)" >&2; exit 1; }
echo "bridge-db-init: ok db=$DB journal_mode=$mode"

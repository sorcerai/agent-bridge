#!/usr/bin/env bash
# Wake the host promptly when a NEW agent->host (agent_to_host) message
# lands. Cursor-based (monotonic messages.seq): each message fires exactly
# one wake. Pure shell, no AI. Wake payload carries message_ids only — bodies are untrusted; the
# woken agent reads them via `scripts/bridge-admin.sh show` (<bridge_untrusted>
# frame) and marks them read with `scripts/bridge-admin.sh ack`.
set -euo pipefail
umask 077

# ---- hook runtime ------------------------------------------------------------
# If BRIDGE_HOOK_RUNTIME names a file, source it; it must define silent/wake/
# log with this contract. Otherwise use the built-in stubs (standalone mode):
#   silent|wake <reason> [payload-json] -> ONE JSON line on stdout, then exit 0
#   log <message> [fields-json]         -> one JSON line on stderr
if [ -n "${BRIDGE_HOOK_RUNTIME:-}" ]; then
  # shellcheck disable=SC1090
  source "$BRIDGE_HOOK_RUNTIME"
else
  _bridge_hook_emit() {
    python3 - "$@" <<'PYEOF' || exit 1
import json, os, sys
decision, reason, payload = (sys.argv[1:] + ["", ""])[:3]
out = {"decision": decision, "reason": reason}
if payload:
    out["payload"] = json.loads(payload)
if os.environ.get("BRIDGE_WAKE_TARGET"):
    out["target"] = os.environ["BRIDGE_WAKE_TARGET"]
print(json.dumps(out, separators=(",", ":")))
PYEOF
    exit 0
  }
  silent() { _bridge_hook_emit silent "${1-}" "${2-}"; }
  wake() { _bridge_hook_emit wake "${1-}" "${2-}"; }
  log() {
    python3 -c 'import json, sys
try:
    rec = json.loads(sys.argv[2]) if sys.argv[2] else {}
    assert isinstance(rec, dict)
except (ValueError, AssertionError):
    rec = {"fields_raw": sys.argv[2][:200]}
rec["message"] = sys.argv[1]
print(json.dumps(rec, separators=(",", ":")))' "${1-}" "${2-}" >&2 || true
  }
fi

STATE="${BRIDGE_STATE_DIR:-$HOME/.local/state/agent-bridge}"
DB="${BRIDGE_DB:-$STATE/bridge.db}"
HOOK_STATE="${BRIDGE_HOOK_STATE_DIR:-$STATE/hooks}/bridge-newmsg-watch"
# Cursor = last-seen messages.seq (INTEGER PRIMARY KEY AUTOINCREMENT:
# monotonic, never reused). Replaces the old created_at timestamp
# watermark, which could skip a row committed between two queries.
CURSOR="$HOOK_STATE/cursor_seq"
LEGACY_WATERMARK="$HOOK_STATE/watermark"
BATCH=100
DRY="${BRIDGE_HOOK_DRY_RUN:-0}"

# Dry run writes NO state (no dirs, no cursor init/advance).
[ "$DRY" = "1" ] || mkdir -p "$HOOK_STATE"

# sqlite3 swallows query output when a meta-command like .timeout leads
# argv, so every query goes via stdin. Every invocation starts with
# .timeout 5000.
sql() { printf '.timeout 5000\n%s\n' "$1" | sqlite3 "$DB" 2>/dev/null; }

save_cursor() { [ "$DRY" = "1" ] || printf '%s\n' "$1" > "$CURSOR"; }

if [ ! -f "$CURSOR" ]; then
  if [ ! -f "$DB" ]; then
    # No DB yet means no pre-existing messages: start from the beginning.
    if [ "$DRY" = "1" ]; then silent "dry-run: bridge db missing; would initialize cursor at seq 0"; fi
    save_cursor 0
    silent "bridge db missing; cursor initialized at seq 0"
  fi
  if [ -f "$LEGACY_WATERMARK" ]; then
    # Upgrade from the timestamp watermark: resume just before the first
    # row the old watermark had NOT covered. seq and created_at can be out
    # of order, so a few already-announced rows may wake once more; none is
    # skipped.
    wm=$(head -n1 "$LEGACY_WATERMARK" | tr -cd '0-9TZ:.-')
    init=$(sql "SELECT COALESCE(
  (SELECT MIN(seq) - 1 FROM messages
   WHERE direction='agent_to_host' AND created_at > '$wm'),
  (SELECT COALESCE(MAX(seq), 0) FROM messages));") || init=""
  else
    init=$(sql "SELECT COALESCE(MAX(seq),0) FROM messages;") || init=""
  fi
  case "$init" in ''|*[!0-9]*) silent "could not read bridge db to initialize cursor";; esac
  if [ "$DRY" = "1" ]; then
    silent "dry-run: would initialize cursor at seq $init"
  fi
  save_cursor "$init"
  if [ ! -f "$LEGACY_WATERMARK" ]; then
    silent "cursor initialized at seq $init; pre-existing messages will not re-fire"
  fi
  cursor="$init"
else
  cursor=$(head -n1 "$CURSOR")
fi
case "$cursor" in ''|*[!0-9]*) silent "cursor file corrupt; refusing to guess (delete $CURSOR to re-initialize)";; esac

[ -f "$DB" ] || silent "bridge db missing"
# ONE query; the next cursor is derived from exactly the rows returned, so
# a row committed after this SELECT has a higher seq and fires next run.
rows=$(sql ".mode list
.separator |
SELECT seq, message_id FROM messages
WHERE direction='agent_to_host' AND seq > $cursor
ORDER BY seq LIMIT $BATCH;") || rows=""

if [ -z "$rows" ]; then
  silent "no new agent->host messages"
fi

ids=$(printf '%s\n' "$rows" | cut -d'|' -f2 | tr '\n' ' ' | sed 's/ *$//')
max_seq=$(printf '%s\n' "$rows" | cut -d'|' -f1 | sort -n | tail -n1)
n=$(printf '%s\n' "$rows" | grep -c '|')
case "$max_seq" in ''|*[!0-9]*) silent "unexpected query output; cursor not advanced";; esac

if [ "$DRY" = "1" ]; then
  silent "dry-run: would wake for: $ids"
fi

save_cursor "$max_seq"
log "new agent->host message(s)" "{\"message_ids\":\"$ids\"}"
wake "new agent->host message(s) on bridge" \
     "{\"count\":$n,\"message_ids\":\"$ids\"}"

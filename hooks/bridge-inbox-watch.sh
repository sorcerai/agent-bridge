#!/usr/bin/env bash
# Inbox liveness gate: agent_to_host messages arriving is NORMAL (the remote
# agent sends via message_send). Wake only when an unacked message sits
# longer than STALE_SECS — meaning the host's consumer is not picking up.
# Pure shell, no AI. Dedupes per stale message_id set.
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
HOOK_STATE="${BRIDGE_HOOK_STATE_DIR:-$STATE/hooks}/bridge-inbox-watch"
SEEN="$HOOK_STATE/stale_seen"
STALE_SECS="${BRIDGE_INBOX_STALE_SECS:-1800}"
DRY="${BRIDGE_HOOK_DRY_RUN:-0}"

# Dry run writes NO state (no dirs, no seen list).
if [ "$DRY" != "1" ]; then
  mkdir -p "$HOOK_STATE"
  touch "$SEEN"
fi
case "$STALE_SECS" in ''|*[!0-9]*) STALE_SECS=1800;; esac

# sqlite3 swallows query output when a meta-command like .timeout leads
# argv, so every query goes via stdin. Every invocation starts with
# .timeout 5000.
sql() { printf '.timeout 5000\n%s\n' "$1" | sqlite3 "$DB" 2>/dev/null; }

cutoff=$(date -u -d "@$(( $(date +%s) - STALE_SECS ))" +"%Y-%m-%dT%H:%M:%S.000Z" 2>/dev/null || printf '1970-01-01T00:00:00.000Z')

stale=""
if [ -f "$DB" ]; then
  stale=$(sql "SELECT message_id FROM messages
WHERE direction='agent_to_host'
  AND status IN ('queued','awaiting_result')
  AND created_at < '$cutoff'
ORDER BY created_at LIMIT 10;") || stale=""
fi

new_stale=""
for mid in $stale; do
  grep -qx "$mid" "$SEEN" 2>/dev/null || new_stale="$new_stale $mid"
done

if [ -z "$new_stale" ]; then
  n=$(printf '%s' "$stale" | wc -w)
  silent "no new stale agent messages (stale_known=$n)"
fi

if [ "$DRY" != "1" ]; then
  for mid in $new_stale; do printf '%s\n' "$mid" >> "$SEEN"; done
fi
log "stale unacked agent message(s): host consumer may be down" \
    "{\"message_ids\":\"$new_stale\"}"
wake "stale unacked agent->host message(s) on bridge" \
     "{\"stale_message_ids\":\"$new_stale\"}"

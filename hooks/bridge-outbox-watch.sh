#!/usr/bin/env bash
# Drive agent-bridge event deliveries (legacy phase-0 outbox path).
# The atomic claim + sign + POST is done by bridge_mcp/deliver.py; this hook
# only triggers it when due rows exist. Silent unless a delivery reaches
# terminal failure (then wake, deduped per event_id). Secret material never
# appears here: deliver.py reads the signing secret from its 0600 file.
# Note: nothing in this template enqueues event_deliveries rows today, so
# this hook stays silent unless you add a producer. Native event delivery
# is performed by bridge_mcp/events.py, not by this hook. deliver.py
# refuses while the bridge is frozen. Requires jq.
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

BRIDGE_HOME="${BRIDGE_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STATE="${BRIDGE_STATE_DIR:-$HOME/.local/state/agent-bridge}"
DB="${BRIDGE_DB:-$STATE/bridge.db}"
DELIVER="$BRIDGE_HOME/bridge_mcp/deliver.py"
HOOK_STATE="${BRIDGE_HOOK_STATE_DIR:-$STATE/hooks}/bridge-outbox-watch"
LOCK="$HOOK_STATE/lock"
SEEN_FAILED="$HOOK_STATE/failed_event_ids"
DRY="${BRIDGE_HOOK_DRY_RUN:-0}"

# Dry run writes NO state (no dirs, no dedupe list).
if [ "$DRY" != "1" ]; then
  mkdir -p "$HOOK_STATE"
  touch "$SEEN_FAILED"
fi

now_iso() { date -u +"%Y-%m-%dT%H:%M:%S.000Z"; }

# sqlite3 swallows query output when a meta-command like .timeout leads
# argv, so every query goes via stdin. Every invocation starts with
# .timeout 5000.
sql() { printf '.timeout 5000\n%s\n' "$1" | sqlite3 "$DB" 2>/dev/null; }

due_count() {
  [ -f "$DB" ] || { echo 0; return 0; }
  local now
  now=$(now_iso)
  # Same predicate as store.claim_delivery, incl. expired 'sending' leases.
  sql "SELECT COUNT(*) FROM event_deliveries
WHERE (status IN ('pending','retry')
       AND next_attempt_at <= '$now'
       AND (lease_until IS NULL OR lease_until < '$now'))
   OR (status = 'sending' AND lease_until IS NOT NULL
       AND lease_until < '$now');" || echo 0
}

n=$(due_count)
n="${n:-0}"
case "$n" in ''|*[!0-9]*) n=0;; esac
if [ "$n" -eq 0 ]; then
  silent "no due event deliveries"
fi

if [ "$DRY" = "1" ]; then
  silent "dry-run: $n due deliverie(s), would run deliver.py --once"
fi

mkdir "$LOCK" 2>/dev/null || silent "delivery already running, skipping"
out=$(python3 "$DELIVER" --once --db "$DB" 2>/dev/null) || true
rmdir "$LOCK" 2>/dev/null || true

outcome=$(jq -r '.outcome // "unknown"' <<<"$out" 2>/dev/null || echo unknown)
event_id=$(jq -r '.event_id // ""' <<<"$out" 2>/dev/null || echo "")
log "delivery attempt finished" "{\"outcome\":\"$outcome\"}"

case "$outcome" in
  idle|delivered|dry_run)
    silent "delivery $outcome"
    ;;
  frozen)
    silent "delivery refused: bridge frozen"
    ;;
  retry)
    silent "delivery scheduled for retry"
    ;;
  failed)
    if grep -qxF "$event_id" "$SEEN_FAILED" 2>/dev/null; then
      silent "delivery failed, alert already sent for $event_id"
    else
      printf '%s\n' "$event_id" >> "$SEEN_FAILED"
      reason=$(jq -r '.reason // "unknown"' <<<"$out" 2>/dev/null || echo unknown)
      wake "bridge event delivery failed terminally" \
        "{\"event_id\":\"$event_id\",\"reason\":\"$reason\"}"
    fi
    ;;
  *)
    log "deliver.py returned unexpected outcome" "{\"raw\":\"$(cut -c1-120 <<<"$out")\"}"
    silent "delivery outcome unclear, logged"
    ;;
esac

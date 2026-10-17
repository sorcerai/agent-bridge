#!/usr/bin/env bash
# Watchdog for the agent-bridge tunnel poller.
# Single-poller invariant: NEVER starts a second live poller (PID file +
# /proc/<pid>/cmdline check, mkdir lock, and the poller itself refuses to
# start while another live poller owns the PID file).
# Silent when healthy. Wakes only when a shell restart fails or the poller
# is flapping (restarted 3+ times in 15 min).
# The poller inherits this script's environment: BRIDGE_TUNNEL_ID,
# OPENAI_API_KEY and BRIDGE_SUBJECT_FINGERPRINT must be set for the scheduler
# that runs this hook.
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
RUN="$STATE/run"; LOGS="$STATE/logs"
PID_FILE="$RUN/tunnel-poll.pid"
HB="$RUN/tunnel-poll.heartbeat"
POLLER="$BRIDGE_HOME/scripts/tunnel-poll.py"
HOOK_STATE="${BRIDGE_HOOK_STATE_DIR:-$STATE/hooks}/bridge-daemon-watch"
LOCK="$HOOK_STATE/lock"
ALERT_TS="$HOOK_STATE/unhealthy_alert_ts"
RESTARTS="$HOOK_STATE/restart_ts"
DRY="${BRIDGE_HOOK_DRY_RUN:-0}"

# Dry run writes NO state (no dirs, restart history, or alert stamps).
if [ "$DRY" != "1" ]; then
  mkdir -p "$HOOK_STATE" "$RUN" "$LOGS"
  touch "$RESTARTS"
fi
now=$(date +%s)

poller_alive() {
  [ -f "$PID_FILE" ] || return 1
  local pid
  pid=$(cat "$PID_FILE" 2>/dev/null) || return 1
  case "$pid" in ''|*[!0-9]*) return 1;; esac
  [ -d "/proc/$pid" ] || return 1
  grep -q "tunnel-poll.py" "/proc/$pid/cmdline" 2>/dev/null
}

poller_pid() { cat "$PID_FILE" 2>/dev/null || echo 0; }

heartbeat_fresh() {
  [ -f "$HB" ] || return 1
  local m
  m=$(stat -c %Y "$HB" 2>/dev/null || echo 0)
  [ $(( now - m )) -le 180 ]
}

record_restart() {
  # keep only restarts within the last 15 min; count flaps
  local cutoff=$(( now - 900 ))
  awk -v c="$cutoff" '$1 >= c' "$RESTARTS" > "$RESTARTS.tmp" 2>/dev/null || true
  printf '%s\n' "$now" >> "$RESTARTS.tmp"
  mv "$RESTARTS.tmp" "$RESTARTS"
  wc -l < "$RESTARTS" | tr -d ' '
}

should_alert() { # at most one unhealthy wake per 30 min
  if [ -f "$ALERT_TS" ]; then
    [ $(( now - $(cat "$ALERT_TS") )) -gt 1800 ]
  else
    return 0
  fi
}

start_poller() {
  mkdir "$LOCK" 2>/dev/null || { log "start lock held, skipping"; return 1; }
  if poller_alive; then rmdir "$LOCK"; return 0; fi  # re-check under lock
  setsid nohup python3 "$POLLER" >>"$LOGS/tunnel-poll.log" 2>&1 &
  disown 2>/dev/null || true
  sleep 3
  rmdir "$LOCK"
  poller_alive
}

# --- healthy path ---
if poller_alive && heartbeat_fresh; then
  silent "tunnel poller healthy"
fi

# --- unhealthy path ---
if [ "$DRY" = "1" ]; then
  silent "dry-run: poller unhealthy, would restart in shell"
fi

if poller_alive && ! heartbeat_fresh; then
  log "poller heartbeat stale, killing stuck poller"
  kill "$(poller_pid)" 2>/dev/null || true
  sleep 2
fi

log "poller down or stuck, attempting shell restart"
if start_poller; then
  n=$(record_restart)
  log "poller restarted OK in shell" "{\"restarts_15m\":$n}"
  if [ "$n" -ge 3 ]; then
    if should_alert; then
      printf '%s' "$now" > "$ALERT_TS"
      wake "tunnel poller flapping ($n restarts in 15m)" "{\"restarts_15m\":$n}"
    else
      silent "poller flapping, alert already sent within 30m"
    fi
  else
    silent "tunnel poller was down, restarted OK in shell"
  fi
else
  log "poller restart failed"
  if should_alert; then
    printf '%s' "$now" > "$ALERT_TS"
    wake "tunnel poller down, shell restart failed" '{"poller":"down","restart":"failed"}'
  else
    silent "poller still down, alert already sent within 30m"
  fi
fi

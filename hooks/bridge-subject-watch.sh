#!/usr/bin/env bash
# Boundary watchdog for agent-bridge — defense in depth.
# The PRIMARY gate is synchronous: the poller rejects private tools/call
# commands whose x-openai-subject fingerprint is not the pinned baseline
# BEFORE the MCP child sees them. This hook is the backup: it re-examines
# the poller log and freezes private tools if anything slipped through.
#
# It also consumes the poller's command_rejected_caller records (the
# synchronous gate's own freezes) and freeze_file_failed records, so a
# gate-triggered freeze wakes the operator too; the bootstrap rejection
# (reason subject_baseline_unset, which never freezes) is exempt.
#
# P0-3: parses complete JSON lines with Python (not text regex), requires
# exactly one valid subject fingerprint per PRIVATE command_dispatched
# record, and fails CLOSED: a private command with a missing/duplicate/
# malformed subject is an anomaly, not a pass. Open discovery/attribution
# methods (server/discover, initialize, tools/list, events/list,
# bridge_status, ping, notifications/*) legitimately carry no
# x-openai-subject — ChatGPT's control plane does not attach one — so
# they are exempt. (An earlier version flagged those and froze the bridge
# on ChatGPT's own discovery calls; verified false positive.)
# Only complete lines are consumed; a partial trailing line is preserved
# for the next run.
#
# BRIDGE_SUBJECT_FINGERPRINT must match the poller's value. If it is unset
# here, every dispatched private call counts as an anomaly (fail closed).
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
LOG="$STATE/logs/tunnel-poll.log"
FROZEN="${BRIDGE_FROZEN_FILE:-$STATE/FROZEN}"
# Pinned baseline (same value the poller uses). Update ONLY after a
# deliberate, operator-approved re-verification.
BASELINE_FP="${BRIDGE_SUBJECT_FINGERPRINT:-}"
HOOK_STATE="${BRIDGE_HOOK_STATE_DIR:-$STATE/hooks}/bridge-subject-watch"
OFFSET="$HOOK_STATE/log_offset"
SEEN="$HOOK_STATE/seen_fps"
ALERT_TS="$HOOK_STATE/unhealthy_alert_ts"
FREEZE_ALERTED="$HOOK_STATE/alerted_freeze_id"
DRY="${BRIDGE_HOOK_DRY_RUN:-0}"

# Dry run writes NO state at all (no dirs, offsets, seen list, dedupe
# stamps, or FROZEN), so a dry run followed by a real run behaves exactly
# like the real run alone.
if [ "$DRY" != "1" ]; then
  mkdir -p "$HOOK_STATE"
  touch "$SEEN"
  [ -f "$OFFSET" ] || printf '0' > "$OFFSET"
fi
[ -n "$BASELINE_FP" ] || log "BRIDGE_SUBJECT_FINGERPRINT unset; any dispatched private call is an anomaly"

last_offset=$(cat "$OFFSET" 2>/dev/null || echo 0)
case "$last_offset" in ''|*[!0-9]*) last_offset=0;; esac
size=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
[ "$size" -lt "$last_offset" ] && last_offset=0  # rotated/truncated

# Scan only complete lines; report back the new offset (start of any
# partial trailing line) so it is re-examined next run.
# Anomalies:
#  - command_dispatched for a PRIVATE method whose subject fingerprint is
#    missing/malformed or not the baseline (something slipped the gate);
#  - command_rejected_caller: the poller's synchronous gate refused (and
#    froze on) an unexpected caller — EXCEPT reason subject_baseline_unset,
#    the documented bootstrap rejection that never freezes;
#  - freeze_file_failed: the poller could not create FROZEN itself.
# Rejections of the PINNED fingerprint are consequences of an existing
# freeze, not new anomalies.
scan_out=$(python3 - "$LOG" "$last_offset" "$BASELINE_FP" <<'PYEOF'
import json, re, sys
path, start, baseline = sys.argv[1], int(sys.argv[2]), sys.argv[3]
unknown, missing, rejected, freeze_failed = set(), 0, 0, 0
try:
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read()
except OSError:
    print("offset:%d" % start); sys.exit(0)
# split keeping line starts; last element may be partial
parts = data.split(b"\n")
consumed = start


def subject_of(rec):
    """The single valid (16 lowercase hex) subject fingerprint, or None.
    Anything else is treated as missing (fail closed)."""
    hfp = rec.get("header_fp")
    fps = hfp.get("x-openai-subject") if isinstance(hfp, dict) else None
    vals = fps if isinstance(fps, list) else [fps]
    if len(vals) != 1 or not isinstance(vals[0], str) \
            or not re.fullmatch(r"[0-9a-f]{16}", vals[0]):
        return None
    return vals[0]


for i, part in enumerate(parts):
    last = (i == len(parts) - 1)
    if last and part:
        break  # partial trailing line: do not consume
    consumed += len(part) + (0 if last else 1)
    if not part.strip():
        continue
    try:
        rec = json.loads(part)
    except Exception:
        continue
    if not isinstance(rec, dict):
        continue
    event = rec.get("event")
    if event == "freeze_file_failed":
        freeze_failed += 1
        continue
    if event == "command_rejected_caller":
        if rec.get("reason") == "subject_baseline_unset":
            continue  # bootstrap: fail-closed rejection, no freeze
        fp = subject_of(rec)
        if fp is not None and baseline and fp == baseline:
            continue  # pinned caller refused because already frozen
        rejected += 1
        if fp is None:
            missing += 1
        else:
            unknown.add(fp)
        continue
    if event != "command_dispatched":
        continue
    # Only private invocations require the pinned subject fingerprint.
    # Open methods legitimately carry no x-openai-subject header.
    _method = rec.get("method")
    _tool = rec.get("tool")
    _private = (_method == "tools/call" and _tool in
                ("inbox_poll", "inbox_ack", "message_send")) or \
               (_method in ("events/subscribe", "events/unsubscribe"))
    if not _private:
        continue
    fp = subject_of(rec)
    if fp is None:
        missing += 1
        continue
    if fp != baseline:
        unknown.add(fp)
print("offset:%d" % consumed)
print("missing:%d" % missing)
print("rejected:%d" % rejected)
print("freezefail:%d" % freeze_failed)
for fp in sorted(unknown):
    print("unknown:%s" % fp)
PYEOF
)

new_offset=$(printf '%s\n' "$scan_out" | sed -n 's/^offset://p')
missing=$(printf '%s\n' "$scan_out" | sed -n 's/^missing://p')
rejected=$(printf '%s\n' "$scan_out" | sed -n 's/^rejected://p')
freezefail=$(printf '%s\n' "$scan_out" | sed -n 's/^freezefail://p')
unknown=$(printf '%s\n' "$scan_out" | sed -n 's/^unknown://p')
case "$new_offset" in ''|*[!0-9]*) new_offset="$last_offset";; esac
case "${missing:-}" in ''|*[!0-9]*) missing=0;; esac
case "${rejected:-}" in ''|*[!0-9]*) rejected=0;; esac
case "${freezefail:-}" in ''|*[!0-9]*) freezefail=0;; esac
[ "$DRY" = "1" ] || printf '%s' "$new_offset" > "$OFFSET"

if [ -z "$unknown" ] && [ "$missing" -eq 0 ] && [ "$rejected" -eq 0 ] \
    && [ "$freezefail" -eq 0 ]; then
  silent "subject fingerprint matches baseline"
fi

# --- anomaly: ALWAYS enforce the freeze (independent of dedupe) ---
if [ "$DRY" != "1" ] && [ ! -e "$FROZEN" ]; then
  : > "$FROZEN" 2>/dev/null || log "could not create FROZEN marker"
fi

# Notification dedupe. Never suppresses a wake for:
#  - a fingerprint not previously reported (not in seen_fps), or
#  - a NEW freeze: the FROZEN marker's identity (device:inode:mtime)
#    differs from the one last alerted (e.g. operator unfroze and the
#    gate froze again, even for an already-seen fingerprint).
# Otherwise repeat alerts for the same freeze are limited to one per 30 min.
fresh=""
for fp in $unknown; do
  grep -qx "$fp" "$SEEN" 2>/dev/null || fresh="$fresh $fp"
done
freeze_id=$(stat -c '%d:%i:%.9Y' "$FROZEN" 2>/dev/null \
  || stat -c '%d:%i:%Y' "$FROZEN" 2>/dev/null || echo "absent")
last_freeze_id=$(cat "$FREEZE_ALERTED" 2>/dev/null || echo "")

should_alert() {
  [ -n "$fresh" ] && return 0
  [ "$freeze_id" != "$last_freeze_id" ] && return 0
  if [ -f "$ALERT_TS" ]; then
    [ $(( $(date +%s) - $(cat "$ALERT_TS") )) -gt 1800 ]
  else
    return 0
  fi
}

all_fps=$(printf '%s' "$unknown" | tr '\n' ' ' | sed 's/ $//')
if should_alert; then
  if [ "$DRY" != "1" ]; then
    for fp in $fresh; do printf '%s\n' "$fp" >> "$SEEN"; done
    printf '%s' "$(date +%s)" > "$ALERT_TS"
    printf '%s' "$freeze_id" > "$FREEZE_ALERTED"
  fi
  log "caller-identity anomaly; private tools frozen" \
      "{\"unknown_fps\":\"$all_fps\",\"missing_subject_records\":$missing,\"rejected_caller_records\":$rejected,\"freeze_file_failed\":$freezefail}"
  wake "agent-bridge caller anomaly — private tools FROZEN" \
       "{\"unknown_subject_fps\":\"$all_fps\",\"new_subject_fps\":\"$(printf '%s' "$fresh" | sed 's/^ //')\",\"missing_subject_records\":$missing,\"rejected_caller_records\":$rejected,\"freeze_file_failed\":$freezefail,\"frozen\":true}"
else
  silent "caller anomaly already alerted (dedupe window)"
fi

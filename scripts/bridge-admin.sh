#!/usr/bin/env bash
# bridge-admin: local (host-side) admin CLI for the agent-bridge queue store.
# All SQL goes through .parameter set (never string interpolation).
# Message bodies shown by `show` are wrapped in a <bridge_untrusted> frame.
set -euo pipefail
umask 077

BRIDGE_HOME="${BRIDGE_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STATE_DIR="${BRIDGE_STATE_DIR:-$HOME/.local/state/agent-bridge}"
DB="${BRIDGE_DB:-$STATE_DIR/bridge.db}"
# The embedded Python (bridge_mcp.paths) must open the same DB as sqlite3.
export BRIDGE_STATE_DIR="$STATE_DIR" BRIDGE_DB="$DB"

command -v sqlite3 >/dev/null || { echo "bridge-admin: sqlite3 missing" >&2; exit 1; }
if [ "${1:-}" != "init" ] && [ ! -f "$DB" ]; then
  echo "bridge-admin: db missing; run bridge-admin init (or bridge-db-init.sh) first" >&2; exit 1
fi

q() { # q <sql> — every invocation starts with .timeout 5000 (via stdin:
      # sqlite3 swallows query output when a meta-command like .timeout leads argv)
  printf '.timeout 5000\n%s\n' "$1" | sqlite3 -json "$DB"
}

usage() {
  cat >&2 <<'EOF'
usage: bridge-admin <command> [args]
  init                            create schema (same as bridge-db-init.sh)
  enqueue --type T --subject S --body B [--correlation-id C]
                                  enqueue a host_to_agent message (secret-scanned)
  list [--direction D] [--status S] [--limit N]
                                  list messages (newest first, no bodies)
  show <message_id>               show one message, body in <bridge_untrusted> frame
  ack <message_id>                mark an agent_to_host message read (acked)
  expire                          sweep past-TTL rows to expired
  events-subs                     list event subscriptions (no secrets)
  events-fire --subscription-id ID [--label L] [--override-frozen]
                                  deliver one synthetic bridge.ping event
EOF
  exit 2
}

cmd_init() { bash "$BRIDGE_HOME/scripts/bridge-db-init.sh"; }

# ---- Optional Slack wake-up ping (host -> remote wake path) --------------
# Fires a push ping whenever a host->agent message is enqueued, so a human
# (or a Slack-connected remote agent) can trigger inbox_poll instead of
# waiting for the next scheduled poll. Best-effort: a Slack failure never
# fails the enqueue. Silently disabled unless BRIDGE_SLACK_CHANNEL_ID is set
# AND a `slack` CLI exposing `call-tool --name slack_send_message` is on
# PATH. Set BRIDGE_SLACK_PING=0 to disable for a single run.
BRIDGE_SLACK_CHANNEL_ID="${BRIDGE_SLACK_CHANNEL_ID:-}"

slack_ping_for_agent() {
  local message_id="$1" msg_type="$2" correlation_id="$3"
  [ "${BRIDGE_SLACK_PING:-1}" = 1 ] || return 0
  [ -n "$BRIDGE_SLACK_CHANNEL_ID" ] || return 0
  command -v slack >/dev/null 2>&1 || return 0
  local text="Message waiting for the remote agent: ${message_id} (type=${msg_type}, corr=${correlation_id}). Ask it to run inbox_poll on the bridge."
  local args
  args=$(python3 -c 'import json,sys; print(json.dumps({"channel_id": sys.argv[1], "message": sys.argv[2]}))' \
    "$BRIDGE_SLACK_CHANNEL_ID" "$text")
  slack call-tool --name slack_send_message --arguments-json "$args" \
    >/dev/null 2>&1 || true
}

cmd_enqueue() {
  local type="" subject="" body="" correlation_id=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --type) type="$2"; shift 2;;
      --subject) subject="$2"; shift 2;;
      --body) body="$2"; shift 2;;
      --correlation-id) correlation_id="$2"; shift 2;;
      *) echo "bridge-admin: unknown enqueue flag $1" >&2; exit 2;;
    esac
  done
  [ -n "$type" ] || { echo "bridge-admin: --type required" >&2; exit 2; }
  case "$type" in request|reply|result|ping|error) ;;
    *) echo "bridge-admin: bad type $type" >&2; exit 2;; esac
  [ -n "$correlation_id" ] || correlation_id="host-$(date +%s)-$RANDOM"
  local out
  out=$(PYTHONPATH="$BRIDGE_HOME" python3 - "$type" "$subject" "$body" "$correlation_id" <<'PYEOF'
import json, re, sys, uuid
from bridge_mcp import schemas, store
mtype, subject, body, corr = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    schemas.check_id("correlation_id", corr)
    payload = {"subject": subject, "body": body, "refs": [], "quoted": []}
    schemas.check_payload(payload)
    schemas.check_no_secrets(payload)   # P1-11: refuse credential-looking bodies
except schemas.ValidationError as e:
    print(json.dumps({"error": "validation", "detail": str(e)})); sys.exit(1)
conn = store.connect()
try:
    res = store.enqueue(conn, direction="host_to_agent", sender="host",
                        recipient="remote-agent", correlation_id=corr,
                        idempotency_key="host-" + uuid.uuid4().hex[:16],
                        msg_type=mtype, payload=payload)
    store.record_tool_call(conn, "bridge_admin.enqueue", [res["message_id"]])
    print(json.dumps(res))
finally:
    conn.close()
PYEOF
) || { echo "$out" >&2; exit 1; }
  echo "$out"
  local mid
  mid=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("message_id") or "")' 2>/dev/null)
  if [ -n "$mid" ]; then
    slack_ping_for_agent "$mid" "$type" "$correlation_id" &
  fi
}

cmd_list() {
  local direction="" status="" limit=20
  while [ $# -gt 0 ]; do
    case "$1" in
      --direction) direction="$2"; shift 2;;
      --status) status="$2"; shift 2;;
      --limit) limit="$2"; shift 2;;
      *) echo "bridge-admin: unknown list flag $1" >&2; exit 2;;
    esac
  done
  case "$limit" in ''|*[!0-9]*) echo "bridge-admin: --limit must be numeric" >&2; exit 2;; esac
  case "$direction" in ""|host_to_agent|agent_to_host) ;;
    *) echo "bridge-admin: bad direction" >&2; exit 2;; esac
  case "$status" in ""|queued|pending_agent_poll|awaiting_result|acked|expired|failed) ;;
    *) echo "bridge-admin: bad status" >&2; exit 2;; esac
  local where="1=1"
  [ -n "$direction" ] && where="$where AND direction='$direction'"
  [ -n "$status" ] && where="$where AND status='$status'"
  # direction/status/limit are shell-validated enums/numerics; values quoted.
  q "SELECT seq, message_id, direction, sender, recipient, correlation_id, type, status, created_at
     FROM messages WHERE $where ORDER BY seq DESC LIMIT $limit;"
}

cmd_show() {
  [ $# -eq 1 ] || { echo "bridge-admin: show <message_id>" >&2; exit 2; }
  local id="$1"
  if ! [[ "$id" =~ ^msg_[A-Za-z0-9]+$ ]]; then
    echo "bridge-admin: bad message_id" >&2; exit 2
  fi
  local row
  row=$(printf ".timeout 5000\n.parameter set @id '%s'\nSELECT * FROM messages WHERE message_id = @id;" "$id" \
        | sqlite3 -json "$DB")
  [ "$row" = "[]" ] && { echo "bridge-admin: not found" >&2; exit 1; }
  PYTHONPATH="$BRIDGE_HOME" python3 - "$row" <<'PYEOF'
import json, sys
from bridge_mcp import taint
row = json.loads(sys.argv[1])[0]
body = json.loads(row["payload_json"]).get("body", "")
print(json.dumps({k: row[k] for k in
      ("message_id","direction","sender","recipient","correlation_id",
       "idempotency_key","created_at","type","status","taint")}, indent=2))
print(taint.quarantine(body, row["sender"]))
PYEOF
}

cmd_ack() {
  [ $# -eq 1 ] || { echo "bridge-admin: ack <message_id>" >&2; exit 2; }
  local id="$1"
  if ! [[ "$id" =~ ^msg_[A-Za-z0-9]+$ ]]; then
    echo "bridge-admin: bad message_id" >&2; exit 2
  fi
  local n
  n=$(printf ".timeout 5000\n.parameter set @id '%s'\nUPDATE messages SET status='acked', acked_at=strftime('%%Y-%%m-%%dT%%H:%%M:%%fZ','now') WHERE message_id=@id AND direction='agent_to_host' AND status IN ('queued','awaiting_result'); SELECT changes();" "$id" \
        | sqlite3 "$DB")
  n="${n:-0}"
  if [ "$n" = "1" ]; then
    echo "{\"acked\": \"$id\"}"
  else
    echo "{\"acked\": null, \"reason\": \"not_found_or_not_ackable\"}" >&2; exit 1
  fi
}

cmd_expire() {  local n
  n=$(PYTHONPATH="$BRIDGE_HOME" python3 - <<'PYEOF'
from bridge_mcp import store
conn = store.connect(); print(store.expire_old(conn)); conn.close()
PYEOF
)
  echo "{\"expired\": $n}"
}

cmd_events_subs() {
  PYTHONPATH="$BRIDGE_HOME" python3 - <<'PYEOF'
import json
from bridge_mcp import store
import urllib.parse
conn = store.connect()
rows = conn.execute(
    "SELECT subscription_id, event_name, arguments_json, status, owner, "
    "created_at, verified_at, expires_at, last_delivery_at, last_error, "
    "callback_url FROM event_subscriptions ORDER BY created_at DESC").fetchall()
conn.close()
out = []
for r in rows:
    d = dict(r)
    try:
        d["callback_host"] = urllib.parse.urlsplit(d.pop("callback_url")).hostname
    except Exception:
        d["callback_host"] = None
    out.append(d)
print(json.dumps(out, indent=2))
PYEOF
}

cmd_events_fire() {
  local subscription_id="" label="" override_frozen=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --subscription-id) subscription_id="$2"; shift 2;;
      --label) label="$2"; shift 2;;
      --override-frozen) override_frozen=1; shift;;
      *) echo "bridge-admin: unknown events-fire flag $1" >&2; exit 2;;
    esac
  done
  if ! [[ "$subscription_id" =~ ^sub_[A-Za-z0-9]+$ ]]; then
    echo "bridge-admin: --subscription-id sub_<...> required" >&2; exit 2
  fi
  if [ "$override_frozen" = 1 ]; then
    echo "bridge-admin: WARNING --override-frozen: firing despite boundary freeze (audited operator override)" >&2
  fi
  OVERRIDE_FROZEN="$override_frozen" PYTHONPATH="$BRIDGE_HOME" python3 - "$subscription_id" "$label" <<'PYEOF'
import json, os, sys
from bridge_mcp import events, store
conn = store.connect()
try:
    outcome = events.fire_synthetic_event(
        conn, sys.argv[1], sys.argv[2] or None,
        allow_frozen=os.environ.get("OVERRIDE_FROZEN") == "1")
finally:
    conn.close()
print(json.dumps(outcome, indent=2))
sys.exit(0 if outcome.get("delivered") else 1)
PYEOF
}

cmd="${1:-}"; shift || true
case "$cmd" in
  init) cmd_init "$@";;
  enqueue) cmd_enqueue "$@";;
  list) cmd_list "$@";;
  show) cmd_show "$@";;
  ack) cmd_ack "$@";;
  expire) cmd_expire "$@";;
  events-subs) cmd_events_subs "$@";;
  events-fire) cmd_events_fire "$@";;
  *) usage;;
esac

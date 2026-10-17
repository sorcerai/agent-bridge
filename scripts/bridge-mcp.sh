#!/usr/bin/env bash
# Launch the bridge MCP server with a scrubbed environment (P1-6).
# Only PATH/HOME plus explicit BRIDGE_* path vars survive; the poller's
# OPENAI_API_KEY (or anything else in the parent env) is never inherited.
#
# Two deliberate exceptions, both without credentials:
#  - Sanitized proxy vars (P1-9): the child performs webhook verification
#    and delivery POSTs; if your egress requires an HTTP proxy, the proxy
#    URL's userinfo is stripped by bridge_mcp/proxyenv.py before
#    passthrough — the child never sees proxy credentials. Values the
#    sanitizer cannot parse are dropped, and a sanitizer failure aborts
#    startup (exit 1) rather than passing anything through.
#  - BRIDGE_FROZEN_FILE (P1-8): the freeze-path override propagates so
#    the child honors the same freeze the poller does. BRIDGE_STATE_DIR is
#    always passed (resolved) so the child's default FROZEN and secrets
#    paths match the poller's.
set -euo pipefail
umask 077

BRIDGE_HOME="${BRIDGE_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STATE_DIR="${BRIDGE_STATE_DIR:-$HOME/.local/state/agent-bridge}"
DB="${BRIDGE_DB:-$STATE_DIR/bridge.db}"
LOG="${BRIDGE_MCP_LOG:-$STATE_DIR/logs/bridge-mcp.log}"
PYTHON="${BRIDGE_PYTHON:-/usr/bin/python3}"

# Sanitized proxy passthrough (P0): the sanitizer's output is captured and
# its exit status checked BEFORE anything is passed on — a sanitizer
# failure aborts child startup instead of degrading to "no sanitization".
# No eval: each KEY=value line is matched against the fixed proxy-variable
# allowlist and handed to env -i as a literal argument. The parent's own
# proxy variables are never referenced below, so a variable the sanitizer
# dropped (unparseable / scheme-less) cannot leak through by default.
if ! proxy_lines=$("$PYTHON" "$BRIDGE_HOME/bridge_mcp/proxyenv.py"); then
  echo "bridge-mcp: proxy sanitizer failed; refusing to start the MCP child" >&2
  exit 1
fi
proxy_env=()
while IFS= read -r line; do
  [ -n "$line" ] || continue
  case "${line%%=*}" in
    https_proxy|http_proxy|all_proxy|HTTPS_PROXY|HTTP_PROXY|ALL_PROXY|no_proxy|NO_PROXY)
      proxy_env+=("$line") ;;
    *)
      echo "bridge-mcp: unexpected proxy sanitizer output; refusing to start the MCP child" >&2
      exit 1 ;;
  esac
done <<<"$proxy_lines"

exec env -i \
  PATH="/usr/bin:/bin" \
  HOME="$HOME" \
  BRIDGE_STATE_DIR="$STATE_DIR" \
  BRIDGE_DB="$DB" \
  BRIDGE_MCP_LOG="$LOG" \
  ${BRIDGE_FROZEN_FILE:+BRIDGE_FROZEN_FILE="$BRIDGE_FROZEN_FILE"} \
  ${proxy_env[@]+"${proxy_env[@]}"} \
  "$PYTHON" "$BRIDGE_HOME/bridge_mcp/server.py"

#!/usr/bin/env python3
"""Sanitized proxy environment for the scrubbed MCP child launcher.

The MCP child (bridge_mcp/server.py) performs webhook verification and
delivery POSTs, and some deployments mandate an HTTP egress proxy. The
launcher (scripts/bridge-mcp.sh) scrubs the environment with ``env -i`` so runtime
credentials are never inherited — but the proxy URL itself carries
userinfo credentials, so it must be sanitized before passthrough.

Fail closed: a proxy value is passed through ONLY if it parses as
``scheme://host[:port][/path]``; the result is rebuilt from the parsed
hostname and port, so userinfo can never survive. Anything the sanitizer
cannot parse — scheme-less ``user:pass@host:port`` (which urllib would
still accept as a proxy), no hostname, a non-numeric or out-of-range
port, ``urlsplit`` errors, control characters — is DROPPED, never echoed.
Dropped variables are reported by NAME only on stderr.

``env_lines()`` returns ``KEY=value`` lines (one per line, values free of
control characters) for the launcher to read without ``eval``.
``shell_exports()`` returns eval-safe ``KEY='value'`` assignments for the
same mapping. Variables that are absent or dropped are omitted entirely.
``no_proxy``/``NO_PROXY`` carry no credentials and pass through unchanged
(control-character values are dropped there too).

Run as ``python3 bridge_mcp/proxyenv.py`` (how the launcher calls it, so
the copy under BRIDGE_HOME is used regardless of cwd): prints
``env_lines()`` and exits 0; any unexpected error exits nonzero so the
launcher aborts.
"""
from __future__ import annotations

import os
import shlex
import sys
import urllib.parse

# Proxy variables that may embed userinfo credentials and must be
# sanitized. no_proxy/NO_PROXY are handled separately (no credentials).
_SANITIZE_VARS = (
    "https_proxy", "http_proxy", "all_proxy",
    "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
)
_PASSTHROUGH_VARS = ("no_proxy", "NO_PROXY")


def _has_control_chars(value: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7f for c in value)


def sanitize_proxy_url(raw: str) -> str | None:
    """Return the proxy URL with any userinfo removed, or None to drop it.

    Never returns a string it could not fully parse: the output is
    rebuilt from the parsed scheme/hostname/port/path, so credentials in
    the input cannot reach the output.
    """
    if not isinstance(raw, str) or not raw or _has_control_chars(raw):
        return None
    if "://" not in raw:
        return None  # scheme-less: urllib accepts it; we do not
    try:
        parts = urllib.parse.urlsplit(raw)
        port = parts.port  # raises ValueError on a bad port
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"  # IPv6 literal
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path
    if "@" in path or "@" in parts.query or "@" in parts.fragment:
        return None  # userinfo-looking text outside the netloc: refuse
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc, path, parts.query, parts.fragment))


def proxy_exports(env: dict | None = None,
                  dropped: list | None = None) -> dict:
    """Compute the sanitized proxy env mapping for the child.

    Names of variables that were present but dropped are appended to
    ``dropped`` (if given). Values are never reported.
    """
    src = os.environ if env is None else env
    out: dict = {}
    for key in _SANITIZE_VARS:
        raw = src.get(key)
        if raw:
            clean = sanitize_proxy_url(raw)
            if clean is None:
                if dropped is not None:
                    dropped.append(key)
            else:
                out[key] = clean
    for key in _PASSTHROUGH_VARS:
        raw = src.get(key)
        if raw:
            if _has_control_chars(raw):
                if dropped is not None:
                    dropped.append(key)
            else:
                out[key] = raw
    return out


def env_lines(env: dict | None = None, dropped: list | None = None) -> str:
    """``KEY=value`` lines for the launcher (no shell quoting, no eval)."""
    return "\n".join(f"{key}={value}" for key, value in
                     proxy_exports(env, dropped).items())


def shell_exports(env: dict | None = None) -> str:
    """Eval-safe shell assignments for the sanitized proxy environment."""
    return "\n".join(
        f"{key}={shlex.quote(value)}"
        for key, value in proxy_exports(env).items()
    )


def main() -> int:
    dropped: list = []
    text = env_lines(dropped=dropped)
    for key in dropped:
        print(f"bridge-mcp: dropping unparseable proxy variable {key}",
              file=sys.stderr)
    if text:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

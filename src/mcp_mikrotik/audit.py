"""Structured audit journal for every guarded write (guard.py) call.

Every `ALLOWLIST`'d write operation in guard.py is wrapped (see guard.py's
`_audited` decorator - the only thing in this package that calls `record()`)
so it emits exactly one JSON-lines audit event per call, regardless of
whether the call previewed (`confirm=False`, outcome "preview"), applied
(`confirm=True`, outcome "applied"), or failed at any point - even a
`WriteDisabledError` raised before the device is ever touched (outcome
"error").

Destination: `MIKROTIK_AUDIT_LOG` (a file path), appended to as one JSON
line per event, if set; otherwise a plain INFO-level line via the standard
`logging` module (stderr, like every other log line this package emits).
The env var is read fresh on every call rather than cached, mirroring
`client.py`'s `MIKROTIK_TIMEOUT` handling - mainly so tests can point it at
a temp file per test without needing to rebuild any settings object.

NEVER writes a device password or any field that looks like a secret - see
`_sanitize()` below. Writing the journal is always best-effort: any failure
(a bad `MIKROTIK_AUDIT_LOG` path, a permissions error, an unserializable
value) is caught, logged as a warning, and never propagates - an
audit-logging problem must not be able to block or fail the write operation
it is describing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

from .exceptions import ValidationError
from .privacy import redact_current_text

logger = logging.getLogger("mcp_mikrotik.audit")

# Any dict key matching this (case-insensitive) is dropped from a journal
# entry's summary, however it got there - defense in depth on top of the
# fact that no current write tool's before/after ever legitimately contains
# one of these (RouterOS device credentials are never part of a path() row;
# see client.py). Keeps the journal safe even if a future allowlist entry
# touches an endpoint (e.g. /ppp/secret, /user) whose rows do carry
# sensitive fields.
#
# `passphrase`/`psk`/`pre-shared-key` (and its `pre_shared_key`/`preshared`
# spellings, and the `wpa-pre-shared`/`wpa2-pre-shared` RouterOS field names
# used by /interface/wifi/security and /interface/wireless/security-profiles)
# were added after a real set_wifi_ssid preview against ROS7 hardware wrote
# the WPA2 passphrase to the journal in plaintext: the original regex only
# covered password/secret/token/credential, and RouterOS's own field name for
# a WPA2 key is `passphrase` (or `wpa2-pre-shared-key`/`wpa-pre-shared-key`),
# none of which that pattern matched.
#
# `private` (v0.13, WireGuard): covers `private-key`/`privatekey`/
# `private_key` - RouterOS's own `/interface/wireguard` reply field name for
# a tunnel interface's private key. This is a SECOND, independent line of
# defense on top of guard.py's own explicit redaction
# (`_redact_wireguard_row`/`formatting.strip_sensitive_fields`, applied
# before a WritePreview is ever constructed) - see guard.py's WireGuard
# module note for why the redaction has to happen there first: this decorator
# only ever sees whatever guard.py already returned, so if a future write
# function ever forgot to redact before returning, this regex is what stands
# between that and a leaked key in the audit journal. `pre.?shared` above
# already covers `preshared-key`/`pre-shared-key`/`presharedkey` (WireGuard's
# own peer-level secret) - no separate term needed for that one.
_SENSITIVE_KEY = re.compile(
    r"password|secret|token|credential|passphrase|psk|pre.?shared|private",
    re.IGNORECASE,
)

_VALID_OUTCOMES = {"preview", "applied", "error"}


def _sanitize(value: Any) -> Any:
    """Recursively drop any dict key that looks sensitive (see
    `_SENSITIVE_KEY`). Lists/tuples are sanitized element-wise; anything
    else is returned unchanged."""
    if isinstance(value, dict):
        return {key: _sanitize(val) for key, val in value.items() if not _SENSITIVE_KEY.search(str(key))}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value


def record(
    *,
    correlation_id: str,
    device_name: str,
    tool: str,
    operation: str,
    action: str,
    confirm: bool,
    outcome: str,
    summary: dict[str, Any],
) -> None:
    """Emit one audit journal entry. Best-effort: never raises.

    `summary` is typically `{"before": ..., "after": ...}` (preview/applied)
    or `{"error": ...}` (error) - always passed through `_sanitize()` before
    being written anywhere, and never includes the device password.
    """
    if outcome not in _VALID_OUTCOMES:
        outcome = "error"  # defensive; guard.py should never pass anything else

    event = {
        "timestamp": time.time(),
        "correlation_id": correlation_id,
        "device_name": device_name,
        "tool": tool,
        "operation": operation,
        "action": action,
        "confirm": confirm,
        "outcome": outcome,
        "summary": _sanitize(summary),
    }

    try:
        line = redact_current_text(json.dumps(event, default=str, sort_keys=True))
    except (TypeError, ValueError):
        logger.warning("Audit journal: failed to serialize event for tool=%s operation=%s", tool, operation)
        return
    except ValidationError:
        logger.warning("Audit journal: network privacy capacity exhausted; event omitted.")
        return

    path = os.environ.get("MIKROTIK_AUDIT_LOG")
    try:
        if path:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        else:
            logger.info(line)
    except OSError as exc:
        try:
            message = redact_current_text(f"Audit journal: failed to write event to {path!r}: {exc}")
        except ValidationError:
            message = "Audit journal: failed to write event."
        logger.warning(message)

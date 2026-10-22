"""Local, reversible network-address pseudonyms at the MCP boundary.

One instance belongs to one server process. Maps never leave memory; tokens
are random, not hashes of low-entropy IP addresses. This is pseudonymization,
not a guarantee that other returned network metadata cannot identify a host.
"""

from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import re
import secrets
import threading
from collections.abc import Iterator
from typing import Any

from .exceptions import ValidationError

# MACs must be recognized before IPv6 (six colon-separated octets also
# match the IPv6 candidate expression). Accept common RouterOS and Cisco spellings.
_ADDRESS = re.compile(
    r"(?<![\w])(?:"
    r"(?P<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}|"
    r"[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})(?![\w-]|:[0-9a-f:])|"
    r"(?P<v6>[0-9a-f:.]*:[0-9a-f:.]*:[0-9a-f:.]*)(?![\w:])|"
    r"(?P<v4>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?![\w]|\.[0-9])"
    r")",
    re.IGNORECASE,
)
_TOKEN = re.compile(r"\b(?:IP4|IP6|MAC)_[0-9a-f]{32}\b")
_TOKEN_LIKE = re.compile(r"\b(?:IP4|IP6|MAC)_[A-Za-z0-9_]+\b")
_CURRENT: contextvars.ContextVar[NetworkAnonymizer | None] = contextvars.ContextVar("network_privacy", default=None)


class NetworkAnonymizer:
    """Thread-safe, per-process aliases. Preserve prefixes/ports, not topology."""

    def __init__(self, max_addresses: int = 100_000) -> None:
        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, str] = {}
        self._lock = threading.RLock()
        self._max_addresses = max_addresses

    def _alias(self, kind: str, canonical: str, *, mask_on_capacity: bool = False) -> str:
        with self._lock:
            key = (kind, canonical)
            if key not in self._forward:
                if len(self._forward) >= self._max_addresses:
                    if mask_on_capacity:
                        return "[network address omitted: pseudonym capacity reached]"
                    raise ValidationError("Network pseudonym capacity reached; restart the local MCP server.")
                token = f"{kind}_{secrets.token_hex(16)}"
                while token in self._reverse:
                    token = f"{kind}_{secrets.token_hex(16)}"
                self._forward[key] = token
                self._reverse[token] = canonical
            return self._forward[key]

    def redact_text(self, text: str, *, mask_on_capacity: bool = False) -> str:
        """Replace literal IPs/MACs anywhere in text, including log messages."""

        def replace(match: re.Match[str]) -> str:
            value = match.group()
            # A sentence's final period is not part of an IPv6 literal.
            suffix = ""
            if match.group("v6"):
                stripped = value.rstrip(".")
                suffix = value[len(stripped) :]
                value = stripped
            if match.group("mac"):
                digits = re.sub(r"[:.-]", "", value).upper()
                canonical = ":".join(digits[i : i + 2] for i in range(0, 12, 2))
                return self._alias("MAC", canonical, mask_on_capacity=mask_on_capacity)
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                # A prose separator after a valid IPv6 literal is not part
                # of the address (e.g. "2001:db8::1: timeout").
                if match.group("v6") and value.endswith(":"):
                    try:
                        address = ipaddress.IPv6Address(value[:-1])
                    except ValueError:
                        pass
                    else:
                        return self._alias("IP6", str(address), mask_on_capacity=mask_on_capacity) + ":" + suffix
                # IPv4:port is also matched by the IPv6 candidate; parse the
                # IPv4 inside it without changing the port or surrounding text.
                if match.group("v6") and "." in value:
                    return re.sub(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", redact_ipv4, value)
                return value
            return self._alias(f"IP{address.version}", str(address), mask_on_capacity=mask_on_capacity) + suffix

        def redact_ipv4(match: re.Match[str]) -> str:
            try:
                address = ipaddress.IPv4Address(match.group())
            except ValueError:
                return match.group()
            return self._alias("IP4", str(address), mask_on_capacity=mask_on_capacity)

        return _ADDRESS.sub(replace, text)

    def resolve_text(self, text: str) -> str:
        """Resolve issued tokens locally; reject stale/unknown tokens early."""

        def replace(match: re.Match[str]) -> str:
            token = match.group()
            with self._lock:
                original = self._reverse.get(token)
            if original is None:
                raise ValidationError("Unknown network pseudonym; read the address again in this MCP server session.")
            return original

        # Also reject malformed tokens instead of treating them as hostnames.
        for candidate in _TOKEN_LIKE.finditer(text):
            if not _TOKEN.fullmatch(candidate.group()):
                raise ValidationError("Malformed network pseudonym.")
        return _TOKEN.sub(replace, text)

    def transform(self, value: Any, *, resolve: bool = False, mask_on_capacity: bool = False) -> Any:
        """Copy JSON-shaped data recursively, including string dictionary keys."""
        if isinstance(value, str):
            return self.resolve_text(value) if resolve else self.redact_text(value, mask_on_capacity=mask_on_capacity)
        if isinstance(value, dict):
            return {
                self.transform(key, resolve=resolve, mask_on_capacity=mask_on_capacity): self.transform(
                    val, resolve=resolve, mask_on_capacity=mask_on_capacity
                )
                for key, val in value.items()
            }
        if isinstance(value, list):
            return [self.transform(item, resolve=resolve, mask_on_capacity=mask_on_capacity) for item in value]
        if isinstance(value, tuple):
            return tuple(self.transform(item, resolve=resolve, mask_on_capacity=mask_on_capacity) for item in value)
        return value

    def require_capacity(self) -> None:
        """Reject new confirmed operations before any guarded router access."""
        with self._lock:
            if len(self._forward) >= self._max_addresses:
                raise ValidationError("Network pseudonym capacity reached; restart the local MCP server.")

    @contextlib.contextmanager
    def bind(self) -> Iterator[None]:
        """Give the audit layer the same aliases as this tool's MCP result."""
        # Keep capacity admission, router execution, audit and result redaction
        # atomic with respect to other tool calls/alias allocations.
        with self._lock:
            token = _CURRENT.set(self)
            try:
                yield
            finally:
                _CURRENT.reset(token)


def redact_current_text(text: str, *, mask_on_capacity: bool = False) -> str:
    """Audit/log hook; outside a protected tool call retains upstream behavior."""
    anonymizer = _CURRENT.get()
    return anonymizer.redact_text(text, mask_on_capacity=mask_on_capacity) if anonymizer else text


def require_current_capacity() -> None:
    """Guard hook: no effect for explicit privacy opt-out or standalone guards."""
    anonymizer = _CURRENT.get()
    if anonymizer:
        anonymizer.require_capacity()

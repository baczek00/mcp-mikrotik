# Local network address privacy

This fork defaults `MIKROTIK_ANONYMIZE_ADDRESSES=true`. The local stdio MCP
server replaces literal IPv4, IPv6 and MAC addresses before returning any tool
result to its MCP client. It also protects application error messages and the
write audit journal produced during those calls. Existing password/key
redaction remains in place.

## Start and use

Install this fork with `python -m pip install -e '.[dev]'`. Configure devices
locally in devices.yaml, then launch `mcp-mikrotik` through your stdio-capable
MCP client. The server itself does not load .env files; export variables or set
them in the client's process environment. For example:

```json
{
  "mcpServers": {
    "mikrotik": {
      "command": "mcp-mikrotik",
      "env": {
        "MIKROTIK_DEVICES_FILE": "/absolute/path/to/devices.yaml",
        "MIKROTIK_ANONYMIZE_ADDRESSES": "true",
        "MIKROTIK_ALLOW_WRITE": "false"
      }
    }
  }
}
```

Read `dhcp_leases`, `ip_addresses`, `arp_table`, or other tools normally.
An address becomes `IP4_<random-token>`, `IP6_<random-token>` or
`MAC_<random-token>`. Use that exact returned token in subsequent arguments
(e.g. ping address, queue target, MAC address or gateway). The server resolves
it back to the original locally, then runs the original validation and guards.
Opaque aliases are conveyed in MCP initialization instructions as well.

CIDR lengths, ports, brackets, zone/interface suffixes, ranges and comma lists
are retained: an IPv4 /24 becomes `IP4_<random-token>/24`. Canonical IPv6
spellings and common MAC spellings share a token. Unknown/stale/malformed
tokens fail before device access. Literal addresses may also be supplied
locally; if you type a real address into a cloud chat, the MCP server cannot
undo that disclosure.

Write tools remain disabled unless separately enabled. Preview with
`confirm=false` and apply only after explicit confirmation. Both preview and
apply use the same aliases, while RouterOS receives the actual address.

## Scope and limitations

This is **pseudonymization of network-address literals**, not complete network
anonymity. Hostnames, usernames, SSIDs, device names, interface names, comments
without address literals, serial numbers, public keys and topology metadata
are not anonymized. Address aliases preserve equality, not subnet membership
or ordering; CIDR lengths do not make aliases usable for subnet arithmetic.
Applications consuming returned IP fields must understand these opaque tokens.
The map is process-wide for the single local stdio client, not isolated between
multiple remote users. Do not reuse this design unchanged for HTTP hosting.

Each server process has its own random map, stored only in RAM; restart
invalidates tokens. The map has a 100,000-address limit; exhaustion fails
closed and requires a restart. It is not written to files, responses or logs.
IP/MAC literals in application audit records and handled application errors
are covered. Raw RouterOS data and the mapping necessarily exist in local
memory. Third-party debug tracing, OS crash dumps, startup configuration
errors and client-side logging are outside this tool-call protection.
No real-router test or cloud HTTP deployment is performed by the test suite.
This server still exposes stdio only, so a cloud client needs its own supported
local bridge; this change does not add such a bridge.

To deliberately retain upstream raw-address output for a trusted local client,
set `MIKROTIK_ANONYMIZE_ADDRESSES=false` before startup. Malformed values are
rejected, not silently interpreted as opt-out. The setting is fixed when a
server instance is built.

## Review and checks

Repository-wide instructions and custom review rules are in AGENTS.md. CI
already runs tests (Python 3.11, 3.12, 3.13), a 95% coverage floor, ruff and mypy.
Run those checks before opening a PR. Codex automatic GitHub reviews require
separate repository configuration in Codex; adding AGENTS.md alone does not
activate them. Once the repository is connected and review enabled, request a
review on a PR with `@codex review`.

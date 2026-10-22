# Project instructions

This fork adds local IPv4/IPv6/MAC pseudonymization to the upstream
MikroTik RouterOS MCP server. Python 3.11–3.13, FastMCP 1.x, librouteros;
stdio transport only. Read CONTRIBUTING.md and docs/PRIVACY.md before changes.

## Build and validation

Install with `python -m pip install -e '.[dev]'`. Before proposing a change run:

- `pytest --cov=mcp_mikrotik --cov-report=term-missing --cov-fail-under=95`
- `ruff check .`
- `ruff format --check .`
- `mypy src/mcp_mikrotik`

Use the fake router layer in tests; do not contact a real router. Add regression
tests for altered behavior and error paths. Preserve the GPL-3.0-or-later license
and upstream attribution. Never commit devices.yaml, .env, credentials or maps
of original network addresses. Keep project commands and this file current.

## Code Review Rules

### Network privacy

- Every registered tool must use the central protected boundary. Flag real
  IPv4/IPv6/MAC literals leaking through successful structured or text results,
  nested fields, dictionary keys, exceptions, audit files or application logs
  while privacy is enabled. Preserve upstream secret-field redaction.
- Resolve pseudonyms locally before existing argument validation and device
  access. Unknown, malformed or stale aliases must fail before a connection
  or write. Do not synthesize a target or silently treat an alias as a hostname.
- The same canonical address must have one alias per server process, across
  read tools, preview/apply responses and audit entries. Maps remain local and
  in memory. Do not replace random aliases with unsalted hashes or persist maps.
- Capacity or redaction errors must never return/log raw data as a fallback.
  Defaults protect addresses; invalid privacy configuration fails startup.
  Explicit local opt-out is supported and must remain documented and tested.

### Router operations

- Preserve read-only defaults, guard.ALLOWLIST, explicit confirm=False previews,
  ambiguity checks and the dead-man rollback for risky wireless writes.
  Anonymization must not bypass these controls or change write retry behavior.
- Never add an arbitrary command/path tool. Preserve structured librouteros
  calls, TLS verification defaults and existing ROS6/ROS7 compatibility.
- Identify consequential bugs with a concrete trigger and affected behavior.
  Keep formatting/lint checks in CI; do not request cosmetic rewrites as review
  findings. Distinguish tested fake-router behavior from hardware verification.

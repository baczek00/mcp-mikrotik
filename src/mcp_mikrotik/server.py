"""MCP server entrypoint.

Registers the read tools plus every guarded write tool (set_identity,
enable_interface/disable_interface, set_wifi_ssid, set_client_bandwidth,
add_static_dhcp_lease, remove_simple_queue, add_to_address_list,
remove_from_address_list, set_poe_out, start_container/stop_container,
set_route_distance, enable_route/disable_route, add_route/remove_route,
add_netwatch/remove_netwatch,
add_static_dns/remove_static_dns, clear_dns_cache, remove_dhcp_lease,
wake_on_lan, enable_firewall_rule/disable_firewall_rule,
add_wireguard_interface/add_wireguard_peer/remove_wireguard_peer,
add_hotspot_user, create_backup, add_vlan/remove_vlan, move_firewall_rule,
add_ppp_secret/remove_ppp_secret, enable_nat_rule/disable_nat_rule,
enable_mangle_rule/disable_mangle_rule, set_ntp_servers (v1.8) -
see guard.py's ALLOWLIST for the full write-tool inventory), plus the
read-only connection_tracking tool (v0.11), the read-only
security_audit/security_events tools (v0.12 - see security.py), the
read-only wireguard_interfaces tool (v0.13), three more read-only tools from
v0.14 - hotspot_active, torch, list_backups - (v1.2) one more read-only
tool - list_vlans - (v1.3) one more read-only tool - ppp_secrets - (v1.4)
one more read-only tool - firewall_mangle - (v1.6) four more read-only
tools - certificates, users, user_active, radius - see "AAA/PKI visibility"
below - (v1.7) five more read-only tools - interface_monitor, dhcp_servers,
dhcp_networks, bridge_ports, bridge_vlans - and (v1.8) two more read-only
tools - ntp_client, system_clock - closing out ROADMAP.md's Tier 2. (v1.9)
five more read-only tools - ipv6_addresses, ipv6_routes,
ipv6_firewall_filter, ipv6_neighbors, ipv6_firewall_address_lists - IPv6
READ parity (ROADMAP.md's Tier 3). (v1.10) six more guarded write tools -
enable_ipv6_firewall_rule/disable_ipv6_firewall_rule, add_ipv6_route/
remove_ipv6_route, add_to_ipv6_address_list/remove_from_ipv6_address_list -
IPv6 WRITE parity, closing out the IPv6 parity item entirely. (v1.11) one
more read-only tool - get_wireless_link_quality (CCQ/SNR/rate/distance
normalized from the same registration-table wireless_registrations already
reads) - plus five more guarded write tools: set_wireless_channel/
set_wireless_tx_power/set_wireless_tuning (RF tuning on
`/interface/wireless`) and the reusable dead-man primitive itself,
arm_dead_man/cancel_dead_man - see guard.py's module note above their
ALLOWLIST entries and README's "Dead-man / lockout-proof writes" section.
Transport is stdio only - this process is meant to run on
the operator's own machine, launched by an MCP client (e.g. Claude Code)
over stdio, with no network exposure at all.

TODO(http-transport): if a streamable-http transport is added later, it
MUST default to binding 127.0.0.1 (never 0.0.0.0) and MUST require a bearer
token supplied via an environment variable, checked on every request. Do not
add HTTP transport without both of those in place.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
from collections.abc import AsyncIterator
from dataclasses import asdict
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from . import correlation, guard, security
from .client import ClientFactory, ClientPool, MikrotikClient, get_client
from .config import Settings, load_settings
from .exceptions import DeviceCommandError, MikrotikMCPError, ValidationError
from .formatting import (
    WIREGUARD_SENSITIVE_FIELDS,
    coerce_ros_bool,
    coerce_ros_number,
    days_until,
    filter_disabled,
    normalize_wireless_registration,
    rows_to_list,
    split_address_port,
    strip_sensitive_fields,
)
from .privacy import NetworkAnonymizer
from .validation import (
    validate_conntrack_dst_port,
    validate_conntrack_protocol,
    validate_interface_name,
    validate_ip_address,
    validate_ping_address,
    validate_positive_limit,
)

logger = logging.getLogger("mcp_mikrotik")

DEFAULT_LOG_LIMIT = 50
MAX_LOG_LIMIT = 500
DEFAULT_PING_COUNT = 4
MAX_PING_COUNT = 20
MAX_ROUTE_LIMIT = 500
# Traceroute is capped tightly (count, max_hops, and a fixed 1s per-hop
# timeout baked into MikrotikClient.traceroute) so the worst case - every
# hop timing out - stays well under RouterOS's own ~60s API command timeout:
# MAX_TRACEROUTE_MAX_HOPS * MAX_TRACEROUTE_COUNT * 1s = 20s.
DEFAULT_TRACEROUTE_COUNT = 1
MAX_TRACEROUTE_COUNT = 2
DEFAULT_TRACEROUTE_MAX_HOPS = 10
MAX_TRACEROUTE_MAX_HOPS = 10
# v0.11: connection_tracking's hard result cap - regardless of how many rows
# actually match the caller's filter, at most this many are ever returned;
# `truncated` in the result signals when more matched than were returned.
# See connection_tracking's own docstring for why a filter is mandatory in
# the first place.
MAX_CONNTRACK_LIMIT = 100
# v0.12: security_events' limit, same cap/default shape as logs' own
# limit (DEFAULT_LOG_LIMIT/MAX_LOG_LIMIT) - it reads the same /log table,
# just pre-filtered to security-relevant rows (see security.py).
DEFAULT_SECURITY_EVENTS_LIMIT = 50
MAX_SECURITY_EVENTS_LIMIT = 500
# v0.14: torch's hard result cap - regardless of how many flows RouterOS
# reports for the requested instant, at most this many are ever returned
# (the biggest talkers by tx+rx bytes first) - same "cap it, tell the caller
# how many really matched" shape as connection_tracking's MAX_CONNTRACK_LIMIT
# above. A live traffic snapshot on a busy interface can carry far more rows
# than an LLM caller's context/token budget can sensibly absorb.
MAX_TORCH_LIMIT = 50

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_DEFAULT_LOG_LEVEL = "INFO"

# v0.8/v0.13: WireGuard private/preshared keys must never be returned by any
# read tool - see wireguard_peers/wireguard_interfaces below,
# strip_sensitive_fields' docstring, and formatting.WIREGUARD_SENSITIVE_FIELDS
# (the same constant guard.py's write-preview redaction uses, so read and
# write paths can never drift out of sync).
_WIREGUARD_REDACTED_FIELDS = WIREGUARD_SENSITIVE_FIELDS

# v1.3: a /ppp/secret row's `password` field must never be returned by
# `ppp_secrets` - same "never a secret in a read tool's output" rule
# `_WIREGUARD_REDACTED_FIELDS` above enforces for WireGuard.
_PPP_SECRET_REDACTED_FIELDS = frozenset({"password"})

# v1.6: /certificate's own API reply never carries a private key (RouterOS
# only returns certificate metadata over the API) - this is defensive
# belt-and-suspenders in case a future RouterOS version or firmware quirk
# ever adds one, same "strip it regardless of whether it's expected today"
# reasoning `strip_sensitive_fields`' docstring lays out for WireGuard.
_CERTIFICATE_REDACTED_FIELDS = frozenset({"private-key"})

# v1.6: /radius's `secret` field is the plaintext RADIUS shared secret -
# must never be returned by `radius`, same "never a secret in a read tool's
# output" rule as `_PPP_SECRET_REDACTED_FIELDS`/`_WIREGUARD_REDACTED_FIELDS`
# above.
_RADIUS_REDACTED_FIELDS = frozenset({"secret"})


class _PrivacyFastMCP(FastMCP):
    """Cover framework input/output validation errors outside the tool wrapper."""

    def __init__(self, anonymizer: NetworkAnonymizer | None, **kwargs: Any) -> None:
        self._anonymizer = anonymizer
        super().__init__("mikrotik", **kwargs)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            return await super().call_tool(name, arguments)
        except Exception as exc:
            if self._anonymizer is None:
                raise
            try:
                message = self._anonymizer.redact_text(str(exc))
            except ValidationError:
                message = "Network privacy error; restart the local MCP server."
            raise ToolError(message) from None


def _wireless_registration_rows(client: MikrotikClient) -> list[dict[str, Any]]:
    """Shared by `wireless_registrations` and `get_wireless_link_quality`
    (v1.11): read `/interface/wifi/registration-table` (ROS7) falling back
    to `/interface/wireless/registration-table` (ROS6), returning RAW rows -
    an empty list (not an error) if neither path answers (a wired-only
    device, or the relevant package not installed). Factored out so
    `get_wireless_link_quality`'s normalization (formatting.
    normalize_wireless_registration) reuses this exact fallback instead of
    duplicating it.
    """
    for segments in (
        ("interface", "wifi", "registration-table"),
        ("interface", "wireless", "registration-table"),
    ):
        try:
            return rows_to_list(client.path(*segments))
        except DeviceCommandError:
            continue
    return []


def build_server(settings: Settings | None = None, client_factory: ClientFactory = get_client) -> FastMCP:
    """Build the FastMCP server and register every tool.

    `settings` and `client_factory` are injectable so tests can run the
    exact tool functions registered here against a fake device layer,
    without touching environment variables or a real router.
    """
    settings = settings or load_settings()
    # N2+N3: one MikrotikClient (and its underlying connection) per device
    # name, reused across tool calls instead of reconnecting every time, and
    # closed deterministically by the lifespan hook below rather than
    # leaking sockets until GC - see client.ClientPool's docstring.
    pool = ClientPool(settings, client_factory)
    anonymizer = NetworkAnonymizer() if settings.anonymize_addresses else None

    @contextlib.asynccontextmanager
    async def _lifespan(_server: FastMCP) -> AsyncIterator[dict[str, Any]]:
        try:
            yield {}
        finally:
            pool.close_all()

    instructions = None
    if anonymizer:
        instructions = (
            "Network address privacy is enabled. IP4_*, IP6_* and MAC_* are opaque, "
            "process-local pseudonyms. Use them unchanged in subsequent tool arguments, "
            "including CIDRs and address lists. The local server resolves them before validation. "
            "Tokens expire when the server restarts. Do not guess addresses from tokens. "
            "Write tools still require the existing read-only gate and explicit confirmation."
        )
    mcp = _PrivacyFastMCP(anonymizer, lifespan=_lifespan, instructions=instructions)

    def _client(device_name: str) -> MikrotikClient:
        return pool.get(device_name)

    def _safe(fn):
        """Make sure nothing unexpected leaks a raw traceback or a secret,
        and give every call (read or write) a short correlation id (v0.5)
        that ties its logs - and, for write tools, its audit journal entry
        (see guard.py's `_audited`) - back to one specific call end to end.

        Deliberately re-raises rather than returning an error dict: each
        tool's return type is annotated (e.g. `list[dict[str, Any]]`) and
        FastMCP validates successful results against that schema, so an
        error path can't return a different shape without tripping output
        validation. Letting a clean exception propagate instead lets
        FastMCP/MCP's own error path turn it into a proper isError tool
        result carrying just the exception's message - see
        MikrotikMCPError subclasses in exceptions.py, whose messages are
        already safe to show a caller. The correlation id is prefixed onto
        the server-side log line only - never appended to the exception's
        own message - so no caller-facing error text changes shape.

        Uses functools.wraps (not just __name__/__doc__) so FastMCP's schema
        introspection - which follows __wrapped__ - still sees the original
        function's parameter names/types instead of a generic (*args, **kwargs).
        """

        @functools.wraps(fn)
        def inner(*args: Any, **kwargs: Any) -> Any:
            privacy_context = anonymizer.bind() if anonymizer else contextlib.nullcontext()
            with correlation.bind() as correlation_id, privacy_context:
                try:
                    if anonymizer:
                        args = anonymizer.transform(args, resolve=True)
                        kwargs = anonymizer.transform(kwargs, resolve=True)
                    result = fn(*args, **kwargs)
                    return anonymizer.transform(result) if anonymizer else result
                except MikrotikMCPError as exc:
                    message = str(exc)
                    if anonymizer:
                        # Capacity exhaustion must never fall back to raw data.
                        try:
                            message = anonymizer.redact_text(message)
                        except ValidationError:
                            message = "Network privacy error; restart the local MCP server."
                        logger.info("[%s] tool %s failed: %s", correlation_id, fn.__name__, message)
                        raise MikrotikMCPError(message) from None
                    logger.info("[%s] tool %s failed: %s", correlation_id, fn.__name__, message)
                    raise
                except Exception:
                    if anonymizer:
                        # Exception tracebacks can embed arbitrary router data.
                        logger.error("[%s] Unhandled error in tool %s", correlation_id, fn.__name__)
                    else:
                        logger.exception("[%s] Unhandled error in tool %s", correlation_id, fn.__name__)
                    raise RuntimeError("Internal error handling this tool call; see server logs.") from None

        return inner

    # --- Read tools ---------------------------------------------------

    @mcp.tool()
    @_safe
    def list_devices() -> list[dict[str, Any]]:
        """List configured MikroTik devices. Read-only; passwords are never included."""
        return [device.to_public_dict() for device in settings.devices.values()]

    @mcp.tool()
    @_safe
    def system_info(device_name: str) -> dict[str, Any]:
        """Get RouterOS identity + resource info (board, version, uptime, CPU/memory)."""
        client = _client(device_name)
        identity = client.path("system", "identity")
        resource = client.path("system", "resource")
        return {
            "identity": identity[0] if identity else {},
            "resource": resource[0] if resource else {},
        }

    @mcp.tool()
    @_safe
    def interfaces(device_name: str, include_disabled: bool = False) -> list[dict[str, Any]]:
        """List network interfaces on a device."""
        client = _client(device_name)
        return filter_disabled(client.path("interface"), include_disabled)

    @mcp.tool()
    @_safe
    def list_vlans(device_name: str, include_disabled: bool = False) -> list[dict[str, Any]]:
        """List VLAN interfaces (`/interface/vlan`): `name`, `vlan-id`,
        `interface` (the parent interface it rides on top of), `mtu`,
        `running`, `disabled`, `comment` (if set).

        Excludes disabled VLAN interfaces by default, like `interfaces`;
        pass `include_disabled=True` to see them too.
        """
        client = _client(device_name)
        return filter_disabled(client.path("interface", "vlan"), include_disabled)

    @mcp.tool()
    @_safe
    def ip_addresses(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 addresses configured on a device."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "address"))

    @mcp.tool()
    @_safe
    def ip_routes(device_name: str, limit: int | None = None) -> list[dict[str, Any]]:
        """List the IPv4 routing table of a device.

        `limit`, if given, caps the number of rows returned (capped at 500);
        omit it to get the full table, mirroring `logs`' `limit` parameter.
        """
        client = _client(device_name)
        rows = rows_to_list(client.path("ip", "route"))
        if limit is not None:
            capped_limit = validate_positive_limit(limit, MAX_ROUTE_LIMIT, "limit")
            rows = rows[:capped_limit]
        return rows

    @mcp.tool()
    @_safe
    def neighbors(device_name: str) -> list[dict[str, Any]]:
        """List neighbors discovered via RouterOS neighbor discovery (CDP/MNDP/LLDP)."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "neighbor"))

    @mcp.tool()
    @_safe
    def dhcp_leases(device_name: str) -> list[dict[str, Any]]:
        """List DHCP server leases (address, mac, host-name, status, server, comment)."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "dhcp-server", "lease"))

    @mcp.tool()
    @_safe
    def simple_queues(device_name: str) -> list[dict[str, Any]]:
        """List Simple Queue entries (/queue/simple): name, target, max-limit,
        limit-at, bytes counters, disabled. Use this to see which clients
        already have a bandwidth limit and how much traffic they've moved
        (the `bytes` counter), before deciding who to limit with
        set_client_bandwidth.
        """
        client = _client(device_name)
        return rows_to_list(client.path("queue", "simple"))

    @mcp.tool()
    @_safe
    def address_lists(device_name: str) -> list[dict[str, Any]]:
        """List firewall address-list entries (/ip/firewall/address-list):
        list, address, timeout, dynamic, disabled. See who's currently in
        which named list (e.g. a "blocked-clients" list a firewall rule
        drops), before adding/removing entries with add_to_address_list /
        remove_from_address_list.
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "firewall", "address-list"))

    @mcp.tool()
    @_safe
    def firewall_nat(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 firewall NAT rules (/ip/firewall/nat): chain, action,
        to-addresses, etc. Read-only - does not add/modify/remove rules.
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "firewall", "nat"))

    @mcp.tool()
    @_safe
    def scheduler(device_name: str) -> list[dict[str, Any]]:
        """List scheduled tasks (/system/scheduler): name, on-event,
        interval, next-run, disabled. Read-only.
        """
        client = _client(device_name)
        return rows_to_list(client.path("system", "scheduler"))

    @mcp.tool()
    @_safe
    def ip_pools(device_name: str) -> list[dict[str, Any]]:
        """List IP pools (/ip/pool): name, ranges. Read-only."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "pool"))

    @mcp.tool()
    @_safe
    def wireless_registrations(device_name: str) -> list[dict[str, Any]]:
        """List wireless clients currently associated to the device (mac, signal, interface, uptime).

        RouterOS exposes this under two different paths depending on
        generation: ROS7's wifi package (/interface/wifi/registration-table)
        or ROS6's wireless package (/interface/wireless/registration-table).
        This tries ROS7 first, falls back to ROS6, and returns an empty list
        - rather than raising - for a device with no wireless radio at all
        (or the relevant package not installed), since that is a completely
        normal, expected state for a wired-only device.

        RAW rows, as RouterOS returns them - see `get_wireless_link_quality`
        (v1.11) for the same registration-table data normalized into a fixed
        CCQ/rate/distance shape for PtP/PtMP diagnosis.
        """
        client = _client(device_name)
        return _wireless_registration_rows(client)

    @mcp.tool()
    @_safe
    def get_wireless_link_quality(device_name: str, interface: str | None = None) -> list[dict[str, Any]]:
        """PtP/PtMP link-quality diagnosis: the same registration-table data
        `wireless_registrations` reads, normalized per peer into `interface`,
        `mac_address`, `signal_strength`, `signal_to_noise`, `tx_ccq`,
        `rx_ccq`, `tx_rate`, `rx_rate`, `distance`, `uptime` (see
        `formatting.normalize_wireless_registration`).

        This is the read to run before AND after `set_wireless_channel`/
        `set_wireless_tx_power`/`set_wireless_tuning` to judge whether an RF
        change actually helped - CCQ (Client Connection Quality) and
        signal-to-noise are the two numbers that matter most for a PtP link;
        `tx_rate`/`rx_rate` dropping right after a channel/power change is
        expected for a few seconds while rates re-adapt, not a failure (see
        `set_wireless_tx_power`'s docstring).

        Optional `interface` filters to peers associated on that one local
        interface (validated for shape like every other `interface_name`
        parameter in this package).

        Field availability genuinely differs by generation: ROS7's newer
        `/interface/wifi/registration-table` does not publish
        `signal-to-noise`/`tx-ccq`/`rx-ccq`/`distance` at all (per MikroTik's
        own docs) - those fields come back `None` rather than fabricated.
        `/interface/wireless` (confirmed against real hardware today - see
        docs/api-notes-wireless-rf.md) publishes all of them. Empty list
        (not an error) for a device with no wireless radio, same convention
        as `wireless_registrations`.
        """
        client = _client(device_name)
        rows = _wireless_registration_rows(client)
        if interface is not None:
            validated_interface = validate_interface_name(interface)
            rows = [row for row in rows if row.get("interface") == validated_interface]
        return [normalize_wireless_registration(row) for row in rows]

    @mcp.tool()
    @_safe
    def wireguard_peers(device_name: str) -> list[dict[str, Any]]:
        """List WireGuard VPN peers (/interface/wireguard/peers): name,
        interface, public-key, endpoint-address/endpoint-port,
        current-endpoint-address/current-endpoint-port, last-handshake,
        rx/tx byte counters, allowed-address, disabled.

        SECURITY: a `private-key` field never appears in RouterOS's own
        /interface/wireguard/peers reply (only /interface/wireguard - the
        tunnel interfaces themselves - carries one; see wireguard_interfaces
        below), but this strips it defensively anyway, along with any
        `preshared-key` a configured peer may genuinely carry (a real, if
        optional, RouterOS field on this menu) - see
        formatting.WIREGUARD_SENSITIVE_FIELDS and
        test_wireguard_peers_never_exposes_private_key/
        test_wireguard_peers_never_exposes_preshared_key.

        Returns an empty list (never an error) for a device with no
        WireGuard package/interfaces at all - same "empty, not an error"
        convention as wireless_registrations/system_health for optional
        features.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("interface", "wireguard", "peers"))
        except DeviceCommandError:
            return []
        return strip_sensitive_fields(rows, _WIREGUARD_REDACTED_FIELDS)

    @mcp.tool()
    @_safe
    def wireguard_interfaces(device_name: str) -> list[dict[str, Any]]:
        """List WireGuard tunnel interfaces (/interface/wireguard): name,
        listen-port, public-key, running, disabled, mtu.

        SECURITY: RouterOS's own /interface/wireguard reply carries the
        interface's `private-key` - this is ALWAYS stripped before
        returning (formatting.strip_sensitive_fields with
        formatting.WIREGUARD_SENSITIVE_FIELDS), the same mechanism
        wireguard_peers (v0.8) already used defensively for a peer's
        private-key/preshared-key. A private-key never leaves this process.
        See test_wireguard_interfaces_never_exposes_private_key.

        Returns an empty list (never an error) for a device with no
        WireGuard package/interfaces at all - same convention as
        wireguard_peers.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("interface", "wireguard"))
        except DeviceCommandError:
            return []
        return strip_sensitive_fields(rows, _WIREGUARD_REDACTED_FIELDS)

    @mcp.tool()
    @_safe
    def ppp_active(device_name: str) -> list[dict[str, Any]]:
        """List active PPP sessions (/ppp/active): name, service
        (l2tp/pptp/sstp/ovpn/pppoe), caller-id, address, uptime - VPN
        server sessions currently connected to this device.

        Returns an empty list (never an error) for a device with no PPP
        server configured, or simply no sessions active right now.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ppp", "active"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def ppp_secrets(device_name: str) -> list[dict[str, Any]]:
        """List CONFIGURED PPP/PPPoE secrets (/ppp/secret): name, service
        (pppoe/pptp/l2tp/ovpn/sstp/any), profile, remote-address,
        local-address (if set), disabled, comment, last-logged-out (if set)
        - the dial-in credentials themselves, as opposed to `ppp_active`'s
        currently-CONNECTED sessions. See "PPP/PPPoE secrets" below.

        SECURITY: RouterOS's own /ppp/secret reply carries each secret's
        plaintext `password` - this is ALWAYS stripped before returning
        (formatting.strip_sensitive_fields), the same mechanism
        `wireguard_interfaces` uses for a tunnel interface's private-key. A
        secret's password never leaves this process via this tool. See
        test_ppp_secrets_never_exposes_password.

        Returns an empty list (never an error) for a device with no PPP
        package configured at all - same convention as `ppp_active`.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("ppp", "secret"))
        except DeviceCommandError:
            return []
        return strip_sensitive_fields(rows, _PPP_SECRET_REDACTED_FIELDS)

    @mcp.tool()
    @_safe
    def ipsec_active_peers(device_name: str) -> list[dict[str, Any]]:
        """List active IPsec peers (/ip/ipsec/active-peers): remote-address,
        state, uptime, rx/tx byte counters, side (initiator/responder).

        Returns an empty list (never an error) for a device that doesn't
        use IPsec at all - a completely normal state.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ip", "ipsec", "active-peers"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def bgp_sessions(device_name: str) -> list[dict[str, Any]]:
        """List BGP session status: remote-address/remote-as, state
        (established/idle/...), uptime, prefix-count.

        RouterOS exposes this under two different paths depending on
        generation, the same split wireless_registrations already handles
        for wifi: ROS7's routing package (/routing/bgp/session) or ROS6's
        (/routing/bgp/peer). This tries ROS7 first, falls back to ROS6, and
        returns an empty list - rather than raising - for a device that
        doesn't run BGP at all.
        """
        client = _client(device_name)
        for segments in (
            ("routing", "bgp", "session"),
            ("routing", "bgp", "peer"),
        ):
            try:
                return rows_to_list(client.path(*segments))
            except DeviceCommandError:
                continue
        return []

    @mcp.tool()
    @_safe
    def ospf_neighbors(device_name: str) -> list[dict[str, Any]]:
        """List OSPF neighbor adjacencies (/routing/ospf/neighbor):
        address, state (Full/Down/...), router-id, adjacency.

        Returns an empty list (never an error) for a device that doesn't
        run OSPF at all.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("routing", "ospf", "neighbor"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def netwatch(device_name: str) -> list[dict[str, Any]]:
        """List Netwatch host monitors (/tool/netwatch): host, status
        (up/down), interval, since, comment, disabled, plus
        `has-up-script`/`has-down-script` booleans.

        Netwatch is the usual way a RouterOS device itself watches a
        gateway or peer's reachability (e.g. to drive a failover script on
        down/up) - this is read-only groundwork for future failover
        tooling; see README's "VPN & routing diagnostics".

        The up-script/down-script fields are surfaced only as presence
        booleans (`has-up-script`/`has-down-script`), never as the raw
        script body, which can contain arbitrary RouterOS commands (e.g.
        route/credential changes) that don't belong in a read tool's
        output.

        Returns an empty list (never an error) for a device with no
        Netwatch entries configured.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("tool", "netwatch"))
        except DeviceCommandError:
            return []
        result: list[dict[str, Any]] = []
        for row in rows:
            entry = dict(row)
            entry["has-up-script"] = bool(entry.pop("up-script", ""))
            entry["has-down-script"] = bool(entry.pop("down-script", ""))
            result.append(entry)
        return result

    @mcp.tool()
    @_safe
    def dns_cache(device_name: str) -> list[dict[str, Any]]:
        """List cached DNS records on the device (name, type, data, ttl)."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "dns", "cache"))

    @mcp.tool()
    @_safe
    def firewall_filter(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 firewall filter rules (chain, action, etc). Read-only - does not add/modify/remove rules."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "firewall", "filter"))

    @mcp.tool()
    @_safe
    def firewall_mangle(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 firewall mangle rules (/ip/firewall/mangle): chain
        (e.g. prerouting/postrouting/forward/input/output, or a custom
        jump-target chain), action (e.g. mark-connection/mark-packet/
        mark-routing), comment, disabled, plus whatever other fields
        RouterOS returns for a given rule (protocol, src/dst-address, etc -
        these vary per rule/action, same as `firewall_filter`/`firewall_nat`
        - not every rule has every field, and this returns each row as-is
        rather than assuming a fixed shape). Read-only - does not add/
        modify/remove rules. See "NAT & mangle rule toggle (by comment)"
        below for the guarded enable_mangle_rule/disable_mangle_rule pair.
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "firewall", "mangle"))

    @mcp.tool()
    @_safe
    def connection_tracking(
        device_name: str,
        src_address: str | None = None,
        dst_address: str | None = None,
        dst_port: int | None = None,
        protocol: str | None = None,
    ) -> dict[str, Any]:
        """List active connections from RouterOS's connection tracking table
        (/ip/firewall/connection) - FILTERED. At least ONE of `src_address`,
        `dst_address`, `dst_port`, `protocol` is REQUIRED.

        WHY a filter is mandatory (unlike every other read tool in this
        package): on a production router, the full connection-tracking table
        can be large enough to blow past an LLM caller's context/token
        budget on its own. Calling this with no filter at all raises a
        ValidationError instead of returning the whole table.

        Filtering happens in Python after reading the table - the same
        reasoning `logs`' `topics` filter already documents (RouterOS's
        structured API doesn't expose a query-by-field read here either).
        `src_address`/`dst_address` match a row's IP, ignoring the port
        RouterOS packs into the same field (e.g. "192.0.2.1:80" ->
        address "192.0.2.1"); `dst_port` matches the destination's port
        component. `protocol` is a RouterOS protocol name (e.g.
        "tcp"/"udp"/"icmp", case-insensitive) or a numeric IP protocol
        number (0-255).

        Regardless of how many rows match, the result is capped at
        MAX_CONNTRACK_LIMIT (100) entries - `truncated` is `true` whenever
        more rows matched than were returned, and `total_matched` always
        reports the real (pre-truncation) match count, so a caller always
        knows whether it's seeing everything that matched.

        Each returned entry: `protocol`, `src-address`/`src-port`,
        `dst-address`/`dst-port` (address and port split apart - see
        formatting.split_address_port), `tcp-state` (populated for TCP
        connections), `timeout`, and the `assured`/`confirmed`/`seen-reply`
        flags - RouterOS's own closest equivalent to a generic "connection
        state" for this table.
        """
        if not any([src_address, dst_address, dst_port is not None, protocol]):
            raise ValidationError(
                "connection_tracking requires at least one of 'src_address', 'dst_address', "
                "'dst_port', 'protocol' - the full connection-tracking table on a production "
                "router is too large to return unfiltered."
            )

        validated_src = validate_ip_address(src_address) if src_address else None
        validated_dst = validate_ip_address(dst_address) if dst_address else None
        validated_port = validate_conntrack_dst_port(dst_port) if dst_port is not None else None
        validated_protocol = validate_conntrack_protocol(protocol) if protocol else None

        client = _client(device_name)
        rows = rows_to_list(client.path("ip", "firewall", "connection"))

        matches: list[dict[str, Any]] = []
        for row in rows:
            src_ip, src_port = split_address_port(row.get("src-address", ""))
            dst_ip, matched_dst_port = split_address_port(row.get("dst-address", ""))
            if validated_src is not None and src_ip != validated_src:
                continue
            if validated_dst is not None and dst_ip != validated_dst:
                continue
            if validated_port is not None and matched_dst_port != str(validated_port):
                continue
            if validated_protocol is not None and (row.get("protocol") or "").lower() != validated_protocol:
                continue
            matches.append(
                {
                    "protocol": row.get("protocol"),
                    "src-address": src_ip,
                    "src-port": src_port,
                    "dst-address": dst_ip,
                    "dst-port": matched_dst_port,
                    "tcp-state": row.get("tcp-state"),
                    "timeout": row.get("timeout"),
                    "assured": row.get("assured"),
                    "confirmed": row.get("confirmed"),
                    "seen-reply": row.get("seen-reply"),
                }
            )

        total_matched = len(matches)
        truncated = total_matched > MAX_CONNTRACK_LIMIT
        return {
            "connections": matches[:MAX_CONNTRACK_LIMIT],
            "total_matched": total_matched,
            "truncated": truncated,
        }

    @mcp.tool()
    @_safe
    def system_health(device_name: str) -> list[dict[str, Any]]:
        """Read system health metrics (e.g. voltage, temperature), if the device exposes them.

        Not every RouterOS device/board type has health sensors (e.g. some
        CHR/virtual instances have none) - in that case this returns an
        empty list instead of raising.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("system", "health"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def logs(device_name: str, limit: int = DEFAULT_LOG_LIMIT, topics: str | None = None) -> list[dict[str, Any]]:
        """Read recent RouterOS log entries (most recent last).

        `limit` must be positive and is capped at 500. `topics`, if given, is
        matched as a plain substring against each entry's topics field - no
        regex, no unbounded scans - and is applied BEFORE the `limit` cut:
        the full log is filtered by `topics` first, then the last `limit`
        matching entries are returned (not the last `limit` raw entries,
        then filtered - that would silently drop matches).

        R1: this reads the whole `/log` table via librouteros' path().select()
        and slices in Python rather than asking RouterOS for only the last
        `limit` rows. librouteros' structured API doesn't expose a clean
        "give me only the tail" query for /log (RouterOS's own count-only
        print flags aren't reachable through path().select() the way a
        `.limit()`/offset would be), so a "request fewer rows" optimization
        here would mean building a fragile ad-hoc workaround for a table
        that is small in practice (a few hundred to low thousands of rows on
        RouterOS's own ring buffer). Left as-is; revisit if a real device
        turns out to have a much larger log buffer than expected.
        """
        client = _client(device_name)
        capped_limit = validate_positive_limit(limit, MAX_LOG_LIMIT, "limit")
        rows = rows_to_list(client.path("log"))
        if topics:
            rows = [row for row in rows if topics in row.get("topics", "")]
        return rows[-capped_limit:]

    @mcp.tool()
    @_safe
    def ping(device_name: str, address: str, count: int = DEFAULT_PING_COUNT) -> list[dict[str, Any]]:
        """Ping an address from a device. `address` must be a valid IPv4/IPv6 address or hostname."""
        validated_address = validate_ping_address(address)
        capped_count = validate_positive_limit(count, MAX_PING_COUNT, "count")
        client = _client(device_name)
        return client.ping(validated_address, count=capped_count)

    @mcp.tool()
    @_safe
    def traceroute(
        device_name: str,
        address: str,
        count: int = DEFAULT_TRACEROUTE_COUNT,
        max_hops: int = DEFAULT_TRACEROUTE_MAX_HOPS,
    ) -> list[dict[str, Any]]:
        """Traceroute to an address from a device; returns the list of hops.

        `address` must be a valid IPv4/IPv6 address or hostname (validated
        exactly like `ping`'s). `count` (probes per hop) and `max_hops` are
        both capped low (see MAX_TRACEROUTE_COUNT/MAX_TRACEROUTE_MAX_HOPS)
        and a fixed short per-hop timeout is used internally, so the command
        can't run long enough to hit RouterOS's own ~60s API command
        timeout.

        Diagnostic only - this never changes device state, so it is not
        gated by MIKROTIK_ALLOW_WRITE and needs no confirm/preview.
        """
        validated_address = validate_ping_address(address)
        capped_count = validate_positive_limit(count, MAX_TRACEROUTE_COUNT, "count")
        capped_max_hops = validate_positive_limit(max_hops, MAX_TRACEROUTE_MAX_HOPS, "max_hops")
        client = _client(device_name)
        return client.traceroute(validated_address, count=capped_count, max_hops=capped_max_hops)

    @mcp.tool()
    @_safe
    def arp_table(device_name: str) -> list[dict[str, Any]]:
        """List the IPv4 ARP table (/ip/arp): address, mac-address,
        interface, dynamic, complete.

        Use this to cross-reference an IP to a MAC (or vice versa) for a
        statically-addressed device that never shows up in `dhcp_leases`
        (it never requested a DHCP lease, so it has no lease entry - but it
        does get an ARP entry once it has exchanged traffic with the
        device).
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "arp"))

    @mcp.tool()
    @_safe
    def bridge_hosts(device_name: str) -> list[dict[str, Any]]:
        """List /interface/bridge/host entries: mac-address, on-interface
        (the physical bridge port), bridge, dynamic, local.

        Use this to find which physical port of a bridge a given MAC is
        currently learned on - e.g. to identify which PoE-capable ethernet
        port a locked-up device is plugged into, before using `poe_status`/
        `set_poe_out` on it (see "Physical layer & PoE control" in the
        README).
        """
        client = _client(device_name)
        return rows_to_list(client.path("interface", "bridge", "host"))

    @mcp.tool()
    @_safe
    def interface_traffic(device_name: str, interface: str) -> dict[str, Any]:
        """Current rx/tx traffic rate of one interface
        (/interface/monitor-traffic interface=<interface> once=yes).

        `interface` is validated for shape (validate_interface_name) before
        it is ever sent to the device - existence isn't checked separately
        here (unlike the guarded write tools), so a typo'd/unknown interface
        name simply produces whatever error RouterOS itself returns.

        Returns a single reply dict - typically rx-bits-per-second/
        tx-bits-per-second and rx-packets-per-second/tx-packets-per-second -
        or an empty dict if the device returned nothing. `once=yes` makes
        this a single instantaneous reading, not a continuous stream, so the
        call always returns promptly.
        """
        validated_interface = validate_interface_name(interface)
        client = _client(device_name)
        return client.monitor_traffic(validated_interface)

    @mcp.tool()
    @_safe
    def poe_status(device_name: str) -> list[dict[str, Any]]:
        """PoE status/consumption per port, for every PoE-capable ethernet
        port on the device.

        Reads /interface/ethernet and keeps only rows that have a `poe-out`
        field (i.e. are PoE-capable on this hardware - e.g. the CRS318-16P's
        high/low PoE ports), then reads
        /interface/ethernet/poe/monitor once=yes for each one to get its
        live voltage/current/power/poe-out-status. Each entry looks like
        {"interface", "poe-out" (configured mode), "poe-out-status",
        "voltage", "current", "power"} - the monitor fields are omitted for
        a port whose live monitor call fails (kept resilient rather than
        failing the whole tool for one bad port).

        `voltage`/`current`/`power` are normalized to `int | float | None`
        via `formatting.coerce_ros_number`, never passed through raw: real
        hardware (CRS318-16P-2S+, ROS6.49.20) mixes `int` and string-decimal
        (e.g. `"4.7"`) types for these same three fields within a single
        monitor reply, and across different ports of the same device - see
        that helper's docstring. Without this, a caller comparing
        `voltage > 0` (see README's PoE power-cycle walkthrough) could get a
        string on one port and a number on another.

        Returns an empty list (never an error) for a device with no PoE
        hardware at all - that's a completely normal state, same as
        `wireless_registrations` for a wired-only device.
        """
        client = _client(device_name)
        ethernet_rows = rows_to_list(client.path("interface", "ethernet"))
        poe_rows = [row for row in ethernet_rows if "poe-out" in row]

        result: list[dict[str, Any]] = []
        for row in poe_rows:
            name = row.get("name", "")
            entry: dict[str, Any] = {"interface": name, "poe-out": row.get("poe-out")}
            try:
                monitor = client.poe_monitor(name)
            except DeviceCommandError:
                monitor = {}
            if monitor:
                entry["poe-out-status"] = monitor.get("poe-out-status")
                entry["voltage"] = coerce_ros_number(monitor.get("poe-out-voltage"))
                entry["current"] = coerce_ros_number(monitor.get("poe-out-current"))
                entry["power"] = coerce_ros_number(monitor.get("poe-out-power"))
            result.append(entry)
        return result

    @mcp.tool()
    @_safe
    def lte_status(device_name: str, interface: str) -> dict[str, Any]:
        """Signal/status of one LTE/5G modem interface
        (`/interface/lte/monitor <interface> once=yes`).

        Returns a single reply dict - typically operator (`current-operator`),
        technology (`access-technology`: 3G/LTE/5G), signal
        (`rsrp`/`rsrq`/`sinr`/`rssi`), `band`, `registration-status`,
        `cell-id` - or an empty dict if the device has no LTE hardware/package
        at all, or `interface` doesn't match one (same "empty, not an error"
        convention as `poe_status`/`system_health` for optional hardware).

        `interface` is validated for shape (`validate_interface_name`) before
        it is ever sent to the device.
        """
        validated_interface = validate_interface_name(interface)
        client = _client(device_name)
        try:
            return client.lte_monitor(validated_interface)
        except DeviceCommandError:
            return {}

    @mcp.tool()
    @_safe
    def lte_interfaces(device_name: str) -> list[dict[str, Any]]:
        """List LTE/5G modem interfaces (`/interface/lte`): name, running,
        disabled, apn-profiles, etc. Returns an empty list (never an error)
        for a device with no LTE hardware/package at all.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("interface", "lte"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def containers(device_name: str) -> list[dict[str, Any]]:
        """List containers (`/container`): name/tag, status, ram-usage,
        root-dir, interface, os, etc. Returns an empty list (never an error)
        for a device with no container package/hardware support at all.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("container"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def container_config(device_name: str) -> dict[str, Any]:
        """Container subsystem configuration (`/container/config`):
        registry-url, tmpdir, ram-high, etc - a single-row menu. Returns an
        empty dict (never an error) for a device with no container package.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("container", "config"))
        except DeviceCommandError:
            return {}
        return rows[0] if rows else {}

    @mcp.tool()
    @_safe
    def usb_devices(device_name: str) -> dict[str, Any]:
        """USB hardware on a device: physical USB ports
        (`/system/routerboard/usb`, if the board exposes them) plus attached
        storage (`/disk` - USB flash drives, and USB LTE/5G modems that
        surface as a disk rather than under routerboard/usb). Combined into
        one read since which of the two a given USB device shows up under
        depends on the hardware.

        Returns `{"usb_ports": [...], "disks": [...]}` - either or both
        lists empty (never an error) if the board doesn't expose that
        menu/hardware at all.
        """
        client = _client(device_name)
        try:
            usb_ports = rows_to_list(client.path("system", "routerboard", "usb"))
        except DeviceCommandError:
            usb_ports = []
        try:
            disks = rows_to_list(client.path("disk"))
        except DeviceCommandError:
            disks = []
        return {"usb_ports": usb_ports, "disks": disks}

    # --- v1.7: SFP/optical monitor, DHCP-server config, bridge VLAN --------
    # --- filtering (Tier 2 network-config visibility) ----------------------

    @mcp.tool()
    @_safe
    def interface_monitor(device_name: str, interface: str) -> dict[str, Any]:
        """Link/optical status of one ethernet `interface`
        (`/interface/ethernet/monitor once=yes`) - `status` (link-ok/
        no-link), `rate`, `full-duplex` (coerced to `bool | None` - see
        `formatting.coerce_ros_bool`), `auto-negotiation` (RouterOS's raw
        value - a "done"/"incomplete"-style state, not a strict boolean, so
        left as-is), plus SFP/DDM optics fields WHEN the port has an SFP
        cage and a module is present: `sfp-temperature`,
        `sfp-supply-voltage`, `sfp-tx-power`, `sfp-rx-power`,
        `sfp-tx-bias-current`, `sfp-vendor-name`, `sfp-vendor-part-number`,
        `sfp-wavelength`, `sfp-module-present` (also coerced to
        `bool | None`).

        A plain copper port (the vast majority) has NONE of the sfp-*
        fields in RouterOS's reply at all - each is only added to the
        result when the device's reply actually carries it (`.get`/`in`
        checks throughout, nothing invented). The reference hardware this
        project was verified against (a mANTBox) has no SFP cage, so the
        command path itself is confirmed but the DDM field VALUES are not
        yet verified against real SFP optics - see `ROADMAP.md`.

        `interface` is validated for shape (`validate_interface_name`)
        before it is ever sent to the device - existence isn't checked
        separately, so a typo'd/unknown interface name simply produces
        whatever error RouterOS itself returns. Returns an empty dict if
        the device answers with nothing (same "once" convention as
        `interface_traffic`/`poe_status`/`lte_status`).
        """
        validated_interface = validate_interface_name(interface)
        client = _client(device_name)
        row = client.ethernet_monitor(validated_interface)
        if not row:
            return {}

        entry: dict[str, Any] = {
            "interface": validated_interface,
            "status": row.get("status"),
            "rate": row.get("rate"),
            "full-duplex": coerce_ros_bool(row.get("full-duplex")),
            "auto-negotiation": row.get("auto-negotiation"),
        }
        for field in (
            "sfp-temperature",
            "sfp-supply-voltage",
            "sfp-tx-power",
            "sfp-rx-power",
            "sfp-tx-bias-current",
            "sfp-vendor-name",
            "sfp-vendor-part-number",
            "sfp-wavelength",
        ):
            if field in row:
                entry[field] = row[field]
        if "sfp-module-present" in row:
            entry["sfp-module-present"] = coerce_ros_bool(row["sfp-module-present"])
        return entry

    @mcp.tool()
    @_safe
    def dhcp_servers(device_name: str) -> list[dict[str, Any]]:
        """List DHCP server CONFIG (`/ip/dhcp-server`) - as opposed to
        `dhcp_leases`, which lists the leases a server has handed out. Each
        entry keeps every field RouterOS returns (`name`, `interface`,
        `address-pool`, `lease-time`, `authoritative`, `comment`, ...), with
        `disabled` normalized to `bool | None` (`formatting.coerce_ros_bool`
        - never a `== "true"` string-equality trap, see that helper's
        docstring). `authoritative` is left as RouterOS's own raw value
        (it can be `"yes"`/`"no"`/`"after-2sec-delay"`/... - not a strict
        boolean - so it is not coerced).
        """
        client = _client(device_name)
        rows = rows_to_list(client.path("ip", "dhcp-server"))
        result: list[dict[str, Any]] = []
        for row in rows:
            entry = dict(row)
            entry["disabled"] = coerce_ros_bool(row.get("disabled"))
            result.append(entry)
        return result

    @mcp.tool()
    @_safe
    def dhcp_networks(device_name: str) -> list[dict[str, Any]]:
        """List DHCP server networks (`/ip/dhcp-server/network`): `address`,
        `gateway`, `dns-server`, `netmask`, `domain`, `comment` - the
        per-subnet options a DHCP server (see `dhcp_servers`) hands out to
        clients on lease. No boolean fields here to normalize.
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "dhcp-server", "network"))

    @mcp.tool()
    @_safe
    def bridge_ports(device_name: str) -> list[dict[str, Any]]:
        """List bridge port membership (`/interface/bridge/port`): `bridge`,
        `interface`, `pvid`, `disabled`, `edge`, `horizon`, `learn`,
        `comment`. Only `disabled` is normalized to `bool | None`
        (`formatting.coerce_ros_bool`) - `edge`/`learn` are RouterOS enums
        (e.g. `auto`/`yes`/`no`/`yes-discover`/`no-discover`), not strict
        booleans, so they are left as RouterOS's own raw value rather than
        coerced.

        Use this (with `bridge_vlans` below) to see which physical port of
        a managed switch's bridge a VLAN actually applies to - `bridge_hosts`
        only shows the MAC table, not port/VLAN configuration.
        """
        client = _client(device_name)
        rows = rows_to_list(client.path("interface", "bridge", "port"))
        result: list[dict[str, Any]] = []
        for row in rows:
            entry = dict(row)
            entry["disabled"] = coerce_ros_bool(row.get("disabled"))
            result.append(entry)
        return result

    @mcp.tool()
    @_safe
    def bridge_vlans(device_name: str) -> list[dict[str, Any]]:
        """List bridge VLAN filtering table entries (`/interface/bridge/vlan`):
        `bridge`, `vlan-ids`, `tagged`, `untagged`, `comment`, plus
        `current-tagged`/`current-untagged` when the device's reply carries
        them (RouterOS's own computed effective port lists - not present on
        every ROS6/ROS7 version, so only added when actually present, never
        invented).

        This is the honest completion of the VLAN story for a MANAGED
        SWITCH (CRS/hEX-style hardware): the v1.2 `list_vlans`/`add_vlan`/
        `remove_vlan` tools operate on standalone `/interface/vlan`
        interfaces (router-on-a-stick style routing), which is a DIFFERENT
        RouterOS mechanism from bridge VLAN filtering - a switch that
        segments traffic by VLAN across bridge ports needs THIS table, not
        `/interface/vlan`. See `bridge_ports` above for per-port
        `pvid`/`edge`/`learn` config.
        """
        client = _client(device_name)
        return rows_to_list(client.path("interface", "bridge", "vlan"))

    # --- v1.8: NTP client + clock (closes out Tier 2) -----------------------

    @mcp.tool()
    @_safe
    def ntp_client(device_name: str) -> dict[str, Any]:
        """NTP client configuration/status (`/system/ntp/client`) - a
        single-row menu, same shape as `container_config`. Every field
        RouterOS's own reply carries is returned as-is (`.get`-based,
        nothing invented) - only `enabled` is normalized to `bool | None`
        (`formatting.coerce_ros_bool`).

        ROS7 fields: `enabled`, `mode`, `servers` (a comma-joined string of
        every configured NTP server - left exactly as RouterOS sends it, NOT
        split into a list; same "no invented shape" convention
        `bridge_vlans`' `tagged`/`untagged` fields already follow),
        `freq-drift`, `status`, `synced-server`, `synced-stratum`.

        ROS6 fields: `enabled`, `primary-ntp`, `secondary-ntp`,
        `server-dns-names`, `mode`. See `set_ntp_servers` for how a write
        detects and targets whichever of these two shapes a device actually
        speaks.

        Returns an empty dict (never an error) for a device with no NTP
        client menu at all.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("system", "ntp", "client"))
        except DeviceCommandError:
            return {}
        if not rows:
            return {}
        entry = dict(rows[0])
        entry["enabled"] = coerce_ros_bool(rows[0].get("enabled"))
        return entry

    @mcp.tool()
    @_safe
    def system_clock(device_name: str) -> dict[str, Any]:
        """Device clock (`/system/clock`): `time`, `date`, `time-zone-name`,
        `time-zone-autodetect` (normalized to `bool | None` -
        `formatting.coerce_ros_bool`), `gmt-offset`, `dst-active` (also
        normalized) - a single-row menu, same shape as `container_config`/
        `ntp_client`.

        Clock drift breaks certificate validation (see `certificates`'
        `daysUntilExpiry`), log timestamps, and scheduler timing - check
        this alongside `ntp_client`'s `status`/`synced-server` when
        diagnosing any of those. Returns an empty dict (never an error) for
        a device with no `/system/clock` menu at all (not expected on any
        real RouterOS device, but handled the same defensive way every
        other single-row read here is).
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("system", "clock"))
        except DeviceCommandError:
            return {}
        if not rows:
            return {}
        entry = dict(rows[0])
        entry["time-zone-autodetect"] = coerce_ros_bool(rows[0].get("time-zone-autodetect"))
        entry["dst-active"] = coerce_ros_bool(rows[0].get("dst-active"))
        return entry

    # --- v0.14: hotspot vouchers, live traffic (torch), backup -------------

    @mcp.tool()
    @_safe
    def hotspot_active(device_name: str) -> list[dict[str, Any]]:
        """List clients currently logged into the RouterOS hotspot
        (`/ip/hotspot/active`): `user`, `address`, `mac-address`, `uptime`,
        `bytes-in`/`bytes-out` - who is on the hotspot right now, and how
        much they've each moved this session.

        Returns an empty list (never an error) for a device with no hotspot
        server configured, or simply no one logged in right now - same
        convention as `ppp_active`/`ipsec_active_peers` for an optional
        feature with no active sessions.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ip", "hotspot", "active"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def torch(
        device_name: str,
        interface: str,
        src_address: str | None = None,
        dst_address: str | None = None,
        port: int | None = None,
    ) -> dict[str, Any]:
        """Live traffic snapshot of one `interface`
        (`/tool/torch interface=<interface> once=yes`) - RouterOS's own
        real-time traffic monitor, useful to answer "who is consuming
        bandwidth on this link RIGHT NOW". `interface` is validated for
        shape (`validate_interface_name`) before it is ever sent to the
        device - existence isn't checked separately, so a typo'd/unknown
        interface name simply produces whatever error RouterOS itself
        returns.

        `src_address`/`dst_address` (plain IPv4/IPv6 addresses -
        `validate_ip_address`) and `port` (1-65535 -
        `validate_conntrack_dst_port`, reused here for the same "TCP/UDP
        port" shape) are all optional filters forwarded to RouterOS itself,
        narrowing the snapshot BEFORE it ever leaves the device - use them
        to cut down volume on a busy interface rather than fetching every
        flow and filtering client-side.

        `once=yes` makes this a single instantaneous snapshot, not a
        continuous stream (same "once" convention as `interface_traffic`/
        `poe_status`/`lte_status` - see `client.MikrotikClient.torch`), so
        the call always returns promptly instead of opening RouterOS's
        normal interactive torch stream.

        VOLUME CAP: regardless of how many flows RouterOS reports for this
        snapshot, the result's `flows` list is sorted by total traffic
        (tx+rx bytes, biggest first - the "top talkers") and hard-capped at
        `MAX_TORCH_LIMIT` (50) entries - `truncated` is `true` whenever more
        flows matched than were returned, and `total_matched` always reports
        the real (pre-cap) count. RouterOS's own torch field names for a
        flow's traffic volume aren't perfectly uniform across RouterOS
        versions/hardware - this sorts by whichever of `tx`/`rx` (bits- or
        bytes-per-second, depending on version) the device actually
        returned, defaulting a flow with neither to 0 (sorted last) rather
        than failing the whole call over one unexpected row shape.
        """
        validated_interface = validate_interface_name(interface)
        validated_src = validate_ip_address(src_address) if src_address else None
        validated_dst = validate_ip_address(dst_address) if dst_address else None
        validated_port = validate_conntrack_dst_port(port) if port is not None else None

        client = _client(device_name)
        rows = client.torch(
            validated_interface, src_address=validated_src, dst_address=validated_dst, port=validated_port
        )

        def _traffic_volume(row: dict[str, Any]) -> int:
            total = 0
            for key in ("tx", "rx"):
                try:
                    total += int(row.get(key, 0))
                except (TypeError, ValueError):
                    continue
            return total

        sorted_rows = sorted(rows, key=_traffic_volume, reverse=True)
        total_matched = len(sorted_rows)
        return {
            "flows": sorted_rows[:MAX_TORCH_LIMIT],
            "total_matched": total_matched,
            "truncated": total_matched > MAX_TORCH_LIMIT,
        }

    @mcp.tool()
    @_safe
    def list_backups(device_name: str) -> list[dict[str, Any]]:
        """List backup files stored on the device (`/file`, filtered to
        names ending in `.backup`): `name`, `size`, `creation-time`.

        Reads the same `/file` menu `create_backup`'s duplicate-name check
        uses - call this after `create_backup` to confirm a new backup
        landed and see its real size. Returns an empty list (never an
        error) if the device has no backup files at all.
        """
        client = _client(device_name)
        rows = rows_to_list(client.path("file"))
        return [
            {"name": row.get("name"), "size": row.get("size"), "creation-time": row.get("creation-time")}
            for row in rows
            if str(row.get("name", "")).endswith(".backup")
        ]

    @mcp.tool()
    @_safe
    def list_write_operations() -> list[dict[str, Any]]:
        """List every guarded write operation and the RouterOS path/action it maps to.

        Read-only: this only surfaces guard.ALLOWLIST's metadata (D3) - it
        does not perform or preview a write, and is not gated by
        MIKROTIK_ALLOW_WRITE.
        """
        return [
            {
                "name": op.name,
                "path": "/".join(op.path),
                "action": op.action,
                "description": op.description,
            }
            for op in guard.ALLOWLIST.values()
        ]

    # --- v1.6: AAA/PKI visibility (certificates, users, RADIUS) --------

    @mcp.tool()
    @_safe
    def certificates(device_name: str) -> list[dict[str, Any]]:
        """List certificates (`/certificate`): `name`, `common-name`,
        subject/issuer fields (if present), `invalid-before`/`invalid-after`
        (raw RouterOS date strings, kept as-is), `key-size`/`key-type`,
        `fingerprint`, and RouterOS's own flags (`expired`, `trusted`) - all
        returned exactly as the device sends them (booleans may come back as
        Python `bool` or be omitted entirely; see `formatting.coerce_ros_bool`
        for a caller that needs to branch on `expired`/`trusted` rather than
        just display them).

        Adds a computed `daysUntilExpiry` (int, negative once past due) from
        `invalid-after` whenever it can be parsed - see
        `formatting.parse_ros_datetime`'s docstring for the two RouterOS date
        shapes handled (`"2027-01-15 12:00:00"` and
        `"jan/15/2027 12:00:00"`). RouterOS's own date rendering varies by
        version/locale; parsing is DEFENSIVE and never raises - a row whose
        `invalid-after` doesn't match either known shape simply has no
        `daysUntilExpiry` key added, with the raw `invalid-after` string left
        untouched so a caller can still see it.

        SECURITY: `/certificate`'s own API reply never carries a private key
        (RouterOS only returns certificate metadata over the API) - a
        `private-key` field is nonetheless stripped defensively before
        returning, in case a future RouterOS version or firmware quirk ever
        adds one (same `strip_sensitive_fields` mechanism `ppp_secrets`/
        `wireguard_interfaces` use). See
        `test_certificates_strips_private_key_defensively`.

        See also `security_audit`'s certificate-expiry check (v1.6), which
        flags an expired or soon-to-expire (<=30 days) certificate as a
        finding using this same expiry logic.

        Returns an empty list (never an error) for a device with no
        certificates configured.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("certificate"))
        except DeviceCommandError:
            return []
        rows = strip_sensitive_fields(rows, _CERTIFICATE_REDACTED_FIELDS)
        result: list[dict[str, Any]] = []
        for row in rows:
            entry = dict(row)
            remaining_days = days_until(entry.get("invalid-after"))
            if remaining_days is not None:
                entry["daysUntilExpiry"] = remaining_days
            result.append(entry)
        return result

    @mcp.tool()
    @_safe
    def users(device_name: str) -> list[dict[str, Any]]:
        """List RouterOS login accounts (`/user`): `name`, `group`,
        `address` (an allowed-source restriction, if the account has one),
        `last-logged-in` (if RouterOS exposes it), `disabled`, `comment`.

        `/user`'s own API reply never carries a password at all - RouterOS
        doesn't expose it over the API, so there is nothing to strip here
        (unlike `ppp_secrets`/`radius`, whose underlying menus DO carry a
        secret). This is a READ only: creating/editing a `/user` login stays
        deliberately out of scope for this package (see `ROADMAP.md`'s
        "Explicitly NOT on the roadmap" - a router login is a device/API
        credential, a different risk class from a service credential like a
        PPP secret or hotspot user).

        Returns an empty list (never an error) if `/user` is unavailable for
        some reason - `/user` always exists on RouterOS in practice, but this
        keeps the same "empty, not an error" convention every other optional
        read in this package uses.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("user"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def user_active(device_name: str) -> list[dict[str, Any]]:
        """List currently active RouterOS login sessions (`/user/active`):
        `name`, `address`, `via` (e.g. `api`/`winbox`/`ssh`/`web`), `when`
        (session start time) - who is logged into the device's own
        management right now, as opposed to `users`' CONFIGURED accounts.

        Returns an empty list (never an error) for a device with nobody
        currently logged in, or if `/user/active` is unavailable.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("user", "active"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def radius(device_name: str) -> list[dict[str, Any]]:
        """List RADIUS server configuration (`/radius`): `service`,
        `address`, `timeout`, `accounting-port`, `authentication-port`, and
        whatever other fields RouterOS returns for a given entry.

        SECURITY: RouterOS's own `/radius` reply carries the plaintext
        shared `secret` - this is ALWAYS stripped before returning
        (`formatting.strip_sensitive_fields`), the same mechanism
        `ppp_secrets` uses for `/ppp/secret`'s `password` and
        `wireguard_interfaces` uses for a tunnel interface's `private-key`.
        A RADIUS shared secret never leaves this process via this tool. See
        `test_radius_never_exposes_secret`.

        Returns an empty list (never an error) for a device with no RADIUS
        servers configured.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("radius"))
        except DeviceCommandError:
            return []
        return strip_sensitive_fields(rows, _RADIUS_REDACTED_FIELDS)

    # --- v0.12: security audit + security-relevant log events ----------

    @mcp.tool()
    @_safe
    def security_audit(device_name: str) -> dict[str, Any]:
        """Read-only security audit of a device's configuration - gives an
        LLM caller (or operator) a structured list of findings to review, so
        it can "look at the security of this router" without an operator
        manually walking every menu.

        Aggregates several independent, defensive checks - see
        `src/mcp_mikrotik/security.py` for the full list and reasoning:
        insecure management services (`/ip/service`: telnet/ftp/www/api
        enabled, and whether they're open to any address), whether the
        firewall's input chain ends in a drop/reject rule (heuristic),
        SNMP community exposure (`/snmp/community`), an open DNS resolver
        (`/ip/dns` allow-remote-requests), outdated RouterOS
        (`/system/package/update`), open wireless/wifi networks (no
        security profile / no passphrase), a count of users with a
        write/full policy, and (v1.6) an expired or soon-to-expire
        (<=30 days) certificate (`/certificate`).

        Each check reads its own menu(s) and skips itself (contributing no
        findings) if that menu doesn't exist on this device/RouterOS
        generation - one missing/unsupported menu never fails the whole
        audit. NEVER a scanner, NEVER definitive - this is a heuristic,
        best-effort read meant to prompt a human decision, not to replace
        one; see README's "Security audit" section for the full disclaimer.

        READ-ONLY: does not change anything on the device, and is not gated
        by MIKROTIK_ALLOW_WRITE.

        NO SECRET IS EVER RETURNED: no finding ever includes a password,
        passphrase, or SNMP community string - see security.py's module
        docstring for exactly how each check avoids that.

        Returns `{"findings": [{"severity", "category", "title", "detail",
        "recommendation"}, ...], "summary": {"high", "medium", "low",
        "info"}}` - `findings` sorted by severity (high first), `summary`
        always including all four keys (0 for a severity with no findings).
        """
        client = _client(device_name)
        return security.run_security_audit(client)

    @mcp.tool()
    @_safe
    def security_events(device_name: str, limit: int = DEFAULT_SECURITY_EVENTS_LIMIT) -> list[dict[str, Any]]:
        """Recent RouterOS log entries filtered down to security-relevant
        ones - login/logout/authentication-failure events (topic
        "account"), "critical"/"error" topic entries, and generic
        "system,info" rows whose message looks like a login/logout - so a
        caller can correlate access attempts/anomalies without reading the
        entire (often much larger) unfiltered log via `logs`.

        Filtering happens in Python, same reasoning `logs`' `topics` filter
        already documents (RouterOS's structured API doesn't expose a
        query-by-field read here either) - and is applied BEFORE the
        `limit` cut, so this returns the most recent `limit` MATCHING
        entries (not the last `limit` raw entries filtered afterward, which
        would silently drop matches on a busy log).

        `limit` must be positive and is capped at 500 (default 50), the same
        shape as `logs`' own `limit`.

        READ-ONLY: not gated by MIKROTIK_ALLOW_WRITE.
        """
        client = _client(device_name)
        capped_limit = validate_positive_limit(limit, MAX_SECURITY_EVENTS_LIMIT, "limit")
        rows = rows_to_list(client.path("log"))
        return security.filter_security_events(rows, capped_limit)

    # --- Write tools ---------------------------------------------------
    # Every write tool must call a dedicated function in guard.py - never
    # MikrotikClient.update/add/remove directly. See guard.py's module
    # docstring for how to add the next one.

    @mcp.tool()
    @_safe
    def set_identity(device_name: str, new_name: str, confirm: bool = False) -> dict[str, Any]:
        """Set a device's RouterOS identity (hostname).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it.
        """
        client = _client(device_name)
        preview = guard.set_identity(client, settings, new_name=new_name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def enable_interface(device_name: str, interface_name: str, confirm: bool = False) -> dict[str, Any]:
        """Enable a network interface by name (sets disabled=no).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        `interface_name` does not exist on the device - it is never created.
        """
        client = _client(device_name)
        preview = guard.enable_interface(client, settings, interface_name=interface_name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_interface(device_name: str, interface_name: str, confirm: bool = False) -> dict[str, Any]:
        """Disable a network interface by name (sets disabled=yes).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        `interface_name` does not exist on the device - it is never created.
        """
        client = _client(device_name)
        preview = guard.disable_interface(client, settings, interface_name=interface_name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_wifi_ssid(device_name: str, interface_name: str, new_ssid: str, confirm: bool = False) -> dict[str, Any]:
        """Set a wireless interface's SSID.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Works against
        either RouterOS generation - it looks for `interface_name` under the
        ROS7 wifi package first, then the ROS6 wireless package - and errors
        clearly if it isn't found under either; it is never created.

        On ROS7, a wifi interface running the standard production layout (a
        named `configuration`) has no ssid field of its own - the actual
        write lands on the referenced /interface/wifi/configuration profile
        instead, resolved automatically. The before/after preview always
        reflects the real location the ssid is read from and written to.
        """
        client = _client(device_name)
        preview = guard.set_wifi_ssid(
            client, settings, interface_name=interface_name, new_ssid=new_ssid, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_client_bandwidth(
        device_name: str, target: str, max_limit: str, limit_at: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Limit a client's bandwidth via a RouterOS Simple Queue (/queue/simple).

        `target` is the client's IP address or subnet (e.g. "10.0.0.5" or
        "10.0.0.0/24"). `max_limit` is a RouterOS rate pair in
        "upload/download" form (e.g. "10M/5M"); `limit_at` is the optional
        guaranteed-rate (CIR) pair in the same form. If a Simple Queue
        already targets `target`, its max-limit/limit-at is UPDATED;
        otherwise a new one is CREATED with a name derived from `target` -
        the returned `operation` field ("set_client_bandwidth_update" vs
        "set_client_bandwidth_add") tells you which happened (or would
        happen, with confirm=False).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it.

        GOTCHA - FastTrack: if the device has a FastTrack rule in its
        firewall (common on RouterOS's own quick-set wizards), fasttracked
        connections bypass queueing entirely, so this queue may have no
        visible effect on a client whose traffic is already fasttracked -
        see README's "Security model" section.
        """
        client = _client(device_name)
        preview = guard.set_client_bandwidth(
            client, settings, target=target, max_limit=max_limit, limit_at=limit_at, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_static_dhcp_lease(
        device_name: str,
        address: str,
        mac_address: str,
        comment: str | None = None,
        server: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a static DHCP lease (/ip/dhcp-server/lease), pinning
        `address` to `mac_address`. Useful to give a client a stable,
        predictable IP - e.g. before limiting it with set_client_bandwidth.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if a lease for `mac_address` already
        exists on the device - it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_static_dhcp_lease(
            client,
            settings,
            address=address,
            mac_address=mac_address,
            comment=comment,
            server=server,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_simple_queue(
        device_name: str, target: str | None = None, name: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a Simple Queue by `target` or by `name` - undoes a
        bandwidth limit previously set with set_client_bandwidth. At least
        one of `target`/`name` must be given and must match an existing
        queue.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it.
        """
        client = _client(device_name)
        preview = guard.remove_simple_queue(client, settings, target=target, name=name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_to_address_list(
        device_name: str,
        list_name: str,
        address: str,
        comment: str | None = None,
        timeout: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add `address` (an IP or subnet) to a named firewall address-list
        (/ip/firewall/address-list).

        IMPORTANT: this only manages the *list* - it does NOT create or
        modify any firewall rule. Adding an address here only blocks or
        allows traffic if a `/ip/firewall/filter` (or NAT) rule on the
        device already references `list_name` (e.g.
        `src-address-list=list_name`, action=drop). See README's
        "Blocking/allowing a client via address lists" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if this exact `list_name`+`address` pair
        already exists on the device - it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_to_address_list(
            client,
            settings,
            list_name=list_name,
            address=address,
            comment=comment,
            timeout=timeout,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_from_address_list(
        device_name: str, list_name: str, address: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove the entry matching `list_name`+`address` from a firewall
        address-list (/ip/firewall/address-list).

        Like add_to_address_list, this only manages the *list* - see that
        tool's docstring and README's "Blocking/allowing a client via
        address lists" section for why this alone doesn't guarantee a
        change in blocking/allowing behavior.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it. Errors clearly if no entry
        matches `list_name`+`address`.
        """
        client = _client(device_name)
        preview = guard.remove_from_address_list(
            client, settings, list_name=list_name, address=address, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_poe_out(device_name: str, interface_name: str, poe_out: str, confirm: bool = False) -> dict[str, Any]:
        """Set a PoE-capable ethernet port's PoE output mode
        (/interface/ethernet set [interface_name] poe-out=<poe_out>).

        `poe_out` must be one of "auto-on", "forced-on", "off".

        Primary use case: reset a locked-up antenna/camera/AP powered over
        PoE by cycling its power - call with poe_out="off" (confirm=true),
        wait for it to actually power down, then call again with
        poe_out="auto-on" to bring it back up.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without changing anything) if `interface_name` doesn't exist on the
        device, or exists but isn't PoE-capable - it never creates or
        coerces anything.
        """
        client = _client(device_name)
        preview = guard.set_poe_out(client, settings, interface_name=interface_name, poe_out=poe_out, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def start_container(device_name: str, container: str, confirm: bool = False) -> dict[str, Any]:
        """Start a container by `name` or `tag` (`/container/start`).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if `container` doesn't match any
        `/container` row's `name` or `tag` on the device - it is never
        created.

        The `after.status` in the preview is the status RouterOS sets
        immediately ("starting"), not a guaranteed final state - the
        container transitions to "running" asynchronously; use `containers`
        again afterward to see the settled status.
        """
        client = _client(device_name)
        preview = guard.start_container(client, settings, container=container, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def stop_container(device_name: str, container: str, confirm: bool = False) -> dict[str, Any]:
        """Stop a container by `name` or `tag` (`/container/stop`).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without changing anything) if `container` doesn't match any
        `/container` row's `name` or `tag` on the device - it is never
        created.

        The `after.status` in the preview is the status RouterOS sets
        immediately ("stopping"), not a guaranteed final state - use
        `containers` again afterward to see the settled status.
        """
        client = _client(device_name)
        preview = guard.stop_container(client, settings, container=container, confirm=confirm)
        return asdict(preview)

    # --- v0.9: atomic failover writes -----------------------------------

    @mcp.tool()
    @_safe
    def set_route_distance(
        device_name: str, dst_address: str, gateway: str, distance: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Adjust an existing route's `distance` (failover priority - lower
        distance wins) via `/ip/route set distance=<distance>`.

        Resolved by the STABLE (`dst_address`, `gateway`) pair - never a
        dynamic `.id`/list index, which can silently shift as routes are
        added/removed elsewhere on the device between a preview and the
        confirmed apply. Errors clearly (without changing anything) if no
        route matches that pair, or if more than one still does
        (`AmbiguousResourceError`) - this never guesses which route to
        touch.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. See README's
        "Failover control" section for the recommended step-by-step flow.
        """
        client = _client(device_name)
        preview = guard.set_route_distance(
            client, settings, dst_address=dst_address, gateway=gateway, distance=distance, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def enable_route(
        device_name: str,
        dst_address: str,
        gateway: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Enable a route (`/ip/route set disabled=no`), resolved by
        `dst_address` - narrowed by `gateway`/`comment` when more than one
        route shares that `dst_address` (e.g. two default routes to
        different gateways, the standard failover shape). Errors clearly if
        nothing matches, or if the match is still ambiguous after
        narrowing.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it.
        """
        client = _client(device_name)
        preview = guard.enable_route(
            client, settings, dst_address=dst_address, gateway=gateway, comment=comment, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_route(
        device_name: str,
        dst_address: str,
        gateway: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Disable a route (`/ip/route set disabled=yes`), resolved by
        `dst_address` - narrowed by `gateway`/`comment` when more than one
        route shares that `dst_address`. Errors clearly if nothing matches,
        or if the match is still ambiguous after narrowing.

        RISK: disabling the default route (`dst_address="0.0.0.0/0"` or
        `"::/0"`) cuts all outbound traffic that relies on this gateway. The
        returned preview's `warning` field is non-null whenever this is the
        case - always check it before calling again with `confirm=true`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the `warning`
        field) without changing anything; call again with confirm=True to
        actually apply it.
        """
        client = _client(device_name)
        preview = guard.disable_route(
            client, settings, dst_address=dst_address, gateway=gateway, comment=comment, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_route(
        device_name: str,
        dst_address: str,
        gateway: str,
        distance: int | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add a static route (`/ip/route add`): `dst_address` and
        `gateway` are required, `distance` (failover priority - lower wins)
        and `comment` are optional. Never refuses a duplicate `dst_address`
        - multiple routes sharing one is the normal failover shape.

        RISK: adding/overriding the default route (`dst_address="0.0.0.0/0"`
        or `"::/0"`) redirects all outbound traffic through the new
        gateway. The returned preview's `warning` field is non-null
        whenever this is the case - always check it before calling again
        with `confirm=true`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the `warning`
        field) without changing anything; call again with confirm=True to
        actually apply it.
        """
        client = _client(device_name)
        preview = guard.add_route(
            client,
            settings,
            dst_address=dst_address,
            gateway=gateway,
            distance=distance,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_route(
        device_name: str,
        dst_address: str,
        gateway: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Remove a static route (`/ip/route remove`), resolved by
        `dst_address` - narrowed by `gateway` when more than one route
        shares that `dst_address`. Errors clearly if nothing matches, or if
        the match is still ambiguous after narrowing.

        SAFETY: refuses outright (raises an error, does not remove
        anything) if the resolved route is dynamic (`dynamic=true` - a
        connected/DHCP/OSPF/BGP-installed route). Only static,
        admin-created routes can be removed by this tool - removing a
        device's connected/dynamic route can sever the network.

        The returned preview's `warning` field is non-null (but not
        blocking) whenever the resolved route's `dst_address` is the
        default route (`0.0.0.0/0`/`::/0`) - check it before calling again
        with `confirm=true`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the `warning`
        field) without changing anything; call again with confirm=True to
        actually apply it.
        """
        client = _client(device_name)
        preview = guard.remove_route(client, settings, dst_address=dst_address, gateway=gateway, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_netwatch(
        device_name: str,
        host: str,
        interval: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a Netwatch host monitor (`/tool/netwatch add`): `host`
        (a plain IPv4/IPv6 address), optional `interval` (a RouterOS
        duration, e.g. "10s"/"00:00:10") and optional `comment`.

        SECURITY: this tool does NOT accept an up-script/down-script - a
        Netwatch script body can run arbitrary RouterOS commands (route or
        credential changes, ...), so it is deliberately outside what this
        guarded write tool will ever send to a device. Configure up/down
        scripts manually on the device once the monitor exists (WinBox/CLI)
        - see README's "Failover control" section. The read-only `netwatch`
        tool already only ever surfaces `has-up-script`/`has-down-script` as
        presence booleans, never a script body, for the same reason.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if a monitor for `host` already exists -
        it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_netwatch(client, settings, host=host, interval=interval, comment=comment, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_netwatch(
        device_name: str, host: str | None = None, comment: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a Netwatch host monitor by `host` or `comment`
        (`/tool/netwatch remove`). At least one of `host`/`comment` must be
        given and must match an existing monitor (`host` is tried first if
        both are given).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it.
        """
        client = _client(device_name)
        preview = guard.remove_netwatch(client, settings, host=host, comment=comment, confirm=confirm)
        return asdict(preview)

    # --- v0.10: static DNS, DNS cache flush, DHCP lease removal, WoL -----

    @mcp.tool()
    @_safe
    def add_static_dns(
        device_name: str,
        name: str,
        address: str,
        record_type: str = "A",
        ttl: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a static DNS entry (`/ip/dns/static add`) resolving `name`
        to `address`.

        `record_type` is `"A"` (default) or `"CNAME"`: for `"A"`, `address`
        is a literal IPv4/IPv6 address; for `"CNAME"`, `address` is itself
        another hostname (the alias target), written to RouterOS's `cname`
        field. Useful to block a malicious domain (point it at `0.0.0.0`) or
        set up an internal DNS override.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if a row already matches this exact
        `name`+`record_type` pair - it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_static_dns(
            client,
            settings,
            name=name,
            address=address,
            record_type=record_type,
            ttl=ttl,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_static_dns(
        device_name: str, name: str, record_type: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a static DNS entry (`/ip/dns/static remove`) by `name`,
        optionally narrowed by `record_type` (`"A"`/`"CNAME"`).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it. Errors clearly if nothing
        matches `name` (narrowed by `record_type`), or if more than one row
        still matches after narrowing (`AmbiguousResourceError`) - never
        guesses which one to remove.
        """
        client = _client(device_name)
        preview = guard.remove_static_dns(client, settings, name=name, record_type=record_type, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def clear_dns_cache(device_name: str, confirm: bool = False) -> dict[str, Any]:
        """Flush the device's DNS resolver cache (`/ip/dns/cache/flush`) -
        no arguments, clears every cached DNS answer at once.

        Benign (only cached answers are cleared - repopulated on the next
        resolution - never device configuration), but still guarded/
        confirm-gated like every other write tool here.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview the current cached-entry count without changing
        anything; call again with confirm=True to actually flush it.
        """
        client = _client(device_name)
        preview = guard.clear_dns_cache(client, settings, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_dhcp_lease(
        device_name: str, address: str | None = None, mac_address: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a DHCP lease (`/ip/dhcp-server/lease remove`) by `address`
        or `mac_address` - typically to force a client to renew its IP. At
        least one of `address`/`mac_address` must be given and must match an
        existing lease (`mac_address` is tried first if both are given).

        Removes EITHER a dynamic or a static lease. **If the resolved lease
        is STATIC** (`dynamic=false` - i.e. it was pinned with
        `add_static_dhcp_lease`), the returned preview's `warning` field is
        non-null: removing it deletes the pinned IP<->MAC mapping itself,
        not just a renewable cache entry. Always check `warning` before
        calling again with `confirm=true`. No warning for a dynamic lease -
        that is this tool's ordinary use case.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview (including the `warning` field) without
        changing anything; call again with confirm=True to actually remove
        it. Errors clearly if nothing matches.
        """
        client = _client(device_name)
        preview = guard.remove_dhcp_lease(client, settings, address=address, mac_address=mac_address, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def wake_on_lan(device_name: str, mac_address: str, interface: str, confirm: bool = False) -> dict[str, Any]:
        """Send a Wake-on-LAN magic packet (`/tool/wol`) for `mac_address`,
        out `interface`.

        Benign - it never changes device configuration and targets no
        existing RouterOS row - but still guarded/confirm-gated like every
        other write tool here, so an LLM caller can't wake a machine "by
        accident". Does NOT verify `interface` exists on the device first;
        RouterOS itself rejects an unknown interface name at send time.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be sent without changing
        anything; call again with confirm=True to actually send it.
        """
        client = _client(device_name)
        preview = guard.wake_on_lan(client, settings, mac_address=mac_address, interface=interface, confirm=confirm)
        return asdict(preview)

    # --- v0.11: firewall rule toggle (by comment, never create) ---------

    @mcp.tool()
    @_safe
    def enable_firewall_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Enable an EXISTING firewall filter rule (`/ip/firewall/filter set
        disabled=no`), resolved by its `comment` - optionally narrowed by
        `chain` if more than one rule shares that comment.

        SAFE BY DESIGN: this NEVER creates a rule. Intended workflow: an
        admin creates a rule ahead of time on the device with a descriptive
        `comment` (e.g. `comment="Bloqueio_Ataque_X"`), reviews it once, and
        leaves it disabled; an LLM caller later enables it via this tool
        when it detects the condition the rule exists to guard against. If
        it goes wrong, the admin knows exactly which rule was toggled - the
        same one they already wrote and reviewed. See README's "Firewall
        rule toggle (by comment)" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview - the FULL matched rule, not
        just its `disabled` field, so you can confirm WHICH rule this is -
        without changing anything; call again with confirm=True to actually
        apply it. Errors clearly if no rule matches `comment` (narrowed by
        `chain`), or if more than one still does (`AmbiguousResourceError`)
        - never guesses which one to toggle.
        """
        client = _client(device_name)
        preview = guard.enable_firewall_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_firewall_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Disable an EXISTING firewall filter rule (`/ip/firewall/filter set
        disabled=yes`), resolved by its `comment` - optionally narrowed by
        `chain` if more than one rule shares that comment.

        Same "never creates a rule" guarantee and comment-based resolution
        as `enable_firewall_rule` - see its docstring and README's "Firewall
        rule toggle (by comment)" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        no rule matches `comment` (narrowed by `chain`), or if more than one
        still does (`AmbiguousResourceError`).
        """
        client = _client(device_name)
        preview = guard.disable_firewall_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    # --- v1.4: NAT & mangle rule toggle (by comment, never create) ------

    @mcp.tool()
    @_safe
    def enable_nat_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Enable an EXISTING firewall NAT rule (`/ip/firewall/nat set
        disabled=no`), resolved by its `comment` - optionally narrowed by
        `chain` (`srcnat`/`dstnat`) if more than one rule shares that
        comment.

        Same "never creates a rule" guarantee and comment-based resolution
        as `enable_firewall_rule` (see its docstring and README's "Firewall
        rule toggle (by comment)" section) - extended to /ip/firewall/nat.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview - the FULL matched rule, not
        just its `disabled` field - without changing anything; call again
        with confirm=True to actually apply it. Errors clearly if no rule
        matches `comment` (narrowed by `chain`), or if more than one still
        does (`AmbiguousResourceError`) - never guesses which one to toggle.
        """
        client = _client(device_name)
        preview = guard.enable_nat_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_nat_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Disable an EXISTING firewall NAT rule (`/ip/firewall/nat set
        disabled=yes`), resolved by its `comment` - optionally narrowed by
        `chain` (`srcnat`/`dstnat`).

        Same "never creates a rule" guarantee and comment-based resolution
        as `enable_nat_rule`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        no rule matches `comment` (narrowed by `chain`), or if more than one
        still does (`AmbiguousResourceError`).
        """
        client = _client(device_name)
        preview = guard.disable_nat_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def enable_mangle_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Enable an EXISTING firewall mangle rule (`/ip/firewall/mangle set
        disabled=no`), resolved by its `comment` - optionally narrowed by
        `chain` (e.g. `prerouting`/`postrouting`/`forward`/`input`/`output`)
        if more than one rule shares that comment.

        Same "never creates a rule" guarantee and comment-based resolution
        as `enable_firewall_rule` - extended to /ip/firewall/mangle.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview - the FULL matched rule, not
        just its `disabled` field - without changing anything; call again
        with confirm=True to actually apply it. Errors clearly if no rule
        matches `comment` (narrowed by `chain`), or if more than one still
        does (`AmbiguousResourceError`) - never guesses which one to toggle.
        """
        client = _client(device_name)
        preview = guard.enable_mangle_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_mangle_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Disable an EXISTING firewall mangle rule (`/ip/firewall/mangle set
        disabled=yes`), resolved by its `comment` - optionally narrowed by
        `chain`.

        Same "never creates a rule" guarantee and comment-based resolution
        as `enable_mangle_rule`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        no rule matches `comment` (narrowed by `chain`), or if more than one
        still does (`AmbiguousResourceError`).
        """
        client = _client(device_name)
        preview = guard.disable_mangle_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    # --- v0.13: WireGuard VPN management ---------------------------------

    @mcp.tool()
    @_safe
    def add_wireguard_interface(
        device_name: str, name: str, listen_port: int | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Create a WireGuard tunnel interface (`/interface/wireguard add`).

        RouterOS generates the interface's private-key internally - this
        tool never accepts (or returns) one. The `confirm=False` preview's
        `after` only describes what will be created (`name`, `listen-port`
        if given) - it does not invent a `public-key`, since RouterOS hasn't
        generated the key pair yet at preview time. The `confirm=True`
        applied result re-reads the created interface and reports its real
        `public-key`, with `private-key` always stripped. See README's
        "WireGuard management" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview without changing anything; call again with
        confirm=True to actually create it. Errors clearly if `name` already
        exists - never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_wireguard_interface(client, settings, name=name, listen_port=listen_port, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_wireguard_peer(
        device_name: str,
        interface: str,
        public_key: str,
        allowed_address: str,
        endpoint_address: str | None = None,
        endpoint_port: int | None = None,
        persistent_keepalive: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add a WireGuard peer (`/interface/wireguard/peers add`) to an
        existing tunnel `interface`.

        `public_key` is the REMOTE peer's own public key (base64, 44 chars).
        `allowed_address` is a comma-separated list of CIDR ranges routed
        through this peer (e.g. "10.0.0.2/32,10.0.0.3/32").
        `endpoint_address`/`endpoint_port` (the peer's reachable
        address/port, if any) and `persistent_keepalive` (a RouterOS
        duration, e.g. "25s") are optional.

        Does NOT accept a private-key or preshared-key parameter - the
        remote peer's own private key, and any preshared key, are entirely
        out of this tool's scope.

        `interface` must already exist - create it first with
        add_wireguard_interface; errors clearly if it doesn't. Refuses to
        add a duplicate peer (same `public_key` already registered on the
        same `interface`) - never creates a duplicate.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview without changing anything; call again with
        confirm=True to actually add it.
        """
        client = _client(device_name)
        preview = guard.add_wireguard_peer(
            client,
            settings,
            interface=interface,
            public_key=public_key,
            allowed_address=allowed_address,
            endpoint_address=endpoint_address,
            endpoint_port=endpoint_port,
            persistent_keepalive=persistent_keepalive,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_wireguard_peer(
        device_name: str,
        interface: str,
        public_key: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Remove a WireGuard peer (`/interface/wireguard/peers remove`)
        from `interface`, resolved by `public_key` or `comment` (`public_key`
        tried first if both are given). At least one of the two must be
        given.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview what would be removed without changing
        anything; call again with confirm=True to actually remove it.
        Errors clearly if nothing matches, or if more than one peer still
        matches (AmbiguousResourceError) - never guesses which one to
        remove.
        """
        client = _client(device_name)
        preview = guard.remove_wireguard_peer(
            client, settings, interface=interface, public_key=public_key, comment=comment, confirm=confirm
        )
        return asdict(preview)

    # --- v0.14: hotspot vouchers + backup --------------------------------

    @mcp.tool()
    @_safe
    def add_hotspot_user(
        device_name: str,
        name: str,
        password: str,
        profile: str | None = None,
        limit_uptime: str | None = None,
        limit_bytes_total: int | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a hotspot voucher user (`/ip/hotspot/user add`) for a
        visitor - `name`/`password` are the login credentials; `profile`
        (an existing hotspot user profile), `limit_uptime` (a RouterOS
        duration, e.g. "01:00:00"), and `limit_bytes_total` (a positive
        integer byte quota) are all optional.

        QR/VOUCHER: the result always also includes `username`, `password`
        (the plaintext voucher credentials - THIS IS THE POINT: the visitor
        needs them), and `qr_payload` - a plain STRING the caller renders as
        a QR code itself; this package deliberately does NOT generate a QR
        IMAGE (no extra imaging dependency). Format chosen for `qr_payload`:
        `"<username>:<password>"` - a plain, self-describing credential
        pair, NOT a login URL and NOT a `WIFI:` payload. Two alternatives
        were considered and rejected: a login URL
        (`http://<hotspot>/login?username=..&password=..`) would need a
        reliably-known hotspot LAN address, which this package has no way to
        determine for an arbitrary device/deployment - and RouterOS's actual
        captive-portal login is normally a POST with additional
        session-specific tokens (`chap-id`/`chap-challenge`), so a bare GET
        URL with a plaintext password wouldn't even reliably work; a `WIFI:`
        payload is for auto-joining a WPA network, which is a different
        credential than a hotspot LOGIN (walled-garden HTTP auth) entirely.
        `username:password` makes no claim about network topology or login
        mechanics that could be wrong for a given deployment - a caller
        integrating with a specific captive portal can build its own login
        URL from these two fields plus its own known portal address.

        PASSWORD IN THE JOURNAL: unlike every secret this package has
        handled before (a device password, a WireGuard private-key), this
        tool's `password` is DELIBERATELY present in its result - but still
        never written to the audit journal. See `guard.add_hotspot_user`'s
        docstring for exactly how that asymmetry holds.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview (including `qr_payload`) without changing
        anything; call again with confirm=True to actually create it.
        Errors clearly (without creating anything) if `name` already exists
        on the device - it never creates a duplicate or resets an existing
        voucher's password.
        """
        client = _client(device_name)
        preview = guard.add_hotspot_user(
            client,
            settings,
            name=name,
            password=password,
            profile=profile,
            limit_uptime=limit_uptime,
            limit_bytes_total=limit_bytes_total,
            confirm=confirm,
        )
        result = asdict(preview)
        voucher_username = preview.after.get("name")
        voucher_password = preview.after.get("password")
        result["username"] = voucher_username
        result["password"] = voucher_password
        result["qr_payload"] = f"{voucher_username}:{voucher_password}"
        return result

    @mcp.tool()
    @_safe
    def create_backup(
        device_name: str, name: str, password: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Create a RouterOS system backup file (`/system/backup/save
        name=<name>`) - captures the device's full configuration into one
        binary `.backup` file on its own storage. Use `list_backups`
        afterward to confirm it landed and see its real size/creation-time.

        `password`, if given, is RouterOS's own backup-FILE encryption
        option (unrelated to any device/API credential) - forwarded to the
        device, but NEVER included in the returned preview, and never
        journaled. See `guard.create_backup`'s docstring for how that
        redaction is enforced.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of the file that would be created without
        changing anything; call again with confirm=True to actually create
        it. Errors clearly (without creating anything) if a `.backup` file
        matching `name` already exists on the device - it never silently
        overwrites one.
        """
        client = _client(device_name)
        preview = guard.create_backup(client, settings, name=name, password=password, confirm=confirm)
        return asdict(preview)

    # --- v1.2: VLAN management + firewall rule reorder -------------------

    @mcp.tool()
    @_safe
    def add_vlan(
        device_name: str,
        name: str,
        vlan_id: int,
        interface: str,
        mtu: int | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a VLAN interface (`/interface/vlan add`): `name` (the new
        RouterOS interface name, e.g. "vlan100"), `vlan_id` (1-4094, the
        IEEE 802.1Q tag), `interface` (the parent interface it rides on top
        of, e.g. "bridge1"/"ether2" - not verified to exist here; RouterOS
        itself rejects an unknown one at write time). `mtu`/`comment` are
        optional.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually create it. Errors clearly
        (without creating anything) if `name` already exists on the device -
        it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_vlan(
            client,
            settings,
            name=name,
            vlan_id=vlan_id,
            interface=interface,
            mtu=mtu,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_vlan(device_name: str, name: str, confirm: bool = False) -> dict[str, Any]:
        """Remove a VLAN interface (`/interface/vlan remove`) by `name`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually remove it. Errors clearly
        if no VLAN interface matches `name`.
        """
        client = _client(device_name)
        preview = guard.remove_vlan(client, settings, name=name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def move_firewall_rule(
        device_name: str,
        comment: str,
        chain: str | None = None,
        before_comment: str | None = None,
        position: int | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Reorder an EXISTING firewall filter rule (`/ip/firewall/filter
        move`), resolved by its `comment` - optionally narrowed by `chain`
        if more than one rule shares that comment, same resolution
        `enable_firewall_rule`/`disable_firewall_rule` use.

        SAFE BY DESIGN: this NEVER creates or otherwise edits a rule's
        fields - only its position in the chain's evaluation order changes.

        Exactly one of `before_comment` (move the rule to appear immediately
        before the EXISTING rule with this comment) or `position` (move the
        rule to this 0-based index among the OTHER rules - a value at or
        beyond the end of that list moves it to the very end) must be given.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (the rule's `comment`/`chain`
        plus its current vs. new position) without changing anything; call
        again with confirm=True to actually apply it. Errors clearly if no
        rule matches `comment` (narrowed by `chain`), if `before_comment` is
        given but matches no rule, or if either still matches more than one
        rule (`AmbiguousResourceError`) - never guesses.
        """
        client = _client(device_name)
        preview = guard.move_firewall_rule(
            client,
            settings,
            comment=comment,
            chain=chain,
            before_comment=before_comment,
            position=position,
            confirm=confirm,
        )
        return asdict(preview)

    # --- v1.3: PPP/PPPoE secrets ------------------------------------------

    @mcp.tool()
    @_safe
    def add_ppp_secret(
        device_name: str,
        name: str,
        password: str,
        service: str = "any",
        profile: str | None = None,
        remote_address: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a PPP/PPPoE secret (`/ppp/secret add`) - `name`/`password`
        are the dial-in login credentials for a PPPoE/PPTP/L2TP/OpenVPN/SSTP
        service. `service` (default `"any"`) restricts which PPP service the
        secret may authenticate for - one of "pppoe"/"pptp"/"l2tp"/"ovpn"/
        "sstp"/"any". `profile` (an existing `/ppp/profile` name, e.g. to
        assign an address pool or rate limit), `remote_address` (a literal
        IP handed to the client on connect), and `comment` are all optional.

        PASSWORD IN THE RESULT: like `add_hotspot_user`'s voucher password,
        this tool's `password` is DELIBERATELY present in its result (the
        caller supplied it and gets it echoed back as confirmation) - but
        still never written to the audit journal. See
        `guard.add_ppp_secret`'s docstring for exactly how that asymmetry
        holds.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview without changing anything; call again
        with confirm=True to actually create it. Errors clearly (without
        creating anything) if `name` already exists on the device - it
        never creates a duplicate or resets an existing secret's password.
        """
        client = _client(device_name)
        preview = guard.add_ppp_secret(
            client,
            settings,
            name=name,
            password=password,
            service=service,
            profile=profile,
            remote_address=remote_address,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_ppp_secret(device_name: str, name: str, confirm: bool = False) -> dict[str, Any]:
        """Remove a PPP/PPPoE secret (`/ppp/secret remove`) by `name`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually remove it. Errors clearly
        if no secret matches `name` (`ResourceNotFoundError`), or if more
        than one somehow does (`AmbiguousResourceError`) - never guesses
        which one to remove. **The returned preview's `before` never
        includes the secret's `password`** - redacted before the preview is
        ever built (see `guard.remove_ppp_secret`'s docstring).
        """
        client = _client(device_name)
        preview = guard.remove_ppp_secret(client, settings, name=name, confirm=confirm)
        return asdict(preview)

    # --- v1.8: NTP client servers --------------------------------------

    @mcp.tool()
    @_safe
    def set_ntp_servers(device_name: str, servers: list[str], confirm: bool = False) -> dict[str, Any]:
        """Set the NTP server(s) a device syncs its clock against
        (`/system/ntp/client`). `servers` is a list of one or more IPv4/
        IPv6 addresses or hostnames.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Never
        enables/disables the NTP client itself - only the server list
        changes; the returned preview's `warning` says so if the client is
        currently disabled.

        Works against either RouterOS generation, detected by reading
        `/system/ntp/client` first: ROS7 writes the full `servers` list;
        ROS6 has no such list - `servers[0]`/`servers[1]` map onto its fixed
        `primary-ntp`/`secondary-ntp` slots instead (extras beyond two are
        dropped, called out in `warning`). A hostname destined for one of
        those two ROS6 slots is folded into `server-dns-names` if the device
        has that field, otherwise it is not applied - `warning` says so. See
        `guard.set_ntp_servers`'s docstring for the full detection/mapping
        rules.
        """
        client = _client(device_name)
        preview = guard.set_ntp_servers(client, settings, servers=servers, confirm=confirm)
        return asdict(preview)

    # --- v1.9: IPv6 read parity ------------------------------------------
    # Tier 3's largest single coverage gap (see ROADMAP.md "IPv6 parity"):
    # five read tools mirroring the equivalent /ip/* menu field-for-field,
    # READ-ONLY only - IPv6 writes (firewall toggle, route add/remove) are
    # left for a later release. TRAP: the whole /ipv6/* subtree raises if
    # the `ipv6` package is disabled on the device (a common, fully
    # supported state - not every deployment runs IPv6), so every tool
    # below uses the same skip-if-missing pattern already established for
    # other optional features (wireguard_peers, ppp_active, bgp_sessions,
    # ospf_neighbors, ...): catch DeviceCommandError and return [] rather
    # than propagate.

    @mcp.tool()
    @_safe
    def ipv6_addresses(device_name: str) -> list[dict[str, Any]]:
        """List IPv6 addresses configured on a device (`/ipv6/address`):
        address, interface, advertise, disabled, dynamic, plus whatever
        other fields RouterOS's own reply carries (e.g. its global/
        link-local classification). Mirrors `ip_addresses` for IPv6.

        Returns an empty list (never an error) if the `ipv6` package is
        disabled on the device - see "IPv6 read parity (v1.9)" in the
        README.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ipv6", "address"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def ipv6_routes(device_name: str, limit: int | None = None) -> list[dict[str, Any]]:
        """List the IPv6 routing table of a device (`/ipv6/route`):
        dst-address, gateway, distance, active, dynamic, disabled. Mirrors
        `ip_routes` for IPv6, including its optional `limit` (capped at
        500, same MAX_ROUTE_LIMIT); omit it to get the full table.

        Returns an empty list (never an error) if the `ipv6` package is
        disabled on the device - see "IPv6 read parity (v1.9)" in the
        README.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("ipv6", "route"))
        except DeviceCommandError:
            return []
        if limit is not None:
            capped_limit = validate_positive_limit(limit, MAX_ROUTE_LIMIT, "limit")
            rows = rows[:capped_limit]
        return rows

    @mcp.tool()
    @_safe
    def ipv6_firewall_filter(device_name: str) -> list[dict[str, Any]]:
        """List IPv6 firewall filter rules (`/ipv6/firewall/filter`): chain,
        action, etc. Mirrors `firewall_filter` for IPv6. Read-only - does
        not add/modify/remove rules.

        Returns an empty list (never an error) if the `ipv6` package is
        disabled on the device - see "IPv6 read parity (v1.9)" in the
        README.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ipv6", "firewall", "filter"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def ipv6_neighbors(device_name: str) -> list[dict[str, Any]]:
        """List the IPv6 neighbor discovery table (`/ipv6/neighbor`):
        address, mac-address, interface, status, dynamic. IPv6's neighbor-
        discovery equivalent of `arp_table`'s IPv4 ARP table.

        Returns an empty list (never an error) if the `ipv6` package is
        disabled on the device - see "IPv6 read parity (v1.9)" in the
        README.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ipv6", "neighbor"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def ipv6_firewall_address_lists(device_name: str) -> list[dict[str, Any]]:
        """List IPv6 firewall address-list entries
        (`/ipv6/firewall/address-list`): list, address, dynamic, disabled.
        Mirrors `address_lists` for IPv6.

        Returns an empty list (never an error) if the `ipv6` package is
        disabled on the device - see "IPv6 read parity (v1.9)" in the
        README.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ipv6", "firewall", "address-list"))
        except DeviceCommandError:
            return []

    # --- v1.10: IPv6 write parity -----------------------------------------
    # Closes the follow-up v1.9 explicitly left open: six guarded write
    # tools mirroring their IPv4 counterparts field-for-field on the
    # equivalent /ipv6/* path - enable_ipv6_firewall_rule/
    # disable_ipv6_firewall_rule (mirrors enable_firewall_rule/
    # disable_firewall_rule), add_ipv6_route/remove_ipv6_route (mirrors
    # add_route/remove_route, INCLUDING remove_ipv6_route's refusal to
    # remove a dynamic route), add_to_ipv6_address_list/
    # remove_from_ipv6_address_list (mirrors add_to_address_list/
    # remove_from_address_list). See guard.py's ALLOWLIST entries for each.
    #
    # UNLIKE the v1.9 reads above, none of these six catch DeviceCommandError
    # - if the `ipv6` package is disabled on the device, the resolution step
    # (reading existing rows to find the target rule/route/entry) raises
    # DeviceCommandError, and it propagates as a normal write-tool error
    # (still one clean audited entry - see guard._audited) instead of being
    # silently swallowed into an empty-list-shaped success. Returning `[]`
    # (the read tools' skip-if-missing pattern) would be actively misleading
    # here: a write tool has no "empty" success shape to fall back to, and
    # silently reporting nothing changed would look identical to "there was
    # nothing to toggle/remove" rather than "the ipv6 package is off - fix
    # that first". See "IPv6 write parity (v1.10)" in the README.

    @mcp.tool()
    @_safe
    def enable_ipv6_firewall_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Enable an EXISTING IPv6 firewall filter rule (`/ipv6/firewall/filter
        set disabled=no`), resolved by its `comment` - optionally narrowed by
        `chain` if more than one rule shares that comment. Mirrors
        `enable_firewall_rule` on the IPv6 menu - see its docstring and
        README's "Firewall rule toggle (by comment)" section for the full
        admin-creates/LLM-enables workflow.

        SAFE BY DESIGN: this NEVER creates a rule.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview - the FULL matched rule, not
        just its `disabled` field - without changing anything; call again
        with confirm=True to actually apply it. Errors clearly if no rule
        matches `comment` (narrowed by `chain`), or if more than one still
        does (`AmbiguousResourceError`) - never guesses which one to
        toggle. Also errors clearly (does not return an empty result) if
        the `ipv6` package is disabled on the device - see "IPv6 write
        parity (v1.10)" in the README.
        """
        client = _client(device_name)
        preview = guard.enable_ipv6_firewall_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_ipv6_firewall_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Disable an EXISTING IPv6 firewall filter rule (`/ipv6/firewall/
        filter set disabled=yes`), resolved by its `comment` - optionally
        narrowed by `chain` if more than one rule shares that comment.
        Mirrors `disable_firewall_rule` on the IPv6 menu.

        Same "never creates a rule" guarantee and comment-based resolution
        as `enable_ipv6_firewall_rule`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        no rule matches `comment` (narrowed by `chain`), or if more than one
        still does (`AmbiguousResourceError`). Also errors clearly if the
        `ipv6` package is disabled on the device.
        """
        client = _client(device_name)
        preview = guard.disable_ipv6_firewall_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_ipv6_route(
        device_name: str,
        dst_address: str,
        gateway: str,
        distance: int | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add a static IPv6 route (`/ipv6/route add`): `dst_address` and
        `gateway` are required, `distance` (failover priority - lower wins)
        and `comment` are optional. Mirrors `add_route` on the IPv6 menu -
        never refuses a duplicate `dst_address`, multiple routes sharing one
        is the normal failover shape.

        `dst_address`/`gateway` must be IPv6 (an IPv4 address/subnet in
        either is rejected before the device is ever touched - `/ipv6/route`
        has no IPv4 concept).

        RISK: adding/overriding the default route (`dst_address="::/0"`)
        redirects all outbound IPv6 traffic through the new gateway. The
        returned preview's `warning` field is non-null whenever this is the
        case - always check it before calling again with `confirm=true`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the `warning`
        field) without changing anything; call again with confirm=True to
        actually apply it. Also errors clearly if the `ipv6` package is
        disabled on the device.
        """
        client = _client(device_name)
        preview = guard.add_ipv6_route(
            client,
            settings,
            dst_address=dst_address,
            gateway=gateway,
            distance=distance,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_ipv6_route(
        device_name: str,
        dst_address: str,
        gateway: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Remove a static IPv6 route (`/ipv6/route remove`), resolved by
        `dst_address` - narrowed by `gateway` when more than one route
        shares that `dst_address`. Mirrors `remove_route` on the IPv6 menu,
        INCLUDING its most important safety property. Errors clearly if
        nothing matches, or if the match is still ambiguous after
        narrowing.

        `dst_address`/`gateway` must be IPv6 (an IPv4 address/subnet in
        either is rejected before the device is ever touched).

        SAFETY: refuses outright (raises an error, does not remove
        anything) if the resolved route is dynamic (`dynamic=true` - a
        connected/DHCP/router-advertisement-installed route). Only static,
        admin-created IPv6 routes can be removed by this tool.

        RISK: removing the default route (`dst_address="::/0"`) cuts all
        outbound IPv6 traffic that relies on this gateway. The returned
        preview's `warning` field is non-null whenever this is the case
        (not blocking - removing a static default route is legitimate).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the `warning`
        field) without changing anything; call again with confirm=True to
        actually apply it. Also errors clearly if the `ipv6` package is
        disabled on the device.
        """
        client = _client(device_name)
        preview = guard.remove_ipv6_route(client, settings, dst_address=dst_address, gateway=gateway, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_to_ipv6_address_list(
        device_name: str,
        list_name: str,
        address: str,
        comment: str | None = None,
        timeout: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add `address` (an IPv6 address or subnet) to a named IPv6
        firewall address-list (`/ipv6/firewall/address-list`). Mirrors
        `add_to_address_list` on the IPv6 menu.

        IMPORTANT: this only manages the *list* - it does NOT create or
        modify any firewall rule. Adding an address here only blocks or
        allows traffic if an `/ipv6/firewall/filter` rule on the device
        already references `list_name`. See README's "Blocking/allowing a
        client via address lists" section.

        `address` must be IPv6 (an IPv4 address/subnet is rejected before
        the device is ever touched).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if this exact `list_name`+`address`
        pair already exists on the device - it never creates a duplicate.
        Also errors clearly if the `ipv6` package is disabled on the
        device.
        """
        client = _client(device_name)
        preview = guard.add_to_ipv6_address_list(
            client,
            settings,
            list_name=list_name,
            address=address,
            comment=comment,
            timeout=timeout,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_from_ipv6_address_list(
        device_name: str, list_name: str, address: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove the entry matching `list_name`+`address` from an IPv6
        firewall address-list (`/ipv6/firewall/address-list`). Mirrors
        `remove_from_address_list` on the IPv6 menu.

        `address` must be IPv6 (an IPv4 address/subnet is rejected before
        the device is ever touched).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it. Errors clearly if no entry
        matches `list_name`+`address`. Also errors clearly if the `ipv6`
        package is disabled on the device.
        """
        client = _client(device_name)
        preview = guard.remove_from_ipv6_address_list(
            client, settings, list_name=list_name, address=address, confirm=confirm
        )
        return asdict(preview)

    # --- v1.11: wireless RF tuning + the dead-man primitive -----------------
    #
    # set_wireless_channel/set_wireless_tx_power are LOCKOUT-RISK writes (see
    # guard.py's module note above their ALLOWLIST entries) - by default they
    # arm a dead-man (guard.arm_dead_man) before applying, so a bad channel/
    # power on a management-path PtP link self-heals instead of stranding the
    # device. arm_dead_man/cancel_dead_man are also exposed standalone here,
    # since the primitive is reusable for ANY future risky write, not just
    # these two - see README's "Dead-man / lockout-proof writes" section.

    @mcp.tool()
    @_safe
    def set_wireless_channel(
        device_name: str,
        interface_name: str,
        frequency: int,
        channel_width: str | None = None,
        arm_deadman: bool = True,
        deadman_minutes: int = 3,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Set a `/interface/wireless` interface's `frequency` (MHz) and
        optionally `channel_width`.

        LOCKOUT-RISK on a PtP link that is itself the management path to the
        far end: a bad frequency (or a DFS Channel Availability Check stall)
        can cut the only route back to the device. By default
        (`arm_deadman=True`), a `confirm=True` apply FIRST arms a dead-man
        (`arm_dead_man`) that restores the interface's prior frequency/
        channel-width after `deadman_minutes` (1-60, default 3) unless
        cancelled - call `cancel_dead_man(device_name, dead_man["name"])`
        once the new channel is confirmed good. Set `arm_deadman=False` only
        for an interface known NOT to be a management path.

        The returned preview's `warning` ALWAYS reports whether `frequency`
        needs a DFS Channel Availability Check under this interface's
        CURRENT `frequency-mode` (superchannel: none, instant; otherwise
        ~60s in the general DFS range 5250-5725MHz, ~600s in the
        5600-5650MHz weather-radar sub-band - verified against real
        hardware). See docs/api-notes-wireless-rf.md.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the DFS warning,
        without arming anything) without changing anything; call again with
        confirm=True to actually apply it. Errors if `interface_name`
        doesn't exist on `/interface/wireless` - never creates one. This
        targets `/interface/wireless` only - see guard.py's module note for
        why ROS7's newer `/interface/wifi` package is out of scope this
        round.
        """
        client = _client(device_name)
        preview = guard.set_wireless_channel(
            client,
            settings,
            interface_name=interface_name,
            frequency=frequency,
            channel_width=channel_width,
            arm_deadman=arm_deadman,
            deadman_minutes=deadman_minutes,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_wireless_tx_power(
        device_name: str,
        interface_name: str,
        tx_power: int,
        arm_deadman: bool = True,
        deadman_minutes: int = 3,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Set a `/interface/wireless` interface's `tx_power` (dBm),
        forcing `tx-power-mode=all-rates-fixed`.

        CONFIRMED AGAINST REAL HARDWARE TODAY: on a short link, the default
        (maximum) tx-power SATURATES the receiver and PRODUCES A WORSE CCQ
        than a lower power (measured: -27dBm/CCQ 34 at default, -47dBm/CCQ
        94 at ~8dBm). There is no single "right" power for every link - use
        `get_wireless_link_quality` before/after to judge the effect.

        LOCKOUT-RISK for the same reason as `set_wireless_channel` - same
        `arm_deadman`/`deadman_minutes` dead-man behavior (default armed),
        restoring BOTH `tx-power-mode` and `tx-power` on revert.

        The returned preview's `warning` always notes that CCQ/rate briefly
        re-adapt (a few seconds) right after a power change - expected, not
        a failure.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors if
        `interface_name` doesn't exist on `/interface/wireless` - never
        creates one.
        """
        client = _client(device_name)
        preview = guard.set_wireless_tx_power(
            client,
            settings,
            interface_name=interface_name,
            tx_power=tx_power,
            arm_deadman=arm_deadman,
            deadman_minutes=deadman_minutes,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_wireless_tuning(
        device_name: str,
        interface_name: str,
        adaptive_noise_immunity: str | None = None,
        distance: int | str | None = None,
        arm_deadman: bool = True,
        deadman_minutes: int = 3,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Set a `/interface/wireless` interface's `adaptive_noise_immunity`
        ("none"/"client-mode"/"ap-and-client-mode") and/or `distance`
        ("dynamic"/"indoors"/an integer number of km). At least one must be
        given.

        `adaptive_noise_immunity` alone is reception-only tuning - CONFIRMED
        SAFE against real hardware today (does not drop an already-
        associated link), never arms a dead-man. CONFIRMED TODAY: with good
        signal but poor CCQ (interference, not distance),
        `adaptive_noise_immunity="ap-and-client-mode"` measurably helped.

        A NUMERIC `distance` (unlike the named "dynamic"/"indoors" modes)
        directly changes the ACK-timeout/TDMA timing - LOCKOUT-RISK,
        CONFIRMED LIVE it can silently drop an already-associated link on a
        mismatch (e.g. too short for the real link length). By default
        (`arm_deadman=True`), a numeric `distance` arms a dead-man
        (`arm_dead_man`) that restores the interface's prior `distance`
        after `deadman_minutes` (1-60, default 3) unless cancelled - same
        mechanism as `set_wireless_channel`/`set_wireless_tx_power`. For a
        long verified PtP link, an explicit `distance` (e.g. 9 for ~9km)
        gave a better ACK timeout than leaving it on "dynamic".

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the LOCKOUT-RISK
        warning for a numeric distance, without arming anything) without
        changing anything; call again with confirm=True to actually apply
        it. Errors if `interface_name` doesn't exist on `/interface/wireless`
        - never creates one.
        """
        client = _client(device_name)
        preview = guard.set_wireless_tuning(
            client,
            settings,
            interface_name=interface_name,
            adaptive_noise_immunity=adaptive_noise_immunity,
            distance=distance,
            arm_deadman=arm_deadman,
            deadman_minutes=deadman_minutes,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def arm_dead_man(
        device_name: str, revert_commands: list[str], minutes: int = 3, confirm: bool = False
    ) -> dict[str, Any]:
        """Arm a local, self-removing RouterOS scheduler on `device_name`
        that reverts a change after `minutes` (1-60) unless cancelled first
        (`cancel_dead_man`) - the anti-lockout primitive behind every
        LOCKOUT-RISK write in this package (`set_wireless_channel`/
        `set_wireless_tx_power` use it automatically by default). See
        README's "Dead-man / lockout-proof writes" section for the full
        design and the real-hardware incident that validated it.

        NOT wireless-specific: `revert_commands` is any non-empty list (max
        10 items) of RouterOS script statements that restore a known-good
        prior state - a route, a bridge port, a firewall rule, anything -
        run in order when the dead-man fires, after logging a warning
        (visible in `logs`/`security_events`) and before the scheduler
        removes itself. Build each command from state you already read from
        the device, not free-form text.

        The returned preview's `after["name"]` (also `after` more broadly)
        is the exact scheduler that would be armed (or was armed, if
        `confirm=True`) - pass that `name` to `cancel_dead_man` once the
        change it guards is confirmed good.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview the exact scheduler that would be armed without
        touching the device; call again with confirm=True to actually arm
        it.
        """
        client = _client(device_name)
        preview = guard.arm_dead_man(
            client, settings, revert_commands=revert_commands, minutes=minutes, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def cancel_dead_man(device_name: str, name: str, confirm: bool = False) -> dict[str, Any]:
        """Cancel a dead-man scheduler armed by `arm_dead_man` (or
        automatically by `set_wireless_channel`/`set_wireless_tx_power`),
        once the change it guards is confirmed good - removes it from
        `/system/scheduler` before it can fire and revert.

        `name` MUST be the exact "deadman-<hex>" handle `arm_dead_man`
        returned (`after["name"]`, or a wireless write's `dead_man["name"]`)
        - by construction this can never target an unrelated scheduler
        entry (e.g. an admin's own "backup-daily" task).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview what would be cancelled; call again with
        confirm=True to actually cancel it. Errors clearly if `name` doesn't
        match an armed scheduler - which can mean it already fired and
        self-removed (it wasn't cancelled in time), or was already
        cancelled.
        """
        client = _client(device_name)
        preview = guard.cancel_dead_man(client, settings, name=name, confirm=confirm)
        return asdict(preview)

    return mcp


def _resolve_log_level(raw: str | None) -> str:
    """Validate MIKROTIK_LOG_LEVEL against Python logging's level names (E4).

    An invalid value used to be passed straight to logging.basicConfig(),
    which raises ValueError and crashes the server before it even starts.
    Falls back to INFO (with a warning) instead.
    """
    level = (raw or _DEFAULT_LOG_LEVEL).strip().upper()
    if level not in _VALID_LOG_LEVELS:
        logger.warning(
            "Invalid MIKROTIK_LOG_LEVEL %r; falling back to %s. Valid values: %s",
            raw,
            _DEFAULT_LOG_LEVEL,
            ", ".join(sorted(_VALID_LOG_LEVELS)),
        )
        return _DEFAULT_LOG_LEVEL
    return level


def main() -> None:  # pragma: no cover - process entrypoint; server.run()
    # blocks on stdio for the life of the process, so this is exercised by
    # actually running `mcp-mikrotik`/`python -m mcp_mikrotik.server`, not
    # by the test suite. build_server() (everything up to the blocking
    # run() call) is exactly what tests/test_server.py exercises instead.
    logging.basicConfig(level=_resolve_log_level(os.environ.get("MIKROTIK_LOG_LEVEL")))
    server = build_server()
    server.run()


if __name__ == "__main__":  # pragma: no cover - see main() above
    main()

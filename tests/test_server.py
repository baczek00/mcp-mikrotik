"""Server-level smoke tests: tool registration, and each tool's happy/error
paths driven through FastMCP's own call_tool (not by calling the plain
Python functions directly), against fake devices only.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest
from librouteros.exceptions import LibRouterosError
from mcp.server.fastmcp.exceptions import ToolError

from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import DeviceCommandError
from mcp_mikrotik.server import _resolve_log_level
from mcp_mikrotik.server import build_server as _build_server

from .fakes import FakeConnection, FakePath, RaisingConnection, TransportErrorConnection

EXPECTED_TOOLS = {
    "list_devices",
    "system_info",
    "interfaces",
    "list_vlans",
    "ip_addresses",
    "ip_routes",
    "neighbors",
    "dhcp_leases",
    "simple_queues",
    "address_lists",
    "firewall_nat",
    "scheduler",
    "ip_pools",
    "wireless_registrations",
    "wireguard_peers",
    "wireguard_interfaces",
    "ppp_active",
    "ppp_secrets",
    "ipsec_active_peers",
    "bgp_sessions",
    "ospf_neighbors",
    "netwatch",
    "dns_cache",
    "firewall_filter",
    "system_health",
    "logs",
    "ping",
    "traceroute",
    "arp_table",
    "bridge_hosts",
    "interface_traffic",
    "poe_status",
    "lte_status",
    "lte_interfaces",
    "containers",
    "container_config",
    "usb_devices",
    "interface_monitor",
    "dhcp_servers",
    "dhcp_networks",
    "bridge_ports",
    "bridge_vlans",
    "list_write_operations",
    "set_identity",
    "enable_interface",
    "disable_interface",
    "set_wifi_ssid",
    "set_client_bandwidth",
    "add_static_dhcp_lease",
    "remove_simple_queue",
    "add_to_address_list",
    "remove_from_address_list",
    "set_poe_out",
    "start_container",
    "stop_container",
    "set_route_distance",
    "enable_route",
    "disable_route",
    "add_route",
    "remove_route",
    "add_netwatch",
    "remove_netwatch",
    "add_static_dns",
    "remove_static_dns",
    "clear_dns_cache",
    "remove_dhcp_lease",
    "wake_on_lan",
    "connection_tracking",
    "enable_firewall_rule",
    "disable_firewall_rule",
    "security_audit",
    "security_events",
    "add_wireguard_interface",
    "add_wireguard_peer",
    "remove_wireguard_peer",
    "hotspot_active",
    "torch",
    "list_backups",
    "add_hotspot_user",
    "create_backup",
    "add_vlan",
    "remove_vlan",
    "move_firewall_rule",
    "add_ppp_secret",
    "remove_ppp_secret",
    "firewall_mangle",
    "enable_nat_rule",
    "disable_nat_rule",
    "enable_mangle_rule",
    "disable_mangle_rule",
    "certificates",
    "users",
    "user_active",
    "radius",
    "ntp_client",
    "system_clock",
    "set_ntp_servers",
    "ipv6_addresses",
    "ipv6_routes",
    "ipv6_firewall_filter",
    "ipv6_neighbors",
    "ipv6_firewall_address_lists",
    "enable_ipv6_firewall_rule",
    "disable_ipv6_firewall_rule",
    "add_ipv6_route",
    "remove_ipv6_route",
    "add_to_ipv6_address_list",
    "remove_from_ipv6_address_list",
    "get_wireless_link_quality",
    "set_wireless_channel",
    "set_wireless_tx_power",
    "set_wireless_tuning",
    "arm_dead_man",
    "cancel_dead_man",
}


def build_server(settings: Settings, client_factory):
    """Upstream assertions intentionally exercise explicit raw-address opt-out.

    Default-on privacy and round-trips are covered in test_privacy.py.
    """
    return _build_server(replace(settings, anonymize_addresses=False), client_factory)


def _factory(fake_connection: FakeConnection):
    def factory(settings: Settings, device_name: str) -> MikrotikClient:
        device = settings.get_device(device_name)
        return MikrotikClient(device, connection=fake_connection)

    return factory


@pytest.mark.asyncio
async def test_all_expected_tools_are_registered(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == EXPECTED_TOOLS


@pytest.mark.asyncio
async def test_lifespan_closes_every_pooled_client_on_shutdown(settings: Settings, fake_connection: FakeConnection):
    """build_server's lifespan hook must close every pooled MikrotikClient
    (N2+N3 - see client.ClientPool's docstring) when the MCP session ends,
    not leak sockets until GC. Drives the actual FastMCP lifespan protocol
    (not just ClientPool.close_all() directly) to prove the hook is wired
    up, not just that the method it calls works in isolation."""
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))

    # Populate the pool with one client by making a normal tool call first.
    await mcp.call_tool("system_info", {"device_name": "core-switch"})
    assert fake_connection.closed is False

    async with mcp._mcp_server.lifespan(mcp._mcp_server):
        pass

    assert fake_connection.closed is True


@pytest.mark.asyncio
async def test_list_devices_never_exposes_password(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    _content, result = await mcp.call_tool("list_devices", {})
    assert "password" not in result["result"][0]
    assert "s3cret" not in str(result)


@pytest.mark.asyncio
async def test_system_info_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("system_info", {"device_name": "core-switch"})
    assert result["identity"] == {"name": "MikroTik"}
    assert result["resource"]["board-name"] == "hAP ac2"


@pytest.mark.asyncio
async def test_interfaces_filters_disabled_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("interfaces", {"device_name": "core-switch"})
    names = {row["name"] for row in result["result"]}
    assert names == {"ether1"}

    _content, result_all = await mcp.call_tool("interfaces", {"device_name": "core-switch", "include_disabled": True})
    names_all = {row["name"] for row in result_all["result"]}
    assert names_all == {"ether1", "ether2"}


@pytest.mark.asyncio
async def test_ip_addresses_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ip_addresses", {"device_name": "core-switch"})
    assert result["result"][0]["address"] == "10.0.0.1/24"


@pytest.mark.asyncio
async def test_neighbors_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("neighbors", {"device_name": "core-switch"})
    assert result["result"][0]["identity"] == "ap-1"


@pytest.mark.asyncio
async def test_dhcp_leases_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("dhcp_leases", {"device_name": "core-switch"})
    assert result["result"][0]["host-name"] == "laptop-1"


@pytest.mark.asyncio
async def test_simple_queues_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("simple_queues", {"device_name": "core-switch"})
    assert result["result"][0]["target"] == "10.0.0.50/32"
    assert result["result"][0]["max-limit"] == "10M/5M"


@pytest.mark.asyncio
async def test_address_lists_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("address_lists", {"device_name": "core-switch"})
    assert result["result"][0]["list"] == "blocked-clients"
    assert result["result"][0]["address"] == "10.0.0.60"


@pytest.mark.asyncio
async def test_firewall_nat_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("firewall_nat", {"device_name": "core-switch"})
    assert result["result"][0]["chain"] == "srcnat"
    assert result["result"][0]["action"] == "masquerade"


@pytest.mark.asyncio
async def test_scheduler_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("scheduler", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "backup-daily"


@pytest.mark.asyncio
async def test_ip_pools_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ip_pools", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "dhcp-pool"
    assert result["result"][0]["ranges"] == "10.0.0.100-10.0.0.200"


@pytest.mark.asyncio
async def test_dns_cache_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("dns_cache", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "example.com"


@pytest.mark.asyncio
async def test_firewall_filter_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("firewall_filter", {"device_name": "core-switch"})
    assert result["result"][0]["chain"] == "input"


@pytest.mark.asyncio
async def test_firewall_mangle_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("firewall_mangle", {"device_name": "core-switch"})
    assert result["result"][0]["chain"] == "forward"
    assert result["result"][0]["action"] == "mark-packet"
    assert result["result"][0]["comment"] == "mark-voip"


@pytest.mark.asyncio
async def test_firewall_mangle_tolerates_rows_missing_common_fields(settings: Settings):
    """A mangle rule's fields vary a lot by action - e.g. a `mark-routing`
    rule has no `new-packet-mark`, an unlabeled row may have no `comment` at
    all. firewall_mangle must return whatever RouterOS sent, never raise
    (e.g. via a bare `row["comment"]` lookup) just because a common-ish
    field is absent from one particular row."""
    fake = FakeConnection(
        data={
            ("ip", "firewall", "mangle"): [
                {".id": "*1", "chain": "prerouting", "action": "mark-routing"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("firewall_mangle", {"device_name": "core-switch"})
    assert result["result"] == [{".id": "*1", "chain": "prerouting", "action": "mark-routing"}]
    assert "comment" not in result["result"][0]
    assert "disabled" not in result["result"][0]


@pytest.mark.asyncio
async def test_system_health_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("system_health", {"device_name": "core-switch"})
    names = {row["name"] for row in result["result"]}
    assert names == {"voltage", "temperature"}


@pytest.mark.asyncio
async def test_system_health_returns_empty_when_unsupported(settings: Settings):
    fake = FakeConnection(raise_for={("system", "health"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("system_health", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_wireless_registrations_ros7_happy_path(settings: Settings):
    fake = FakeConnection(
        data={
            ("interface", "wifi", "registration-table"): [
                {"mac-address": "AA:BB:CC:DD:EE:01", "signal-strength": "-55dBm", "interface": "wifi1", "uptime": "1h"}
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireless_registrations", {"device_name": "core-switch"})
    assert result["result"][0]["interface"] == "wifi1"


@pytest.mark.asyncio
async def test_wireless_registrations_falls_back_to_ros6(settings: Settings):
    fake = FakeConnection(
        raise_for={("interface", "wifi", "registration-table"): LibRouterosError("no such command")},
        data={
            ("interface", "wireless", "registration-table"): [
                {"mac-address": "AA:BB:CC:DD:EE:02", "signal-strength": "-60", "interface": "wlan1", "uptime": "2h"}
            ]
        },
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireless_registrations", {"device_name": "core-switch"})
    assert result["result"][0]["interface"] == "wlan1"


@pytest.mark.asyncio
async def test_wireless_registrations_returns_empty_when_no_radio(settings: Settings):
    fake = FakeConnection(
        raise_for={
            ("interface", "wifi", "registration-table"): LibRouterosError("no such command"),
            ("interface", "wireless", "registration-table"): LibRouterosError("no such command"),
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireless_registrations", {"device_name": "core-switch"})
    assert result["result"] == []


# --- get_wireless_link_quality (v1.11) ---------------------------------------


def _link_quality_fake() -> FakeConnection:
    return FakeConnection(
        raise_for={("interface", "wifi", "registration-table"): LibRouterosError("no such command")},
        data={
            ("interface", "wireless", "registration-table"): [
                {
                    "interface": "wlan1",
                    "mac-address": "AA:BB:CC:DD:EE:90",
                    "signal-strength": "-47",
                    "signal-to-noise": "45",
                    "tx-ccq": "94",
                    "rx-ccq": "90",
                    "tx-rate": "300Mbps",
                    "rx-rate": "300Mbps",
                    "distance": "8800",
                    "uptime": "2d3h",
                },
                {
                    "interface": "wlan2",
                    "mac-address": "AA:BB:CC:DD:EE:91",
                    "signal-strength": "-70",
                    "uptime": "5m",
                },
            ]
        },
    )


@pytest.mark.asyncio
async def test_get_wireless_link_quality_normalizes_ccq_snr_rate_distance(settings: Settings):
    fake = _link_quality_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("get_wireless_link_quality", {"device_name": "core-switch"})
    rows = result["result"]
    assert len(rows) == 2
    wlan1 = next(row for row in rows if row["interface"] == "wlan1")
    assert wlan1 == {
        "interface": "wlan1",
        "mac_address": "AA:BB:CC:DD:EE:90",
        "signal_strength": -47,
        "signal_to_noise": 45,
        "tx_ccq": 94,
        "rx_ccq": 90,
        "tx_rate": "300Mbps",
        "rx_rate": "300Mbps",
        "distance": "8800",
        "uptime": "2d3h",
    }


@pytest.mark.asyncio
async def test_get_wireless_link_quality_omits_fields_absent_on_this_generation(settings: Settings):
    """ROS7's newer /interface/wifi registration-table doesn't publish
    signal-to-noise/tx-ccq/rx-ccq/distance at all - normalized fields must
    come back None, never fabricated."""
    fake = _link_quality_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("get_wireless_link_quality", {"device_name": "core-switch"})
    wlan2 = next(row for row in result["result"] if row["interface"] == "wlan2")
    assert wlan2["signal_to_noise"] is None
    assert wlan2["tx_ccq"] is None
    assert wlan2["rx_ccq"] is None
    assert wlan2["distance"] is None
    assert wlan2["signal_strength"] == -70


@pytest.mark.asyncio
async def test_get_wireless_link_quality_filters_by_interface(settings: Settings):
    fake = _link_quality_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool(
        "get_wireless_link_quality", {"device_name": "core-switch", "interface": "wlan1"}
    )
    assert {row["interface"] for row in result["result"]} == {"wlan1"}


@pytest.mark.asyncio
async def test_get_wireless_link_quality_returns_empty_when_no_radio(settings: Settings):
    fake = FakeConnection(
        raise_for={
            ("interface", "wifi", "registration-table"): LibRouterosError("no such command"),
            ("interface", "wireless", "registration-table"): LibRouterosError("no such command"),
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("get_wireless_link_quality", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_get_wireless_link_quality_rejects_invalid_interface_shape(settings: Settings):
    fake = _link_quality_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("get_wireless_link_quality", {"device_name": "core-switch", "interface": "bad name!"})
    assert "interface" in str(exc_info.value).lower()


# --- v1.11: wireless RF tuning + dead-man (server-level) ---------------------


def _wireless_write_fake() -> FakeConnection:
    return FakeConnection(
        data={
            ("interface", "wireless"): [
                {
                    ".id": "*1",
                    "name": "wlan1",
                    "frequency": "5500",
                    "channel-width": "20mhz",
                    "frequency-mode": "regulatory-domain",
                    "tx-power-mode": "default",
                    "tx-power": "20",
                    "adaptive-noise-immunity": "none",
                    "distance": "dynamic",
                }
            ],
            ("system", "scheduler"): [],
        }
    )


@pytest.mark.asyncio
async def test_set_wireless_channel_blocked_read_only_by_default(settings: Settings):
    fake = _wireless_write_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wireless_channel",
            {"device_name": "core-switch", "interface_name": "wlan1", "frequency": 5300, "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_wireless_channel_preview_then_confirm_arms_dead_man(device: Device):
    fake = _wireless_write_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_wireless_channel",
        {"device_name": "core-switch", "interface_name": "wlan1", "frequency": 5300, "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["dead_man"] is None
    assert preview["warning"] is not None and "DFS" in preview["warning"]

    _content, applied = await mcp.call_tool(
        "set_wireless_channel",
        {"device_name": "core-switch", "interface_name": "wlan1", "frequency": 5300, "confirm": True},
    )
    assert applied["applied"] is True
    assert applied["dead_man"]["name"].startswith("deadman-")
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["frequency"] == "5300"
    assert len(fake.path("system", "scheduler")._rows) == 1


@pytest.mark.asyncio
async def test_set_wireless_channel_arm_deadman_false(device: Device):
    fake = _wireless_write_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, applied = await mcp.call_tool(
        "set_wireless_channel",
        {
            "device_name": "core-switch",
            "interface_name": "wlan1",
            "frequency": 5300,
            "arm_deadman": False,
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    assert applied["dead_man"] is None
    assert fake.path("system", "scheduler")._rows == []


@pytest.mark.asyncio
async def test_set_wireless_channel_unknown_interface_raises_clear_error(device: Device):
    fake = _wireless_write_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wireless_channel",
            {"device_name": "core-switch", "interface_name": "ghost-wlan", "frequency": 5300, "confirm": True},
        )
    assert "not found" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_set_wireless_tx_power_blocked_read_only_by_default(settings: Settings):
    fake = _wireless_write_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wireless_tx_power",
            {"device_name": "core-switch", "interface_name": "wlan1", "tx_power": 8, "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_wireless_tx_power_preview_then_confirm_arms_dead_man(device: Device):
    fake = _wireless_write_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_wireless_tx_power",
        {"device_name": "core-switch", "interface_name": "wlan1", "tx_power": 8, "confirm": False},
    )
    assert preview["applied"] is False

    _content, applied = await mcp.call_tool(
        "set_wireless_tx_power",
        {"device_name": "core-switch", "interface_name": "wlan1", "tx_power": 8, "confirm": True},
    )
    assert applied["applied"] is True
    assert applied["dead_man"]["name"].startswith("deadman-")
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["tx-power"] == "8"
    assert updated["tx-power-mode"] == "all-rates-fixed"


@pytest.mark.asyncio
async def test_set_wireless_tx_power_rejects_out_of_range_power(device: Device):
    fake = _wireless_write_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wireless_tx_power",
            {"device_name": "core-switch", "interface_name": "wlan1", "tx_power": 999, "confirm": True},
        )
    assert "tx_power" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_wireless_tuning_blocked_read_only_by_default(settings: Settings):
    fake = _wireless_write_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wireless_tuning",
            {"device_name": "core-switch", "interface_name": "wlan1", "distance": 9, "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_wireless_tuning_preview_then_confirm_never_arms_dead_man(device: Device):
    fake = _wireless_write_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_wireless_tuning",
        {
            "device_name": "core-switch",
            "interface_name": "wlan1",
            "adaptive_noise_immunity": "ap-and-client-mode",
            "confirm": False,
        },
    )
    assert preview["applied"] is False

    _content, applied = await mcp.call_tool(
        "set_wireless_tuning",
        {
            "device_name": "core-switch",
            "interface_name": "wlan1",
            "adaptive_noise_immunity": "ap-and-client-mode",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    assert applied["dead_man"] is None
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["adaptive-noise-immunity"] == "ap-and-client-mode"
    assert fake.path("system", "scheduler")._rows == []


@pytest.mark.asyncio
async def test_set_wireless_tuning_requires_at_least_one_field(device: Device):
    fake = _wireless_write_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wireless_tuning",
            {"device_name": "core-switch", "interface_name": "wlan1", "confirm": True},
        )
    assert "at least one" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_arm_dead_man_blocked_read_only_by_default(settings: Settings):
    fake = FakeConnection(data={("system", "scheduler"): []})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "arm_dead_man",
            {
                "device_name": "core-switch",
                "revert_commands": ['/interface/wireless set [find name="wlan1"] frequency=5500'],
                "minutes": 3,
                "confirm": True,
            },
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_arm_dead_man_then_cancel_dead_man_round_trip(device: Device):
    fake = FakeConnection(data={("system", "scheduler"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, armed = await mcp.call_tool(
        "arm_dead_man",
        {
            "device_name": "core-switch",
            "revert_commands": ['/interface/wireless set [find name="wlan1"] frequency=5500'],
            "minutes": 3,
            "confirm": True,
        },
    )
    assert armed["applied"] is True
    name = armed["after"]["name"]
    assert len(fake.path("system", "scheduler")._rows) == 1

    _content, cancelled = await mcp.call_tool(
        "cancel_dead_man", {"device_name": "core-switch", "name": name, "confirm": True}
    )
    assert cancelled["applied"] is True
    assert fake.path("system", "scheduler")._rows == []


@pytest.mark.asyncio
async def test_cancel_dead_man_rejects_name_not_matching_dead_man_shape(device: Device):
    fake = FakeConnection(data={("system", "scheduler"): [{".id": "*1", "name": "backup-daily"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("cancel_dead_man", {"device_name": "core-switch", "name": "backup-daily", "confirm": True})
    assert "deadman-" in str(exc_info.value)
    # Never touched the unrelated scheduler entry.
    assert fake.path("system", "scheduler")._rows == [{".id": "*1", "name": "backup-daily"}]


# --- VPN & routing diagnostics (v0.8, read-only) -----------------------------


@pytest.mark.asyncio
async def test_wireguard_peers_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("wireguard_peers", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "peer1"
    assert result["result"][0]["public-key"] == "PUBKEYAAAA=="
    assert result["result"][0]["allowed-address"] == "10.10.0.2/32"


@pytest.mark.asyncio
async def test_wireguard_peers_never_exposes_private_key(settings: Settings):
    """SECURITY: even if a device/future RouterOS version ever included a
    private-key field on a /interface/wireguard/peers row, wireguard_peers
    must strip it before the row ever reaches a caller - see
    strip_sensitive_fields' docstring."""
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {
                    ".id": "*1",
                    "name": "peer1",
                    "public-key": "PUBKEYAAAA==",
                    "private-key": "SUPERSECRETPRIVATEKEY==",
                }
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireguard_peers", {"device_name": "core-switch"})
    assert "private-key" not in result["result"][0]
    assert "SUPERSECRETPRIVATEKEY==" not in str(result)


@pytest.mark.asyncio
async def test_wireguard_peers_returns_empty_when_no_wireguard(settings: Settings):
    fake = FakeConnection(raise_for={("interface", "wireguard", "peers"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireguard_peers", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_wireguard_peers_never_exposes_preshared_key(settings: Settings):
    """SECURITY (v0.13): a peer's preshared-key (a real, optional RouterOS
    field on /interface/wireguard/peers, unlike private-key which never
    appears there) must be stripped exactly like private-key."""
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {
                    ".id": "*1",
                    "name": "peer1",
                    "public-key": "PUBKEYAAAA==",
                    "preshared-key": "SUPERSECRETPRESHAREDKEY==",
                }
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireguard_peers", {"device_name": "core-switch"})
    assert "preshared-key" not in result["result"][0]
    assert "SUPERSECRETPRESHAREDKEY==" not in str(result)


# --- wireguard_interfaces (v0.13, read-only) ---------------------------------


@pytest.mark.asyncio
async def test_wireguard_interfaces_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("wireguard_interfaces", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "wg1"
    assert result["result"][0]["public-key"] == "SERVERPUBKEYAAAA=="
    assert result["result"][0]["listen-port"] == "13231"


@pytest.mark.asyncio
async def test_wireguard_interfaces_never_exposes_private_key(settings: Settings):
    """SECURITY: /interface/wireguard's own reply DOES genuinely carry a
    private-key on a real device (unlike wireguard_peers) - this must never
    reach a caller."""
    fake = FakeConnection(
        data={
            ("interface", "wireguard"): [
                {
                    ".id": "*1",
                    "name": "wg1",
                    "public-key": "PUBKEYAAAA==",
                    "private-key": "SUPERSECRETPRIVATEKEY==",
                }
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireguard_interfaces", {"device_name": "core-switch"})
    assert "private-key" not in result["result"][0]
    assert "SUPERSECRETPRIVATEKEY==" not in str(result)


@pytest.mark.asyncio
async def test_wireguard_interfaces_returns_empty_when_no_wireguard(settings: Settings):
    fake = FakeConnection(raise_for={("interface", "wireguard"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireguard_interfaces", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_ppp_active_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ppp_active", {"device_name": "core-switch"})
    assert result["result"][0]["service"] == "l2tp"
    assert result["result"][0]["caller-id"] == "198.51.100.9"


@pytest.mark.asyncio
async def test_ppp_active_returns_empty_when_no_ppp_server(settings: Settings):
    fake = FakeConnection(raise_for={("ppp", "active"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ppp_active", {"device_name": "core-switch"})
    assert result["result"] == []


# --- ppp_secrets (v1.3, read-only) -------------------------------------------


@pytest.mark.asyncio
async def test_ppp_secrets_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ppp_secrets", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "pppoe-client1"
    assert result["result"][0]["service"] == "pppoe"
    assert result["result"][0]["remote-address"] == "10.40.0.10"


@pytest.mark.asyncio
async def test_ppp_secrets_never_exposes_password(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ppp_secrets", {"device_name": "core-switch"})
    assert "password" not in result["result"][0]
    assert "s3cret-fake" not in str(result)


@pytest.mark.asyncio
async def test_ppp_secrets_returns_empty_when_no_ppp_server(settings: Settings):
    fake = FakeConnection(raise_for={("ppp", "secret"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ppp_secrets", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_ipsec_active_peers_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ipsec_active_peers", {"device_name": "core-switch"})
    assert result["result"][0]["remote-address"] == "198.51.100.10"
    assert result["result"][0]["state"] == "established"


@pytest.mark.asyncio
async def test_ipsec_active_peers_returns_empty_when_ipsec_unused(settings: Settings):
    fake = FakeConnection(raise_for={("ip", "ipsec", "active-peers"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ipsec_active_peers", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_bgp_sessions_ros7_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("bgp_sessions", {"device_name": "core-switch"})
    assert result["result"][0]["remote-address"] == "198.51.100.20"
    assert result["result"][0]["state"] == "established"


@pytest.mark.asyncio
async def test_bgp_sessions_falls_back_to_ros6(settings: Settings):
    fake = FakeConnection(
        raise_for={("routing", "bgp", "session"): LibRouterosError("no such command")},
        data={
            ("routing", "bgp", "peer"): [
                {".id": "*1", "remote-address": "198.51.100.21", "remote-as": "65002", "state": "established"}
            ]
        },
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("bgp_sessions", {"device_name": "core-switch"})
    assert result["result"][0]["remote-address"] == "198.51.100.21"


@pytest.mark.asyncio
async def test_bgp_sessions_returns_empty_when_bgp_not_running(settings: Settings):
    fake = FakeConnection(
        raise_for={
            ("routing", "bgp", "session"): LibRouterosError("no such command"),
            ("routing", "bgp", "peer"): LibRouterosError("no such command"),
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("bgp_sessions", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_ospf_neighbors_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ospf_neighbors", {"device_name": "core-switch"})
    assert result["result"][0]["state"] == "Full"
    assert result["result"][0]["router-id"] == "10.30.0.2"


@pytest.mark.asyncio
async def test_ospf_neighbors_returns_empty_when_ospf_not_running(settings: Settings):
    fake = FakeConnection(raise_for={("routing", "ospf", "neighbor"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ospf_neighbors", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_netwatch_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("netwatch", {"device_name": "core-switch"})
    entry = result["result"][0]
    assert entry["host"] == "8.8.8.8"
    assert entry["status"] == "up"
    assert entry["has-up-script"] is False
    assert entry["has-down-script"] is True
    assert "up-script" not in entry
    assert "down-script" not in entry


@pytest.mark.asyncio
async def test_netwatch_returns_empty_when_no_entries(settings: Settings):
    fake = FakeConnection(data={("tool", "netwatch"): []})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("netwatch", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_netwatch_returns_empty_when_device_has_no_netwatch_package(settings: Settings):
    """Distinct from the "zero entries configured" case above: here the
    /tool/netwatch menu itself is unreadable (DeviceCommandError), which
    must degrade to an empty list rather than propagate as an error - same
    convention as poe_status/system_health/lte_status for optional
    hardware/packages."""
    fake = FakeConnection(raise_for={("tool", "netwatch"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("netwatch", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_unknown_device_returns_clean_error_not_a_crash(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: s.get_device(n))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("system_info", {"device_name": "ghost"})
    assert "ghost" in str(exc_info.value)


@pytest.mark.asyncio
async def test_ping_rejects_invalid_address_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("ping", {"device_name": "core-switch", "address": "8.8.8.8; reboot"})
    assert "not a valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_ping_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ping", {"device_name": "core-switch", "address": "8.8.8.8"})
    assert result["result"][0]["host"] == "8.8.8.8"


# --- traceroute (v0.4, diagnostic - not gated by MIKROTIK_ALLOW_WRITE) -----


@pytest.mark.asyncio
async def test_traceroute_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8"})
    assert result["result"][0]["address"] == "10.0.0.254"
    assert result["result"][1]["address"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_traceroute_rejects_invalid_address_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8; reboot"})
    assert "not a valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_traceroute_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    """Diagnostic, read-only tool: must work even with MIKROTIK_ALLOW_WRITE=false."""
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8"})
    assert result["result"]


@pytest.mark.asyncio
async def test_traceroute_caps_count_and_max_hops_sent_to_device(settings: Settings):
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    await mcp.call_tool(
        "traceroute",
        {"device_name": "core-switch", "address": "8.8.8.8", "count": 999, "max_hops": 999},
    )
    cmd, kwargs = fake.calls[-1]
    assert cmd == "/tool/traceroute"
    assert kwargs["count"] == "2"  # MAX_TRACEROUTE_COUNT
    assert kwargs["max-hops"] == "10"  # MAX_TRACEROUTE_MAX_HOPS
    assert kwargs["timeout"] == "00:00:01"  # fixed short per-hop timeout


@pytest.mark.asyncio
async def test_traceroute_rejects_non_positive_count(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8", "count": 0})
    assert "positive" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_set_identity_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True})
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    assert fake_connection.path("system", "identity")._rows == [{"name": "MikroTik"}]


@pytest.mark.asyncio
async def test_set_identity_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": False}
    )
    assert preview["applied"] is False
    assert fake_connection.path("system", "identity")._rows == [{"name": "MikroTik"}]

    _content, applied = await mcp.call_tool(
        "set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake_connection.path("system", "identity")._rows == [{"name": "renamed"}]


# --- arp_table / bridge_hosts (v0.6, read-only) -----------------------------


@pytest.mark.asyncio
async def test_arp_table_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("arp_table", {"device_name": "core-switch"})
    assert result["result"] == [
        {
            ".id": "*1",
            "address": "10.0.0.70",
            "mac-address": "AA:BB:CC:DD:EE:70",
            "interface": "ether1",
            "dynamic": False,
            "complete": True,
        }
    ]


@pytest.mark.asyncio
async def test_bridge_hosts_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("bridge_hosts", {"device_name": "core-switch"})
    assert result["result"] == [
        {
            ".id": "*1",
            "mac-address": "AA:BB:CC:DD:EE:70",
            "on-interface": "ether1",
            "bridge": "bridge1",
            "dynamic": False,
            "local": False,
        }
    ]


# --- interface_traffic / poe_status (v0.6, read-only - not gated by --------
# --- MIKROTIK_ALLOW_WRITE) --------------------------------------------------


@pytest.mark.asyncio
async def test_interface_traffic_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("interface_traffic", {"device_name": "core-switch", "interface": "ether1"})
    # A dict-returning tool's structured content is the dict itself - not
    # wrapped under a "result" key (that wrapping only applies to
    # list-returning tools; see e.g. set_identity's `preview["applied"]`).
    assert result["rx-bits-per-second"] == "1000000"
    assert result["tx-bits-per-second"] == "500000"


@pytest.mark.asyncio
async def test_interface_traffic_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("interface_traffic", {"device_name": "core-switch", "interface": "ether1"})
    assert result


@pytest.mark.asyncio
async def test_interface_traffic_rejects_invalid_interface_name_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("interface_traffic", {"device_name": "core-switch", "interface": "ether1; reboot"})
    assert "not valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_interface_traffic_sends_once_flag_as_structured_param(settings: Settings):
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    await mcp.call_tool("interface_traffic", {"device_name": "core-switch", "interface": "ether1"})
    cmd, kwargs = fake.calls[-1]
    assert cmd == "/interface/monitor-traffic"
    assert kwargs == {"interface": "ether1", "once": ""}


@pytest.mark.asyncio
async def test_poe_status_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    rows = {row["interface"]: row for row in result["result"]}
    # sfp1 (no `poe-out` field on the fixture device) must never appear.
    assert set(rows) == {"ether1", "ether2"}
    assert rows["ether1"]["poe-out"] == "auto-on"
    assert rows["ether1"]["poe-out-status"] == "powered-on"
    # conftest's poe_monitor_replies deliberately mixes int/string-decimal
    # types across fields and ports (real CRS318 hardware finding) -
    # poe_status must normalize all of them via coerce_ros_number, never
    # pass a raw string through for a field that came back as one.
    assert rows["ether1"]["voltage"] == 48.0
    assert isinstance(rows["ether1"]["voltage"], float)
    assert rows["ether1"]["current"] == 204
    assert isinstance(rows["ether1"]["current"], int)
    assert rows["ether1"]["power"] == 4.7
    assert isinstance(rows["ether1"]["power"], float)
    assert rows["ether2"]["poe-out"] == "off"
    assert rows["ether2"]["poe-out-status"] == "poe-out-off"
    assert rows["ether2"]["voltage"] == 23.5
    assert isinstance(rows["ether2"]["voltage"], float)
    assert rows["ether2"]["current"] == 0
    assert isinstance(rows["ether2"]["current"], int)
    assert rows["ether2"]["power"] == 1
    assert isinstance(rows["ether2"]["power"], int)


@pytest.mark.asyncio
async def test_poe_status_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    assert result["result"]


@pytest.mark.asyncio
async def test_poe_status_returns_empty_list_for_device_with_no_poe(settings: Settings):
    """A device with no PoE hardware at all has no `poe-out` field on any
    /interface/ethernet row - poe_status must return an empty list, not an
    error, exactly like wireless_registrations does for a wired-only device."""
    fake = FakeConnection(
        data={("interface", "ethernet"): [{".id": "*1", "name": "ether1"}, {".id": "*2", "name": "ether2"}]}
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_poe_status_survives_a_failed_monitor_call_for_one_port(settings: Settings):
    """A PoE-capable port whose live monitor call fails must still be listed
    (with its configured `poe-out`, just without live monitor fields) -
    one bad port must not fail the whole tool. `fake_connection`'s __call__
    is a bound method looked up on the type for the implicit `connection(...)`
    call form (client.py's poe_monitor), so it can't be monkeypatched per
    instance - a small standalone fake connection is used instead."""

    class _FlakyMonitorConnection:
        def path(self, *segments: str) -> FakePath:
            if segments == ("interface", "ethernet"):
                return FakePath([{".id": "*1", "name": "ether1", "poe-out": "auto-on"}])
            return FakePath([])

        def __call__(self, cmd: str, **kwargs):
            if cmd == "/interface/ethernet/poe/monitor":
                raise LibRouterosError("no such port")
            return []

        def close(self) -> None:
            pass

    def factory(s: Settings, n: str) -> MikrotikClient:
        return MikrotikClient(s.get_device(n), connection=_FlakyMonitorConnection())

    mcp = build_server(settings=settings, client_factory=factory)
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    assert result["result"] == [{"interface": "ether1", "poe-out": "auto-on"}]


# --- lte_status / lte_interfaces (v0.7, read-only) --------------------------


@pytest.mark.asyncio
async def test_lte_status_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("lte_status", {"device_name": "core-switch", "interface": "lte1"})
    assert result["current-operator"] == "Vivo"
    assert result["access-technology"] == "lte"
    assert result["rsrp"] == "-85"
    assert result["registration-status"] == "registered"


@pytest.mark.asyncio
async def test_lte_status_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("lte_status", {"device_name": "core-switch", "interface": "lte1"})
    assert result


@pytest.mark.asyncio
async def test_lte_status_returns_empty_dict_for_device_with_no_lte(settings: Settings):
    """A device with no LTE hardware/package raises DeviceCommandError from
    the monitor-once call - lte_status must return an empty dict instead of
    propagating that as an error, same convention as poe_status/
    system_health for optional hardware.

    lte_monitor's read goes through the connection's CALLABLE form
    (connection("/interface/lte/monitor", ...)), not .path() - so
    FakeConnection's path-keyed `raise_for` can't intercept it (an empty
    `lte_monitor_replies` mapping already yields {} "for free", without ever
    exercising server.py's own except DeviceCommandError branch).
    TransportErrorConnection raises on every operation, including the
    callable form, so it genuinely exercises that branch."""
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(
            s.get_device(n), connection=TransportErrorConnection(LibRouterosError("no such command"))
        ),
    )
    _content, result = await mcp.call_tool("lte_status", {"device_name": "core-switch", "interface": "lte1"})
    assert result == {}


@pytest.mark.asyncio
async def test_lte_status_sends_once_flag_as_structured_param(settings: Settings):
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    await mcp.call_tool("lte_status", {"device_name": "core-switch", "interface": "lte1"})
    cmd, kwargs = fake.calls[-1]
    assert cmd == "/interface/lte/monitor"
    assert kwargs == {"interface": "lte1", "once": ""}


@pytest.mark.asyncio
async def test_lte_status_rejects_invalid_interface_name_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("lte_status", {"device_name": "core-switch", "interface": "lte1; reboot"})
    assert "not valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_lte_interfaces_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("lte_interfaces", {"device_name": "core-switch"})
    assert result["result"] == [
        {".id": "*1", "name": "lte1", "running": True, "disabled": False, "apn-profiles": "default"}
    ]


@pytest.mark.asyncio
async def test_lte_interfaces_returns_empty_list_for_device_with_no_lte(settings: Settings):
    fake = FakeConnection(raise_for={("interface", "lte"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("lte_interfaces", {"device_name": "core-switch"})
    assert result["result"] == []


# --- containers / container_config (v0.7, read-only) ------------------------


@pytest.mark.asyncio
async def test_containers_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("containers", {"device_name": "core-switch"})
    rows = {row.get("name") or row["tag"]: row for row in result["result"]}
    assert rows["grafana"]["status"] == "running"
    assert rows["alpine:latest"]["status"] == "stopped"


@pytest.mark.asyncio
async def test_containers_returns_empty_list_for_device_with_no_container_support(settings: Settings):
    fake = FakeConnection(raise_for={("container",): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("containers", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_container_config_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("container_config", {"device_name": "core-switch"})
    assert result["registry-url"] == "https://registry-1.docker.io"


@pytest.mark.asyncio
async def test_container_config_returns_empty_dict_for_device_with_no_container_support(settings: Settings):
    fake = FakeConnection(raise_for={("container", "config"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("container_config", {"device_name": "core-switch"})
    assert result == {}


# --- usb_devices (v0.7, read-only) -------------------------------------------


@pytest.mark.asyncio
async def test_usb_devices_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("usb_devices", {"device_name": "core-switch"})
    assert result["usb_ports"] == [{".id": "*1", "port": "1", "power-reset": "auto-on"}]
    assert result["disks"][0]["slot"] == "usb1"


@pytest.mark.asyncio
async def test_usb_devices_returns_empty_lists_for_board_with_no_usb(settings: Settings):
    fake = FakeConnection(
        raise_for={
            ("system", "routerboard", "usb"): LibRouterosError("no such command"),
            ("disk",): LibRouterosError("no such command"),
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("usb_devices", {"device_name": "core-switch"})
    assert result == {"usb_ports": [], "disks": []}


# --- interface_monitor / dhcp_servers / dhcp_networks / bridge_ports / -----
# --- bridge_vlans (v1.7, read-only) -----------------------------------------


@pytest.mark.asyncio
async def test_interface_monitor_happy_path_no_sfp(settings: Settings, fake_connection: FakeConnection):
    """A plain copper port (no SFP cage) must never carry any sfp-* key -
    `fake_connection`'s "ether1" reply has none, mirroring a real device."""
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("interface_monitor", {"device_name": "core-switch", "interface": "ether1"})
    assert result["interface"] == "ether1"
    assert result["status"] == "link-ok"
    assert result["rate"] == "1Gbps"
    # RouterOS hands this back as a real Python bool (never the string
    # "true") - see coerce_ros_bool's docstring (Lição B).
    assert result["full-duplex"] is True
    assert result["auto-negotiation"] == "done"
    assert not any(key.startswith("sfp-") for key in result)


@pytest.mark.asyncio
async def test_interface_monitor_happy_path_with_sfp_module(settings: Settings, fake_connection: FakeConnection):
    """An SFP-capable port WITH a module inserted must surface every
    DDM/SFP field the device reply carries, with sfp-module-present coerced
    to a real bool."""
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("interface_monitor", {"device_name": "core-switch", "interface": "sfp1"})
    assert result["sfp-module-present"] is True
    assert result["sfp-vendor-name"] == "MikroTik"
    assert result["sfp-vendor-part-number"] == "S-3553LC20D"
    assert result["sfp-wavelength"] == "1310"
    assert result["sfp-temperature"] == "35"
    assert result["sfp-supply-voltage"] == "3.3"
    assert result["sfp-tx-power"] == "-3.0"
    assert result["sfp-rx-power"] == "-4.2"
    assert result["sfp-tx-bias-current"] == "8.5"


@pytest.mark.asyncio
async def test_interface_monitor_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("interface_monitor", {"device_name": "core-switch", "interface": "ether1"})
    assert result


@pytest.mark.asyncio
async def test_interface_monitor_returns_empty_dict_when_device_replies_nothing(settings: Settings):
    """Same "empty, not an error" convention as interface_traffic/poe_status/
    lte_status for a monitor-once call the device answers with nothing."""
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("interface_monitor", {"device_name": "core-switch", "interface": "ether5"})
    assert result == {}


@pytest.mark.asyncio
async def test_interface_monitor_rejects_invalid_interface_name_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("interface_monitor", {"device_name": "core-switch", "interface": "ether1; reboot"})
    assert "not valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_interface_monitor_sends_once_flag_as_structured_param(settings: Settings):
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    await mcp.call_tool("interface_monitor", {"device_name": "core-switch", "interface": "ether1"})
    cmd, kwargs = fake.calls[-1]
    assert cmd == "/interface/ethernet/monitor"
    # RouterOS selects the port here via `numbers=`, not `interface=` (verified
    # on ROS6/ROS7 - the latter gives "unknown parameter").
    assert kwargs == {"numbers": "ether1", "once": ""}


@pytest.mark.asyncio
async def test_dhcp_servers_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("dhcp_servers", {"device_name": "core-switch"})
    rows = {row["name"]: row for row in result["result"]}
    assert rows["dhcp1"]["interface"] == "ether1"
    assert rows["dhcp1"]["address-pool"] == "pool1"
    assert rows["dhcp1"]["lease-time"] == "1d"
    assert rows["dhcp1"]["authoritative"] == "yes"
    # *1 omits `disabled` entirely (ROS6-style implicit-false) - must
    # coerce to None (unknown/absent), never crash or silently become True.
    assert rows["dhcp1"]["disabled"] is None
    # *2 carries an explicit ROS7-style `False` - must coerce to a real
    # bool, never left as the raw value or a string-equality trap.
    assert rows["dhcp2"]["disabled"] is False


@pytest.mark.asyncio
async def test_dhcp_servers_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("dhcp_servers", {"device_name": "core-switch"})
    assert result["result"]


@pytest.mark.asyncio
async def test_dhcp_networks_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("dhcp_networks", {"device_name": "core-switch"})
    assert result["result"] == [
        {
            ".id": "*1",
            "address": "10.0.0.0/24",
            "gateway": "10.0.0.1",
            "dns-server": "10.0.0.1",
            "netmask": "24",
            "domain": "lan",
            "comment": "main LAN",
        }
    ]


@pytest.mark.asyncio
async def test_bridge_ports_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("bridge_ports", {"device_name": "core-switch"})
    rows = {row["interface"]: row for row in result["result"]}
    assert rows["ether2"]["pvid"] == "1"
    assert rows["ether2"]["disabled"] is False
    assert rows["ether2"]["edge"] == "auto"
    assert rows["ether2"]["learn"] == "auto"
    assert rows["ether3"]["pvid"] == "20"
    # RouterOS's own bool, not the string "true" - must coerce, not compare.
    assert rows["ether3"]["disabled"] is True
    assert rows["ether3"]["comment"] == "camera vlan"


@pytest.mark.asyncio
async def test_bridge_ports_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("bridge_ports", {"device_name": "core-switch"})
    assert result["result"]


@pytest.mark.asyncio
async def test_bridge_vlans_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("bridge_vlans", {"device_name": "core-switch"})
    assert result["result"] == [
        {
            ".id": "*1",
            "bridge": "bridge1",
            "vlan-ids": "20",
            "tagged": "bridge1,ether1",
            "untagged": "ether3",
            "current-tagged": "bridge1,ether1",
            "current-untagged": "ether3",
            "comment": "cameras",
        }
    ]


@pytest.mark.asyncio
async def test_bridge_vlans_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("bridge_vlans", {"device_name": "core-switch"})
    assert result["result"]


# --- ntp_client / system_clock (v1.8) --------------------------------------


@pytest.mark.asyncio
async def test_ntp_client_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ntp_client", {"device_name": "core-switch"})
    # A dict-typed tool result is returned as the object itself (its own
    # keys as top-level fields), unlike a list-typed tool's `result["result"]`
    # - see container_config's tests for the same convention.
    assert result["enabled"] is True
    assert result["mode"] == "unicast"
    # ROS7's `servers` stays the raw comma-joined string RouterOS sends -
    # never split into a list, same "no invented shape" convention
    # bridge_vlans' tagged/untagged fields already follow.
    assert result["servers"] == "1.2.3.4,pool.ntp.org"
    assert result["status"] == "synchronized"
    assert result["synced-server"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_ntp_client_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ntp_client", {"device_name": "core-switch"})
    assert result


@pytest.mark.asyncio
async def test_ntp_client_returns_empty_when_menu_absent(settings: Settings):
    fake = FakeConnection(raise_for={("system", "ntp", "client"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ntp_client", {"device_name": "core-switch"})
    assert result == {}


@pytest.mark.asyncio
async def test_ntp_client_returns_empty_when_menu_has_no_rows(settings: Settings):
    """The menu exists but replies with zero rows (as opposed to raising) -
    same empty-dict result, distinct code path from a raised
    DeviceCommandError above."""
    fake = FakeConnection(data={("system", "ntp", "client"): []})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ntp_client", {"device_name": "core-switch"})
    assert result == {}


@pytest.mark.asyncio
async def test_ntp_client_ros6_shape_returned_as_is(settings: Settings):
    """ROS6's field shape (primary-ntp/secondary-ntp, no `servers` list) is
    returned exactly as the device sends it - nothing invented."""
    fake = FakeConnection(
        data={
            ("system", "ntp", "client"): [
                {"enabled": False, "primary-ntp": "10.0.0.1", "secondary-ntp": "0.0.0.0", "mode": "unicast"}
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ntp_client", {"device_name": "core-switch"})
    assert result["enabled"] is False
    assert result["primary-ntp"] == "10.0.0.1"
    assert "servers" not in result


@pytest.mark.asyncio
async def test_system_clock_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("system_clock", {"device_name": "core-switch"})
    assert result["time"] == "12:00:00"
    assert result["date"] == "jan/01/2026"
    assert result["time-zone-name"] == "America/Sao_Paulo"
    assert result["time-zone-autodetect"] is True
    assert result["dst-active"] is False


@pytest.mark.asyncio
async def test_system_clock_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("system_clock", {"device_name": "core-switch"})
    assert result


@pytest.mark.asyncio
async def test_system_clock_returns_empty_when_menu_absent(settings: Settings):
    fake = FakeConnection(raise_for={("system", "clock"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("system_clock", {"device_name": "core-switch"})
    assert result == {}


@pytest.mark.asyncio
async def test_system_clock_returns_empty_when_menu_has_no_rows(settings: Settings):
    """The menu exists but replies with zero rows (as opposed to raising) -
    same empty-dict result, distinct code path from a raised
    DeviceCommandError above."""
    fake = FakeConnection(data={("system", "clock"): []})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("system_clock", {"device_name": "core-switch"})
    assert result == {}


# --- enable_interface / disable_interface --------------------------------


@pytest.mark.asyncio
async def test_enable_interface_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_interface", {"device_name": "core-switch", "interface_name": "ether2", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": False, "ether2": True}


@pytest.mark.asyncio
async def test_disable_interface_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "disable_interface", {"device_name": "core-switch", "interface_name": "ether1", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_interface_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "enable_interface", {"device_name": "core-switch", "interface_name": "ether2", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["disabled"] is True
    assert preview["after"]["disabled"] == "no"
    # Preview must not have touched the device.
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows["ether2"] is True

    _content, applied = await mcp.call_tool(
        "enable_interface", {"device_name": "core-switch", "interface_name": "ether2", "confirm": True}
    )
    assert applied["applied"] is True
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": False, "ether2": "no"}


@pytest.mark.asyncio
async def test_disable_interface_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "disable_interface", {"device_name": "core-switch", "interface_name": "ether1", "confirm": True}
    )
    assert applied["applied"] is True
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": "yes", "ether2": True}


@pytest.mark.asyncio
async def test_enable_interface_unknown_interface_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_interface", {"device_name": "core-switch", "interface_name": "ghost0", "confirm": False}
        )
    assert "ghost0" in str(exc_info.value)
    # Nothing was created.
    names = {row["name"] for row in fake_connection.path("interface")._rows}
    assert names == {"ether1", "ether2"}


# --- set_wifi_ssid ---------------------------------------------------------


@pytest.mark.asyncio
async def test_set_wifi_ssid_blocked_read_only_by_default(settings: Settings):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wifi_ssid",
            {"device_name": "core-switch", "interface_name": "wifi1", "new_ssid": "new-ssid", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_wifi_ssid_ros7_preview_then_confirm(device: Device):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_wifi_ssid",
        {"device_name": "core-switch", "interface_name": "wifi1", "new_ssid": "new-ssid", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["operation"] == "set_wifi_ssid_ros7"
    assert fake.path("interface", "wifi")._rows[0]["ssid"] == "old-ssid"

    _content, applied = await mcp.call_tool(
        "set_wifi_ssid",
        {"device_name": "core-switch", "interface_name": "wifi1", "new_ssid": "new-ssid", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake.path("interface", "wifi")._rows[0]["ssid"] == "new-ssid"


@pytest.mark.asyncio
async def test_set_wifi_ssid_falls_back_to_ros6_when_ros7_path_unsupported(device: Device):
    fake = FakeConnection(
        raise_for={("interface", "wifi"): LibRouterosError("no such command")},
        data={("interface", "wireless"): [{".id": "*1", "name": "wlan1", "ssid": "old-ssid"}]},
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, applied = await mcp.call_tool(
        "set_wifi_ssid",
        {"device_name": "core-switch", "interface_name": "wlan1", "new_ssid": "new-ssid", "confirm": True},
    )
    assert applied["applied"] is True
    assert applied["operation"] == "set_wifi_ssid_ros6"
    assert fake.path("interface", "wireless")._rows[0]["ssid"] == "new-ssid"


@pytest.mark.asyncio
async def test_set_wifi_ssid_unknown_interface_raises_clear_error(device: Device):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wifi_ssid",
            {"device_name": "core-switch", "interface_name": "ghost-radio", "new_ssid": "x", "confirm": False},
        )
    assert "ghost-radio" in str(exc_info.value)


# --- set_client_bandwidth ---------------------------------------------------


@pytest.mark.asyncio
async def test_set_client_bandwidth_blocked_read_only_by_default(settings: Settings):
    fake = FakeConnection(data={("queue", "simple"): []})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_client_bandwidth",
            {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "10M/5M", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert fake.path("queue", "simple")._rows == []


@pytest.mark.asyncio
async def test_set_client_bandwidth_creates_then_updates(device: Device):
    fake = FakeConnection(data={("queue", "simple"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_client_bandwidth",
        {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "10M/5M", "confirm": False},
    )
    assert preview["operation"] == "set_client_bandwidth_add"
    assert preview["applied"] is False
    assert fake.path("queue", "simple")._rows == []

    _content, applied = await mcp.call_tool(
        "set_client_bandwidth",
        {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "10M/5M", "confirm": True},
    )
    assert applied["operation"] == "set_client_bandwidth_add"
    assert applied["applied"] is True
    assert len(fake.path("queue", "simple")._rows) == 1

    # Calling it again for the same target updates the existing queue instead of adding a second one.
    _content, updated = await mcp.call_tool(
        "set_client_bandwidth",
        {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "20M/10M", "confirm": True},
    )
    assert updated["operation"] == "set_client_bandwidth_update"
    assert updated["applied"] is True
    rows = fake.path("queue", "simple")._rows
    assert len(rows) == 1
    assert rows[0]["max-limit"] == "20M/10M"


@pytest.mark.asyncio
async def test_set_client_bandwidth_rejects_invalid_max_limit_before_touching_device(settings: Settings):
    fake = FakeConnection(data={("queue", "simple"): []})
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_client_bandwidth",
            {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "not-a-rate", "confirm": True},
        )
    assert "rate pair" in str(exc_info.value).lower()
    assert fake.path("queue", "simple")._rows == []


# --- add_static_dhcp_lease ---------------------------------------------------


@pytest.mark.asyncio
async def test_add_static_dhcp_lease_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_static_dhcp_lease",
            {"device_name": "core-switch", "address": "10.0.0.60", "mac_address": "AA:BB:CC:DD:EE:02", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "dhcp-server", "lease")._rows) == 1


@pytest.mark.asyncio
async def test_add_static_dhcp_lease_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_static_dhcp_lease",
        {"device_name": "core-switch", "address": "10.0.0.60", "mac_address": "AA:BB:CC:DD:EE:02", "confirm": False},
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "dhcp-server", "lease")._rows) == 1

    _content, applied = await mcp.call_tool(
        "add_static_dhcp_lease",
        {"device_name": "core-switch", "address": "10.0.0.60", "mac_address": "AA:BB:CC:DD:EE:02", "confirm": True},
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "dhcp-server", "lease")._rows
    assert any(row["mac-address"] == "AA:BB:CC:DD:EE:02" for row in rows)


@pytest.mark.asyncio
async def test_add_static_dhcp_lease_rejects_duplicate_mac(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_static_dhcp_lease",
            {"device_name": "core-switch", "address": "10.0.0.99", "mac_address": "AA:BB:CC:DD:EE:01", "confirm": True},
        )
    assert "already exists" in str(exc_info.value)
    assert len(fake_connection.path("ip", "dhcp-server", "lease")._rows) == 1


# --- remove_simple_queue ------------------------------------------------------


@pytest.mark.asyncio
async def test_remove_simple_queue_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.50/32", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("queue", "simple")._rows) == 1


@pytest.mark.asyncio
async def test_remove_simple_queue_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.50/32", "confirm": False}
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("queue", "simple")._rows) == 1

    _content, applied = await mcp.call_tool(
        "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.50/32", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake_connection.path("queue", "simple")._rows == []


@pytest.mark.asyncio
async def test_remove_simple_queue_unknown_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.99", "confirm": True}
        )
    assert "10.0.0.99" in str(exc_info.value)


# --- add_to_address_list / remove_from_address_list (v0.4) ------------------


@pytest.mark.asyncio
async def test_add_to_address_list_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_to_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.61", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


@pytest.mark.asyncio
async def test_add_to_address_list_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_to_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.61", "confirm": False},
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1

    _content, applied = await mcp.call_tool(
        "add_to_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.61", "confirm": True},
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "address-list")._rows
    assert any(row["list"] == "blocked-clients" and row["address"] == "10.0.0.61" for row in rows)


@pytest.mark.asyncio
async def test_add_to_address_list_rejects_duplicate(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_to_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": True},
        )
    assert "already exists" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


@pytest.mark.asyncio
async def test_remove_from_address_list_blocked_read_only_by_default(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_from_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


@pytest.mark.asyncio
async def test_remove_from_address_list_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_from_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": False},
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1

    _content, applied = await mcp.call_tool(
        "remove_from_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake_connection.path("ip", "firewall", "address-list")._rows == []


@pytest.mark.asyncio
async def test_remove_from_address_list_unknown_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_from_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.99", "confirm": True},
        )
    assert "10.0.0.99" in str(exc_info.value)


# --- set_poe_out (v0.6) ------------------------------------------------------


@pytest.mark.asyncio
async def test_set_poe_out_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "off", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    assert fake_connection.path("interface", "ethernet")._rows[0]["poe-out"] == "auto-on"


@pytest.mark.asyncio
async def test_set_poe_out_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "set_poe_out",
        {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "off", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["before"]["poe-out"] == "auto-on"
    assert preview["after"]["poe-out"] == "off"
    assert fake_connection.path("interface", "ethernet")._rows[0]["poe-out"] == "auto-on"

    _content, applied = await mcp.call_tool(
        "set_poe_out",
        {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "off", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake_connection.path("interface", "ethernet")._rows[0]["poe-out"] == "off"


@pytest.mark.asyncio
async def test_set_poe_out_unknown_interface_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "ghost0", "poe_out": "off", "confirm": True},
        )
    assert "ghost0" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_poe_out_non_poe_interface_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "sfp1", "poe_out": "off", "confirm": True},
        )
    assert "sfp1" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_poe_out_rejects_invalid_poe_out_value_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "on", "confirm": True},
        )
    assert "not valid" in str(exc_info.value)


# --- start_container / stop_container (v0.7) ---------------------------------


def _containers_factory(fake: FakeConnection):
    def factory(settings: Settings, device_name: str) -> MikrotikClient:
        return MikrotikClient(settings.get_device(device_name), connection=fake)

    return factory


@pytest.mark.asyncio
async def test_start_container_blocked_read_only_by_default(settings: Settings):
    fake = FakeConnection(data={("container",): [{".id": "*1", "name": "grafana", "status": "stopped"}]})
    mcp = build_server(settings=settings, client_factory=_containers_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("start_container", {"device_name": "core-switch", "container": "grafana", "confirm": True})
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    assert fake.path("container")._rows[0]["status"] == "stopped"


@pytest.mark.asyncio
async def test_start_container_preview_then_confirm(device: Device):
    fake = FakeConnection(data={("container",): [{".id": "*1", "name": "grafana", "status": "stopped"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_containers_factory(fake))

    _content, preview = await mcp.call_tool(
        "start_container", {"device_name": "core-switch", "container": "grafana", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["status"] == "stopped"
    assert preview["after"]["status"] == "starting"
    assert fake.path("container")._rows[0]["status"] == "stopped"

    _content, applied = await mcp.call_tool(
        "start_container", {"device_name": "core-switch", "container": "grafana", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake.path("container")._rows[0]["status"] == "running"


@pytest.mark.asyncio
async def test_stop_container_preview_then_confirm(device: Device):
    fake = FakeConnection(data={("container",): [{".id": "*1", "name": "grafana", "status": "running"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_containers_factory(fake))

    _content, preview = await mcp.call_tool(
        "stop_container", {"device_name": "core-switch", "container": "grafana", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["after"]["status"] == "stopping"
    assert fake.path("container")._rows[0]["status"] == "running"

    _content, applied = await mcp.call_tool(
        "stop_container", {"device_name": "core-switch", "container": "grafana", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake.path("container")._rows[0]["status"] == "stopped"


@pytest.mark.asyncio
async def test_stop_container_resolves_by_tag_when_no_name(device: Device):
    fake = FakeConnection(data={("container",): [{".id": "*1", "tag": "alpine:latest", "status": "running"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_containers_factory(fake))

    _content, applied = await mcp.call_tool(
        "stop_container", {"device_name": "core-switch", "container": "alpine:latest", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake.path("container")._rows[0]["status"] == "stopped"


@pytest.mark.asyncio
async def test_start_container_unknown_container_raises_clear_error(device: Device):
    fake = FakeConnection(data={("container",): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_containers_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("start_container", {"device_name": "core-switch", "container": "ghost", "confirm": True})
    assert "ghost" in str(exc_info.value)


@pytest.mark.asyncio
async def test_stop_container_rejects_invalid_container_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "stop_container", {"device_name": "core-switch", "container": "grafana\nrm -rf /", "confirm": True}
        )
    assert "not valid" in str(exc_info.value) or "control characters" in str(exc_info.value)


# --- set_route_distance / enable_route / disable_route (v0.9) ---------------


@pytest.mark.asyncio
async def test_set_route_distance_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_route_distance",
            {
                "device_name": "core-switch",
                "dst_address": "0.0.0.0/0",
                "gateway": "10.0.0.254",
                "distance": 5,
                "confirm": True,
            },
        )
    assert "read-only" in str(exc_info.value)
    assert "distance" not in fake_connection.path("ip", "route")._rows[0]


@pytest.mark.asyncio
async def test_set_route_distance_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "set_route_distance",
        {
            "device_name": "core-switch",
            "dst_address": "0.0.0.0/0",
            "gateway": "10.0.0.254",
            "distance": 5,
            "confirm": False,
        },
    )
    assert preview["applied"] is False
    assert preview["after"]["distance"] == "5"
    assert "distance" not in fake_connection.path("ip", "route")._rows[0]

    _content, applied = await mcp.call_tool(
        "set_route_distance",
        {
            "device_name": "core-switch",
            "dst_address": "0.0.0.0/0",
            "gateway": "10.0.0.254",
            "distance": 5,
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    assert fake_connection.path("ip", "route")._rows[0]["distance"] == "5"


@pytest.mark.asyncio
async def test_set_route_distance_unknown_route_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_route_distance",
            {
                "device_name": "core-switch",
                "dst_address": "10.10.10.0/24",
                "gateway": "10.0.0.254",
                "distance": 5,
                "confirm": True,
            },
        )
    assert "10.10.10.0/24" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_route_distance_ambiguous_route_raises_clear_error(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "dup"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_route_distance",
            {
                "device_name": "core-switch",
                "dst_address": "0.0.0.0/0",
                "gateway": "10.0.0.254",
                "distance": 5,
                "confirm": True,
            },
        )
    assert "ambiguous" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_set_route_distance_rejects_invalid_distance_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_route_distance",
            {
                "device_name": "core-switch",
                "dst_address": "0.0.0.0/0",
                "gateway": "10.0.0.254",
                "distance": 999,
                "confirm": True,
            },
        )
    assert "1-255" in str(exc_info.value) or "out of range" in str(exc_info.value)


@pytest.mark.asyncio
async def test_disable_route_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "disable_route",
        {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["after"]["disabled"] == "yes"

    _content, applied = await mcp.call_tool(
        "disable_route",
        {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake_connection.path("ip", "route")._rows[0]["disabled"] == "yes"


@pytest.mark.asyncio
async def test_disable_route_default_route_preview_carries_warning(device: Device, fake_connection: FakeConnection):
    """CRITICAL for this round: disabling the default route (dst 0.0.0.0/0,
    route *1 in the fixture) is the dangerous case this write exists to
    flag - the preview's `warning` field must be non-null and mention the
    default route, so a caller can't miss it before confirming."""
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "disable_route",
        {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "confirm": False},
    )
    assert preview["warning"] is not None
    assert "0.0.0.0/0" in preview["warning"]
    assert "default" in preview["warning"].lower()


@pytest.mark.asyncio
async def test_disable_route_non_default_route_preview_has_no_warning(device: Device):
    fake = FakeConnection(
        data={("ip", "route"): [{".id": "*1", "dst-address": "10.10.0.0/24", "gateway": "10.0.0.254"}]}
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "disable_route",
        {"device_name": "core-switch", "dst_address": "10.10.0.0/24", "gateway": "10.0.0.254", "confirm": False},
    )
    assert preview["warning"] is None


@pytest.mark.asyncio
async def test_enable_route_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    await mcp.call_tool(
        "disable_route",
        {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "confirm": True},
    )
    _content, applied = await mcp.call_tool(
        "enable_route",
        {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "confirm": True},
    )
    assert applied["applied"] is True
    assert applied["warning"] is None
    assert fake_connection.path("ip", "route")._rows[0]["disabled"] == "no"


@pytest.mark.asyncio
async def test_enable_route_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_route",
            {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_disable_route_ambiguous_without_disambiguator_raises_clear_error(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "primary"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.253", "comment": "backup"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "disable_route", {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "confirm": True}
        )
    assert "ambiguous" in str(exc_info.value).lower()


# --- add_route / remove_route (v1.5) -----------------------------------------


@pytest.mark.asyncio
async def test_add_route_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_route",
            {"device_name": "core-switch", "dst_address": "10.40.0.0/24", "gateway": "10.0.0.254", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "route")._rows) == 3


@pytest.mark.asyncio
async def test_add_route_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_route",
        {
            "device_name": "core-switch",
            "dst_address": "10.40.0.0/24",
            "gateway": "10.0.0.254",
            "distance": 2,
            "comment": "backup link",
            "confirm": False,
        },
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "route")._rows) == 3

    _content, applied = await mcp.call_tool(
        "add_route",
        {
            "device_name": "core-switch",
            "dst_address": "10.40.0.0/24",
            "gateway": "10.0.0.254",
            "distance": 2,
            "comment": "backup link",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "route")._rows
    created = next(row for row in rows if row["dst-address"] == "10.40.0.0/24")
    assert created["gateway"] == "10.0.0.254"
    assert created["distance"] == "2"
    assert created["comment"] == "backup link"


@pytest.mark.asyncio
async def test_add_route_default_route_preview_carries_warning(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_route",
        {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.253", "confirm": False},
    )
    assert preview["warning"] is not None
    assert "0.0.0.0/0" in preview["warning"]
    assert "default" in preview["warning"].lower()


@pytest.mark.asyncio
async def test_add_route_never_refuses_duplicate_dst_address(device: Device, fake_connection: FakeConnection):
    """Adding a second route to an already-used dst-address (the normal
    failover shape) must never raise ResourceAlreadyExistsError."""
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "add_route",
        {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.253", "confirm": True},
    )
    assert applied["applied"] is True
    matches = [row for row in fake_connection.path("ip", "route")._rows if row["dst-address"] == "0.0.0.0/0"]
    assert len(matches) == 2


@pytest.mark.asyncio
async def test_add_route_rejects_invalid_gateway_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_route",
            {"device_name": "core-switch", "dst_address": "10.40.0.0/24", "gateway": "not-a-gateway!", "confirm": True},
        )
    assert "gateway" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_remove_route_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_route", {"device_name": "core-switch", "dst_address": "10.20.0.0/24", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "route")._rows) == 3


@pytest.mark.asyncio
async def test_remove_route_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_route", {"device_name": "core-switch", "dst_address": "10.20.0.0/24", "confirm": False}
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "route")._rows) == 3

    _content, applied = await mcp.call_tool(
        "remove_route", {"device_name": "core-switch", "dst_address": "10.20.0.0/24", "confirm": True}
    )
    assert applied["applied"] is True
    remaining = {row["dst-address"] for row in fake_connection.path("ip", "route")._rows}
    assert "10.20.0.0/24" not in remaining
    assert len(fake_connection.path("ip", "route")._rows) == 2


@pytest.mark.asyncio
async def test_remove_route_refuses_dynamic_route(device: Device, fake_connection: FakeConnection):
    """CRITICAL for this round: route *3 in the fixture is dynamic
    (dynamic=true, a connected-route look-alike) - removing it must raise
    a ToolError through the MCP boundary and must NOT remove the row."""
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_route", {"device_name": "core-switch", "dst_address": "10.30.0.0/24", "confirm": True}
        )
    assert "dynamic" in str(exc_info.value).lower()
    remaining = {row["dst-address"] for row in fake_connection.path("ip", "route")._rows}
    assert "10.30.0.0/24" in remaining
    assert len(fake_connection.path("ip", "route")._rows) == 3


@pytest.mark.asyncio
async def test_remove_route_default_route_preview_carries_warning(device: Device):
    fake = FakeConnection(data={("ip", "route"): [{".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_route", {"device_name": "core-switch", "dst_address": "0.0.0.0/0", "confirm": False}
    )
    assert preview["warning"] is not None
    assert "0.0.0.0/0" in preview["warning"]
    assert "default" in preview["warning"].lower()


@pytest.mark.asyncio
async def test_remove_route_unknown_dst_address_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_route", {"device_name": "core-switch", "dst_address": "10.50.0.0/24", "confirm": True}
        )
    assert "10.50.0.0/24" in str(exc_info.value)


# --- add_netwatch / remove_netwatch (v0.9) -----------------------------------


@pytest.mark.asyncio
async def test_add_netwatch_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("add_netwatch", {"device_name": "core-switch", "host": "1.1.1.1", "confirm": True})
    assert "read-only" in str(exc_info.value)
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "1.1.1.1" not in hosts


@pytest.mark.asyncio
async def test_add_netwatch_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_netwatch",
        {"device_name": "core-switch", "host": "1.1.1.1", "interval": "30s", "comment": "secondary", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["after"] == {"host": "1.1.1.1", "interval": "30s", "comment": "secondary"}
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "1.1.1.1" not in hosts

    _content, applied = await mcp.call_tool(
        "add_netwatch",
        {"device_name": "core-switch", "host": "1.1.1.1", "interval": "30s", "comment": "secondary", "confirm": True},
    )
    assert applied["applied"] is True
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "1.1.1.1" in hosts


@pytest.mark.asyncio
async def test_add_netwatch_rejects_duplicate_host(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("add_netwatch", {"device_name": "core-switch", "host": "8.8.8.8", "confirm": True})
    assert "8.8.8.8" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_netwatch_rejects_invalid_host_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("add_netwatch", {"device_name": "core-switch", "host": "not-an-ip", "confirm": True})
    assert "not a valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_netwatch_tool_schema_has_no_up_script_or_down_script_parameter(settings: Settings):
    """SECURITY: the add_netwatch MCP tool's own parameter schema must never
    expose an up_script/down_script field - there is no way for a caller to
    even attempt to pass an executable RouterOS script through this tool,
    let alone have it accepted (see guard.add_netwatch's docstring)."""
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    tools = {t.name: t for t in await mcp.list_tools()}
    properties = tools["add_netwatch"].inputSchema.get("properties", {})
    assert "up_script" not in properties
    assert "down_script" not in properties
    assert set(properties) == {"device_name", "host", "interval", "comment", "confirm"}


@pytest.mark.asyncio
async def test_remove_netwatch_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("remove_netwatch", {"device_name": "core-switch", "host": "8.8.8.8", "confirm": True})
    assert "read-only" in str(exc_info.value)
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "8.8.8.8" in hosts


@pytest.mark.asyncio
async def test_remove_netwatch_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_netwatch", {"device_name": "core-switch", "host": "8.8.8.8", "confirm": False}
    )
    assert preview["applied"] is False
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "8.8.8.8" in hosts

    _content, applied = await mcp.call_tool(
        "remove_netwatch", {"device_name": "core-switch", "host": "8.8.8.8", "confirm": True}
    )
    assert applied["applied"] is True
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "8.8.8.8" not in hosts


@pytest.mark.asyncio
async def test_remove_netwatch_unknown_host_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("remove_netwatch", {"device_name": "core-switch", "host": "9.9.9.9", "confirm": True})
    assert "9.9.9.9" in str(exc_info.value)


# --- add_static_dns / remove_static_dns (v0.10) -------------------------------


@pytest.mark.asyncio
async def test_add_static_dns_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_static_dns",
            {"device_name": "core-switch", "name": "blocked.example.com", "address": "0.0.0.0", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    names = {row["name"] for row in fake_connection.path("ip", "dns", "static")._rows}
    assert "blocked.example.com" not in names


@pytest.mark.asyncio
async def test_add_static_dns_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_static_dns",
        {"device_name": "core-switch", "name": "blocked.example.com", "address": "0.0.0.0", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["after"] == {"name": "blocked.example.com", "type": "A", "address": "0.0.0.0"}
    names = {row["name"] for row in fake_connection.path("ip", "dns", "static")._rows}
    assert "blocked.example.com" not in names

    _content, applied = await mcp.call_tool(
        "add_static_dns",
        {"device_name": "core-switch", "name": "blocked.example.com", "address": "0.0.0.0", "confirm": True},
    )
    assert applied["applied"] is True
    names = {row["name"] for row in fake_connection.path("ip", "dns", "static")._rows}
    assert "blocked.example.com" in names


@pytest.mark.asyncio
async def test_add_static_dns_cname_writes_cname_field(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "add_static_dns",
        {
            "device_name": "core-switch",
            "name": "www.example.com",
            "address": "target.example.com",
            "record_type": "CNAME",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    row = next(row for row in fake_connection.path("ip", "dns", "static")._rows if row["name"] == "www.example.com")
    assert row["cname"] == "target.example.com"
    assert "address" not in row


@pytest.mark.asyncio
async def test_add_static_dns_rejects_duplicate_name_and_type(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    await mcp.call_tool(
        "add_static_dns",
        {"device_name": "core-switch", "name": "blocked.example.com", "address": "0.0.0.0", "confirm": True},
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_static_dns",
            {"device_name": "core-switch", "name": "blocked.example.com", "address": "1.2.3.4", "confirm": True},
        )
    assert "blocked.example.com" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_static_dns_rejects_invalid_name_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_static_dns",
            {"device_name": "core-switch", "name": "not a host", "address": "0.0.0.0", "confirm": True},
        )
    assert "not a valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_static_dns_blocked_read_only_by_default(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "dns", "static"): [{".id": "*1", "name": "blocked.example.com", "type": "A", "address": "0.0.0.0"}]
        }
    )
    settings = Settings(allow_write=False, devices={device.name: device})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_static_dns", {"device_name": "core-switch", "name": "blocked.example.com", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_static_dns_preview_then_confirm(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "dns", "static"): [{".id": "*1", "name": "blocked.example.com", "type": "A", "address": "0.0.0.0"}]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_static_dns", {"device_name": "core-switch", "name": "blocked.example.com", "confirm": False}
    )
    assert preview["applied"] is False
    names = {row["name"] for row in fake.path("ip", "dns", "static")._rows}
    assert "blocked.example.com" in names

    _content, applied = await mcp.call_tool(
        "remove_static_dns", {"device_name": "core-switch", "name": "blocked.example.com", "confirm": True}
    )
    assert applied["applied"] is True
    names = {row["name"] for row in fake.path("ip", "dns", "static")._rows}
    assert "blocked.example.com" not in names


@pytest.mark.asyncio
async def test_remove_static_dns_unknown_name_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_static_dns", {"device_name": "core-switch", "name": "ghost.example.com", "confirm": True}
        )
    assert "ghost.example.com" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_static_dns_ambiguous_without_record_type_raises_clear_error(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "dns", "static"): [
                {".id": "*1", "name": "roundrobin.example.com", "type": "A", "address": "10.0.0.1"},
                {".id": "*2", "name": "roundrobin.example.com", "type": "A", "address": "10.0.0.2"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_static_dns", {"device_name": "core-switch", "name": "roundrobin.example.com", "confirm": True}
        )
    assert "ambiguous" in str(exc_info.value).lower()


# --- clear_dns_cache (v0.10) --------------------------------------------------


@pytest.mark.asyncio
async def test_clear_dns_cache_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("clear_dns_cache", {"device_name": "core-switch", "confirm": True})
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_clear_dns_cache_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    """The shared fixture's ("ip", "dns", "cache") has exactly one cached entry."""
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool("clear_dns_cache", {"device_name": "core-switch", "confirm": False})
    assert preview["applied"] is False
    assert preview["before"] == {"cached_entries": 1}
    assert preview["after"] == {"cached_entries": 0}

    _content, applied = await mcp.call_tool("clear_dns_cache", {"device_name": "core-switch", "confirm": True})
    assert applied["applied"] is True
    assert ("/ip/dns/cache/flush", {}) in fake_connection.calls


# --- remove_dhcp_lease (v0.10) ------------------------------------------------


def _dhcp_leases_server_fixture() -> FakeConnection:
    return FakeConnection(
        data={
            ("ip", "dhcp-server", "lease"): [
                {".id": "*1", "address": "10.0.0.50", "mac-address": "AA:BB:CC:DD:EE:01", "dynamic": "true"},
                {".id": "*2", "address": "10.0.0.60", "mac-address": "AA:BB:CC:DD:EE:02", "dynamic": "false"},
            ]
        }
    )


@pytest.mark.asyncio
async def test_remove_dhcp_lease_blocked_read_only_by_default(device: Device):
    fake = _dhcp_leases_server_fixture()
    settings = Settings(allow_write=False, devices={device.name: device})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_dhcp_lease", {"device_name": "core-switch", "mac_address": "AA:BB:CC:DD:EE:01", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_dhcp_lease_dynamic_preview_then_confirm_carries_no_warning(device: Device):
    fake = _dhcp_leases_server_fixture()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_dhcp_lease", {"device_name": "core-switch", "mac_address": "AA:BB:CC:DD:EE:01", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["warning"] is None

    _content, applied = await mcp.call_tool(
        "remove_dhcp_lease", {"device_name": "core-switch", "mac_address": "AA:BB:CC:DD:EE:01", "confirm": True}
    )
    assert applied["applied"] is True
    macs = {row["mac-address"] for row in fake.path("ip", "dhcp-server", "lease")._rows}
    assert "AA:BB:CC:DD:EE:01" not in macs


@pytest.mark.asyncio
async def test_remove_dhcp_lease_static_lease_carries_warning(device: Device):
    fake = _dhcp_leases_server_fixture()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_dhcp_lease", {"device_name": "core-switch", "mac_address": "AA:BB:CC:DD:EE:02", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["warning"] is not None
    assert "STATIC" in preview["warning"]


@pytest.mark.asyncio
async def test_remove_dhcp_lease_unknown_raises_clear_error(device: Device):
    fake = _dhcp_leases_server_fixture()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_dhcp_lease", {"device_name": "core-switch", "mac_address": "AA:BB:CC:DD:EE:99", "confirm": True}
        )
    assert "AA:BB:CC:DD:EE:99" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_dhcp_lease_requires_address_or_mac(device: Device):
    fake = _dhcp_leases_server_fixture()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("remove_dhcp_lease", {"device_name": "core-switch", "confirm": True})
    assert "address" in str(exc_info.value).lower() or "mac_address" in str(exc_info.value).lower()


# --- wake_on_lan (v0.10) -------------------------------------------------------


@pytest.mark.asyncio
async def test_wake_on_lan_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "wake_on_lan",
            {"device_name": "core-switch", "mac_address": "AA:BB:CC:DD:EE:FF", "interface": "ether1", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_wake_on_lan_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "wake_on_lan",
        {"device_name": "core-switch", "mac_address": "aa:bb:cc:dd:ee:ff", "interface": "ether1", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["after"] == {"mac_address": "AA:BB:CC:DD:EE:FF", "interface": "ether1"}

    _content, applied = await mcp.call_tool(
        "wake_on_lan",
        {"device_name": "core-switch", "mac_address": "aa:bb:cc:dd:ee:ff", "interface": "ether1", "confirm": True},
    )
    assert applied["applied"] is True
    assert ("/tool/wol", {"mac-address": "AA:BB:CC:DD:EE:FF", "interface": "ether1"}) in fake_connection.calls


@pytest.mark.asyncio
async def test_wake_on_lan_rejects_invalid_mac_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "wake_on_lan",
            {"device_name": "core-switch", "mac_address": "not-a-mac", "interface": "ether1", "confirm": True},
        )
    assert "not valid" in str(exc_info.value)


# --- connection_tracking (v0.11) -----------------------------------------
#
# The shared fixture's ("ip", "firewall", "connection") table (see
# conftest) has two rows: a TCP connection (10.0.0.50:51413 ->
# 93.184.216.34:443, tcp-state "established") and a UDP one
# (10.0.0.60:33221 -> 8.8.8.8:53).


@pytest.mark.asyncio
async def test_connection_tracking_requires_at_least_one_filter(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("connection_tracking", {"device_name": "core-switch"})
    assert "filter" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_connection_tracking_not_gated_by_read_only(settings: Settings, fake_connection: FakeConnection):
    """Read-only, unlike every write tool - must work with the default
    (allow_write=False) settings fixture."""
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("connection_tracking", {"device_name": "core-switch", "protocol": "tcp"})
    assert result["total_matched"] == 1


@pytest.mark.asyncio
async def test_connection_tracking_filters_by_src_address(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool(
        "connection_tracking", {"device_name": "core-switch", "src_address": "10.0.0.50"}
    )
    assert result["total_matched"] == 1
    entry = result["connections"][0]
    assert entry["src-address"] == "10.0.0.50"
    assert entry["src-port"] == "51413"
    assert entry["dst-address"] == "93.184.216.34"
    assert entry["dst-port"] == "443"
    assert entry["protocol"] == "tcp"
    assert entry["tcp-state"] == "established"


@pytest.mark.asyncio
async def test_connection_tracking_filters_by_dst_address(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool(
        "connection_tracking", {"device_name": "core-switch", "dst_address": "8.8.8.8"}
    )
    assert result["total_matched"] == 1
    assert result["connections"][0]["protocol"] == "udp"


@pytest.mark.asyncio
async def test_connection_tracking_filters_by_dst_port(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("connection_tracking", {"device_name": "core-switch", "dst_port": 53})
    assert result["total_matched"] == 1
    assert result["connections"][0]["dst-address"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_connection_tracking_filters_by_protocol_only_returns_matches(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("connection_tracking", {"device_name": "core-switch", "protocol": "udp"})
    assert result["total_matched"] == 1
    assert result["connections"][0]["src-address"] == "10.0.0.60"
    assert result["truncated"] is False


@pytest.mark.asyncio
async def test_connection_tracking_combining_filters_that_match_nothing_returns_empty(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool(
        "connection_tracking", {"device_name": "core-switch", "src_address": "10.0.0.50", "protocol": "udp"}
    )
    assert result["connections"] == []
    assert result["total_matched"] == 0
    assert result["truncated"] is False


@pytest.mark.asyncio
async def test_connection_tracking_truncates_and_signals_it(device: Device):
    rows = [
        {
            ".id": f"*{i}",
            "protocol": "tcp",
            "src-address": f"10.0.0.{i % 250 + 1}:1234",
            "dst-address": "93.184.216.34:443",
        }
        for i in range(150)
    ]
    fake = FakeConnection(data={("ip", "firewall", "connection"): rows})
    settings = Settings(allow_write=False, devices={device.name: device})
    mcp = build_server(settings=settings, client_factory=_factory(fake))

    _content, result = await mcp.call_tool("connection_tracking", {"device_name": "core-switch", "protocol": "tcp"})
    assert result["total_matched"] == 150
    assert len(result["connections"]) == 100
    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_connection_tracking_rejects_invalid_dst_port(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("connection_tracking", {"device_name": "core-switch", "dst_port": 70000})
    assert "dst_port" in str(exc_info.value)


@pytest.mark.asyncio
async def test_connection_tracking_rejects_invalid_src_address(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("connection_tracking", {"device_name": "core-switch", "src_address": "not-an-ip"})
    assert "not a valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_connection_tracking_handles_bracketed_ipv6_and_portless_addresses(device: Device):
    """RouterOS's src-address/dst-address field packs address+port together
    - split_address_port (formatting.py) must handle a bracketed IPv6:port
    pair and a bare address with no port at all (e.g. an ICMP entry, which
    has no port concept)."""
    fake = FakeConnection(
        data={
            ("ip", "firewall", "connection"): [
                {
                    ".id": "*1",
                    "protocol": "tcp",
                    "src-address": "[2001:db8::1]:443",
                    "dst-address": "[2001:db8::2]:51413",
                },
                {
                    ".id": "*2",
                    "protocol": "icmp",
                    "src-address": "10.0.0.5",
                    "dst-address": "10.0.0.6",
                },
            ]
        }
    )
    settings = Settings(allow_write=False, devices={device.name: device})
    mcp = build_server(settings=settings, client_factory=_factory(fake))

    _content, result = await mcp.call_tool(
        "connection_tracking", {"device_name": "core-switch", "src_address": "2001:db8::1"}
    )
    assert result["total_matched"] == 1
    entry = result["connections"][0]
    assert entry["src-address"] == "2001:db8::1"
    assert entry["src-port"] == "443"

    _content, result = await mcp.call_tool("connection_tracking", {"device_name": "core-switch", "protocol": "icmp"})
    assert result["total_matched"] == 1
    entry = result["connections"][0]
    assert entry["src-address"] == "10.0.0.5"
    assert entry["src-port"] is None


# --- enable_firewall_rule / disable_firewall_rule (v0.11) -----------------
#
# The shared fixture's ("ip", "firewall", "filter") table (see conftest) has
# a pre-created, disabled rule with comment "Bloqueio_Ataque_X" (chain
# "forward", action "drop") - the admin-creates/LLM-enables workflow this
# tool pair exists for.


@pytest.mark.asyncio
async def test_enable_firewall_rule_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_firewall_rule", {"device_name": "core-switch", "comment": "Bloqueio_Ataque_X", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_firewall_rule_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "enable_firewall_rule", {"device_name": "core-switch", "comment": "Bloqueio_Ataque_X", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["disabled"] is True
    assert preview["after"]["disabled"] == "no"
    # The full matched rule - not just `disabled` - so the operator can
    # confirm WHICH rule this is before applying.
    assert preview["before"]["chain"] == "forward"
    assert preview["before"]["action"] == "drop"
    rows = fake_connection.path("ip", "firewall", "filter")._rows
    assert next(r for r in rows if r["comment"] == "Bloqueio_Ataque_X")["disabled"] is True

    _content, applied = await mcp.call_tool(
        "enable_firewall_rule", {"device_name": "core-switch", "comment": "Bloqueio_Ataque_X", "confirm": True}
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "filter")._rows
    assert next(r for r in rows if r["comment"] == "Bloqueio_Ataque_X")["disabled"] == "no"
    # No rule was created - still exactly the two rules the fixture started with.
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_disable_firewall_rule_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "disable_firewall_rule", {"device_name": "core-switch", "comment": "allow established", "confirm": True}
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "filter")._rows
    assert next(r for r in rows if r["comment"] == "allow established")["disabled"] == "yes"


@pytest.mark.asyncio
async def test_enable_firewall_rule_unknown_comment_raises_clear_error_and_creates_nothing(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_firewall_rule", {"device_name": "core-switch", "comment": "no-such-rule", "confirm": True}
        )
    assert "no-such-rule" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "filter")._rows) == 2


@pytest.mark.asyncio
async def test_enable_firewall_rule_ambiguous_comment_raises_and_disambiguated_by_chain(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "forward", "action": "drop", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("enable_firewall_rule", {"device_name": "core-switch", "comment": "dup", "confirm": True})
    assert "ambiguous" in str(exc_info.value).lower()
    # Neither row was touched.
    assert all(row.get("disabled") == "true" for row in fake.path("ip", "firewall", "filter")._rows)

    _content, applied = await mcp.call_tool(
        "enable_firewall_rule",
        {"device_name": "core-switch", "comment": "dup", "chain": "forward", "confirm": True},
    )
    assert applied["applied"] is True
    rows = {row["chain"]: row["disabled"] for row in fake.path("ip", "firewall", "filter")._rows}
    assert rows == {"input": "true", "forward": "no"}


@pytest.mark.asyncio
async def test_enable_firewall_rule_rejects_empty_comment_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("enable_firewall_rule", {"device_name": "core-switch", "comment": "", "confirm": True})
    assert "non-empty" in str(exc_info.value)


# --- enable_nat_rule / disable_nat_rule (v1.4) -----------------------------
#
# The shared fixture's ("ip", "firewall", "nat") table (see conftest) has an
# enabled "wan-masquerade" row (chain "srcnat") and a pre-created, disabled
# "rdp-forward-maintenance" row (chain "dstnat") - same admin-creates/
# LLM-enables workflow as enable_firewall_rule above, extended to NAT.


@pytest.mark.asyncio
async def test_enable_nat_rule_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_nat_rule", {"device_name": "core-switch", "comment": "rdp-forward-maintenance", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_nat_rule_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "enable_nat_rule", {"device_name": "core-switch", "comment": "rdp-forward-maintenance", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["disabled"] is True
    assert preview["after"]["disabled"] == "no"
    assert preview["before"]["chain"] == "dstnat"
    rows = fake_connection.path("ip", "firewall", "nat")._rows
    assert next(r for r in rows if r["comment"] == "rdp-forward-maintenance")["disabled"] is True

    _content, applied = await mcp.call_tool(
        "enable_nat_rule", {"device_name": "core-switch", "comment": "rdp-forward-maintenance", "confirm": True}
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "nat")._rows
    assert next(r for r in rows if r["comment"] == "rdp-forward-maintenance")["disabled"] == "no"
    # No rule was created - still exactly the two rows the fixture started with.
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_disable_nat_rule_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "disable_nat_rule", {"device_name": "core-switch", "comment": "wan-masquerade", "confirm": True}
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "nat")._rows
    assert next(r for r in rows if r["comment"] == "wan-masquerade")["disabled"] == "yes"


@pytest.mark.asyncio
async def test_enable_nat_rule_unknown_comment_raises_clear_error_and_creates_nothing(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_nat_rule", {"device_name": "core-switch", "comment": "no-such-rule", "confirm": True}
        )
    assert "no-such-rule" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "nat")._rows) == 2


@pytest.mark.asyncio
async def test_enable_nat_rule_ambiguous_comment_raises_and_disambiguated_by_chain(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "nat"): [
                {".id": "*1", "chain": "srcnat", "action": "masquerade", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "dstnat", "action": "dst-nat", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("enable_nat_rule", {"device_name": "core-switch", "comment": "dup", "confirm": True})
    assert "ambiguous" in str(exc_info.value).lower()
    assert all(row.get("disabled") == "true" for row in fake.path("ip", "firewall", "nat")._rows)

    _content, applied = await mcp.call_tool(
        "enable_nat_rule",
        {"device_name": "core-switch", "comment": "dup", "chain": "dstnat", "confirm": True},
    )
    assert applied["applied"] is True
    rows = {row["chain"]: row["disabled"] for row in fake.path("ip", "firewall", "nat")._rows}
    assert rows == {"srcnat": "true", "dstnat": "no"}


@pytest.mark.asyncio
async def test_enable_nat_rule_rejects_empty_comment_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("enable_nat_rule", {"device_name": "core-switch", "comment": "", "confirm": True})
    assert "non-empty" in str(exc_info.value)


# --- enable_mangle_rule / disable_mangle_rule (v1.4) -----------------------
#
# The shared fixture's ("ip", "firewall", "mangle") table (see conftest) has
# an enabled "mark-voip" row (chain "forward") and a pre-created, disabled
# "Mark_Backup_Traffic" row (chain "prerouting") - same admin-creates/
# LLM-enables workflow as enable_firewall_rule above, extended to mangle.


@pytest.mark.asyncio
async def test_enable_mangle_rule_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_mangle_rule", {"device_name": "core-switch", "comment": "Mark_Backup_Traffic", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_mangle_rule_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "enable_mangle_rule", {"device_name": "core-switch", "comment": "Mark_Backup_Traffic", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["disabled"] is True
    assert preview["after"]["disabled"] == "no"
    assert preview["before"]["chain"] == "prerouting"
    rows = fake_connection.path("ip", "firewall", "mangle")._rows
    assert next(r for r in rows if r["comment"] == "Mark_Backup_Traffic")["disabled"] is True

    _content, applied = await mcp.call_tool(
        "enable_mangle_rule", {"device_name": "core-switch", "comment": "Mark_Backup_Traffic", "confirm": True}
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "mangle")._rows
    assert next(r for r in rows if r["comment"] == "Mark_Backup_Traffic")["disabled"] == "no"
    # No rule was created - still exactly the two rows the fixture started with.
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_disable_mangle_rule_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "disable_mangle_rule", {"device_name": "core-switch", "comment": "mark-voip", "confirm": True}
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "mangle")._rows
    assert next(r for r in rows if r["comment"] == "mark-voip")["disabled"] == "yes"


@pytest.mark.asyncio
async def test_enable_mangle_rule_unknown_comment_raises_clear_error_and_creates_nothing(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_mangle_rule", {"device_name": "core-switch", "comment": "no-such-rule", "confirm": True}
        )
    assert "no-such-rule" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "mangle")._rows) == 2


@pytest.mark.asyncio
async def test_enable_mangle_rule_ambiguous_comment_raises_and_disambiguated_by_chain(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "mangle"): [
                {".id": "*1", "chain": "prerouting", "action": "mark-packet", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "forward", "action": "mark-packet", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("enable_mangle_rule", {"device_name": "core-switch", "comment": "dup", "confirm": True})
    assert "ambiguous" in str(exc_info.value).lower()
    assert all(row.get("disabled") == "true" for row in fake.path("ip", "firewall", "mangle")._rows)

    _content, applied = await mcp.call_tool(
        "enable_mangle_rule",
        {"device_name": "core-switch", "comment": "dup", "chain": "forward", "confirm": True},
    )
    assert applied["applied"] is True
    rows = {row["chain"]: row["disabled"] for row in fake.path("ip", "firewall", "mangle")._rows}
    assert rows == {"prerouting": "true", "forward": "no"}


@pytest.mark.asyncio
async def test_enable_mangle_rule_rejects_empty_comment_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("enable_mangle_rule", {"device_name": "core-switch", "comment": "", "confirm": True})
    assert "non-empty" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_mangle_rule_rejects_invalid_chain_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_mangle_rule",
            {"device_name": "core-switch", "comment": "Mark_Backup_Traffic", "chain": "bad chain!", "confirm": True},
        )
    assert "chain" in str(exc_info.value).lower()


# --- WireGuard management (v0.13) -------------------------------------------
#
# The shared fixture's ("interface", "wireguard") table (see conftest) has
# one interface, "wg1"; ("interface", "wireguard", "peers") has one peer,
# "peer1", on interface "wg1". Real-shaped (44-char base64) public keys used
# below - the validator this round adds (validate_wireguard_key) is strict
# about that shape, unlike the shared fixture's own loosely-shaped
# "PUBKEYAAAA==" placeholder (fine for a read-only tool that never validates
# what a device hands back, but not accepted as *caller input* here).

_REMOTE_PEER_PUBKEY_1 = "OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0="
_REMOTE_PEER_PUBKEY_2 = "idtcei5gRabTeh7XqgAXUdSWE5+QsiES7xHooeHonO8="


@pytest.mark.asyncio
async def test_add_wireguard_interface_blocked_read_only_by_default(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("add_wireguard_interface", {"device_name": "core-switch", "name": "wg2", "confirm": True})
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_wireguard_interface_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_wireguard_interface", {"device_name": "core-switch", "name": "wg2", "listen_port": 51820, "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"] == {}
    # The preview never invents a public-key - RouterOS hasn't generated one yet.
    assert preview["after"] == {"name": "wg2", "listen-port": "51820"}
    assert "public-key" not in preview["after"]
    names = {row["name"] for row in fake_connection.path("interface", "wireguard")._rows}
    assert "wg2" not in names

    _content, applied = await mcp.call_tool(
        "add_wireguard_interface", {"device_name": "core-switch", "name": "wg2", "listen_port": 51820, "confirm": True}
    )
    assert applied["applied"] is True
    assert applied["after"]["name"] == "wg2"
    # The applied result DOES report the real public-key RouterOS generated...
    assert "public-key" in applied["after"]
    # ...but never a private-key.
    assert "private-key" not in applied["after"]


@pytest.mark.asyncio
async def test_add_wireguard_interface_rejects_duplicate_name(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("add_wireguard_interface", {"device_name": "core-switch", "name": "wg1", "confirm": True})
    assert "wg1" in str(exc_info.value)
    assert len(fake_connection.path("interface", "wireguard")._rows) == 1


@pytest.mark.asyncio
async def test_add_wireguard_interface_never_leaks_private_key_anywhere(
    device: Device, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """CRITICAL SECURITY TEST (v0.13): the fake device (tests/fakes.py)
    simulates RouterOS generating a real key pair on `add` - including a
    distinctively-marked private-key - so this proves that marker never
    reaches (a) the tool's own return value, or (b) the audit journal
    (before AND after), or (c) any other log line, regardless of how the
    private-key got onto the row RouterOS handed back."""
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "add_wireguard_interface", {"device_name": "core-switch", "name": "wg-secure-test", "confirm": True}
    )

    # (a) the tool's own return value
    assert "private-key" not in applied["after"]
    assert "FAKE-PRIVATE-KEY-MUST-NEVER-LEAK" not in str(applied)
    # The device really did generate one (proves the redaction had something
    # to strip - a vacuous test would prove nothing).
    device_rows = fake_connection.path("interface", "wireguard")._rows
    created_row = next(r for r in device_rows if r["name"] == "wg-secure-test")
    assert "FAKE-PRIVATE-KEY-MUST-NEVER-LEAK" in created_row["private-key"]

    # (b) the audit journal - both before and after
    raw = log_path.read_text(encoding="utf-8")
    assert "FAKE-PRIVATE-KEY-MUST-NEVER-LEAK" not in raw
    event = json.loads(raw.strip().splitlines()[-1])
    assert "private-key" not in event["summary"]["before"]
    assert "private-key" not in event["summary"]["after"]
    assert event["summary"]["after"]["name"] == "wg-secure-test"

    # (c) no other log line either.
    assert "FAKE-PRIVATE-KEY-MUST-NEVER-LEAK" not in str(_content)


@pytest.mark.asyncio
async def test_add_wireguard_peer_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_wireguard_peer",
            {
                "device_name": "core-switch",
                "interface": "wg1",
                "public_key": _REMOTE_PEER_PUBKEY_1,
                "allowed_address": "10.10.0.5/32",
                "confirm": True,
            },
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_wireguard_peer_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_wireguard_peer",
        {
            "device_name": "core-switch",
            "interface": "wg1",
            "public_key": _REMOTE_PEER_PUBKEY_1,
            "allowed_address": "10.10.0.5/32",
            "endpoint_address": "203.0.113.9",
            "endpoint_port": 51820,
            "persistent_keepalive": "25s",
            "comment": "laptop",
            "confirm": False,
        },
    )
    assert preview["applied"] is False
    assert preview["after"]["public-key"] == _REMOTE_PEER_PUBKEY_1
    assert preview["after"]["allowed-address"] == "10.10.0.5/32"
    assert preview["after"]["endpoint-address"] == "203.0.113.9"
    assert preview["after"]["endpoint-port"] == "51820"
    assert preview["after"]["persistent-keepalive"] == "25s"
    peers = fake_connection.path("interface", "wireguard", "peers")._rows
    assert all(row.get("public-key") != _REMOTE_PEER_PUBKEY_1 for row in peers)

    _content, applied = await mcp.call_tool(
        "add_wireguard_peer",
        {
            "device_name": "core-switch",
            "interface": "wg1",
            "public_key": _REMOTE_PEER_PUBKEY_1,
            "allowed_address": "10.10.0.5/32",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    peers = fake_connection.path("interface", "wireguard", "peers")._rows
    assert any(row.get("public-key") == _REMOTE_PEER_PUBKEY_1 for row in peers)


@pytest.mark.asyncio
async def test_add_wireguard_peer_unknown_interface_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_wireguard_peer",
            {
                "device_name": "core-switch",
                "interface": "ghost-tunnel",
                "public_key": _REMOTE_PEER_PUBKEY_1,
                "allowed_address": "10.10.0.5/32",
                "confirm": True,
            },
        )
    assert "ghost-tunnel" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_wireguard_peer_rejects_duplicate_public_key_on_same_interface(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    await mcp.call_tool(
        "add_wireguard_peer",
        {
            "device_name": "core-switch",
            "interface": "wg1",
            "public_key": _REMOTE_PEER_PUBKEY_1,
            "allowed_address": "10.10.0.5/32",
            "confirm": True,
        },
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_wireguard_peer",
            {
                "device_name": "core-switch",
                "interface": "wg1",
                "public_key": _REMOTE_PEER_PUBKEY_1,
                "allowed_address": "10.10.0.6/32",
                "confirm": True,
            },
        )
    assert _REMOTE_PEER_PUBKEY_1 in str(exc_info.value)
    peers = [
        row
        for row in fake_connection.path("interface", "wireguard", "peers")._rows
        if row.get("public-key") == _REMOTE_PEER_PUBKEY_1
    ]
    assert len(peers) == 1


@pytest.mark.asyncio
async def test_add_wireguard_peer_rejects_invalid_public_key_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_wireguard_peer",
            {
                "device_name": "core-switch",
                "interface": "wg1",
                "public_key": "not-a-valid-key",
                "allowed_address": "10.10.0.5/32",
                "confirm": True,
            },
        )
    assert "public_key" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_wireguard_peer_rejects_invalid_allowed_address_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_wireguard_peer",
            {
                "device_name": "core-switch",
                "interface": "wg1",
                "public_key": _REMOTE_PEER_PUBKEY_1,
                "allowed_address": "not-a-cidr",
                "confirm": True,
            },
        )
    assert "not-a-cidr" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_wireguard_peer_blocked_read_only_by_default(settings: Settings):
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {".id": "*1", "interface": "wg1", "public-key": _REMOTE_PEER_PUBKEY_1, "comment": "laptop"}
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_wireguard_peer",
            {"device_name": "core-switch", "interface": "wg1", "public_key": _REMOTE_PEER_PUBKEY_1, "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_wireguard_peer_by_public_key_preview_then_confirm(device: Device):
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {".id": "*1", "interface": "wg1", "public-key": _REMOTE_PEER_PUBKEY_1, "comment": "laptop"}
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_wireguard_peer",
        {"device_name": "core-switch", "interface": "wg1", "public_key": _REMOTE_PEER_PUBKEY_1, "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["before"]["public-key"] == _REMOTE_PEER_PUBKEY_1
    assert preview["after"] == {}
    assert len(fake.path("interface", "wireguard", "peers")._rows) == 1

    _content, applied = await mcp.call_tool(
        "remove_wireguard_peer",
        {"device_name": "core-switch", "interface": "wg1", "public_key": _REMOTE_PEER_PUBKEY_1, "confirm": True},
    )
    assert applied["applied"] is True
    assert fake.path("interface", "wireguard", "peers")._rows == []


@pytest.mark.asyncio
async def test_remove_wireguard_peer_by_comment(device: Device):
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {".id": "*1", "interface": "wg1", "public-key": _REMOTE_PEER_PUBKEY_1, "comment": "laptop"}
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, applied = await mcp.call_tool(
        "remove_wireguard_peer",
        {"device_name": "core-switch", "interface": "wg1", "comment": "laptop", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake.path("interface", "wireguard", "peers")._rows == []


@pytest.mark.asyncio
async def test_remove_wireguard_peer_unknown_public_key_raises_clear_error(device: Device):
    fake = FakeConnection(data={("interface", "wireguard", "peers"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_wireguard_peer",
            {"device_name": "core-switch", "interface": "wg1", "public_key": _REMOTE_PEER_PUBKEY_1, "confirm": True},
        )
    assert _REMOTE_PEER_PUBKEY_1 in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_wireguard_peer_ambiguous_comment_raises_and_disambiguated_by_public_key(device: Device):
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {".id": "*1", "interface": "wg1", "public-key": _REMOTE_PEER_PUBKEY_1, "comment": "dup"},
                {".id": "*2", "interface": "wg1", "public-key": _REMOTE_PEER_PUBKEY_2, "comment": "dup"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_wireguard_peer",
            {"device_name": "core-switch", "interface": "wg1", "comment": "dup", "confirm": True},
        )
    assert "ambiguous" in str(exc_info.value).lower()
    assert len(fake.path("interface", "wireguard", "peers")._rows) == 2

    _content, applied = await mcp.call_tool(
        "remove_wireguard_peer",
        {"device_name": "core-switch", "interface": "wg1", "public_key": _REMOTE_PEER_PUBKEY_2, "confirm": True},
    )
    assert applied["applied"] is True
    remaining = fake.path("interface", "wireguard", "peers")._rows
    assert len(remaining) == 1
    assert remaining[0]["public-key"] == _REMOTE_PEER_PUBKEY_1


@pytest.mark.asyncio
async def test_remove_wireguard_peer_requires_public_key_or_comment(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_wireguard_peer", {"device_name": "core-switch", "interface": "wg1", "confirm": True}
        )
    assert "public_key" in str(exc_info.value) or "comment" in str(exc_info.value)


# --- AAA/PKI visibility: certificates / users / user_active / radius (v1.6) --


@pytest.mark.asyncio
async def test_certificates_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("certificates", {"device_name": "core-switch"})
    row = result["result"][0]
    assert row["name"] == "api-cert"
    assert row["common-name"] == "core-switch.example.com"
    assert row["invalid-after"] == "2099-01-15 12:00:00"
    # Fixture's invalid-after is far in the future - daysUntilExpiry must be
    # computed (present) and clearly positive.
    assert row["daysUntilExpiry"] > 0


@pytest.mark.asyncio
async def test_certificates_parses_ros_abbreviated_date_shape(settings: Settings):
    """RouterOS's OTHER observed invalid-after shape - "jan/15/2027
    12:00:00" - must parse too, not just the ISO-like one the shared fixture
    uses."""
    fake = FakeConnection(
        data={
            ("certificate",): [
                {".id": "*1", "name": "legacy-cert", "invalid-after": "jan/15/2099 12:00:00"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("certificates", {"device_name": "core-switch"})
    assert result["result"][0]["daysUntilExpiry"] > 0


@pytest.mark.asyncio
async def test_certificates_tolerates_unparseable_invalid_after(settings: Settings):
    """A device/RouterOS version rendering invalid-after in some other
    format must never break `certificates` - daysUntilExpiry is simply
    omitted, and the raw field is left untouched."""
    fake = FakeConnection(
        data={
            ("certificate",): [
                {".id": "*1", "name": "weird-cert", "invalid-after": "not-a-real-date"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("certificates", {"device_name": "core-switch"})
    row = result["result"][0]
    assert row["invalid-after"] == "not-a-real-date"
    assert "daysUntilExpiry" not in row


@pytest.mark.asyncio
async def test_certificates_strips_private_key_defensively(settings: Settings):
    """SECURITY: even though RouterOS's own /certificate reply never
    genuinely carries a private-key over the API, `certificates` must strip
    one defensively if it's ever present - same belt-and-suspenders
    reasoning as wireguard_peers/wireguard_interfaces."""
    fake = FakeConnection(
        data={
            ("certificate",): [
                {".id": "*1", "name": "api-cert", "private-key": "SUPERSECRETPRIVATEKEY=="},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("certificates", {"device_name": "core-switch"})
    assert "private-key" not in result["result"][0]
    assert "SUPERSECRETPRIVATEKEY==" not in str(result)


@pytest.mark.asyncio
async def test_certificates_returns_empty_when_no_certificates(settings: Settings):
    fake = FakeConnection(raise_for={("certificate",): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("certificates", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_users_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("users", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "admin"
    assert result["result"][0]["group"] == "full"


@pytest.mark.asyncio
async def test_users_returns_empty_when_menu_absent(settings: Settings):
    fake = FakeConnection(raise_for={("user",): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("users", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_user_active_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("user_active", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "admin"
    assert result["result"][0]["via"] == "api"


@pytest.mark.asyncio
async def test_user_active_returns_empty_when_menu_absent(settings: Settings):
    fake = FakeConnection(raise_for={("user", "active"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("user_active", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_radius_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("radius", {"device_name": "core-switch"})
    assert result["result"][0]["service"] == "ppp"
    assert result["result"][0]["address"] == "10.0.0.200"


@pytest.mark.asyncio
async def test_radius_never_exposes_secret(settings: Settings, fake_connection: FakeConnection):
    """SECURITY: the RADIUS shared secret must never appear in the tool's
    result - see the fixture's "fake-shared-secret" marker."""
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("radius", {"device_name": "core-switch"})
    assert "secret" not in result["result"][0]
    assert "fake-shared-secret" not in str(result)


@pytest.mark.asyncio
async def test_radius_returns_empty_when_no_radius_configured(settings: Settings):
    fake = FakeConnection(raise_for={("radius",): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("radius", {"device_name": "core-switch"})
    assert result["result"] == []


# --- security_audit / security_events (v0.12, read-only) -----------------
#
# security.py's own unit tests (tests/test_security.py) cover every
# individual check and the aggregation/summary/secret-leak behaviour in
# detail; these are end-to-end smoke tests through the actual MCP tool
# layer, confirming both tools are wired up, unaffected by the write gate,
# and validate their inputs the same way `logs` does.


@pytest.mark.asyncio
async def test_security_audit_not_gated_by_read_only(settings: Settings, fake_connection: FakeConnection):
    """Read-only, unlike every write tool - must work with the default
    (allow_write=False) settings fixture."""
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("security_audit", {"device_name": "core-switch"})
    assert "findings" in result
    assert "summary" in result
    assert set(result["summary"]) == {"high", "medium", "low", "info"}


@pytest.mark.asyncio
async def test_security_audit_flags_shared_fixtures_open_input_chain(
    settings: Settings, fake_connection: FakeConnection
):
    """The shared `fake_connection` fixture's chain=input rule (see
    conftest) is action=accept, not drop/reject - security_audit's
    firewall-input-drop heuristic must flag it."""
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("security_audit", {"device_name": "core-switch"})
    categories = {f["category"] for f in result["findings"]}
    assert "firewall" in categories


@pytest.mark.asyncio
async def test_security_audit_findings_are_sorted_by_severity(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "service"): [{"name": "telnet", "disabled": "false", "address": ""}],
            ("user",): [{"name": "admin", "group": "full"}],
            ("ip", "firewall", "filter"): [{"chain": "input", "action": "drop", "disabled": "false"}],
        }
    )
    settings = Settings(allow_write=False, devices={device.name: device})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("security_audit", {"device_name": "core-switch"})
    severities = [f["severity"] for f in result["findings"]]
    assert severities == ["high", "info"]
    assert result["summary"]["high"] == 1
    assert result["summary"]["info"] == 1


@pytest.mark.asyncio
async def test_security_audit_never_touches_the_device_when_read_would_fail(device: Device):
    """Every menu it reads raises - the tool must still return a
    well-formed, empty result rather than propagating an error."""
    fake = FakeConnection(
        raise_for={
            ("ip", "service"): LibRouterosError("no such command"),
            ("ip", "firewall", "filter"): LibRouterosError("no such command"),
            ("snmp", "community"): LibRouterosError("no such command"),
            ("ip", "dns"): LibRouterosError("no such command"),
            ("system", "package", "update"): LibRouterosError("no such command"),
            ("interface", "wireless", "security-profiles"): LibRouterosError("no such command"),
            ("interface", "wifi", "security"): LibRouterosError("no such command"),
            ("user",): LibRouterosError("no such command"),
        }
    )
    settings = Settings(allow_write=False, devices={device.name: device})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("security_audit", {"device_name": "core-switch"})
    assert result["findings"] == []
    assert result["summary"] == {"high": 0, "medium": 0, "low": 0, "info": 0}


@pytest.mark.asyncio
async def test_security_events_not_gated_by_read_only(settings: Settings, device: Device):
    assert settings.allow_write is False
    fake = FakeConnection(
        data={
            ("log",): [
                {".id": "*1", "topics": "system,info,account", "message": "user admin logged in via winbox"},
                {".id": "*2", "topics": "interface,link", "message": "ether1 up"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("security_events", {"device_name": "core-switch"})
    assert len(result["result"]) == 1
    assert result["result"][0]["message"] == "user admin logged in via winbox"


@pytest.mark.asyncio
async def test_security_events_default_limit_and_ordering(device: Device):
    rows = [{".id": f"*{i}", "topics": "system,info,account", "message": f"login {i}"} for i in range(5)]
    fake = FakeConnection(data={("log",): rows})
    settings = Settings(allow_write=False, devices={device.name: device})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("security_events", {"device_name": "core-switch", "limit": 2})
    assert [r["message"] for r in result["result"]] == ["login 3", "login 4"]


@pytest.mark.asyncio
async def test_security_events_rejects_non_positive_limit(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("security_events", {"device_name": "core-switch", "limit": 0})
    assert "positive" in str(exc_info.value).lower()


# --- D3: list_write_operations surfaces guard.ALLOWLIST metadata ---------


@pytest.mark.asyncio
async def test_list_write_operations_exposes_allowlist_metadata(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    _content, result = await mcp.call_tool("list_write_operations", {})
    rows = result["result"]
    entry = next(row for row in rows if row["name"] == "set_identity")
    assert entry["path"] == "system/identity"
    assert entry["action"] == "update"
    assert "identity" in entry["description"].lower()


@pytest.mark.asyncio
async def test_list_write_operations_does_not_require_write_enabled(settings: Settings):
    """Read-only metadata tool: must work even with MIKROTIK_ALLOW_WRITE=false."""
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    _content, result = await mcp.call_tool("list_write_operations", {})
    assert result["result"]


# --- R3: limit/count <= 0 must raise a validation error, not clamp -------


@pytest.mark.asyncio
async def test_logs_happy_path_returns_most_recent_entries_up_to_limit(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("logs", {"device_name": "core-switch", "limit": 1})
    # fake_connection's ("log",) fixture has 2 rows - limit=1 keeps the most
    # recent one only.
    assert len(result["result"]) == 1
    assert result["result"][0]["message"] == "ether1 up"


@pytest.mark.asyncio
async def test_logs_filters_by_topics_substring(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("logs", {"device_name": "core-switch", "topics": "interface"})
    assert [row["message"] for row in result["result"]] == ["ether1 up"]


@pytest.mark.asyncio
async def test_logs_rejects_non_positive_limit(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("logs", {"device_name": "core-switch", "limit": 0})
    assert "positive" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_ping_rejects_non_positive_count(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("ping", {"device_name": "core-switch", "address": "8.8.8.8", "count": -1})
    assert "positive" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_ip_routes_rejects_non_positive_limit(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("ip_routes", {"device_name": "core-switch", "limit": 0})
    assert "positive" in str(exc_info.value).lower()


# --- R2: ip_routes accepts an optional limit, mirroring logs -------------


@pytest.mark.asyncio
async def test_ip_routes_without_limit_returns_all_rows(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ip_routes", {"device_name": "core-switch"})
    assert len(result["result"]) == 3


@pytest.mark.asyncio
async def test_ip_routes_limit_caps_returned_rows(settings: Settings):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0"},
                {".id": "*2", "dst-address": "10.0.0.0/24"},
                {".id": "*3", "dst-address": "192.168.0.0/24"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ip_routes", {"device_name": "core-switch", "limit": 2})
    assert len(result["result"]) == 2


# --- A2: meta-test - server.py must never call a write primitive directly.
# The guard (guard.py) is the only place allowed to call
# MikrotikClient.update()/add()/remove(); server.py must always go through a
# named guard.py function instead. This makes that invariant self-enforcing
# instead of a convention a future PR could silently break. -----------------


def test_server_never_calls_write_primitives_directly():
    server_src = (Path(__file__).resolve().parent.parent / "src" / "mcp_mikrotik" / "server.py").read_text(
        encoding="utf-8"
    )
    forbidden = re.compile(r"\.(update|add|remove|start|stop|flush|wol|save|move)\(")
    match = forbidden.search(server_src)
    assert match is None, (
        f"server.py contains a direct write-primitive call ({match.group() if match else ''!r}) - "
        "every write must go through a dedicated function in guard.py instead "
        "(see guard.py's module docstring)."
    )


# --- E4: MIKROTIK_LOG_LEVEL validation, fallback to INFO with a warning --


@pytest.mark.parametrize("raw,expected", [("DEBUG", "DEBUG"), ("debug", "DEBUG"), ("warning", "WARNING")])
def test_resolve_log_level_accepts_valid_values(raw: str, expected: str):
    assert _resolve_log_level(raw) == expected


def test_resolve_log_level_defaults_to_info_when_unset():
    assert _resolve_log_level(None) == "INFO"


def test_resolve_log_level_falls_back_to_info_on_invalid_value(caplog: pytest.LogCaptureFixture):
    with caplog.at_level("WARNING", logger="mcp_mikrotik"):
        result = _resolve_log_level("NOT_A_LEVEL")
    assert result == "INFO"
    assert any("Invalid MIKROTIK_LOG_LEVEL" in record.message for record in caplog.records)


# --- v0.5: audit journal + correlation id, exercised end to end through ---
# --- FastMCP's call_tool boundary (not by calling guard.py directly) ------


@pytest.mark.asyncio
async def test_write_tool_call_produces_one_audit_journal_entry(
    device: Device, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    await mcp.call_tool("set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True})

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["outcome"] == "applied"
    assert event["tool"] == "set_identity"
    assert "s3cret" not in log_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_read_tool_call_never_writes_to_the_audit_journal(
    settings: Settings, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Only guarded writes are audit-journaled - a plain read tool call must
    not produce a journal entry."""
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    await mcp.call_tool("system_info", {"device_name": "core-switch"})

    assert not log_path.exists() or log_path.read_text(encoding="utf-8") == ""


@pytest.mark.asyncio
async def test_blocked_write_tool_call_still_journals_an_error(
    settings: Settings, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError):
        await mcp.call_tool("set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True})

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["outcome"] == "error"


@pytest.mark.asyncio
async def test_unhandled_error_log_line_is_prefixed_with_a_correlation_id(
    settings: Settings, caplog: pytest.LogCaptureFixture
):
    """server.py's `_safe` wrapper binds a correlation id for every tool
    call and prefixes it onto the server-side log line for that call - see
    server.py's `_safe`/`correlation.bind`."""

    def _broken_factory(_settings: Settings, _device_name: str):
        raise RuntimeError("boom - not a MikrotikMCPError, so _safe's generic path handles it")

    mcp = build_server(settings=settings, client_factory=_broken_factory)

    with caplog.at_level("ERROR", logger="mcp_mikrotik"), pytest.raises(ToolError):
        await mcp.call_tool("system_info", {"device_name": "core-switch"})

    matches = [r for r in caplog.records if "Unhandled error in tool system_info" in r.message]
    assert len(matches) == 1
    # "[<12 hex chars>] Unhandled error in tool system_info"
    prefix = matches[0].message.split("]")[0].lstrip("[")
    assert len(prefix) == 12


# --- hotspot_active / torch / list_backups (v0.14, read-only) --------------


@pytest.mark.asyncio
async def test_hotspot_active_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("hotspot_active", {"device_name": "core-switch"})
    assert result["result"][0]["user"] == "visitor1"
    assert result["result"][0]["address"] == "10.5.0.10"


@pytest.mark.asyncio
async def test_hotspot_active_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("hotspot_active", {"device_name": "core-switch"})
    assert result["result"]


@pytest.mark.asyncio
async def test_hotspot_active_returns_empty_list_for_device_with_no_hotspot(settings: Settings):
    """A device with no hotspot server configured at all raises
    DeviceCommandError from client.path() - treated the same as "no active
    sessions here" rather than a hard failure, same convention as
    ppp_active/ipsec_active_peers."""
    fake = FakeConnection(
        raise_for={
            ("ip", "hotspot", "active"): DeviceCommandError("core-switch", "ip/hotspot/active", "no such command")
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("hotspot_active", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_torch_happy_path_sorts_by_traffic_volume_descending(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("torch", {"device_name": "core-switch", "interface": "ether1"})
    # Fixture's ether1 torch data: flow 1 has tx=500000+rx=1500000=2,000,000;
    # flow 2 has tx=1000+rx=2000=3,000 - flow 1 must sort first.
    assert result["total_matched"] == 2
    assert result["truncated"] is False
    assert len(result["flows"]) == 2
    assert result["flows"][0]["src-address"] == "10.0.0.50"
    assert result["flows"][1]["src-address"] == "10.0.0.60"


@pytest.mark.asyncio
async def test_torch_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("torch", {"device_name": "core-switch", "interface": "ether1"})
    assert result["flows"]


@pytest.mark.asyncio
async def test_torch_returns_empty_flows_for_interface_with_no_traffic(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("torch", {"device_name": "core-switch", "interface": "ether2"})
    assert result == {"flows": [], "total_matched": 0, "truncated": False}


@pytest.mark.asyncio
async def test_torch_treats_unparseable_tx_rx_as_zero_instead_of_failing(settings: Settings):
    """RouterOS's own torch field names/types for a flow's traffic volume
    aren't perfectly uniform - a flow whose tx/rx can't be parsed as an int
    must sort last (treated as 0 traffic), not blow up the whole call."""
    fake = FakeConnection(
        torch_replies={
            "ether1": [
                {"src-address": "10.0.0.70", "tx": "not-a-number", "rx": None},
                {"src-address": "10.0.0.50", "tx": "500000", "rx": "1500000"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("torch", {"device_name": "core-switch", "interface": "ether1"})
    assert result["total_matched"] == 2
    # The well-formed, higher-traffic flow sorts first; the unparseable one
    # is treated as 0 traffic and sorts last, not dropped or erroring out.
    assert result["flows"][0]["src-address"] == "10.0.0.50"
    assert result["flows"][1]["src-address"] == "10.0.0.70"


@pytest.mark.asyncio
async def test_torch_rejects_invalid_interface_name_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("torch", {"device_name": "core-switch", "interface": "ether1; reboot"})
    assert "not valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_torch_sends_optional_filters_and_once_flag_as_structured_params(settings: Settings):
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    await mcp.call_tool(
        "torch",
        {
            "device_name": "core-switch",
            "interface": "ether1",
            "src_address": "10.0.0.50",
            "dst_address": "8.8.8.8",
            "port": 443,
        },
    )
    cmd, kwargs = fake.calls[-1]
    assert cmd == "/tool/torch"
    assert kwargs == {
        "interface": "ether1",
        "once": "",
        "src-address": "10.0.0.50",
        "dst-address": "8.8.8.8",
        "port": "443",
    }


@pytest.mark.asyncio
async def test_torch_caps_results_at_max_torch_limit_and_sets_truncated(settings: Settings):
    fake = FakeConnection(
        torch_replies={"ether1": [{"src-address": f"10.0.0.{i}", "tx": str(i), "rx": "0"} for i in range(60)]}
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("torch", {"device_name": "core-switch", "interface": "ether1"})
    assert result["total_matched"] == 60
    assert result["truncated"] is True
    assert len(result["flows"]) == 50
    # Biggest talker (tx=59) sorts first.
    assert result["flows"][0]["src-address"] == "10.0.0.59"


@pytest.mark.asyncio
async def test_list_backups_happy_path_filters_to_backup_files(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("list_backups", {"device_name": "core-switch"})
    names = {row["name"] for row in result["result"]}
    assert names == {"core-switch-2026-01-01.backup"}
    entry = result["result"][0]
    assert entry["size"] == "524288"
    assert entry["creation-time"] == "jan/01/2026 00:00:00"


@pytest.mark.asyncio
async def test_list_backups_returns_empty_list_when_no_backups_exist(settings: Settings):
    fake = FakeConnection(data={("file",): [{".id": "*1", "name": "flash/skins", "type": "directory"}]})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("list_backups", {"device_name": "core-switch"})
    assert result["result"] == []


# --- add_hotspot_user (v0.14, write, guarded) -------------------------------


@pytest.mark.asyncio
async def test_add_hotspot_user_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_hotspot_user",
            {"device_name": "core-switch", "name": "visitor2", "password": "Passw0rd!", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_hotspot_user_preview_then_confirm_includes_qr_payload(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_hotspot_user",
        {"device_name": "core-switch", "name": "visitor2", "password": "Passw0rd!", "confirm": False},
    )
    assert preview["applied"] is False
    # The tool result DOES contain the plaintext password - this IS the
    # point of a voucher (see guard.add_hotspot_user's docstring).
    assert preview["username"] == "visitor2"
    assert preview["password"] == "Passw0rd!"
    assert preview["qr_payload"] == "visitor2:Passw0rd!"
    names = {row["name"] for row in fake_connection.path("ip", "hotspot", "user")._rows}
    assert "visitor2" not in names

    _content, applied = await mcp.call_tool(
        "add_hotspot_user",
        {"device_name": "core-switch", "name": "visitor2", "password": "Passw0rd!", "confirm": True},
    )
    assert applied["applied"] is True
    assert applied["qr_payload"] == "visitor2:Passw0rd!"
    names = {row["name"] for row in fake_connection.path("ip", "hotspot", "user")._rows}
    assert "visitor2" in names


@pytest.mark.asyncio
async def test_add_hotspot_user_rejects_duplicate_name(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    await mcp.call_tool(
        "add_hotspot_user",
        {"device_name": "core-switch", "name": "visitor2", "password": "Passw0rd!", "confirm": True},
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_hotspot_user",
            {"device_name": "core-switch", "name": "visitor2", "password": "AnotherPass1", "confirm": True},
        )
    assert "visitor2" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_hotspot_user_password_in_result_but_never_in_audit_journal(
    device: Device, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """End-to-end proof of the v0.14 password asymmetry, through the actual
    MCP tool call boundary (not just guard.py directly - see
    tests/test_guard_audit.py's guard-level version of this same proof):
    the tool RESULT contains the plaintext voucher password, but the audit
    journal - fed by the exact same guard.WritePreview - never does."""
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "add_hotspot_user",
        {
            "device_name": "core-switch",
            "name": "visitor-secure",
            "password": "TotallySecretVoucher!",
            "confirm": True,
        },
    )

    # (a) the tool RESULT contains the plaintext password.
    assert applied["password"] == "TotallySecretVoucher!"
    assert applied["qr_payload"] == "visitor-secure:TotallySecretVoucher!"

    # (b) the audit journal never does.
    raw = log_path.read_text(encoding="utf-8")
    assert "TotallySecretVoucher!" not in raw
    event = json.loads(raw.strip().splitlines()[-1])
    assert "password" not in event["summary"]["after"]


# --- create_backup (v0.14, write, guarded) ----------------------------------


@pytest.mark.asyncio
async def test_create_backup_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("create_backup", {"device_name": "core-switch", "name": "nightly-backup", "confirm": True})
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_create_backup_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "create_backup", {"device_name": "core-switch", "name": "nightly-backup", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["after"] == {"name": "nightly-backup"}
    assert ("/system/backup/save", {"name": "nightly-backup"}) not in fake_connection.calls

    _content, applied = await mcp.call_tool(
        "create_backup", {"device_name": "core-switch", "name": "nightly-backup", "confirm": True}
    )
    assert applied["applied"] is True
    assert ("/system/backup/save", {"name": "nightly-backup"}) in fake_connection.calls


@pytest.mark.asyncio
async def test_create_backup_rejects_duplicate_name(device: Device, fake_connection: FakeConnection):
    """The shared fixture's ("file",) table already has a
    "core-switch-2026-01-01.backup" file (see conftest)."""
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "create_backup",
            {"device_name": "core-switch", "name": "core-switch-2026-01-01", "confirm": True},
        )
    assert "core-switch-2026-01-01" in str(exc_info.value)


@pytest.mark.asyncio
async def test_create_backup_password_never_in_result_or_audit_journal(
    device: Device, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Unlike add_hotspot_user's voucher password, create_backup's optional
    encryption `password` must never reach the CALLER either - only the
    device."""
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "create_backup",
        {
            "device_name": "core-switch",
            "name": "encrypted-backup",
            "password": "file-encrypt-key",
            "confirm": True,
        },
    )
    assert "password" not in applied["after"]
    assert "file-encrypt-key" not in str(applied)
    assert (
        "/system/backup/save",
        {"name": "encrypted-backup", "password": "file-encrypt-key"},
    ) in fake_connection.calls

    raw = log_path.read_text(encoding="utf-8")
    assert "file-encrypt-key" not in raw
    event = json.loads(raw.strip().splitlines()[-1])
    assert "password" not in event["summary"]["after"]


# --- list_vlans / add_vlan / remove_vlan (v1.2) ------------------------------


def _vlan_fake() -> FakeConnection:
    return FakeConnection(
        data={
            ("interface", "vlan"): [
                {".id": "*1", "name": "vlan100", "vlan-id": "100", "interface": "bridge1", "disabled": "false"},
                {".id": "*2", "name": "vlan200", "vlan-id": "200", "interface": "bridge1", "disabled": "true"},
            ]
        }
    )


@pytest.mark.asyncio
async def test_list_vlans_filters_disabled_by_default(settings: Settings):
    fake = _vlan_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("list_vlans", {"device_name": "core-switch"})
    names = {row["name"] for row in result["result"]}
    assert names == {"vlan100"}

    _content, result_all = await mcp.call_tool("list_vlans", {"device_name": "core-switch", "include_disabled": True})
    names_all = {row["name"] for row in result_all["result"]}
    assert names_all == {"vlan100", "vlan200"}


@pytest.mark.asyncio
async def test_add_vlan_blocked_read_only_by_default(settings: Settings):
    fake = _vlan_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_vlan",
            {"device_name": "core-switch", "name": "vlan300", "vlan_id": 300, "interface": "bridge1", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake.path("interface", "vlan")._rows) == 2


@pytest.mark.asyncio
async def test_add_vlan_preview_then_confirm(device: Device):
    fake = _vlan_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "add_vlan",
        {
            "device_name": "core-switch",
            "name": "vlan300",
            "vlan_id": 300,
            "interface": "bridge1",
            "comment": "voice",
            "confirm": False,
        },
    )
    assert preview["applied"] is False
    assert len(fake.path("interface", "vlan")._rows) == 2

    _content, applied = await mcp.call_tool(
        "add_vlan",
        {
            "device_name": "core-switch",
            "name": "vlan300",
            "vlan_id": 300,
            "interface": "bridge1",
            "comment": "voice",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    rows = fake.path("interface", "vlan")._rows
    created = next(row for row in rows if row["name"] == "vlan300")
    assert created["vlan-id"] == "300"
    assert created["interface"] == "bridge1"
    assert created["comment"] == "voice"


@pytest.mark.asyncio
async def test_add_vlan_rejects_duplicate_name(device: Device):
    fake = _vlan_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_vlan",
            {"device_name": "core-switch", "name": "vlan100", "vlan_id": 101, "interface": "bridge1", "confirm": True},
        )
    assert "already exists" in str(exc_info.value)
    assert len(fake.path("interface", "vlan")._rows) == 2


@pytest.mark.asyncio
async def test_add_vlan_rejects_invalid_vlan_id_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_vlan",
            {
                "device_name": "core-switch",
                "name": "vlan300",
                "vlan_id": 5000,
                "interface": "bridge1",
                "confirm": True,
            },
        )
    assert "vlan_id" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_vlan_blocked_read_only_by_default(settings: Settings):
    fake = _vlan_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("remove_vlan", {"device_name": "core-switch", "name": "vlan100", "confirm": True})
    assert "read-only" in str(exc_info.value)
    assert len(fake.path("interface", "vlan")._rows) == 2


@pytest.mark.asyncio
async def test_remove_vlan_preview_then_confirm(device: Device):
    fake = _vlan_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_vlan", {"device_name": "core-switch", "name": "vlan100", "confirm": False}
    )
    assert preview["applied"] is False
    assert len(fake.path("interface", "vlan")._rows) == 2

    _content, applied = await mcp.call_tool(
        "remove_vlan", {"device_name": "core-switch", "name": "vlan100", "confirm": True}
    )
    assert applied["applied"] is True
    names = {row["name"] for row in fake.path("interface", "vlan")._rows}
    assert names == {"vlan200"}


@pytest.mark.asyncio
async def test_remove_vlan_unknown_name_raises_clear_error(device: Device):
    fake = _vlan_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("remove_vlan", {"device_name": "core-switch", "name": "ghost-vlan", "confirm": True})
    assert "ghost-vlan" in str(exc_info.value)
    assert len(fake.path("interface", "vlan")._rows) == 2


# --- move_firewall_rule (v1.2) -----------------------------------------------


def _move_fake() -> FakeConnection:
    return FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "forward", "action": "accept", "comment": "rule-a"},
                {".id": "*2", "chain": "forward", "action": "accept", "comment": "rule-b"},
                {".id": "*3", "chain": "forward", "action": "drop", "comment": "rule-c"},
            ]
        }
    )


@pytest.mark.asyncio
async def test_move_firewall_rule_blocked_read_only_by_default(settings: Settings):
    fake = _move_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "move_firewall_rule", {"device_name": "core-switch", "comment": "rule-c", "position": 0, "confirm": True}
        )
    assert "read-only" in str(exc_info.value)
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-a", "rule-b", "rule-c"]


@pytest.mark.asyncio
async def test_move_firewall_rule_preview_then_confirm_by_position(device: Device):
    fake = _move_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "move_firewall_rule", {"device_name": "core-switch", "comment": "rule-c", "position": 0, "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"] == {"comment": "rule-c", "chain": "forward", "position": 2}
    assert preview["after"] == {"comment": "rule-c", "chain": "forward", "position": 0}
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-a", "rule-b", "rule-c"]

    _content, applied = await mcp.call_tool(
        "move_firewall_rule", {"device_name": "core-switch", "comment": "rule-c", "position": 0, "confirm": True}
    )
    assert applied["applied"] is True
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-c", "rule-a", "rule-b"]
    # Never edited any rule's own fields - only reordered.
    moved = next(row for row in fake.path("ip", "firewall", "filter")._rows if row["comment"] == "rule-c")
    assert moved["action"] == "drop"


@pytest.mark.asyncio
async def test_move_firewall_rule_by_before_comment(device: Device):
    fake = _move_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, applied = await mcp.call_tool(
        "move_firewall_rule",
        {"device_name": "core-switch", "comment": "rule-c", "before_comment": "rule-a", "confirm": True},
    )
    assert applied["applied"] is True
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-c", "rule-a", "rule-b"]


@pytest.mark.asyncio
async def test_move_firewall_rule_requires_exactly_one_of_before_comment_or_position(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("move_firewall_rule", {"device_name": "core-switch", "comment": "rule-c", "confirm": True})
    assert "exactly one" in str(exc_info.value)


@pytest.mark.asyncio
async def test_move_firewall_rule_unknown_comment_raises_clear_error_and_creates_nothing(device: Device):
    fake = _move_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "move_firewall_rule", {"device_name": "core-switch", "comment": "ghost", "position": 0, "confirm": True}
        )
    assert "ghost" in str(exc_info.value)
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-a", "rule-b", "rule-c"]


@pytest.mark.asyncio
async def test_move_firewall_rule_ambiguous_comment_raises_and_disambiguated_by_chain(device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "dup"},
                {".id": "*2", "chain": "forward", "action": "accept", "comment": "anchor"},
                {".id": "*3", "chain": "forward", "action": "drop", "comment": "dup"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "move_firewall_rule",
            {"device_name": "core-switch", "comment": "dup", "before_comment": "anchor", "confirm": True},
        )
    assert "ambiguous" in str(exc_info.value).lower()

    _content, applied = await mcp.call_tool(
        "move_firewall_rule",
        {
            "device_name": "core-switch",
            "comment": "dup",
            "chain": "forward",
            "before_comment": "anchor",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    order = [row[".id"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["*1", "*3", "*2"]


# --- add_ppp_secret / remove_ppp_secret (v1.3, write, guarded) --------------


@pytest.mark.asyncio
async def test_add_ppp_secret_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_ppp_secret",
            {"device_name": "core-switch", "name": "customer2", "password": "Passw0rd!", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_ppp_secret_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_ppp_secret",
        {
            "device_name": "core-switch",
            "name": "customer2",
            "password": "Passw0rd!",
            "service": "pppoe",
            "confirm": False,
        },
    )
    assert preview["applied"] is False
    assert preview["after"] == {"name": "customer2", "password": "Passw0rd!", "service": "pppoe"}
    names = {row["name"] for row in fake_connection.path("ppp", "secret")._rows}
    assert "customer2" not in names

    _content, applied = await mcp.call_tool(
        "add_ppp_secret",
        {
            "device_name": "core-switch",
            "name": "customer2",
            "password": "Passw0rd!",
            "service": "pppoe",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    names = {row["name"] for row in fake_connection.path("ppp", "secret")._rows}
    assert "customer2" in names


@pytest.mark.asyncio
async def test_add_ppp_secret_preview_with_optional_fields(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "add_ppp_secret",
        {
            "device_name": "core-switch",
            "name": "customer3",
            "password": "Passw0rd!",
            "service": "pppoe",
            "profile": "default-encryption",
            "remote_address": "10.40.0.20",
            "comment": "new fiber customer",
            "confirm": True,
        },
    )
    assert applied["after"] == {
        "name": "customer3",
        "password": "Passw0rd!",
        "service": "pppoe",
        "profile": "default-encryption",
        "remote-address": "10.40.0.20",
        "comment": "new fiber customer",
    }


@pytest.mark.asyncio
async def test_add_ppp_secret_rejects_duplicate_name(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_ppp_secret",
            {"device_name": "core-switch", "name": "pppoe-client1", "password": "Passw0rd!", "confirm": True},
        )
    assert "pppoe-client1" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_ppp_secret_rejects_invalid_service_before_touching_device(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_ppp_secret",
            {
                "device_name": "core-switch",
                "name": "customer4",
                "password": "Passw0rd!",
                "service": "not-a-service",
                "confirm": True,
            },
        )
    assert "service" in str(exc_info.value).lower()
    names = {row["name"] for row in fake_connection.path("ppp", "secret")._rows}
    assert "customer4" not in names


@pytest.mark.asyncio
async def test_add_ppp_secret_rejects_invalid_name_before_touching_device(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError):
        await mcp.call_tool(
            "add_ppp_secret",
            {"device_name": "core-switch", "name": "bad name!", "password": "Passw0rd!", "confirm": True},
        )


@pytest.mark.asyncio
async def test_add_ppp_secret_password_in_result_but_never_in_audit_journal(
    device: Device, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """End-to-end proof of the v1.3 password asymmetry (mirroring
    add_hotspot_user's own, v0.14), through the actual MCP tool call
    boundary: the tool RESULT contains the plaintext secret password, but
    the audit journal - fed the exact same guard.WritePreview - never
    does."""
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "add_ppp_secret",
        {
            "device_name": "core-switch",
            "name": "customer-secure",
            "password": "TotallySecretDialup!",
            "confirm": True,
        },
    )

    # (a) the tool RESULT contains the plaintext password.
    assert applied["after"]["password"] == "TotallySecretDialup!"

    # (b) the audit journal never does.
    raw = log_path.read_text(encoding="utf-8")
    assert "TotallySecretDialup!" not in raw
    event = json.loads(raw.strip().splitlines()[-1])
    assert "password" not in event["summary"]["after"]


@pytest.mark.asyncio
async def test_remove_ppp_secret_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_ppp_secret", {"device_name": "core-switch", "name": "pppoe-client1", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_ppp_secret_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_ppp_secret", {"device_name": "core-switch", "name": "pppoe-client1", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["name"] == "pppoe-client1"
    names = {row["name"] for row in fake_connection.path("ppp", "secret")._rows}
    assert "pppoe-client1" in names

    _content, applied = await mcp.call_tool(
        "remove_ppp_secret", {"device_name": "core-switch", "name": "pppoe-client1", "confirm": True}
    )
    assert applied["applied"] is True
    names = {row["name"] for row in fake_connection.path("ppp", "secret")._rows}
    assert "pppoe-client1" not in names


@pytest.mark.asyncio
async def test_remove_ppp_secret_preview_never_includes_password(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_ppp_secret", {"device_name": "core-switch", "name": "pppoe-client1", "confirm": False}
    )
    assert "password" not in preview["before"]
    assert "s3cret-fake" not in str(preview)


@pytest.mark.asyncio
async def test_remove_ppp_secret_unknown_name_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_ppp_secret", {"device_name": "core-switch", "name": "ghost-secret", "confirm": True}
        )
    assert "ghost-secret" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_ppp_secret_ambiguous_name_raises_and_removes_nothing(device: Device):
    fake = FakeConnection(
        data={
            ("ppp", "secret"): [
                {".id": "*1", "name": "dup-secret", "password": "one-fake", "service": "pppoe"},
                {".id": "*2", "name": "dup-secret", "password": "two-fake", "service": "l2tp"},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("remove_ppp_secret", {"device_name": "core-switch", "name": "dup-secret", "confirm": True})
    assert "ambiguous" in str(exc_info.value).lower()
    rows = [row for row in fake.path("ppp", "secret")._rows if row["name"] == "dup-secret"]
    assert len(rows) == 2


# --- set_ntp_servers (v1.8) --------------------------------------------------


def _ros7_ntp_fake() -> FakeConnection:
    return FakeConnection(data={("system", "ntp", "client"): [{"enabled": True, "servers": "10.0.0.1"}]})


def _ros6_ntp_fake() -> FakeConnection:
    return FakeConnection(
        data={("system", "ntp", "client"): [{"enabled": True, "primary-ntp": "10.0.0.1", "secondary-ntp": "0.0.0.0"}]}
    )


@pytest.mark.asyncio
async def test_set_ntp_servers_blocked_read_only_by_default(settings: Settings):
    fake = _ros7_ntp_fake()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("set_ntp_servers", {"device_name": "core-switch", "servers": ["1.2.3.4"], "confirm": True})
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    assert fake.path("system", "ntp", "client")._rows[0]["servers"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_set_ntp_servers_ros7_preview_then_confirm(device: Device):
    fake = _ros7_ntp_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_ntp_servers", {"device_name": "core-switch", "servers": ["1.2.3.4", "pool.ntp.org"], "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["servers"] == "10.0.0.1"
    assert preview["after"]["servers"] == "1.2.3.4,pool.ntp.org"
    # Preview must not touch the device.
    assert fake.path("system", "ntp", "client")._rows[0]["servers"] == "10.0.0.1"

    _content, applied = await mcp.call_tool(
        "set_ntp_servers", {"device_name": "core-switch", "servers": ["1.2.3.4", "pool.ntp.org"], "confirm": True}
    )
    assert applied["applied"] is True
    assert fake.path("system", "ntp", "client")._rows[0]["servers"] == "1.2.3.4,pool.ntp.org"


@pytest.mark.asyncio
async def test_set_ntp_servers_ros6_maps_to_primary_secondary(device: Device):
    fake = _ros6_ntp_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, applied = await mcp.call_tool(
        "set_ntp_servers", {"device_name": "core-switch", "servers": ["1.2.3.4", "5.6.7.8"], "confirm": True}
    )
    assert applied["applied"] is True
    row = fake.path("system", "ntp", "client")._rows[0]
    assert row["primary-ntp"] == "1.2.3.4"
    assert row["secondary-ntp"] == "5.6.7.8"
    assert "servers" not in row


@pytest.mark.asyncio
async def test_set_ntp_servers_invalid_server_raises_clear_error(device: Device):
    fake = _ros7_ntp_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_ntp_servers", {"device_name": "core-switch", "servers": ["not a valid host!!"], "confirm": True}
        )
    assert "not a valid" in str(exc_info.value).lower()
    # Nothing was written.
    assert fake.path("system", "ntp", "client")._rows[0]["servers"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_set_ntp_servers_requires_at_least_one_server(device: Device):
    fake = _ros7_ntp_fake()
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("set_ntp_servers", {"device_name": "core-switch", "servers": [], "confirm": True})
    assert "at least one" in str(exc_info.value).lower()


# --- IPv6 read parity (v1.9, read-only) --------------------------------------
#
# Mirrors ip_addresses/ip_routes/firewall_filter/arp_table/address_lists
# field-for-field on the /ipv6/* paths. TRAP (see ROADMAP.md "IPv6 parity"):
# /ipv6/* raises if the `ipv6` package is disabled on the device - every
# tool below is tested both against the shared fixture's happy-path data
# AND against a dedicated FakeConnection whose /ipv6/* path raises, proving
# the skip-if-missing behaviour (empty list, never an error) documented in
# each tool's docstring.


@pytest.mark.asyncio
async def test_ipv6_addresses_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ipv6_addresses", {"device_name": "core-switch"})
    assert result["result"][0]["address"] == "2001:db8::1/64"
    assert result["result"][0]["interface"] == "ether1"
    assert result["result"][0]["advertise"] is True
    assert result["result"][0]["disabled"] is False


@pytest.mark.asyncio
async def test_ipv6_addresses_returns_empty_when_ipv6_package_disabled(settings: Settings):
    fake = FakeConnection(raise_for={("ipv6", "address"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ipv6_addresses", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_ipv6_routes_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ipv6_routes", {"device_name": "core-switch"})
    assert len(result["result"]) == 2
    assert result["result"][0]["dst-address"] == "::/0"
    assert result["result"][0]["gateway"] == "fe80::1"
    assert result["result"][0]["active"] is True
    assert result["result"][1]["dynamic"] is True


@pytest.mark.asyncio
async def test_ipv6_routes_limit_caps_returned_rows(settings: Settings):
    fake = FakeConnection(
        data={
            ("ipv6", "route"): [
                {".id": "*1", "dst-address": "::/0"},
                {".id": "*2", "dst-address": "2001:db8:10::/64"},
                {".id": "*3", "dst-address": "2001:db8:20::/64"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ipv6_routes", {"device_name": "core-switch", "limit": 2})
    assert len(result["result"]) == 2


@pytest.mark.asyncio
async def test_ipv6_routes_rejects_non_positive_limit(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("ipv6_routes", {"device_name": "core-switch", "limit": 0})
    assert "positive" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_ipv6_routes_returns_empty_when_ipv6_package_disabled(settings: Settings):
    fake = FakeConnection(raise_for={("ipv6", "route"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ipv6_routes", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_ipv6_firewall_filter_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ipv6_firewall_filter", {"device_name": "core-switch"})
    assert result["result"][0]["chain"] == "input"
    assert result["result"][0]["action"] == "accept"
    assert result["result"][0]["disabled"] is False


@pytest.mark.asyncio
async def test_ipv6_firewall_filter_returns_empty_when_ipv6_package_disabled(settings: Settings):
    fake = FakeConnection(raise_for={("ipv6", "firewall", "filter"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ipv6_firewall_filter", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_ipv6_neighbors_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ipv6_neighbors", {"device_name": "core-switch"})
    assert result["result"][0]["address"] == "2001:db8::70"
    assert result["result"][0]["mac-address"] == "AA:BB:CC:DD:EE:70"
    assert result["result"][0]["status"] == "reachable"
    assert result["result"][0]["dynamic"] is True


@pytest.mark.asyncio
async def test_ipv6_neighbors_returns_empty_when_ipv6_package_disabled(settings: Settings):
    fake = FakeConnection(raise_for={("ipv6", "neighbor"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ipv6_neighbors", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_ipv6_firewall_address_lists_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ipv6_firewall_address_lists", {"device_name": "core-switch"})
    assert result["result"][0]["list"] == "blocked-clients-v6"
    assert result["result"][0]["address"] == "2001:db8::60/128"
    assert result["result"][0]["dynamic"] is False


@pytest.mark.asyncio
async def test_ipv6_firewall_address_lists_returns_empty_when_ipv6_package_disabled(settings: Settings):
    fake = FakeConnection(raise_for={("ipv6", "firewall", "address-list"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ipv6_firewall_address_lists", {"device_name": "core-switch"})
    assert result["result"] == []


# --- IPv6 write parity (v1.10) -----------------------------------------------
#
# Mirrors enable_firewall_rule/disable_firewall_rule, add_route/remove_route,
# add_to_address_list/remove_from_address_list field-for-field on the
# equivalent /ipv6/* path - closing out ROADMAP.md's "IPv6 parity" item
# entirely. These smoke tests exercise each tool once end to end through
# FastMCP's call_tool (guard.py's own test_guard.py has the exhaustive
# validation/resolution/refusal coverage) plus the ONE thing this round is
# genuinely new/risky on: unlike the v1.9 reads directly above (which return
# an empty list, never an error, when the `ipv6` package is disabled), a
# WRITE tool must let that error propagate as a normal ToolError - see each
# write tool's "returns_error_when_ipv6_package_disabled" test below.


@pytest.mark.asyncio
async def test_enable_ipv6_firewall_rule_blocked_read_only_by_default(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_ipv6_firewall_rule",
            {"device_name": "core-switch", "comment": "allow-v6-mgmt", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_ipv6_firewall_rule_preview_then_confirm(device: Device):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "accept", "comment": "allow-v6-mgmt", "disabled": True},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "enable_ipv6_firewall_rule", {"device_name": "core-switch", "comment": "allow-v6-mgmt", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["after"]["disabled"] == "no"
    assert fake.path("ipv6", "firewall", "filter")._rows[0]["disabled"] is True

    _content, applied = await mcp.call_tool(
        "enable_ipv6_firewall_rule", {"device_name": "core-switch", "comment": "allow-v6-mgmt", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake.path("ipv6", "firewall", "filter")._rows[0]["disabled"] == "no"
    # Never creates a rule.
    assert len(fake.path("ipv6", "firewall", "filter")._rows) == 1


@pytest.mark.asyncio
async def test_disable_ipv6_firewall_rule_preview_then_confirm(device: Device):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "filter"): [
                {".id": "*1", "chain": "forward", "action": "drop", "comment": "block-v6-guest", "disabled": False},
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, applied = await mcp.call_tool(
        "disable_ipv6_firewall_rule", {"device_name": "core-switch", "comment": "block-v6-guest", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake.path("ipv6", "firewall", "filter")._rows[0]["disabled"] == "yes"


@pytest.mark.asyncio
async def test_disable_ipv6_firewall_rule_unknown_comment_raises_clear_error(device: Device):
    fake = FakeConnection(data={("ipv6", "firewall", "filter"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "disable_ipv6_firewall_rule", {"device_name": "core-switch", "comment": "no-such-rule", "confirm": True}
        )
    assert "no-such-rule" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_ipv6_firewall_rule_returns_error_when_ipv6_package_disabled(device: Device):
    """UNLIKE the v1.9 reads (ipv6_firewall_filter etc.), a write tool must
    NOT swallow this into an empty/no-op result - the caller needs to know
    the ipv6 package is off, not think there was simply no rule to toggle."""
    fake = FakeConnection(raise_for={("ipv6", "firewall", "filter"): LibRouterosError("no such command")})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_ipv6_firewall_rule", {"device_name": "core-switch", "comment": "allow-v6-mgmt", "confirm": True}
        )
    assert "ipv6" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_add_ipv6_route_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_ipv6_route",
            {
                "device_name": "core-switch",
                "dst_address": "2001:db8:40::/64",
                "gateway": "2001:db8::254",
                "confirm": True,
            },
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_ipv6_route_preview_then_confirm(device: Device):
    fake = FakeConnection(data={("ipv6", "route"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "add_ipv6_route",
        {
            "device_name": "core-switch",
            "dst_address": "2001:db8:40::/64",
            "gateway": "2001:db8::254",
            "confirm": False,
        },
    )
    assert preview["applied"] is False
    assert fake.path("ipv6", "route")._rows == []

    _content, applied = await mcp.call_tool(
        "add_ipv6_route",
        {
            "device_name": "core-switch",
            "dst_address": "2001:db8:40::/64",
            "gateway": "2001:db8::254",
            "confirm": True,
        },
    )
    assert applied["applied"] is True
    created = fake.path("ipv6", "route")._rows[0]
    assert created == {"dst-address": "2001:db8:40::/64", "gateway": "2001:db8::254"}


@pytest.mark.asyncio
async def test_add_ipv6_route_default_route_carries_warning(device: Device):
    fake = FakeConnection(data={("ipv6", "route"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "add_ipv6_route",
        {"device_name": "core-switch", "dst_address": "::/0", "gateway": "2001:db8::254", "confirm": False},
    )
    assert preview["warning"] is not None
    assert "::/0" in preview["warning"]


@pytest.mark.asyncio
async def test_add_ipv6_route_rejects_ipv4_dst_address(device: Device):
    fake = FakeConnection(data={("ipv6", "route"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_ipv6_route",
            {"device_name": "core-switch", "dst_address": "10.40.0.0/24", "gateway": "2001:db8::254", "confirm": True},
        )
    assert "ipv6" in str(exc_info.value).lower()
    assert fake.path("ipv6", "route")._rows == []


@pytest.mark.asyncio
async def test_add_ipv6_route_returns_error_when_ipv6_package_disabled(device: Device):
    fake = FakeConnection(raise_for={("ipv6", "route"): LibRouterosError("no such command")})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_ipv6_route",
            {
                "device_name": "core-switch",
                "dst_address": "2001:db8:40::/64",
                "gateway": "2001:db8::254",
                "confirm": True,
            },
        )
    assert "ipv6" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_remove_ipv6_route_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_ipv6_route", {"device_name": "core-switch", "dst_address": "2001:db8:20::/64", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_ipv6_route_preview_then_confirm(device: Device):
    fake = FakeConnection(
        data={("ipv6", "route"): [{".id": "*1", "dst-address": "2001:db8:20::/64", "gateway": "2001:db8::254"}]}
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_ipv6_route", {"device_name": "core-switch", "dst_address": "2001:db8:20::/64", "confirm": False}
    )
    assert preview["applied"] is False
    assert len(fake.path("ipv6", "route")._rows) == 1

    _content, applied = await mcp.call_tool(
        "remove_ipv6_route", {"device_name": "core-switch", "dst_address": "2001:db8:20::/64", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake.path("ipv6", "route")._rows == []


@pytest.mark.asyncio
async def test_remove_ipv6_route_refuses_dynamic_route(device: Device):
    """CRITICAL for this round, exercised end to end (not just guard.py
    directly): a dynamic IPv6 route must be refused, never removed - same
    dynamic=True Python-bool refusal as remove_route (IPv4)."""
    fake = FakeConnection(
        data={
            ("ipv6", "route"): [{".id": "*1", "dst-address": "2001:db8:30::/64", "gateway": "ether1", "dynamic": True}]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_ipv6_route", {"device_name": "core-switch", "dst_address": "2001:db8:30::/64", "confirm": True}
        )
    assert "dynamic" in str(exc_info.value).lower()
    assert len(fake.path("ipv6", "route")._rows) == 1


@pytest.mark.asyncio
async def test_remove_ipv6_route_returns_error_when_ipv6_package_disabled(device: Device):
    fake = FakeConnection(raise_for={("ipv6", "route"): LibRouterosError("no such command")})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_ipv6_route", {"device_name": "core-switch", "dst_address": "2001:db8:20::/64", "confirm": True}
        )
    assert "ipv6" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_add_to_ipv6_address_list_blocked_read_only_by_default(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_to_ipv6_address_list",
            {
                "device_name": "core-switch",
                "list_name": "blocked-clients-v6",
                "address": "2001:db8::61",
                "confirm": True,
            },
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_add_to_ipv6_address_list_preview_then_confirm(device: Device):
    fake = FakeConnection(data={("ipv6", "firewall", "address-list"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "add_to_ipv6_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients-v6", "address": "2001:db8::61", "confirm": False},
    )
    assert preview["applied"] is False
    assert fake.path("ipv6", "firewall", "address-list")._rows == []

    _content, applied = await mcp.call_tool(
        "add_to_ipv6_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients-v6", "address": "2001:db8::61", "confirm": True},
    )
    assert applied["applied"] is True
    rows = fake.path("ipv6", "firewall", "address-list")._rows
    assert any(row["list"] == "blocked-clients-v6" and row["address"] == "2001:db8::61" for row in rows)


@pytest.mark.asyncio
async def test_add_to_ipv6_address_list_rejects_ipv4_address(device: Device):
    fake = FakeConnection(data={("ipv6", "firewall", "address-list"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_to_ipv6_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients-v6", "address": "10.0.0.61", "confirm": True},
        )
    assert "ipv6" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_add_to_ipv6_address_list_returns_error_when_ipv6_package_disabled(device: Device):
    fake = FakeConnection(raise_for={("ipv6", "firewall", "address-list"): LibRouterosError("no such command")})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_to_ipv6_address_list",
            {
                "device_name": "core-switch",
                "list_name": "blocked-clients-v6",
                "address": "2001:db8::61",
                "confirm": True,
            },
        )
    assert "ipv6" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_remove_from_ipv6_address_list_blocked_read_only_by_default(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_from_ipv6_address_list",
            {
                "device_name": "core-switch",
                "list_name": "blocked-clients-v6",
                "address": "2001:db8::60",
                "confirm": True,
            },
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_remove_from_ipv6_address_list_preview_then_confirm(device: Device):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "address-list"): [
                {".id": "*1", "list": "blocked-clients-v6", "address": "2001:db8::60"}
            ]
        }
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "remove_from_ipv6_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients-v6", "address": "2001:db8::60", "confirm": False},
    )
    assert preview["applied"] is False
    assert len(fake.path("ipv6", "firewall", "address-list")._rows) == 1

    _content, applied = await mcp.call_tool(
        "remove_from_ipv6_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients-v6", "address": "2001:db8::60", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake.path("ipv6", "firewall", "address-list")._rows == []


@pytest.mark.asyncio
async def test_remove_from_ipv6_address_list_returns_error_when_ipv6_package_disabled(device: Device):
    fake = FakeConnection(raise_for={("ipv6", "firewall", "address-list"): LibRouterosError("no such command")})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_from_ipv6_address_list",
            {
                "device_name": "core-switch",
                "list_name": "blocked-clients-v6",
                "address": "2001:db8::60",
                "confirm": True,
            },
        )
    assert "ipv6" in str(exc_info.value).lower()

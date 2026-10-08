from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from mcp_mikrotik import audit
from mcp_mikrotik.config import Settings, load_settings
from mcp_mikrotik.exceptions import DeviceCommandError, ValidationError
from mcp_mikrotik.privacy import NetworkAnonymizer, redact_current_text
from mcp_mikrotik.server import build_server

from .test_server import _factory


@pytest.mark.parametrize(
    "address",
    [
        "192.0.2.1",
        "10.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "2001:db8::1",
        "2001:db8::",
        "fe80::1",
        "::1",
        "::",
        "::ffff:192.0.2.1",
        "AA:BB:CC:DD:EE:01",
        "aa-bb-cc-dd-ee-01",
        "aabb.ccdd.ee01",
    ],
)
def test_literals_are_reversible(address):
    p = NetworkAnonymizer()
    alias = p.redact_text(address)
    assert address not in alias
    assert p.redact_text(alias) == alias
    assert p.redact_text(p.resolve_text(alias)) == alias


@pytest.mark.parametrize(
    "text",
    [
        "192.0.2.1/24",
        "192.0.2.1:443",
        "[2001:db8::1]:8729",
        "2001:db8::1/64",
        "fe80::1%ether1",
        "2001:db8::1.",
        "192.0.2.1.",
        "AA:BB:CC:DD:EE:01.",
        "AA:BB:CC:DD:EE:01: timeout",
        "2001:db8::1: timeout",
        "[fe80::1%ether1]:8729",
        "192.0.2.1-192.0.2.99",
        "192.0.2.1,192.0.2.99",
        "login from 192.0.2.1 via AA:BB:CC:DD:EE:01",
        "gateway=2001:db8::1%ether1,192.0.2.1",
    ],
)
def test_embedded_addresses_round_trip(text):
    p = NetworkAnonymizer()
    redacted = p.redact_text(text)
    assert redacted != text
    assert "192.0.2." not in redacted
    assert "2001:db8" not in redacted
    assert p.resolve_text(redacted) == text


def test_canonical_addresses_share_tokens():
    p = NetworkAnonymizer()
    assert p.redact_text("2001:db8::1") == p.redact_text("2001:0db8:0:0:0:0:0:1")
    assert p.redact_text("AA:BB:CC:DD:EE:01") == p.redact_text("aabb.ccdd.ee01")
    assert p.redact_text("192.0.2.1") != p.redact_text("192.0.2.2")


def test_recursive_copy_and_scalar_preservation():
    p = NetworkAnonymizer()
    original = {"192.0.2.1": [True, 42, None, {"unknown-field": "192.0.2.1/24"}]}
    result = p.transform(original)
    assert "192.0.2.1" not in str(result)
    assert p.transform(result, resolve=True) == original
    assert "192.0.2.1" in original
    assert p.transform(("192.0.2.1", False), resolve=True) == ("192.0.2.1", False)


@pytest.mark.parametrize("value", ["version 1.2.3", "10:00:00", "999.2.3.4", "bad::thing"])
def test_non_addresses_unchanged(value):
    assert NetworkAnonymizer().redact_text(value) == value


def test_concurrent_aliasing_and_session_isolation():
    p = NetworkAnonymizer()
    with ThreadPoolExecutor(max_workers=8) as executor:
        tokens = list(executor.map(p.redact_text, ["192.0.2.1"] * 100))
    assert len(set(tokens)) == 1
    other = NetworkAnonymizer()
    assert other.redact_text("192.0.2.1") != tokens[0]
    with pytest.raises(ValidationError, match="Unknown"):
        other.resolve_text(tokens[0])


@pytest.mark.parametrize("token", ["IP4_deadbeef", "MAC_" + "a" * 32, "IP6_" + "a" * 32])
def test_unknown_and_malformed_tokens_rejected(token):
    with pytest.raises(ValidationError):
        NetworkAnonymizer().resolve_text(token)


def test_capacity_fails_closed():
    p = NetworkAnonymizer(max_addresses=1)
    first = p.redact_text("192.0.2.1")
    with pytest.raises(ValidationError, match="capacity"):
        p.redact_text("192.0.2.2")
    assert p.resolve_text(first) == "192.0.2.1"


def test_audit_context_and_capacity(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(path))
    p = NetworkAnonymizer(max_addresses=1)

    def record():
        audit.record(
            correlation_id="test",
            device_name="router",
            tool="test",
            operation="test",
            action="update",
            confirm=False,
            outcome="preview",
            summary={"address": "192.0.2.1", "password": "never-log"},
        )

    with p.bind():
        assert redact_current_text("192.0.2.1") == p.redact_text("192.0.2.1")
        record()
    assert redact_current_text("192.0.2.1") == "192.0.2.1"
    text = path.read_text()
    assert "192.0.2.1" not in text and "never-log" not in text
    with NetworkAnonymizer(max_addresses=0).bind():
        record()  # no raw fallback and audit failure does not interrupt a write
    assert path.read_text() == text


@pytest.mark.parametrize("value", ["true", "1", "yes", "on"])
def test_config_privacy_enabled(value, tmp_path):
    assert load_settings(tmp_path / "missing", {"MIKROTIK_ANONYMIZE_ADDRESSES": value}).anonymize_addresses


def test_config_default_and_explicit_opt_out(tmp_path):
    assert Settings(allow_write=False).anonymize_addresses
    assert load_settings(tmp_path / "missing", {}).anonymize_addresses
    assert not load_settings(tmp_path / "missing", {"MIKROTIK_ANONYMIZE_ADDRESSES": "false"}).anonymize_addresses
    with pytest.raises(Exception, match="must be a boolean"):
        load_settings(tmp_path / "missing", {"MIKROTIK_ANONYMIZE_ADDRESSES": "typo"})


@pytest.mark.asyncio
async def test_read_write_round_trip_and_audit(device, fake_connection, tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(path))
    settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings, _factory(fake_connection))
    assert "pseudonyms" in mcp.instructions
    content, result = await mcp.call_tool("dhcp_leases", {"device_name": device.name})
    assert "10.0.0.50" not in str(content) + str(result)
    assert "AA:BB:CC:DD:EE:01" not in str(content) + str(result)
    lease = result["result"][0]
    kwargs = {"device_name": device.name, "address": lease["address"], "list_name": "privacy-test"}
    _, preview = await mcp.call_tool("add_to_address_list", kwargs)
    assert not any(
        row.get("list") == "privacy-test" for row in fake_connection._data[("ip", "firewall", "address-list")]
    )
    _, applied = await mcp.call_tool("add_to_address_list", {**kwargs, "confirm": True})
    assert "10.0.0.50" not in str(preview) + str(applied) + path.read_text()
    assert applied["after"]["address"] == lease["address"]
    assert any(
        row.get("address") == "10.0.0.50" and row.get("list") == "privacy-test"
        for row in fake_connection._data[("ip", "firewall", "address-list")]
    )
    assert json.loads(path.read_text().splitlines()[-1])["summary"]["after"]["address"] == lease["address"]
    # MAC token round-trip through a diagnostic write primitive.
    await mcp.call_tool(
        "wake_on_lan",
        {"device_name": device.name, "mac_address": lease["mac-address"], "interface": "ether1", "confirm": False},
    )


@pytest.mark.asyncio
async def test_unknown_token_no_device_access(device):
    def never_connect(*args):
        pytest.fail("Unknown aliases must be rejected before accessing the router")

    mcp = build_server(Settings(allow_write=True, devices={device.name: device}), never_connect)
    with pytest.raises(ToolError, match="Unknown network pseudonym"):
        await mcp.call_tool("ping", {"device_name": device.name, "address": "IP4_" + "0" * 32})


@pytest.mark.asyncio
async def test_errors_and_logs_do_not_leak(device, caplog):
    def fail(*args):
        raise DeviceCommandError(device.name, "ip/address", "192.0.2.1 AA:BB:CC:DD:EE:01")

    mcp = build_server(Settings(allow_write=False, devices={device.name: device}), fail)
    with caplog.at_level(logging.INFO), pytest.raises(ToolError) as error:
        await mcp.call_tool("ip_addresses", {"device_name": device.name})
    assert "192.0.2.1" not in str(error.value) + caplog.text
    assert "AA:BB:CC:DD:EE:01" not in str(error.value) + caplog.text


@pytest.mark.asyncio
async def test_unexpected_exception_no_traceback_or_address(device, caplog):
    def fail(*args):
        raise ValueError("192.0.2.1")

    mcp = build_server(Settings(allow_write=False, devices={device.name: device}), fail)
    with pytest.raises(ToolError, match="Internal error"):
        await mcp.call_tool("ip_addresses", {"device_name": device.name})
    assert "192.0.2.1" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.asyncio
async def test_all_read_outputs_and_default_gate(device, fake_connection):
    mcp = build_server(Settings(allow_write=False, devices={device.name: device}), _factory(fake_connection))
    for name in [
        "list_devices",
        "dhcp_leases",
        "ip_addresses",
        "ip_routes",
        "ipv6_addresses",
        "ipv6_neighbors",
        "arp_table",
        "logs",
        "security_events",
        "wireguard_peers",
        "dns_cache",
        "firewall_filter",
        "connection_tracking",
        "torch",
    ]:
        args = {} if name == "list_devices" else {"device_name": device.name}
        if name == "connection_tracking":
            args["protocol"] = "tcp"
        if name == "torch":
            args["interface"] = "ether1"
        content, result = await mcp.call_tool(name, args)
        rendered = str(content) + str(result)
        assert "10.0.0." not in rendered and "AA:BB:CC:" not in rendered
    with pytest.raises(ToolError, match="read-only"):
        await mcp.call_tool(
            "wake_on_lan",
            {"device_name": device.name, "mac_address": "AA:BB:CC:DD:EE:01", "interface": "ether1", "confirm": True},
        )
    # Explicit local opt-out retains upstream outputs and error behavior.
    plain = build_server(
        replace(Settings(allow_write=False, devices={device.name: device}), anonymize_addresses=False),
        _factory(fake_connection),
    )
    _, result = await plain.call_tool("dhcp_leases", {"device_name": device.name})
    assert result["result"][0]["address"] == "10.0.0.50"


@pytest.mark.asyncio
async def test_framework_validation_error_is_protected(device):
    mcp = build_server(Settings(allow_write=False, devices={device.name: device}), lambda *args: None)
    with pytest.raises(ToolError) as error:
        await mcp.call_tool("logs", {"device_name": device.name, "limit": "192.0.2.1"})
    assert "192.0.2.1" not in str(error.value)
    assert "IP4_" in str(error.value)


@pytest.mark.asyncio
async def test_unknown_tool_name_is_protected():
    mcp = build_server(Settings(allow_write=False))
    with pytest.raises(ToolError) as error:
        await mcp.call_tool("192.0.2.1", {})
    assert "192.0.2.1" not in str(error.value)


@pytest.mark.asyncio
async def test_every_device_tool_resolves_aliases_before_device_access(device):
    def never_connect(*args):
        pytest.fail("No device tool may bypass alias validation")

    mcp = build_server(Settings(allow_write=True, devices={device.name: device}), never_connect)
    tools = await mcp.list_tools()
    checked = 0
    for tool in tools:
        properties = tool.inputSchema.get("properties", {})
        if "device_name" not in properties:
            continue
        arguments = {}
        for key in tool.inputSchema.get("required", []):
            kind = properties[key].get("type", "string")
            arguments[key] = {"integer": 1, "number": 1.0, "boolean": False, "array": []}.get(kind, "placeholder")
        arguments["device_name"] = "IP4_" + "0" * 32
        with pytest.raises(ToolError, match="Unknown network pseudonym"):
            await mcp.call_tool(tool.name, arguments)
        checked += 1
    assert checked == len(tools) - 2  # list_devices/list_write_operations have no device target


def test_random_token_collision_is_retried(monkeypatch):
    tokens = iter(["0" * 32, "0" * 32, "1" * 32])
    monkeypatch.setattr("mcp_mikrotik.privacy.secrets.token_hex", lambda _: next(tokens))
    p = NetworkAnonymizer()
    assert p.redact_text("192.0.2.1") != p.redact_text("192.0.2.2")


@pytest.mark.parametrize("text", ["192.0.2.1:443:timeout", "::999.2.3.4", "bad:::no"])
def test_invalid_ipv6_candidates_keep_text_and_protect_embedded_ipv4(text):
    p = NetworkAnonymizer()
    result = p.redact_text(text)
    assert p.resolve_text(result) == text
    if "192.0.2.1" in text:
        assert "192.0.2.1" not in result


@pytest.mark.asyncio
async def test_capacity_error_at_tool_and_framework_boundary(device, fake_connection, monkeypatch):
    import mcp_mikrotik.server as server

    monkeypatch.setattr(server, "NetworkAnonymizer", lambda: NetworkAnonymizer(max_addresses=0))
    mcp = build_server(Settings(allow_write=False, devices={device.name: device}), _factory(fake_connection))
    with pytest.raises(ToolError, match="capacity"):
        await mcp.call_tool("list_devices", {})
    with pytest.raises(ToolError, match="Network privacy error") as error:
        await mcp.call_tool("logs", {"device_name": device.name, "limit": "192.0.2.1"})
    assert "192.0.2.1" not in str(error.value)


@pytest.mark.asyncio
async def test_capacity_error_never_logs_original_exception(device, monkeypatch, caplog):
    import mcp_mikrotik.server as server

    monkeypatch.setattr(server, "NetworkAnonymizer", lambda: NetworkAnonymizer(max_addresses=0))

    def fail(*args):
        raise DeviceCommandError(device.name, "ip/address", "192.0.2.1")

    mcp = build_server(Settings(allow_write=False, devices={device.name: device}), fail)
    with caplog.at_level(logging.INFO), pytest.raises(ToolError, match="Network privacy error"):
        await mcp.call_tool("ip_addresses", {"device_name": device.name})
    assert "192.0.2.1" not in caplog.text


def test_audit_write_failure_never_logs_original_path(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(tmp_path / "192.0.2.1" / "missing.jsonl"))
    with NetworkAnonymizer(max_addresses=0).bind():
        audit.record(
            correlation_id="test",
            device_name="router",
            tool="test",
            operation="test",
            action="update",
            confirm=False,
            outcome="preview",
            summary={},
        )
    assert "192.0.2.1" not in caplog.text
    assert "failed to write event" in caplog.text

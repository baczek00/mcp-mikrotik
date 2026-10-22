from __future__ import annotations

import pytest

from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings

from .fakes import FakeConnection


@pytest.fixture
def device() -> Device:
    return Device(
        name="core-switch",
        host="10.0.0.1",
        port=8728,
        use_ssl=False,
        username="admin",
        password="s3cret",
        disabled=False,
        comment="lab core switch",
    )


@pytest.fixture
def fake_connection() -> FakeConnection:
    return FakeConnection(
        data={
            ("system", "identity"): [{"name": "MikroTik"}],
            ("system", "resource"): [{"board-name": "hAP ac2", "version": "7.21", "uptime": "3d5h"}],
            ("interface",): [
                {".id": "*1", "name": "ether1", "disabled": False},
                {".id": "*2", "name": "ether2", "disabled": True},
            ],
            ("ip", "address"): [{".id": "*1", "address": "10.0.0.1/24", "interface": "ether1"}],
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"},
                # v1.5: a static route (no `dynamic` field, same as RouterOS's
                # own admin-created rows) and a dynamic/connected route
                # look-alike, added to exercise add_route/remove_route
                # without disturbing *1 above (several existing tests assert
                # exact equality against *1's dict shape).
                {".id": "*2", "dst-address": "10.20.0.0/24", "gateway": "10.0.0.254", "distance": "1"},
                {".id": "*3", "dst-address": "10.30.0.0/24", "gateway": "ether1", "dynamic": True},
            ],
            ("ip", "neighbor"): [{".id": "*1", "address": "10.0.0.2", "identity": "ap-1"}],
            ("log",): [
                {".id": "*1", "time": "10:00:00", "topics": "system,info", "message": "boot"},
                {".id": "*2", "time": "10:00:05", "topics": "interface,link", "message": "ether1 up"},
            ],
            ("ip", "dhcp-server", "lease"): [
                {
                    ".id": "*1",
                    "address": "10.0.0.50",
                    "mac-address": "AA:BB:CC:DD:EE:01",
                    "host-name": "laptop-1",
                    "status": "bound",
                    "server": "dhcp1",
                    "comment": "",
                }
            ],
            # v1.7: DHCP server + network CONFIG (as opposed to the leases
            # it hands out above) - `disabled` deliberately omitted on *1
            # (ROS6-style implicit-false, see coerce_ros_bool's docstring)
            # and explicit `False` on *2 (ROS7-style), so the read tool's
            # coercion is exercised against both shapes.
            ("ip", "dhcp-server"): [
                {
                    ".id": "*1",
                    "name": "dhcp1",
                    "interface": "ether1",
                    "address-pool": "pool1",
                    "lease-time": "1d",
                    "authoritative": "yes",
                    "comment": "main LAN",
                },
                {
                    ".id": "*2",
                    "name": "dhcp2",
                    "interface": "ether2",
                    "address-pool": "pool2",
                    "lease-time": "8h",
                    "disabled": False,
                    "authoritative": "yes",
                    "comment": "",
                },
            ],
            ("ip", "dhcp-server", "network"): [
                {
                    ".id": "*1",
                    "address": "10.0.0.0/24",
                    "gateway": "10.0.0.1",
                    "dns-server": "10.0.0.1",
                    "netmask": "24",
                    "domain": "lan",
                    "comment": "main LAN",
                },
            ],
            ("ip", "dns", "cache"): [{"name": "example.com", "type": "A", "data": "93.184.216.34", "ttl": "1h"}],
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "accept", "comment": "allow established"},
                # v0.11: a pre-created, disabled rule an admin left ready for
                # enable_firewall_rule to flip on by `comment` - the
                # community-suggested "admin creates disabled, LLM enables"
                # workflow (see README's "Firewall rule toggle (by
                # comment)").
                {
                    ".id": "*2",
                    "chain": "forward",
                    "action": "drop",
                    "comment": "Bloqueio_Ataque_X",
                    "disabled": True,
                },
            ],
            # v0.11: connection tracking - one TCP and one UDP entry so
            # tests can filter by src/dst address, port, and protocol
            # independently.
            ("ip", "firewall", "connection"): [
                {
                    ".id": "*1",
                    "protocol": "tcp",
                    "src-address": "10.0.0.50:51413",
                    "dst-address": "93.184.216.34:443",
                    "reply-src-address": "93.184.216.34:443",
                    "reply-dst-address": "10.0.0.50:51413",
                    "tcp-state": "established",
                    "timeout": "1d",
                    "assured": True,
                    "confirmed": True,
                    "seen-reply": True,
                },
                {
                    ".id": "*2",
                    "protocol": "udp",
                    "src-address": "10.0.0.60:33221",
                    "dst-address": "8.8.8.8:53",
                    "reply-src-address": "8.8.8.8:53",
                    "reply-dst-address": "10.0.0.60:33221",
                    "timeout": "10s",
                    "assured": False,
                    "confirmed": True,
                    "seen-reply": True,
                },
            ],
            ("system", "health"): [
                {"name": "voltage", "value": "24.1", "type": "V"},
                {"name": "temperature", "value": "38", "type": "C"},
            ],
            ("queue", "simple"): [
                {
                    ".id": "*1",
                    "name": "limit-10-0-0-50",
                    "target": "10.0.0.50/32",
                    "max-limit": "10M/5M",
                    "limit-at": "0/0",
                    "bytes": "1234567/7654321",
                    "disabled": False,
                }
            ],
            ("ip", "firewall", "address-list"): [
                {
                    ".id": "*1",
                    "list": "blocked-clients",
                    "address": "10.0.0.60",
                    "timeout": "0s",
                    "dynamic": False,
                    "disabled": False,
                }
            ],
            ("ip", "firewall", "nat"): [
                {
                    ".id": "*1",
                    "chain": "srcnat",
                    "action": "masquerade",
                    "out-interface": "ether1",
                    "comment": "wan-masquerade",
                    "disabled": False,
                },
                # v1.4: a pre-created, disabled rule an admin left ready for
                # enable_nat_rule to flip on by `comment` - the same
                # "admin creates disabled, LLM enables" workflow
                # ("ip", "firewall", "filter")'s "Bloqueio_Ataque_X" row
                # above already establishes for filter.
                {
                    ".id": "*2",
                    "chain": "dstnat",
                    "action": "dst-nat",
                    "to-addresses": "10.0.0.80",
                    "to-ports": "3389",
                    "comment": "rdp-forward-maintenance",
                    "disabled": True,
                },
            ],
            # v1.4: firewall mangle - same two-row shape as
            # ("ip", "firewall", "filter") above: one enabled row
            # ("mark-voip", chain "forward") for disable_mangle_rule to flip
            # off, and one pre-created disabled row ("Mark_Backup_Traffic",
            # chain "prerouting") for enable_mangle_rule to flip on.
            ("ip", "firewall", "mangle"): [
                {
                    ".id": "*1",
                    "chain": "forward",
                    "action": "mark-packet",
                    "new-packet-mark": "voip",
                    "comment": "mark-voip",
                    "disabled": False,
                },
                {
                    ".id": "*2",
                    "chain": "prerouting",
                    "action": "mark-connection",
                    "comment": "Mark_Backup_Traffic",
                    "disabled": True,
                },
            ],
            ("system", "scheduler"): [
                {
                    ".id": "*1",
                    "name": "backup-daily",
                    "on-event": "backup",
                    "interval": "1d",
                    "next-run": "jan/01/2030 00:00:00",
                    "disabled": False,
                }
            ],
            ("ip", "pool"): [{".id": "*1", "name": "dhcp-pool", "ranges": "10.0.0.100-10.0.0.200"}],
            # v0.6: physical layer / PoE - a CRS318-16P-2S+-like mix of
            # PoE-capable ethernet ports (ether1: high/48V, ether2: low/24V)
            # and a non-PoE-capable one (sfp1: no `poe-out` field at all,
            # like an SFP+ cage or a device with no PoE hardware).
            ("interface", "ethernet"): [
                {".id": "*1", "name": "ether1", "poe-out": "auto-on"},
                {".id": "*2", "name": "ether2", "poe-out": "off"},
                {".id": "*3", "name": "sfp1"},
            ],
            ("ip", "arp"): [
                {
                    ".id": "*1",
                    "address": "10.0.0.70",
                    "mac-address": "AA:BB:CC:DD:EE:70",
                    "interface": "ether1",
                    "dynamic": False,
                    "complete": True,
                }
            ],
            ("interface", "bridge", "host"): [
                {
                    ".id": "*1",
                    "mac-address": "AA:BB:CC:DD:EE:70",
                    "on-interface": "ether1",
                    "bridge": "bridge1",
                    "dynamic": False,
                    "local": False,
                }
            ],
            # v1.7: bridge port membership + VLAN filtering table - the
            # honest completion of the VLAN story for a managed switch (the
            # v1.2 VLAN tools only cover standalone /interface/vlan).
            ("interface", "bridge", "port"): [
                {
                    ".id": "*1",
                    "bridge": "bridge1",
                    "interface": "ether2",
                    "pvid": "1",
                    "disabled": False,
                    "edge": "auto",
                    "horizon": "none",
                    "learn": "auto",
                    "comment": "",
                },
                {
                    ".id": "*2",
                    "bridge": "bridge1",
                    "interface": "ether3",
                    "pvid": "20",
                    "disabled": True,
                    "edge": "yes",
                    "horizon": "none",
                    "learn": "auto",
                    "comment": "camera vlan",
                },
            ],
            ("interface", "bridge", "vlan"): [
                {
                    ".id": "*1",
                    "bridge": "bridge1",
                    "vlan-ids": "20",
                    "tagged": "bridge1,ether1",
                    "untagged": "ether3",
                    "current-tagged": "bridge1,ether1",
                    "current-untagged": "ether3",
                    "comment": "cameras",
                },
            ],
            # v0.7: LTE/5G, containers, USB.
            ("interface", "lte"): [
                {".id": "*1", "name": "lte1", "running": True, "disabled": False, "apn-profiles": "default"}
            ],
            ("container",): [
                {
                    ".id": "*1",
                    "name": "grafana",
                    "tag": "grafana/grafana:latest",
                    "status": "running",
                    "ram-usage": "52428800",
                    "root-dir": "usb1/grafana",
                    "interface": "veth1",
                    "os": "linux",
                },
                {
                    ".id": "*2",
                    "tag": "alpine:latest",
                    "status": "stopped",
                    "ram-usage": "0",
                    "root-dir": "usb1/alpine",
                    "interface": "veth2",
                    "os": "linux",
                },
            ],
            ("container", "config"): [
                {"registry-url": "https://registry-1.docker.io", "tmpdir": "usb1/tmp", "ram-high": "0"}
            ],
            ("system", "routerboard", "usb"): [{".id": "*1", "port": "1", "power-reset": "auto-on"}],
            ("disk",): [
                {".id": "*1", "slot": "usb1", "type": "usb", "total-size": "32000000000", "free-size": "20000000000"}
            ],
            # v0.8: VPN / routing / failover diagnostics.
            # v0.13: the tunnel interface itself - deliberately no
            # private-key here (a real device's reply would carry one; this
            # fixture only exercises the happy path of visible fields -
            # the explicit private-key-redaction proof uses its own
            # dedicated FakeConnection with a distinctive marker, mirroring
            # test_wireguard_peers_never_exposes_private_key's pattern).
            ("interface", "wireguard"): [
                {
                    ".id": "*1",
                    "name": "wg1",
                    "listen-port": "13231",
                    "public-key": "SERVERPUBKEYAAAA==",
                    "running": True,
                    "disabled": False,
                    "mtu": "1420",
                }
            ],
            ("interface", "wireguard", "peers"): [
                {
                    ".id": "*1",
                    "name": "peer1",
                    "interface": "wg1",
                    "public-key": "PUBKEYAAAA==",
                    "endpoint-address": "203.0.113.5",
                    "endpoint-port": "13231",
                    "current-endpoint-address": "203.0.113.5",
                    "current-endpoint-port": "13231",
                    "last-handshake": "12s",
                    "rx": "1024",
                    "tx": "2048",
                    "allowed-address": "10.10.0.2/32",
                    "disabled": False,
                }
            ],
            ("ppp", "active"): [
                {
                    ".id": "*1",
                    "name": "vpn-user1",
                    "service": "l2tp",
                    "caller-id": "198.51.100.9",
                    "address": "10.20.0.5",
                    "uptime": "1h2m",
                }
            ],
            # v1.3: PPP/PPPoE secrets - the CONFIGURED credential, distinct
            # from ("ppp", "active") above (a currently-connected session).
            # Carries a fake `password` so ppp_secrets' redaction (never
            # returning it) has something real to strip in tests.
            ("ppp", "secret"): [
                {
                    ".id": "*1",
                    "name": "pppoe-client1",
                    "password": "s3cret-fake",
                    "service": "pppoe",
                    "profile": "default-encryption",
                    "remote-address": "10.40.0.10",
                    "disabled": False,
                    "comment": "fiber customer #1",
                }
            ],
            ("ip", "ipsec", "active-peers"): [
                {
                    ".id": "*1",
                    "remote-address": "198.51.100.10",
                    "state": "established",
                    "uptime": "3h",
                    "rx": "4096",
                    "tx": "8192",
                    "side": "responder",
                }
            ],
            ("routing", "bgp", "session"): [
                {
                    ".id": "*1",
                    "remote-address": "198.51.100.20",
                    "remote-as": "65001",
                    "state": "established",
                    "uptime": "1d2h",
                    "prefix-count": "12",
                }
            ],
            ("routing", "ospf", "neighbor"): [
                {
                    ".id": "*1",
                    "address": "10.30.0.2",
                    "state": "Full",
                    "router-id": "10.30.0.2",
                    "adjacency": "5m",
                }
            ],
            ("tool", "netwatch"): [
                {
                    ".id": "*1",
                    "host": "8.8.8.8",
                    "status": "up",
                    "interval": "10s",
                    "since": "jan/01/2030 00:00:00",
                    "up-script": "",
                    "down-script": ':log warning "gw down"',
                    "comment": "primary gateway",
                    "disabled": False,
                }
            ],
            # v0.14: hotspot vouchers + backup.
            ("ip", "hotspot", "active"): [
                {
                    ".id": "*1",
                    "user": "visitor1",
                    "address": "10.5.0.10",
                    "mac-address": "AA:BB:CC:DD:EE:80",
                    "uptime": "12m30s",
                    "bytes-in": "1048576",
                    "bytes-out": "5242880",
                }
            ],
            # A mix of backup and non-backup files, so list_backups' own
            # filtering can be exercised against the shared fixture too, not
            # just a dedicated FakeConnection.
            ("file",): [
                {
                    ".id": "*1",
                    "name": "core-switch-2026-01-01.backup",
                    "size": "524288",
                    "creation-time": "jan/01/2026 00:00:00",
                },
                {".id": "*2", "name": "flash/skins", "type": "directory"},
            ],
            # v1.6: AAA/PKI visibility - certificates, users, RADIUS.
            # A far-future invalid-after so `certificates`' happy-path tests
            # get a stable, always-not-expiring `daysUntilExpiry`; the
            # ISO-like date shape (as opposed to "jan/15/2027 12:00:00")
            # exercises the other RouterOS date rendering
            # formatting.parse_ros_datetime handles - see
            # test_certificates_happy_path/test_certificate_expiry_check
            # for coverage of the abbreviated shape and unparseable dates.
            ("certificate",): [
                {
                    ".id": "*1",
                    "name": "api-cert",
                    "common-name": "core-switch.example.com",
                    "invalid-before": "2026-01-01 00:00:00",
                    "invalid-after": "2099-01-15 12:00:00",
                    "key-size": "2048",
                    "key-type": "rsa",
                    "fingerprint": "AA:BB:CC:DD:EE:FF",
                    "expired": False,
                    "trusted": True,
                }
            ],
            ("user",): [
                {
                    ".id": "*1",
                    "name": "admin",
                    "group": "full",
                    "address": "",
                    "last-logged-in": "jan/01/2026 08:00:00",
                    "disabled": False,
                    "comment": "",
                }
            ],
            ("user", "active"): [
                {
                    ".id": "*1",
                    "name": "admin",
                    "address": "10.0.0.5",
                    "via": "api",
                    "when": "jan/01/2026 08:00:00",
                }
            ],
            # Carries a fake `secret` so `radius`' redaction (never returning
            # it) has something real to strip in tests, same convention as
            # ("ppp", "secret")'s fake `password` above.
            ("radius",): [
                {
                    ".id": "*1",
                    "service": "ppp",
                    "address": "10.0.0.200",
                    "secret": "fake-shared-secret",
                    "timeout": "300ms",
                    "accounting-port": "1813",
                    "authentication-port": "1812",
                }
            ],
            # v1.8: NTP client (ROS7 shape - a `servers` list, kept as
            # RouterOS's own comma-joined string, not split - see
            # `ntp_client`'s docstring) + system clock. `enabled`/
            # `dst-active`/`time-zone-autodetect` are real Python bools, not
            # the strings "true"/"false" - see coerce_ros_bool's docstring -
            # so read-tool coercion is exercised against the same shape a
            # real device sends. The ROS6-shaped (`primary-ntp`/
            # `secondary-ntp`) variant is exercised via its own dedicated
            # FakeConnection in test_guard.py/test_server.py, mirroring
            # set_wifi_ssid's ROS6/ROS7 split.
            ("system", "ntp", "client"): [
                {
                    "enabled": True,
                    "mode": "unicast",
                    "servers": "1.2.3.4,pool.ntp.org",
                    "freq-drift": "0.5ppm",
                    "status": "synchronized",
                    "synced-server": "1.2.3.4",
                    "synced-stratum": "2",
                }
            ],
            ("system", "clock"): [
                {
                    "time": "12:00:00",
                    "date": "jan/01/2026",
                    "time-zone-name": "America/Sao_Paulo",
                    "time-zone-autodetect": True,
                    "gmt-offset": "-03:00",
                    "dst-active": False,
                }
            ],
            # v1.9: IPv6 read parity - mirrors the equivalent ("ip", ...)
            # fixtures above, field-for-field, on the ("ipv6", ...) paths.
            # `disabled`/`dynamic`/`advertise`/`active` are real Python
            # bools (or omitted, ROS6-style implicit-false), never the
            # strings "true"/"false" - same coerce_ros_bool shape every
            # other bool-bearing fixture in this file already uses. The
            # device-with-ipv6-package-disabled case (path raises) is
            # exercised via dedicated FakeConnection(raise_for=...)
            # instances in test_server.py, not this shared fixture.
            ("ipv6", "address"): [
                {
                    ".id": "*1",
                    "address": "2001:db8::1/64",
                    "interface": "ether1",
                    "advertise": True,
                    "disabled": False,
                    "dynamic": False,
                }
            ],
            ("ipv6", "route"): [
                {
                    ".id": "*1",
                    "dst-address": "::/0",
                    "gateway": "fe80::1",
                    "distance": "1",
                    "active": True,
                    "disabled": False,
                },
                {
                    ".id": "*2",
                    "dst-address": "2001:db8:20::/64",
                    "gateway": "ether1",
                    "distance": "0",
                    "active": True,
                    "dynamic": True,
                },
            ],
            ("ipv6", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "accept", "comment": "allow established", "disabled": False}
            ],
            ("ipv6", "neighbor"): [
                {
                    ".id": "*1",
                    "address": "2001:db8::70",
                    "mac-address": "AA:BB:CC:DD:EE:70",
                    "interface": "ether1",
                    "status": "reachable",
                    "dynamic": True,
                }
            ],
            ("ipv6", "firewall", "address-list"): [
                {
                    ".id": "*1",
                    "list": "blocked-clients-v6",
                    "address": "2001:db8::60/128",
                    "dynamic": False,
                    "disabled": False,
                }
            ],
            # v1.11: wireless RF tuning + dead-man - a PtP-shaped
            # /interface/wireless row (frequency-mode=regulatory-domain, so
            # set_wireless_channel's DFS preview has something non-trivial to
            # report by default; a dedicated FakeConnection is used in
            # test_guard.py/test_server.py for the superchannel/no-DFS case).
            ("interface", "wireless"): [
                {
                    ".id": "*1",
                    "name": "wlan1",
                    "mode": "bridge",
                    "ssid": "ptp-link",
                    "frequency": "5500",
                    "channel-width": "20mhz",
                    "frequency-mode": "regulatory-domain",
                    "tx-power-mode": "default",
                    "tx-power": "20",
                    "adaptive-noise-immunity": "none",
                    "distance": "dynamic",
                    "disabled": False,
                    "running": True,
                }
            ],
            ("interface", "wireless", "registration-table"): [
                {
                    ".id": "*1",
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
                }
            ],
        },
        ping_replies=[
            {"seq": "0", "host": "8.8.8.8", "time": "3ms"},
            {"seq": "1", "host": "8.8.8.8", "time": "4ms"},
        ],
        traceroute_replies=[
            {"address": "10.0.0.254", "hop": "1", "status": "", "loss": "0%", "time": "1ms"},
            {"address": "8.8.8.8", "hop": "2", "status": "", "loss": "0%", "time": "5ms"},
        ],
        monitor_traffic_replies={
            "ether1": {
                "rx-bits-per-second": "1000000",
                "tx-bits-per-second": "500000",
                "rx-packets-per-second": "120",
                "tx-packets-per-second": "80",
            },
        },
        # v1.10.1: mixed int/string-decimal types, matching what real
        # hardware (CRS318-16P-2S+, ROS6.49.20, 2026-07-12) actually sent -
        # int and string-decimal for the SAME fields, within one reply and
        # across ports of the same device. Deliberately not uniform, so a
        # regression to raw (un-coerced) passthrough in server.py's
        # poe_status would be caught - see formatting.coerce_ros_number.
        poe_monitor_replies={
            "ether1": {
                "poe-out-status": "powered-on",
                "poe-out-voltage": "48.0",  # string decimal
                "poe-out-current": 204,  # int
                "poe-out-power": "4.7",  # string decimal
            },
            "ether2": {
                "poe-out-status": "poe-out-off",
                "poe-out-voltage": "23.5",  # string decimal
                "poe-out-current": 0,  # int
                "poe-out-power": 1,  # int
            },
        },
        ethernet_monitor_replies={
            # v1.7: a plain copper port with no SFP cage - only the base
            # link fields, no sfp-* keys at all (must be treated as absent
            # by interface_monitor, never invented).
            "ether1": {
                "status": "link-ok",
                "rate": "1Gbps",
                "full-duplex": True,
                "auto-negotiation": "done",
            },
            # An SFP-capable port WITH a module inserted - base fields plus
            # every sfp-*/DDM field interface_monitor is documented to
            # surface, including the boolean sfp-module-present (real bool,
            # not the string "true" - see coerce_ros_bool).
            "sfp1": {
                "status": "link-ok",
                "rate": "1Gbps",
                "full-duplex": True,
                "auto-negotiation": "done",
                "sfp-temperature": "35",
                "sfp-supply-voltage": "3.3",
                "sfp-tx-power": "-3.0",
                "sfp-rx-power": "-4.2",
                "sfp-tx-bias-current": "8.5",
                "sfp-vendor-name": "MikroTik",
                "sfp-vendor-part-number": "S-3553LC20D",
                "sfp-wavelength": "1310",
                "sfp-module-present": True,
            },
        },
        lte_monitor_replies={
            "lte1": {
                "current-operator": "Vivo",
                "access-technology": "lte",
                "rsrp": "-85",
                "rsrq": "-10",
                "sinr": "18",
                "rssi": "-70",
                "band": "B3",
                "registration-status": "registered",
                "cell-id": "12345678",
            },
        },
        torch_replies={
            "ether1": [
                {
                    "src-address": "10.0.0.50",
                    "dst-address": "93.184.216.34",
                    "protocol": "tcp",
                    "tx": "500000",
                    "rx": "1500000",
                },
                {"src-address": "10.0.0.60", "dst-address": "8.8.8.8", "protocol": "udp", "tx": "1000", "rx": "2000"},
            ],
        },
    )


@pytest.fixture
def client(device: Device, fake_connection: FakeConnection) -> MikrotikClient:
    return MikrotikClient(device, connection=fake_connection)


@pytest.fixture
def settings(device: Device) -> Settings:
    return Settings(anonymize_addresses=False, allow_write=False, devices={device.name: device})


@pytest.fixture
def settings_write_enabled(device: Device) -> Settings:
    return Settings(anonymize_addresses=False, allow_write=True, devices={device.name: device})


@pytest.fixture(autouse=True)
def _no_sleep_in_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never actually sleep during the read-retry backoff (client.py's
    MikrotikClient._run_read) - keeps the suite fast and deterministic.
    Tests that specifically exercise retry behaviour assert on call counts
    /exceptions, not on timing, so removing the real delay changes nothing
    they check."""
    monkeypatch.setattr("mcp_mikrotik.client.time.sleep", lambda seconds: None)

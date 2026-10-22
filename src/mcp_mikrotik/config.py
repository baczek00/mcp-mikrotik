"""Device configuration: environment variables + optional devices.yaml.

Devices are described in a YAML file (see devices.yaml.example) that is
git-ignored because it holds credentials. Two environment variables control
server-wide behaviour:

  MIKROTIK_DEVICES_FILE  - path to the devices YAML file (default: devices.yaml)
  MIKROTIK_ALLOW_WRITE   - "true"/"1"/"yes"/"on" to enable write tools (default: false)

See .env.example for the full list.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .exceptions import ConfigError, DeviceNotFoundError

DEFAULT_PORT = 8728
DEFAULT_DEVICES_FILE = "devices.yaml"


@dataclass
class Device:
    """A single MikroTik device from devices.yaml."""

    name: str
    host: str
    port: int = DEFAULT_PORT
    use_ssl: bool = False
    username: str = "admin"
    # repr=False: a stray `logger.debug(device)` / `logger.debug(settings)`
    # must never write a device password to stderr (see docs/REVIEW-FINDINGS.md S1).
    password: str = field(default="", repr=False)
    disabled: bool = False
    comment: str = ""
    # SSL trust: default (True) keeps the existing safe behaviour - a proper
    # certificate chain is validated via ssl.create_default_context(). Set to
    # False only for devices using RouterOS's self-signed api-ssl cert, which
    # trades away MITM protection on that connection; see README "Security
    # model" and devices.yaml.example for the explicit trade-off writeup.
    tls_verify: bool = True
    # Optional path to a CA bundle to validate the device's cert against,
    # instead of the system trust store. Ignored when tls_verify is False.
    tls_ca_cert: str | None = None
    # Per-device connection timeout (seconds). None means "use the
    # MIKROTIK_TIMEOUT env var if set, else client.DEFAULT_TIMEOUT" - see
    # client._resolve_timeout(). Some fleet links are slow enough (15-40s
    # banner) that the old hardcoded 10s was too tight.
    timeout: float | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Representation safe to return through an MCP tool result: never includes the password."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "use_ssl": self.use_ssl,
            "username": self.username,
            "disabled": self.disabled,
            "comment": self.comment,
        }


@dataclass
class Settings:
    """Server-wide settings resolved from environment + devices.yaml."""

    allow_write: bool
    # repr=False: Settings.devices holds every configured Device (each with a
    # password, even though Device.password itself is repr=False - see S1).
    # Keeping the whole dict out of Settings' repr is a second, independent
    # layer so a future field added to Device without repr=False can't leak
    # through `logger.debug(settings)`.
    devices: dict[str, Device] = field(default_factory=dict, repr=False)
    anonymize_addresses: bool = True

    def get_device(self, name: str) -> Device:
        device = self.devices.get(name)
        if device is None or device.disabled:
            raise DeviceNotFoundError(name)
        return device


def _bool_env(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _coerce_str(value: Any, field_name: str, path: Path) -> str:
    """Coerce a YAML scalar into a str for `name`/`host` (E3).

    A bare numeric YAML value like `name: 14` parses as an int, which would
    silently become an int dict key and make the device unreachable by its
    (string) `device_name` tool argument - see docs/REVIEW-FINDINGS.md E3.
    int/float are coerced; anything else (mapping, list, bool, None) is
    rejected with a clear ConfigError instead of failing later in a
    confusing way.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None:
        raise ConfigError(f"{path}: device field {field_name!r} must be a string, got {value!r}.")
    if isinstance(value, (int, float)):
        return str(value)
    raise ConfigError(f"{path}: device field {field_name!r} must be a string, got {value!r}.")


def _device_from_dict(raw: dict[str, Any], path: Path) -> Device:
    if "name" not in raw or "host" not in raw:
        raise ConfigError(f"{path}: each device entry needs at least 'name' and 'host'.")

    name = _coerce_str(raw["name"], "name", path)
    host = _coerce_str(raw["host"], "host", path)

    try:
        port = int(raw.get("port", DEFAULT_PORT))
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"{path}: device {name!r} has an invalid 'port': {raw.get('port')!r}") from exc

    timeout_raw = raw.get("timeout")
    timeout: float | None
    if timeout_raw is None:
        timeout = None
    else:
        try:
            timeout = float(timeout_raw)
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"{path}: device {name!r} has an invalid 'timeout': {timeout_raw!r}") from exc

    return Device(
        name=name,
        host=host,
        port=port,
        use_ssl=bool(raw.get("use_ssl", False)),
        username=raw.get("username", "admin"),
        password=raw.get("password", ""),
        disabled=bool(raw.get("disabled", False)),
        comment=raw.get("comment", ""),
        tls_verify=bool(raw.get("tls_verify", True)),
        tls_ca_cert=raw.get("tls_ca_cert"),
        timeout=timeout,
    )


def load_devices(path: Path) -> dict[str, Device]:
    """Load devices from a YAML file. Returns an empty dict if the file does not exist."""
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level YAML must be a mapping with a 'devices' key.")

    entries = data.get("devices", [])
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: 'devices' must be a list.")

    devices: dict[str, Device] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: each device entry must be a mapping.")
        device = _device_from_dict(raw, path)
        if device.name in devices:
            raise ConfigError(f"{path}: duplicate device name {device.name!r}.")
        devices[device.name] = device
    return devices


def load_settings(devices_path: Path | None = None, env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from environment variables plus the devices YAML file.

    `env` defaults to os.environ; passing an explicit mapping is mainly useful
    for tests so they never depend on the real process environment. Typed as
    `Mapping` (read-only) rather than `dict` since `os.environ` itself is an
    `_Environ[str]`, not a `dict` - both satisfy `Mapping[str, str]`.
    """
    resolved_env: Mapping[str, str] = env if env is not None else os.environ
    path = devices_path or Path(resolved_env.get("MIKROTIK_DEVICES_FILE", DEFAULT_DEVICES_FILE))
    devices = load_devices(path)
    allow_write = _bool_env(resolved_env.get("MIKROTIK_ALLOW_WRITE"), default=False)
    privacy_value = resolved_env.get("MIKROTIK_ANONYMIZE_ADDRESSES", "true").strip().lower()
    if privacy_value not in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
        raise ConfigError("MIKROTIK_ANONYMIZE_ADDRESSES must be a boolean (true/false).")
    return Settings(
        allow_write=allow_write,
        devices=devices,
        anonymize_addresses=_bool_env(privacy_value, default=True),
    )

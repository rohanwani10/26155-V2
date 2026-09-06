"""Vendor registry: the single dispatch point from a raw upload to a vendor's
fact-model parser, identity parser, and vendor-specific remediation text.

This is the seam the spec's "vendor support is an additive parser module"
decision describes: `devices.py` never branches on vendor name itself, it
just asks the registry which profile (if any) recognizes the upload. Adding a
vendor means adding a new module with its own parse/detect functions and
registering a `VendorProfile` for it here -- no change to `devices.py`,
`evaluate.py`, or any other vendor's module.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .facts import parse_cisco_ios_facts
from .vendor_juniper_srx import (
    REMEDIATION_OVERRIDES as _JUNIPER_SRX_REMEDIATION_OVERRIDES,
    detect_juniper_srx,
    parse_juniper_srx_facts,
    parse_juniper_srx_version,
)
from .version_info import DeviceIdentity, parse_cisco_ios_version


@dataclass(frozen=True)
class VendorProfile:
    name: str
    detect: Callable[[str, str], bool]
    """(raw_config, raw_version) -> True if this profile recognizes the upload."""
    parse_facts: Callable[[str], Any]
    """redacted_config -> a facts dataclass with fields matching CIS_CONTROLS' fact_ids."""
    parse_identity: Callable[[str], DeviceIdentity]
    """raw_version -> device identity."""
    remediation_overrides: dict[str, str] = field(default_factory=dict)
    """fact_id -> vendor-specific remediation text, applied across every
    framework that fact appears in. Facts with no override use the
    framework-data remediation text as-is."""


_REGISTRY: list[VendorProfile] = []


def register_vendor(profile: VendorProfile) -> None:
    _REGISTRY.append(profile)


def detect_vendor(raw_config: str, raw_version: str) -> VendorProfile | None:
    """First registered profile whose detect() matches, in registration order.
    None means no known vendor recognized this upload."""
    for profile in _REGISTRY:
        if profile.detect(raw_config, raw_version):
            return profile
    return None


def registered_vendor_names() -> list[str]:
    return [profile.name for profile in _REGISTRY]


def _detect_cisco_ios(raw_config: str, raw_version: str) -> bool:
    # The version/hardware dump is the reliable signal (every "show version"
    # output says "Cisco IOS Software" or similar); the config alone can be
    # too sparse (e.g. a near-empty config) to identify a vendor from.
    return "cisco" in raw_version.lower()


register_vendor(
    VendorProfile(
        name="cisco_ios",
        detect=_detect_cisco_ios,
        parse_facts=parse_cisco_ios_facts,
        parse_identity=parse_cisco_ios_version,
    )
)

register_vendor(
    VendorProfile(
        name="juniper_srx",
        detect=detect_juniper_srx,
        parse_facts=parse_juniper_srx_facts,
        parse_identity=parse_juniper_srx_version,
        remediation_overrides=_JUNIPER_SRX_REMEDIATION_OVERRIDES,
    )
)

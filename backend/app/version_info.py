"""Extracts device identification from a Cisco IOS `show version`-style dump."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceIdentity:
    model: str | None
    serial_number: str | None
    os_version: str | None


def parse_cisco_ios_version(text: str) -> DeviceIdentity:
    model = None
    if m := re.search(r"^cisco (\S+)", text, re.MULTILINE):
        model = m.group(1)
    elif m := re.search(r"Model number\s*:\s*(\S+)", text, re.IGNORECASE):
        model = m.group(1)

    serial_number = None
    if m := re.search(r"System serial number\s*:\s*(\S+)", text, re.IGNORECASE):
        serial_number = m.group(1)
    elif m := re.search(r"Processor board ID\s+(\S+)", text):
        serial_number = m.group(1)

    os_version = None
    if m := re.search(r"Version (\S+),", text):
        os_version = m.group(1)

    return DeviceIdentity(model=model, serial_number=serial_number, os_version=os_version)

"""Extracts the vendor-neutral fact model from a Cisco IOS config.

Runs on the already-redacted config text (see redaction.py) -- these
functions never see a raw secret value, only the typed placeholders left
behind by redaction, which is all compliance evaluation actually needs.
"""

import re
from dataclasses import dataclass

_EXEC_TIMEOUT_RE = re.compile(r"exec-timeout (\d+)(?: (\d+))?")
_ENABLE_SECRET_TYPE_RE = re.compile(r"<redacted:enable_secret type=(\S+)>")
# Cisco type 0 means "stored/entered as cleartext" -- not encrypted at all,
# despite being configured via the `secret` (not `password`) keyword.
_CLEARTEXT_SECRET_TYPE = "0"


@dataclass(frozen=True)
class CiscoIosFacts:
    ssh_version_2: bool
    telnet_enabled: bool
    enable_secret_strong: bool
    service_password_encryption: bool
    banner_configured: bool
    logging_host_configured: bool
    snmp_default_community: bool
    aaa_new_model: bool
    exec_timeout_configured: bool


def _line_blocks(text: str, header_prefix: str) -> list[str]:
    """Cisco IOS config is line-based: a top-level statement like `line vty 0
    4` is followed by indented sub-statements until the next non-indented
    line. This groups a header and its indented body into one block."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith(header_prefix):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None and (line.startswith(" ") or line.startswith("\t")):
            current.append(line)
        elif current is not None:
            blocks.append(current)
            current = None
    if current is not None:
        blocks.append(current)
    return ["\n".join(block) for block in blocks]


def _exec_timeout_is_set(block: str) -> bool | None:
    """None means the block has no exec-timeout statement at all (so it's
    running on whatever the platform default is, which we can't verify from
    the config -- treated as not-configured, not as compliant by default)."""
    m = _EXEC_TIMEOUT_RE.search(block)
    if not m:
        return None
    minutes = int(m.group(1))
    seconds = int(m.group(2)) if m.group(2) else 0
    return minutes > 0 or seconds > 0


def _exec_timeout_configured(text: str) -> bool:
    # CIS-4.3 covers both the console and every VTY range; one hardened range
    # must never mask an insecure sibling range, and console access matters
    # just as much as remote access.
    blocks = _line_blocks(text, "line con") + _line_blocks(text, "line vty")
    if not blocks:
        return False
    return all(_exec_timeout_is_set(block) is True for block in blocks)


def _enable_secret_strong(text: str) -> bool:
    m = _ENABLE_SECRET_TYPE_RE.search(text)
    if not m:
        return False
    return m.group(1) != _CLEARTEXT_SECRET_TYPE


def parse_cisco_ios_facts(redacted_config: str) -> CiscoIosFacts:
    text = redacted_config

    ssh_version_2 = bool(re.search(r"^\s*ip ssh version 2\s*$", text, re.MULTILINE))
    aaa_new_model = bool(re.search(r"^\s*aaa new-model\s*$", text, re.MULTILINE))
    service_password_encryption = bool(
        re.search(r"^\s*service password-encryption\s*$", text, re.MULTILINE)
    )
    banner_configured = bool(
        re.search(r"^\s*banner (login|motd)\b", text, re.MULTILINE)
    )
    logging_host_configured = bool(
        re.search(r"^\s*logging host \S+", text, re.MULTILINE)
    )
    snmp_default_community = bool(
        re.search(r"<redacted:snmp_community value=(public|private)>", text)
    )

    vty_blocks = _line_blocks(text, "line vty")
    telnet_enabled = any(
        re.search(r"transport input .*\btelnet\b", block, re.IGNORECASE)
        for block in vty_blocks
    )

    return CiscoIosFacts(
        ssh_version_2=ssh_version_2,
        telnet_enabled=telnet_enabled,
        enable_secret_strong=_enable_secret_strong(text),
        service_password_encryption=service_password_encryption,
        banner_configured=banner_configured,
        logging_host_configured=logging_host_configured,
        snmp_default_community=snmp_default_community,
        aaa_new_model=aaa_new_model,
        exec_timeout_configured=_exec_timeout_configured(text),
    )

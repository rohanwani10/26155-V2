"""Extracts the vendor-neutral fact model from a Cisco IOS config.

Runs on the already-redacted config text (see redaction.py) -- these
functions never see a raw secret value, only the typed placeholders left
behind by redaction, which is all compliance evaluation actually needs.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

_EXEC_TIMEOUT_RE = re.compile(r"exec-timeout (\d+)(?: (\d+))?")
_ENABLE_SECRET_TYPE_RE = re.compile(r"<redacted:enable_secret type=(\S+)>")
# Cisco type 0 means "stored/entered as cleartext" -- not encrypted at all,
# despite being configured via the `secret` (not `password`) keyword.
_CLEARTEXT_SECRET_TYPE = "0"

# AAA / authentication
_AAA_AUTHN_LOGIN_RE = re.compile(r"^\s*aaa authentication login \S+ \S+", re.MULTILINE)
_AAA_AUTHZ_EXEC_RE = re.compile(r"^\s*aaa authorization exec \S+ \S+", re.MULTILINE)
_AAA_ACCT_EXEC_RE = re.compile(
    r"^\s*aaa accounting exec \S+ start-stop \S+", re.MULTILINE
)
_LOGIN_BLOCK_FOR_RE = re.compile(
    r"^\s*login block-for \d+ attempts \d+ within \d+", re.MULTILINE
)
_MIN_PASSWORD_LENGTH_RE = re.compile(r"^\s*security passwords min-length (\d+)", re.MULTILINE)
_MIN_PASSWORD_LENGTH_REQUIRED = 8
_USER_PASSWORD_MARKER_RE = re.compile(r"<redacted:user_password")

# SSH / management access
_SSH_TIMEOUT_RE = re.compile(r"^\s*ip ssh time-out \d+", re.MULTILINE)
_SSH_AUTH_RETRIES_RE = re.compile(r"^\s*ip ssh authentication-retries (\d+)", re.MULTILINE)
_SSH_AUTH_RETRIES_MAX = 3
# Anchored to line-start so `no access-class 10 in` (explicitly removing the
# restriction) doesn't match as a substring of the enabling form.
_VTY_ACCESS_CLASS_RE = re.compile(r"^\s*access-class \S+ in", re.MULTILINE)
_LOGIN_AUTHENTICATION_RE = re.compile(r"login authentication \S+")
_HTTP_SERVER_DISABLED_RE = re.compile(r"^\s*no ip http server\s*$", re.MULTILINE)

# Insecure global services (enabled by default unless explicitly disabled --
# treated as enabled/non-compliant when the config doesn't say otherwise,
# same fail-safe stance the walking skeleton already takes for exec-timeout).
_CDP_DISABLED_RE = re.compile(r"^\s*no cdp run\s*$", re.MULTILINE)
_BOOTP_DISABLED_RE = re.compile(r"^\s*no ip bootp server\s*$", re.MULTILINE)
_FINGER_DISABLED_RE = re.compile(r"^\s*no (?:service finger|ip finger)\s*$", re.MULTILINE)
_TCP_SMALL_SERVERS_DISABLED_RE = re.compile(
    r"^\s*no service tcp-small-servers\s*$", re.MULTILINE
)
_UDP_SMALL_SERVERS_DISABLED_RE = re.compile(
    r"^\s*no service udp-small-servers\s*$", re.MULTILINE
)
_PAD_SERVICE_DISABLED_RE = re.compile(r"^\s*no service pad\s*$", re.MULTILINE)
_SOURCE_ROUTE_DISABLED_RE = re.compile(r"^\s*no ip source-route\s*$", re.MULTILINE)
_DOMAIN_LOOKUP_DISABLED_RE = re.compile(r"^\s*no ip domain-lookup\s*$", re.MULTILINE)

# Logging
_LOGGING_BUFFERED_RE = re.compile(r"^\s*logging buffered (\d+)", re.MULTILINE)
_LOGGING_BUFFERED_MIN_BYTES = 4096
_LOGGING_TRAP_RE = re.compile(r"^\s*logging trap \S+", re.MULTILINE)
_SERVICE_TIMESTAMPS_RE = re.compile(r"^\s*service timestamps log datetime", re.MULTILINE)

# Banners
_BANNER_MOTD_RE = re.compile(r"^\s*banner motd\b", re.MULTILINE)
_BANNER_EXEC_RE = re.compile(r"^\s*banner exec\b", re.MULTILINE)


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

    aaa_authentication_login_configured: bool
    aaa_authorization_exec_configured: bool
    aaa_accounting_exec_configured: bool
    login_block_for_configured: bool
    username_password_configured: bool
    min_password_length_configured: bool

    ssh_timeout_configured: bool
    ssh_auth_retries_limited: bool
    console_login_local_configured: bool
    http_server_enabled: bool

    cdp_enabled: bool
    bootp_server_enabled: bool
    finger_service_enabled: bool
    tcp_small_servers_enabled: bool
    udp_small_servers_enabled: bool
    pad_service_enabled: bool
    ip_source_route_enabled: bool
    ip_domain_lookup_enabled: bool

    logging_buffered_configured: bool
    logging_trap_configured: bool
    service_timestamps_configured: bool

    vty_access_class_configured: bool
    banner_motd_configured: bool
    banner_exec_configured: bool


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


def _min_password_length_configured(text: str) -> bool:
    m = _MIN_PASSWORD_LENGTH_RE.search(text)
    if not m:
        return False
    return int(m.group(1)) >= _MIN_PASSWORD_LENGTH_REQUIRED


def _ssh_auth_retries_limited(text: str) -> bool:
    m = _SSH_AUTH_RETRIES_RE.search(text)
    if not m:
        return False
    return int(m.group(1)) <= _SSH_AUTH_RETRIES_MAX


def _logging_buffered_configured(text: str) -> bool:
    m = _LOGGING_BUFFERED_RE.search(text)
    if not m:
        return False
    return int(m.group(1)) >= _LOGGING_BUFFERED_MIN_BYTES


def _all_blocks_require(
    text: str, header_prefix: str, block_is_hardened: Callable[[str], bool]
) -> bool:
    """Shared shape for "every line con/vty range must satisfy X, and having
    none at all is not compliant" -- the same fail-safe stance exec-timeout
    already uses."""
    blocks = _line_blocks(text, header_prefix)
    if not blocks:
        return False
    return all(block_is_hardened(block) for block in blocks)


def _console_login_local_configured(text: str) -> bool:
    # "login local" is the walking-skeleton's literal check; "login
    # authentication <list-name>" is the equally valid AAA-method-list form
    # used once `aaa new-model` is enabled.
    return _all_blocks_require(
        text,
        "line con",
        lambda block: "login local" in block or bool(_LOGIN_AUTHENTICATION_RE.search(block)),
    )


def _vty_access_class_configured(text: str) -> bool:
    return _all_blocks_require(
        text, "line vty", lambda block: bool(_VTY_ACCESS_CLASS_RE.search(block))
    )


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
        # These three commands are inert unless `aaa new-model` is also
        # enabled -- without it, IOS never engages the AAA subsystem they
        # configure, so a config with the line but no `aaa new-model` gets no
        # credit for it. `login block-for` is a separate, standalone Login
        # Enhancements feature that works with or without AAA, so it isn't
        # gated the same way.
        aaa_authentication_login_configured=(
            aaa_new_model and bool(_AAA_AUTHN_LOGIN_RE.search(text))
        ),
        aaa_authorization_exec_configured=(
            aaa_new_model and bool(_AAA_AUTHZ_EXEC_RE.search(text))
        ),
        aaa_accounting_exec_configured=(
            aaa_new_model and bool(_AAA_ACCT_EXEC_RE.search(text))
        ),
        login_block_for_configured=bool(_LOGIN_BLOCK_FOR_RE.search(text)),
        username_password_configured=bool(_USER_PASSWORD_MARKER_RE.search(text)),
        min_password_length_configured=_min_password_length_configured(text),
        ssh_timeout_configured=bool(_SSH_TIMEOUT_RE.search(text)),
        ssh_auth_retries_limited=_ssh_auth_retries_limited(text),
        console_login_local_configured=_console_login_local_configured(text),
        http_server_enabled=not _HTTP_SERVER_DISABLED_RE.search(text),
        cdp_enabled=not _CDP_DISABLED_RE.search(text),
        bootp_server_enabled=not _BOOTP_DISABLED_RE.search(text),
        finger_service_enabled=not _FINGER_DISABLED_RE.search(text),
        tcp_small_servers_enabled=not _TCP_SMALL_SERVERS_DISABLED_RE.search(text),
        udp_small_servers_enabled=not _UDP_SMALL_SERVERS_DISABLED_RE.search(text),
        pad_service_enabled=not _PAD_SERVICE_DISABLED_RE.search(text),
        ip_source_route_enabled=not _SOURCE_ROUTE_DISABLED_RE.search(text),
        ip_domain_lookup_enabled=not _DOMAIN_LOOKUP_DISABLED_RE.search(text),
        logging_buffered_configured=_logging_buffered_configured(text),
        logging_trap_configured=bool(_LOGGING_TRAP_RE.search(text)),
        service_timestamps_configured=bool(_SERVICE_TIMESTAMPS_RE.search(text)),
        vty_access_class_configured=_vty_access_class_configured(text),
        banner_motd_configured=bool(_BANNER_MOTD_RE.search(text)),
        banner_exec_configured=bool(_BANNER_EXEC_RE.search(text)),
    )

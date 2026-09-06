"""Extracts the vendor-neutral fact model from a Juniper SRX (Junos `set`-
style) config.

Mirrors facts.py's Cisco IOS parser: runs on the already-redacted config text
(see redaction.py -- this module registers its own Junos-specific secret
patterns at import time), never sees a raw secret value, and produces the
same CiscoIosFacts field set so evaluate.py can evaluate it with zero
vendor-specific branching outside this module.

Junos config is a flat list of `set ...` statements (no Cisco-style indented
line blocks), and a lot of Cisco-specific legacy concepts (CDP, BOOTP server,
Finger, TCP/UDP small servers, PAD, `aaa authorization exec`, ...) have no
literal Junos equivalent. Where that's true, each fact is mapped onto the
closest real Junos mechanism that serves the same security intent -- see the
per-fact comments below and the ticket's Comments section for the specific
judgment calls made.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from .redaction import register_redaction_rule
from .version_info import DeviceIdentity

Replacer = Callable[[re.Match[str]], str]

# --- Vendor-specific redaction -----------------------------------------
# Junos spells secrets very differently from Cisco: no numeric "type"
# digit, just an explicit encrypted-password/plain-text-password choice.

_ROOT_ENCRYPTED_RE = re.compile(
    r'(set system root-authentication encrypted-password) "?([^"\n]+)"?'
)
_ROOT_PLAIN_RE = re.compile(
    r'(set system root-authentication plain-text-password) "?([^"\n]+)"?'
)
_USER_ENCRYPTED_RE = re.compile(
    r'(set system login user \S+ authentication encrypted-password) "?([^"\n]+)"?'
)
_USER_PLAIN_RE = re.compile(
    r'(set system login user \S+ authentication plain-text-password) "?([^"\n]+)"?'
)
_AAA_SERVER_SECRET_RE = re.compile(
    r'(set system (?:radius|tacplus)-server \S+ secret) "?([^"\n]+)"?'
)
_SNMP_COMMUNITY_RE = re.compile(r"(set snmp community) (\S+)")

_DEFAULT_SNMP_COMMUNITIES = {"public", "private"}


def _make_secret_redactor(label: str, kind: str) -> Replacer:
    def _redact(match: re.Match[str]) -> str:
        return f"{match.group(1)} <redacted:{label} type={kind}>"

    return _redact


def _redact_aaa_server_secret(match: re.Match[str]) -> str:
    return f"{match.group(1)} <redacted:aaa_server_secret>"


def _redact_snmp_community(match: re.Match[str]) -> str:
    community = match.group(2).lower()
    marker = community if community in _DEFAULT_SNMP_COMMUNITIES else "custom"
    return f"{match.group(1)} <redacted:snmp_community value={marker}>"


register_redaction_rule(_ROOT_ENCRYPTED_RE, _make_secret_redactor("root_secret", "encrypted"))
register_redaction_rule(_ROOT_PLAIN_RE, _make_secret_redactor("root_secret", "plain"))
register_redaction_rule(_USER_ENCRYPTED_RE, _make_secret_redactor("user_secret", "encrypted"))
register_redaction_rule(_USER_PLAIN_RE, _make_secret_redactor("user_secret", "plain"))
register_redaction_rule(_AAA_SERVER_SECRET_RE, _redact_aaa_server_secret)
register_redaction_rule(_SNMP_COMMUNITY_RE, _redact_snmp_community)


# --- Fact regexes --------------------------------------------------------

_ROOT_SECRET_TYPE_RE = re.compile(r"<redacted:root_secret type=(\S+)>")
_PLAIN_SECRET_ANYWHERE_RE = re.compile(r"<redacted:(?:root_secret|user_secret) type=plain>")
_USER_SECRET_PLAIN_RE = re.compile(r"<redacted:user_secret type=plain>")
_SNMP_DEFAULT_COMMUNITY_RE = re.compile(r"<redacted:snmp_community value=(public|private)>")

_SSH_VERSION_2_RE = re.compile(r"set system services ssh protocol-version v2\b")
_TELNET_RE = re.compile(r"set system services telnet\b")
_LOGIN_MESSAGE_RE = re.compile(r"set system login message\b")
_LOGIN_ANNOUNCEMENT_RE = re.compile(r"set system login announcement\b")
_SYSLOG_HOST_RE = re.compile(r"set system syslog host \S+")
_SYSLOG_HOST_SEVERITY_RE = re.compile(r"set system syslog host \S+ any (\S+)")
_SYSLOG_TIME_FORMAT_RE = re.compile(r"set system syslog time-format\b")
_SYSLOG_ARCHIVE_SIZE_RE = re.compile(r"set system syslog file \S+ archive size (\S+)")
_MIN_LOGGING_BUFFERED_BYTES = 4096

_IDLE_TIMEOUT_RE = re.compile(r"set system login idle-timeout (\d+)")
_SSH_CLIENT_ALIVE_INTERVAL_RE = re.compile(r"set system services ssh client-alive-interval \d+")
_TRIES_BEFORE_DISCONNECT_RE = re.compile(
    r"set system login retry-options tries-before-disconnect (\d+)"
)
_LOCKOUT_PERIOD_RE = re.compile(r"set system login retry-options lockout-period (\d+)")
_SSH_AUTH_RETRIES_MAX = 3

_LOGIN_USER_AUTH_RE = re.compile(
    r"set system login user \S+ authentication (?:encrypted-password|plain-text-password)\b"
)
_MIN_PW_LEN_RE = re.compile(r"set system login password minimum-length (\d+)")
_MIN_PW_LEN_REQUIRED = 8

_WEB_MANAGEMENT_HTTP_RE = re.compile(r"set system services web-management http\b")
_LLDP_RE = re.compile(r"set protocols lldp interface\b")
_BOOTP_HELPERS_RE = re.compile(r"set forwarding-options helpers bootp\b")
_FINGER_RE = re.compile(r"set system services finger\b")
_XNM_CLEAR_TEXT_RE = re.compile(r"set system services xnm-clear-text\b")
_DHCP_LOCAL_SERVER_RE = re.compile(r"set system services dhcp-local-server\b")
_SSH_ROOT_LOGIN_ALLOW_RE = re.compile(r"set system services ssh root-login allow\b")
_NO_SOURCE_ROUTE_RE = re.compile(r"set system internet-options no-source-route\b")
_NAME_SERVER_RE = re.compile(r"set system name-server \S+")

_AUTH_ORDER_RE = re.compile(r"set system authentication-order (?:\[([^\]]+)\]|(\S+))")
_ACCOUNTING_EVENTS_RE = re.compile(r"set system accounting events (?:\[([^\]]+)\]|(\S+))")
_ACCOUNTING_DEST_RE = re.compile(r"set system accounting destination (?:\[([^\]]+)\]|(\S+))")
_RADIUS_SERVER_RE = re.compile(r"set system radius-server \S+")
_TACPLUS_SERVER_RE = re.compile(r"set system tacplus-server \S+")
_LOGIN_REMOTE_CLASS_RE = re.compile(r"set system login user remote class \S+")

_LO0_FILTER_RE = re.compile(r"set interfaces lo0 unit 0 family inet filter input (\S+)")

_AAA_METHODS = {"radius", "tacplus"}


@dataclass(frozen=True)
class JuniperSrxFacts:
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


def _parse_size(token: str) -> int:
    m = re.match(r"(\d+)([kKmMgG]?)", token)
    if not m:
        return 0
    multiplier = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2).lower()]
    return int(m.group(1)) * multiplier


def _tokens(match: re.Match[str] | None) -> set[str]:
    if match is None:
        return set()
    raw = match.group(1) if match.group(1) is not None else match.group(2)
    return set(raw.split())


def _enable_secret_strong(text: str) -> bool:
    m = _ROOT_SECRET_TYPE_RE.search(text)
    return m is not None and m.group(1) == "encrypted"


def _service_password_encryption(text: str) -> bool:
    return _PLAIN_SECRET_ANYWHERE_RE.search(text) is None


def _exec_timeout_configured(text: str) -> bool:
    m = _IDLE_TIMEOUT_RE.search(text)
    return m is not None and int(m.group(1)) > 0


def _login_block_for_configured(text: str) -> bool:
    return bool(_TRIES_BEFORE_DISCONNECT_RE.search(text)) and bool(
        _LOCKOUT_PERIOD_RE.search(text)
    )


def _min_password_length_configured(text: str) -> bool:
    m = _MIN_PW_LEN_RE.search(text)
    return m is not None and int(m.group(1)) >= _MIN_PW_LEN_REQUIRED


def _ssh_auth_retries_limited(text: str) -> bool:
    m = _TRIES_BEFORE_DISCONNECT_RE.search(text)
    return m is not None and int(m.group(1)) <= _SSH_AUTH_RETRIES_MAX


def _logging_buffered_configured(text: str) -> bool:
    m = _SYSLOG_ARCHIVE_SIZE_RE.search(text)
    return m is not None and _parse_size(m.group(1)) >= _MIN_LOGGING_BUFFERED_BYTES


def _logging_trap_configured(text: str) -> bool:
    m = _SYSLOG_HOST_SEVERITY_RE.search(text)
    return m is not None and m.group(1).lower() != "none"


def _auth_order_methods(text: str) -> set[str]:
    return _tokens(_AUTH_ORDER_RE.search(text))


def _aaa_new_model(text: str) -> bool:
    return bool(_auth_order_methods(text) & _AAA_METHODS)


def _aaa_server_configured(text: str) -> bool:
    return bool(_RADIUS_SERVER_RE.search(text)) or bool(_TACPLUS_SERVER_RE.search(text))


def _aaa_authentication_login_configured(text: str) -> bool:
    return _aaa_new_model(text) and _aaa_server_configured(text)


def _aaa_authorization_exec_configured(text: str) -> bool:
    return _aaa_new_model(text) and bool(_LOGIN_REMOTE_CLASS_RE.search(text))


def _aaa_accounting_exec_configured(text: str) -> bool:
    events = _tokens(_ACCOUNTING_EVENTS_RE.search(text))
    dest = _tokens(_ACCOUNTING_DEST_RE.search(text))
    return _aaa_new_model(text) and "login" in events and bool(dest & _AAA_METHODS)


def _vty_access_class_configured(text: str) -> bool:
    m = _LO0_FILTER_RE.search(text)
    if m is None:
        return False
    filter_name = re.escape(m.group(1))
    src_re = re.compile(rf"set firewall filter {filter_name} term \S+ from source-address \S+")
    return bool(src_re.search(text))


def parse_juniper_srx_facts(redacted_config: str) -> JuniperSrxFacts:
    text = redacted_config

    return JuniperSrxFacts(
        ssh_version_2=bool(_SSH_VERSION_2_RE.search(text)),
        telnet_enabled=bool(_TELNET_RE.search(text)),
        enable_secret_strong=_enable_secret_strong(text),
        service_password_encryption=_service_password_encryption(text),
        banner_configured=bool(_LOGIN_MESSAGE_RE.search(text))
        or bool(_LOGIN_ANNOUNCEMENT_RE.search(text)),
        logging_host_configured=bool(_SYSLOG_HOST_RE.search(text)),
        snmp_default_community=bool(_SNMP_DEFAULT_COMMUNITY_RE.search(text)),
        aaa_new_model=_aaa_new_model(text),
        exec_timeout_configured=_exec_timeout_configured(text),
        aaa_authentication_login_configured=_aaa_authentication_login_configured(text),
        aaa_authorization_exec_configured=_aaa_authorization_exec_configured(text),
        aaa_accounting_exec_configured=_aaa_accounting_exec_configured(text),
        login_block_for_configured=_login_block_for_configured(text),
        username_password_configured=bool(_USER_SECRET_PLAIN_RE.search(text)),
        min_password_length_configured=_min_password_length_configured(text),
        ssh_timeout_configured=bool(_SSH_CLIENT_ALIVE_INTERVAL_RE.search(text)),
        ssh_auth_retries_limited=_ssh_auth_retries_limited(text),
        console_login_local_configured=bool(_LOGIN_USER_AUTH_RE.search(text)),
        http_server_enabled=bool(_WEB_MANAGEMENT_HTTP_RE.search(text)),
        cdp_enabled=bool(_LLDP_RE.search(text)),
        bootp_server_enabled=bool(_BOOTP_HELPERS_RE.search(text)),
        finger_service_enabled=bool(_FINGER_RE.search(text)),
        tcp_small_servers_enabled=bool(_XNM_CLEAR_TEXT_RE.search(text)),
        udp_small_servers_enabled=bool(_DHCP_LOCAL_SERVER_RE.search(text)),
        pad_service_enabled=bool(_SSH_ROOT_LOGIN_ALLOW_RE.search(text)),
        ip_source_route_enabled=not bool(_NO_SOURCE_ROUTE_RE.search(text)),
        ip_domain_lookup_enabled=bool(_NAME_SERVER_RE.search(text)),
        logging_buffered_configured=_logging_buffered_configured(text),
        logging_trap_configured=_logging_trap_configured(text),
        service_timestamps_configured=bool(_SYSLOG_TIME_FORMAT_RE.search(text)),
        vty_access_class_configured=_vty_access_class_configured(text),
        banner_motd_configured=bool(_LOGIN_MESSAGE_RE.search(text)),
        banner_exec_configured=bool(_LOGIN_ANNOUNCEMENT_RE.search(text)),
    )


# --- Vendor-specific remediation text ------------------------------------
# The CIS/NIST/STIG remediation text baked into rules.py is written in Cisco
# IOS syntax ("Configure: ip ssh version 2"), which would be actively wrong
# guidance for a Junos admin -- every fact gets a Junos-syntax override here,
# matching the exact mechanism each check above looks for.
REMEDIATION_OVERRIDES: dict[str, str] = {
    "ssh_version_2": "Configure: set system services ssh protocol-version v2",
    "telnet_enabled": "Configure: delete system services telnet",
    "enable_secret_strong": (
        'Configure: set system root-authentication encrypted-password "<hash>" '
        "(avoid plain-text-password)"
    ),
    "service_password_encryption": (
        "Configure: use encrypted-password (never plain-text-password) for every "
        "root-authentication and login user authentication statement"
    ),
    "banner_configured": (
        'Configure: set system login message "<authorized access only notice>"'
    ),
    "logging_host_configured": "Configure: set system syslog host <syslog-server-ip> any any",
    "snmp_default_community": (
        "Configure: delete snmp community public; delete snmp community private; "
        "set snmp community <unique-string> authorization read-only"
    ),
    "aaa_new_model": (
        "Configure: set system authentication-order [ tacplus password ]; "
        'set system tacplus-server <server-ip> secret "<secret>"'
    ),
    "exec_timeout_configured": "Configure: set system login idle-timeout 10",
    "aaa_authentication_login_configured": (
        "Configure: set system authentication-order [ tacplus password ]; "
        'set system tacplus-server <server-ip> secret "<secret>"'
    ),
    "aaa_authorization_exec_configured": (
        "Configure: set system login user remote class <permission-class>"
    ),
    "aaa_accounting_exec_configured": (
        "Configure: set system accounting events [ login interactive-commands ]; "
        "set system accounting destination tacplus"
    ),
    "login_block_for_configured": (
        "Configure: set system login retry-options tries-before-disconnect 3; "
        "set system login retry-options lockout-period 60"
    ),
    "username_password_configured": (
        'Configure: set system login user <user> authentication encrypted-password "<hash>" '
        "(remove any plain-text-password statement)"
    ),
    "min_password_length_configured": "Configure: set system login password minimum-length 8",
    "ssh_timeout_configured": "Configure: set system services ssh client-alive-interval 60",
    "ssh_auth_retries_limited": (
        "Configure: set system login retry-options tries-before-disconnect 3"
    ),
    "console_login_local_configured": (
        'Configure: set system login user <user> authentication encrypted-password "<hash>" '
        "(define at least one local user)"
    ),
    "http_server_enabled": "Configure: delete system services web-management http",
    "cdp_enabled": "Configure: delete protocols lldp interface all",
    "bootp_server_enabled": "Configure: delete forwarding-options helpers bootp",
    "finger_service_enabled": "Configure: delete system services finger",
    "tcp_small_servers_enabled": "Configure: delete system services xnm-clear-text",
    "udp_small_servers_enabled": "Configure: delete system services dhcp-local-server",
    "pad_service_enabled": "Configure: delete system services ssh root-login allow",
    "ip_source_route_enabled": "Configure: set system internet-options no-source-route",
    "ip_domain_lookup_enabled": "Configure: delete system name-server",
    "logging_buffered_configured": "Configure: set system syslog file messages archive size 1m",
    "logging_trap_configured": "Configure: set system syslog host <syslog-server-ip> any info",
    "service_timestamps_configured": "Configure: set system syslog time-format year millisecond",
    "vty_access_class_configured": (
        "Configure: set firewall filter PROTECT-RE term allow-mgmt from source-address "
        "<management-subnet>; set interfaces lo0 unit 0 family inet filter input PROTECT-RE"
    ),
    "banner_motd_configured": (
        'Configure: set system login message "<authorized access only notice>"'
    ),
    "banner_exec_configured": (
        'Configure: set system login announcement "<authorized access only notice>"'
    ),
}


# --- Device identification -------------------------------------------
# Parses a combined `show version` + `show chassis hardware`-style dump.

_MODEL_RE = re.compile(r"^Model:\s*(\S+)", re.MULTILINE)
_OS_VERSION_RE = re.compile(r"^Junos:\s*(\S+)", re.MULTILINE)
_CHASSIS_SERIAL_RE = re.compile(r"^Chassis\s+(\S+)", re.MULTILINE)


def parse_juniper_srx_version(text: str) -> DeviceIdentity:
    model = None
    if m := _MODEL_RE.search(text):
        model = m.group(1)

    serial_number = None
    if m := _CHASSIS_SERIAL_RE.search(text):
        serial_number = m.group(1)

    os_version = None
    if m := _OS_VERSION_RE.search(text):
        os_version = m.group(1)

    return DeviceIdentity(model=model, serial_number=serial_number, os_version=os_version)


def detect_juniper_srx(raw_config: str, raw_version: str) -> bool:
    # Every real Junos `show version` output identifies itself as "Junos" --
    # reliably distinct from Cisco's "Cisco IOS Software" and from arbitrary
    # unrelated text.
    return "junos" in raw_version.lower()

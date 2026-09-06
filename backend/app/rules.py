"""CIS control definitions, mapped to facts in the shared fact model.

This is the data layer the spec describes: adding or updating a control is a
change here, never a change to the parser or the evaluation engine.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    fact_id: str
    control_id: str
    framework: str
    title: str
    severity: str
    remediation: str
    passes_when: bool


CIS_CONTROLS: list[Control] = [
    Control(
        fact_id="ssh_version_2",
        control_id="CIS-4.1",
        framework="CIS",
        title="Use SSH version 2 only",
        severity="high",
        remediation="Configure: ip ssh version 2",
        passes_when=True,
    ),
    Control(
        fact_id="telnet_enabled",
        control_id="CIS-4.2",
        framework="CIS",
        title="Disable Telnet on VTY lines",
        severity="high",
        remediation="Configure: line vty 0 4 / transport input ssh",
        passes_when=False,
    ),
    Control(
        fact_id="enable_secret_strong",
        control_id="CIS-2.1",
        framework="CIS",
        title="Use an encrypted enable secret, not enable password",
        severity="high",
        remediation=(
            "Configure: enable secret <new-secret>; then remove any "
            "'enable password' line"
        ),
        passes_when=True,
    ),
    Control(
        fact_id="service_password_encryption",
        control_id="CIS-2.2",
        framework="CIS",
        title="Encrypt passwords stored in the configuration",
        severity="medium",
        remediation="Configure: service password-encryption",
        passes_when=True,
    ),
    Control(
        fact_id="banner_configured",
        control_id="CIS-1.1",
        framework="CIS",
        title="Configure a legal notification banner",
        severity="low",
        remediation=(
            "Configure: banner login ^C <authorized access only notice> ^C"
        ),
        passes_when=True,
    ),
    Control(
        fact_id="logging_host_configured",
        control_id="CIS-6.1",
        framework="CIS",
        title="Send logs to a centralized syslog host",
        severity="medium",
        remediation="Configure: logging host <syslog-server-ip>",
        passes_when=True,
    ),
    Control(
        fact_id="snmp_default_community",
        control_id="CIS-5.1",
        framework="CIS",
        title="Do not use default SNMP community strings",
        severity="high",
        remediation=(
            "Configure: no snmp-server community public; "
            "no snmp-server community private; "
            "use a strong, unique community string instead"
        ),
        passes_when=False,
    ),
    Control(
        fact_id="aaa_new_model",
        control_id="CIS-3.1",
        framework="CIS",
        title="Enable AAA for centralized authentication",
        severity="medium",
        remediation="Configure: aaa new-model; aaa authentication login default local",
        passes_when=True,
    ),
    Control(
        fact_id="exec_timeout_configured",
        control_id="CIS-4.3",
        framework="CIS",
        title="Configure a session timeout on VTY/console lines",
        severity="low",
        remediation=(
            "Configure: exec-timeout 10 0 under line con 0 and line vty 0 4"
        ),
        passes_when=True,
    ),
    Control(
        fact_id="banner_motd_configured",
        control_id="CIS-1.2",
        framework="CIS",
        title="Configure a message-of-the-day banner",
        severity="low",
        remediation="Configure: banner motd ^C <authorized access only notice> ^C",
        passes_when=True,
    ),
    Control(
        fact_id="banner_exec_configured",
        control_id="CIS-1.3",
        framework="CIS",
        title="Configure an EXEC-mode banner",
        severity="low",
        remediation="Configure: banner exec ^C <authorized access only notice> ^C",
        passes_when=True,
    ),
    Control(
        fact_id="vty_access_class_configured",
        control_id="CIS-1.4",
        framework="CIS",
        title="Restrict VTY access with an access-class",
        severity="high",
        remediation=(
            "Configure: access-list 10 permit <management-subnet>; then "
            "access-class 10 in under every line vty range"
        ),
        passes_when=True,
    ),
    Control(
        fact_id="username_password_configured",
        control_id="CIS-2.3",
        framework="CIS",
        title="Do not use unencrypted local user passwords",
        severity="high",
        remediation=(
            "Configure: username <user> secret <new-secret>; then remove any "
            "'username ... password' line"
        ),
        passes_when=False,
    ),
    Control(
        fact_id="min_password_length_configured",
        control_id="CIS-2.4",
        framework="CIS",
        title="Enforce a minimum local password length",
        severity="medium",
        remediation="Configure: security passwords min-length 8",
        passes_when=True,
    ),
    Control(
        fact_id="aaa_authentication_login_configured",
        control_id="CIS-3.2",
        framework="CIS",
        title="Configure AAA login authentication",
        severity="high",
        remediation="Configure: aaa authentication login default local",
        passes_when=True,
    ),
    Control(
        fact_id="aaa_authorization_exec_configured",
        control_id="CIS-3.3",
        framework="CIS",
        title="Configure AAA exec authorization",
        severity="medium",
        remediation="Configure: aaa authorization exec default local",
        passes_when=True,
    ),
    Control(
        fact_id="aaa_accounting_exec_configured",
        control_id="CIS-3.4",
        framework="CIS",
        title="Configure AAA exec accounting",
        severity="low",
        remediation="Configure: aaa accounting exec default start-stop group tacacs+",
        passes_when=True,
    ),
    Control(
        fact_id="login_block_for_configured",
        control_id="CIS-3.5",
        framework="CIS",
        title="Configure login brute-force lockout",
        severity="medium",
        remediation="Configure: login block-for 120 attempts 3 within 60",
        passes_when=True,
    ),
    Control(
        fact_id="ssh_timeout_configured",
        control_id="CIS-4.4",
        framework="CIS",
        title="Configure the SSH negotiation timeout",
        severity="low",
        remediation="Configure: ip ssh time-out 60",
        passes_when=True,
    ),
    Control(
        fact_id="ssh_auth_retries_limited",
        control_id="CIS-4.5",
        framework="CIS",
        title="Limit SSH authentication retries",
        severity="medium",
        remediation="Configure: ip ssh authentication-retries 3",
        passes_when=True,
    ),
    Control(
        fact_id="console_login_local_configured",
        control_id="CIS-4.6",
        framework="CIS",
        title="Require local login authentication on the console",
        severity="medium",
        remediation="Configure: login local under line con 0",
        passes_when=True,
    ),
    Control(
        fact_id="http_server_enabled",
        control_id="CIS-4.7",
        framework="CIS",
        title="Disable the HTTP management server",
        severity="medium",
        remediation="Configure: no ip http server",
        passes_when=False,
    ),
    Control(
        fact_id="cdp_enabled",
        control_id="CIS-7.1",
        framework="CIS",
        title="Disable CDP unless required",
        severity="low",
        remediation="Configure: no cdp run",
        passes_when=False,
    ),
    Control(
        fact_id="bootp_server_enabled",
        control_id="CIS-7.2",
        framework="CIS",
        title="Disable the BOOTP server",
        severity="medium",
        remediation="Configure: no ip bootp server",
        passes_when=False,
    ),
    Control(
        fact_id="finger_service_enabled",
        control_id="CIS-7.3",
        framework="CIS",
        title="Disable the Finger service",
        severity="low",
        remediation="Configure: no service finger",
        passes_when=False,
    ),
    Control(
        fact_id="tcp_small_servers_enabled",
        control_id="CIS-7.4",
        framework="CIS",
        title="Disable TCP small servers",
        severity="medium",
        remediation="Configure: no service tcp-small-servers",
        passes_when=False,
    ),
    Control(
        fact_id="udp_small_servers_enabled",
        control_id="CIS-7.5",
        framework="CIS",
        title="Disable UDP small servers",
        severity="medium",
        remediation="Configure: no service udp-small-servers",
        passes_when=False,
    ),
    Control(
        fact_id="pad_service_enabled",
        control_id="CIS-7.6",
        framework="CIS",
        title="Disable the PAD service",
        severity="low",
        remediation="Configure: no service pad",
        passes_when=False,
    ),
    Control(
        fact_id="ip_source_route_enabled",
        control_id="CIS-7.7",
        framework="CIS",
        title="Disable IP source routing",
        severity="high",
        remediation="Configure: no ip source-route",
        passes_when=False,
    ),
    Control(
        fact_id="ip_domain_lookup_enabled",
        control_id="CIS-7.8",
        framework="CIS",
        title="Disable DNS lookups for unqualified commands",
        severity="low",
        remediation="Configure: no ip domain-lookup",
        passes_when=False,
    ),
    Control(
        fact_id="logging_buffered_configured",
        control_id="CIS-6.2",
        framework="CIS",
        title="Configure a sized local logging buffer",
        severity="low",
        remediation="Configure: logging buffered 16384",
        passes_when=True,
    ),
    Control(
        fact_id="logging_trap_configured",
        control_id="CIS-6.3",
        framework="CIS",
        title="Configure a syslog trap severity level",
        severity="medium",
        remediation="Configure: logging trap informational",
        passes_when=True,
    ),
    Control(
        fact_id="service_timestamps_configured",
        control_id="CIS-6.4",
        framework="CIS",
        title="Timestamp log messages with date and time",
        severity="low",
        remediation="Configure: service timestamps log datetime",
        passes_when=True,
    ),
]


@dataclass(frozen=True)
class FrameworkMapping:
    """A fact's NIST SP 800-53 (Rev. 5) and DISA STIG (Cisco IOS Router/Switch
    STIG naming convention) identities. Severity, remediation, and
    passes_when are the same underlying technical judgment as CIS for that
    fact, so they're borrowed from CIS_CONTROLS rather than re-typed here --
    only the framework-specific control ID and requirement wording differ."""

    nist_id: str
    nist_title: str
    stig_id: str
    stig_title: str


# One entry per fact_id in CiscoIosFacts -- the same 1:1 technical granularity
# CIS uses. Adding/updating a NIST or STIG mapping is a data change here.
FACT_FRAMEWORK_MAPPINGS: dict[str, FrameworkMapping] = {
    "ssh_version_2": FrameworkMapping(
        "AC-17(2)",
        "Remote access sessions must use SSH version 2 with encryption meeting FIPS-validated cryptography",
        "CISC-ND-000660",
        "The device must be configured to use SSH version 2 for management connections",
    ),
    "telnet_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: unencrypted remote management protocols (Telnet) must be disabled",
        "CISC-ND-000670",
        "The device must not have Telnet enabled for management access",
    ),
    "enable_secret_strong": FrameworkMapping(
        "IA-5(1)",
        "Password-Based Authentication: privileged-level passwords must be stored using a one-way encryption algorithm",
        "CISC-ND-000330",
        "The device must be configured with an encrypted privileged-level (enable) password",
    ),
    "service_password_encryption": FrameworkMapping(
        "IA-5(1)",
        "Password-Based Authentication: locally stored passwords must be encrypted in the configuration",
        "CISC-ND-000340",
        "The device must encrypt all locally stored passwords",
    ),
    "banner_configured": FrameworkMapping(
        "AC-8",
        "System Use Notification: a warning banner must be displayed before granting access",
        "CISC-ND-000010",
        "The device must display the DoD-approved (or organization-approved) warning banner before a logon prompt",
    ),
    "logging_host_configured": FrameworkMapping(
        "AU-6(3)",
        "Audit Record Review, Analysis, and Reporting: audit records must be sent to a central log server",
        "CISC-RT-000420",
        "The device must be configured to send log data to a central log server",
    ),
    "snmp_default_community": FrameworkMapping(
        "IA-5",
        "Authenticator Management: default authenticators (SNMP community strings) must be changed",
        "CISC-ND-000870",
        "The device must not use default SNMP community strings",
    ),
    "aaa_new_model": FrameworkMapping(
        "IA-2",
        "Identification and Authentication (Organizational Users): AAA services must be enabled for all administrative access",
        "CISC-ND-000630",
        "The device must use AAA services for authentication of privileged sessions",
    ),
    "exec_timeout_configured": FrameworkMapping(
        "AC-12",
        "Session Termination: management sessions must be automatically terminated after a period of inactivity",
        "CISC-ND-000230",
        "The device must terminate idle management sessions after a defined period of inactivity",
    ),
    "aaa_authentication_login_configured": FrameworkMapping(
        "IA-2",
        "Identification and Authentication: all administrative logons must be authenticated via AAA",
        "CISC-ND-000640",
        "The device must authenticate all administrative access using AAA",
    ),
    "aaa_authorization_exec_configured": FrameworkMapping(
        "AC-3",
        "Access Enforcement: privileged EXEC access must be authorized via AAA",
        "CISC-ND-000650",
        "The device must use AAA to enforce authorization for EXEC-level access",
    ),
    "aaa_accounting_exec_configured": FrameworkMapping(
        "AU-12",
        "Audit Record Generation: accounting records must be generated for privileged EXEC sessions",
        "CISC-ND-000680",
        "The device must generate accounting records for EXEC-level administrative sessions",
    ),
    "login_block_for_configured": FrameworkMapping(
        "AC-7",
        "Unsuccessful Logon Attempts: the device must enforce a delay/lockout after repeated failed logon attempts",
        "CISC-ND-000220",
        "The device must enforce a lockout period after a defined number of consecutive failed logon attempts",
    ),
    "username_password_configured": FrameworkMapping(
        "IA-5(1)",
        "Password-Based Authentication: local user passwords must not be stored or configured in cleartext-reversible form",
        "CISC-ND-000350",
        "The device must not have local user accounts configured with unencrypted passwords",
    ),
    "min_password_length_configured": FrameworkMapping(
        "IA-5(1)",
        "Password-Based Authentication: a minimum password length must be enforced",
        "CISC-ND-000360",
        "The device must enforce a minimum password length for locally defined accounts",
    ),
    "ssh_timeout_configured": FrameworkMapping(
        "AC-12",
        "Session Termination: SSH sessions that fail to complete authentication within a set time must be dropped",
        "CISC-ND-000240",
        "The device must terminate an SSH session that fails to authenticate within a configured time period",
    ),
    "ssh_auth_retries_limited": FrameworkMapping(
        "AC-7",
        "Unsuccessful Logon Attempts: SSH authentication attempts must be limited",
        "CISC-ND-000225",
        "The device must limit the number of SSH authentication attempts per connection",
    ),
    "console_login_local_configured": FrameworkMapping(
        "IA-2",
        "Identification and Authentication: console access must require authentication",
        "CISC-ND-000645",
        "The device must require authentication for access via the console port",
    ),
    "http_server_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: unnecessary management interfaces (HTTP server) must be disabled",
        "CISC-ND-000690",
        "The device must have the HTTP management interface disabled",
    ),
    "cdp_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: unnecessary discovery protocols (CDP) must be disabled unless required",
        "CISC-RT-000430",
        "The device must have CDP disabled on all interfaces unless explicitly required",
    ),
    "bootp_server_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: the BOOTP server must be disabled",
        "CISC-RT-000440",
        "The device must have the BOOTP server service disabled",
    ),
    "finger_service_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: the Finger service must be disabled",
        "CISC-RT-000450",
        "The device must have the Finger service disabled",
    ),
    "tcp_small_servers_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: TCP small servers must be disabled",
        "CISC-RT-000460",
        "The device must have TCP small servers disabled",
    ),
    "udp_small_servers_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: UDP small servers must be disabled",
        "CISC-RT-000470",
        "The device must have UDP small servers disabled",
    ),
    "pad_service_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: the PAD service must be disabled",
        "CISC-RT-000480",
        "The device must have the PAD service disabled",
    ),
    "ip_source_route_enabled": FrameworkMapping(
        "SC-5",
        "Denial of Service Protection: IP source routing must be disabled to prevent spoofing/redirection",
        "CISC-RT-000490",
        "The device must have IP source routing disabled",
    ),
    "ip_domain_lookup_enabled": FrameworkMapping(
        "CM-7",
        "Least Functionality: DNS lookups for unqualified commands must be disabled",
        "CISC-RT-000500",
        "The device must have DNS lookup for unqualified commands disabled",
    ),
    "logging_buffered_configured": FrameworkMapping(
        "AU-4",
        "Audit Log Storage Capacity: a local logging buffer of adequate size must be allocated",
        "CISC-RT-000410",
        "The device must allocate a local logging buffer of adequate size for audit record retention",
    ),
    "logging_trap_configured": FrameworkMapping(
        "AU-12",
        "Audit Record Generation: log messages must be generated at an appropriate severity level",
        "CISC-RT-000415",
        "The device must generate log messages at the informational level or higher",
    ),
    "service_timestamps_configured": FrameworkMapping(
        "AU-8",
        "Time Stamps: audit/log records must include a date and time stamp",
        "CISC-RT-000425",
        "The device must timestamp all log messages with date and time",
    ),
    "vty_access_class_configured": FrameworkMapping(
        "SC-7",
        "Boundary Protection: remote management access must be restricted to authorized source addresses",
        "CISC-ND-000700",
        "The device must restrict VTY access to authorized management addresses via an access-class",
    ),
    "banner_motd_configured": FrameworkMapping(
        "AC-8",
        "System Use Notification: a message-of-the-day banner must be displayed",
        "CISC-ND-000015",
        "The device must display an approved message-of-the-day banner",
    ),
    "banner_exec_configured": FrameworkMapping(
        "AC-8",
        "System Use Notification: a banner must be displayed upon successful logon",
        "CISC-ND-000020",
        "The device must display an approved banner upon successful logon (EXEC)",
    ),
}


def _mapped_controls(framework: str, id_attr: str, title_attr: str) -> list[Control]:
    """Builds a framework's Control list by pairing each CIS control's fact,
    severity, remediation, and passes_when (the shared technical judgment)
    with that framework's own control ID and requirement text. No code path
    here is framework-specific -- CIS, NIST, and STIG all flow through this
    same generic combinator; only the data in FACT_FRAMEWORK_MAPPINGS above
    changes per framework."""
    return [
        Control(
            fact_id=cis.fact_id,
            control_id=getattr(FACT_FRAMEWORK_MAPPINGS[cis.fact_id], id_attr),
            framework=framework,
            title=getattr(FACT_FRAMEWORK_MAPPINGS[cis.fact_id], title_attr),
            severity=cis.severity,
            remediation=cis.remediation,
            passes_when=cis.passes_when,
        )
        for cis in CIS_CONTROLS
    ]


NIST_CONTROLS: list[Control] = _mapped_controls(
    "NIST SP 800-53", "nist_id", "nist_title"
)
STIG_CONTROLS: list[Control] = _mapped_controls("DISA STIG", "stig_id", "stig_title")


@dataclass(frozen=True)
class IsoAnnexControl:
    """ISO/IEC 27001 Annex A is a control-objective standard, not a
    line-item technical checklist: one Annex A control is typically
    demonstrated by many pieces of technical evidence at once. This is
    deliberately a different shape from Control (no passes_when, no single
    severity) so it can't be evaluated as a false per-control pass/fail --
    see evaluate.evaluate_iso."""

    control_id: str
    title: str
    fact_ids: tuple[str, ...]


# Every fact_id in CiscoIosFacts appears in exactly one of these groups
# (see test_rules.py for the coverage check). Annex A control numbers/titles
# are from ISO/IEC 27001:2013 Annex A.
ISO_ANNEX_CONTROLS: list[IsoAnnexControl] = [
    IsoAnnexControl(
        "A.9.2.3",
        "Management of privileged access rights",
        (
            "enable_secret_strong",
            "service_password_encryption",
            "username_password_configured",
            "min_password_length_configured",
        ),
    ),
    IsoAnnexControl(
        "A.9.4.2",
        "Secure log-on procedures",
        (
            "aaa_new_model",
            "aaa_authentication_login_configured",
            "login_block_for_configured",
            "ssh_auth_retries_limited",
            "console_login_local_configured",
            "exec_timeout_configured",
            "ssh_timeout_configured",
            "banner_configured",
            "banner_motd_configured",
            "banner_exec_configured",
        ),
    ),
    IsoAnnexControl(
        "A.9.1.2",
        "Access to networks and network services",
        (
            "ssh_version_2",
            "telnet_enabled",
            "vty_access_class_configured",
            "http_server_enabled",
        ),
    ),
    IsoAnnexControl(
        "A.9.4.1",
        "Information access restriction",
        (
            "aaa_authorization_exec_configured",
            "aaa_accounting_exec_configured",
        ),
    ),
    IsoAnnexControl(
        "A.12.4.1",
        "Event logging",
        (
            "logging_host_configured",
            "logging_buffered_configured",
            "logging_trap_configured",
            "service_timestamps_configured",
        ),
    ),
    IsoAnnexControl(
        "A.13.1.1",
        "Network controls",
        (
            "snmp_default_community",
            "cdp_enabled",
            "bootp_server_enabled",
            "finger_service_enabled",
            "tcp_small_servers_enabled",
            "udp_small_servers_enabled",
            "pad_service_enabled",
            "ip_source_route_enabled",
            "ip_domain_lookup_enabled",
        ),
    ),
]

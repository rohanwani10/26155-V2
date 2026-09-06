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

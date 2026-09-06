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
]

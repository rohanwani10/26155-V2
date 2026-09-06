"""Extracts the vendor-neutral fact model from an AWS Security Group.

Unlike Cisco IOS, the input here is JSON shaped like `aws ec2
describe-security-groups` output, not line-oriented CLI text -- this module
is the proof point that the fact model normalizes across CLI and JSON/API
configuration sources equally well.

A security group is just an ingress/egress ACL: it has no privileged-mode
secret, no AAA subsystem, no console port, no legacy CLI services. Most of
the 33 Cisco-centric facts have no real equivalent here. For those, the field
is set to whichever value satisfies that fact's `passes_when` in rules.py (so
it evaluates as a harmless, always-compliant no-op rather than a spurious
fail), with a comment explaining the N/A call. The facts that DO have a
genuine analog for an ingress/egress ACL are implemented for real -- see the
per-field comments below.
"""

import json
from dataclasses import dataclass
from typing import Any

from .version_info import DeviceIdentity

# Remote-management ports considered when checking for unrestricted exposure.
# Mirrors what a VTY line historically protects (interactive remote admin
# access): SSH, Telnet, RDP.
_MANAGEMENT_PORTS = (22, 23, 3389)
_TELNET_PORT = 23
_SSH_PORT = 22
_HTTP_PORT = 80
_OPEN_IPV4 = "0.0.0.0/0"
_OPEN_IPV6 = "::/0"


@dataclass(frozen=True)
class AwsSecurityGroupFacts:
    # Exact same 33 field names as CiscoIosFacts -- evaluate.py looks these
    # up by fact_id from rules.py, so the field names are a hard contract,
    # not a style choice.
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


def _extract_security_group(data: dict[str, Any]) -> dict[str, Any]:
    """Accepts either a raw `describe-security-groups` response
    (`{"SecurityGroups": [...]}`) or a single security group object, so
    fixtures/tests can use whichever shape reads more naturally."""
    if "SecurityGroups" in data:
        groups = data["SecurityGroups"]
        result: dict[str, Any] = groups[0] if groups else {}
        return result
    return data


def _permission_open_to_internet(permission: dict[str, Any]) -> bool:
    ip_ranges = permission.get("IpRanges") or []
    ipv6_ranges = permission.get("Ipv6Ranges") or []
    return any(r.get("CidrIp") == _OPEN_IPV4 for r in ip_ranges) or any(
        r.get("CidrIpv6") == _OPEN_IPV6 for r in ipv6_ranges
    )


def _permission_covers_port(permission: dict[str, Any], port: int) -> bool:
    protocol = str(permission.get("IpProtocol", "")).lower()
    if protocol in ("-1", "all"):
        return True
    if protocol != "tcp":
        return False
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return bool(from_port <= port <= to_port)


def _ingress_open_on_port(security_group: dict[str, Any], port: int) -> bool:
    permissions = security_group.get("IpPermissions") or []
    return any(
        _permission_covers_port(p, port) and _permission_open_to_internet(p)
        for p in permissions
    )


def _any_management_port_open(security_group: dict[str, Any]) -> bool:
    return any(_ingress_open_on_port(security_group, p) for p in _MANAGEMENT_PORTS)


def _flow_logs(security_group: dict[str, Any]) -> list[dict[str, Any]]:
    logs: list[dict[str, Any]] = security_group.get("FlowLogs") or []
    return logs


def _flow_logs_active(security_group: dict[str, Any]) -> bool:
    # Signal design: this project's own describe-security-groups upload
    # pairs the SG dump with the VPC's `describe-flow-logs` entries under a
    # `FlowLogs` key (not a real AWS API field) -- any ACTIVE entry means
    # VPC Flow Logs are associated for this SG's VPC, our stand-in for
    # "centralized log host configured".
    return any(fl.get("FlowLogStatus") == "ACTIVE" for fl in _flow_logs(security_group))


def _flow_logs_capture_all_traffic(security_group: dict[str, Any]) -> bool:
    # An ACTIVE flow log with TrafficType "ALL" captures both accepted and
    # rejected traffic -- our stand-in for a broad syslog trap severity
    # level (vs. e.g. ACCEPT-only, which is a narrower capture).
    return any(
        fl.get("FlowLogStatus") == "ACTIVE" and fl.get("TrafficType") == "ALL"
        for fl in _flow_logs(security_group)
    )


def parse_aws_security_group_facts(redacted_config: str) -> AwsSecurityGroupFacts:
    data: dict[str, Any] = json.loads(redacted_config)
    security_group = _extract_security_group(data)

    return AwsSecurityGroupFacts(
        # Repurposed: a security group has no SSH protocol-version concept,
        # so this stands in for "SSH access is not broadly exposed" --
        # passes when TCP 22 isn't open to 0.0.0.0/0 or ::/0.
        ssh_version_2=not _ingress_open_on_port(security_group, _SSH_PORT),
        # Genuine: literal Telnet exposure -- ingress allowing TCP 23 from
        # anywhere.
        telnet_enabled=_ingress_open_on_port(security_group, _TELNET_PORT),
        # N/A: no privileged-mode secret concept for an ACL. Defaults to
        # compliant.
        enable_secret_strong=True,
        # N/A: no locally stored passwords. Defaults to compliant.
        service_password_encryption=True,
        # N/A: no login banner concept. Defaults to compliant.
        banner_configured=True,
        # Genuine: treated as satisfied when VPC Flow Logs are associated
        # and active for this SG's VPC (see _flow_logs_active above).
        logging_host_configured=_flow_logs_active(security_group),
        # N/A: no SNMP community-string concept. Defaults to compliant
        # (i.e. not "using a default community").
        snmp_default_community=False,
        # N/A: no AAA subsystem. Defaults to compliant.
        aaa_new_model=True,
        # N/A: no interactive session concept for an ACL. Defaults to
        # compliant.
        exec_timeout_configured=True,
        # N/A: defaults to compliant.
        aaa_authentication_login_configured=True,
        # N/A: defaults to compliant.
        aaa_authorization_exec_configured=True,
        # N/A: defaults to compliant.
        aaa_accounting_exec_configured=True,
        # N/A: no login lockout concept. Defaults to compliant.
        login_block_for_configured=True,
        # N/A: no local user accounts. Defaults to compliant (i.e. not
        # "configured with a cleartext password").
        username_password_configured=False,
        # N/A: defaults to compliant.
        min_password_length_configured=True,
        # N/A: no SSH session-negotiation concept for an ACL. Defaults to
        # compliant.
        ssh_timeout_configured=True,
        # N/A: defaults to compliant.
        ssh_auth_retries_limited=True,
        # N/A: no console port. Defaults to compliant.
        console_login_local_configured=True,
        # Genuine: an ingress rule allowing TCP 80 from anywhere is treated
        # as an exposed, unencrypted HTTP management surface.
        http_server_enabled=_ingress_open_on_port(security_group, _HTTP_PORT),
        # N/A: no CDP concept. Defaults to compliant.
        cdp_enabled=False,
        # N/A: defaults to compliant.
        bootp_server_enabled=False,
        # N/A: defaults to compliant.
        finger_service_enabled=False,
        # N/A: defaults to compliant.
        tcp_small_servers_enabled=False,
        # N/A: defaults to compliant.
        udp_small_servers_enabled=False,
        # N/A: defaults to compliant.
        pad_service_enabled=False,
        # N/A: defaults to compliant.
        ip_source_route_enabled=False,
        # N/A: defaults to compliant.
        ip_domain_lookup_enabled=False,
        # N/A: no local logging buffer concept. Defaults to compliant.
        logging_buffered_configured=True,
        # Genuine: satisfied when the associated flow log captures ALL
        # traffic (accept + reject), see _flow_logs_capture_all_traffic.
        logging_trap_configured=_flow_logs_capture_all_traffic(security_group),
        # N/A: a VPC Flow Log record always carries start/end timestamps by
        # format -- not a configurable knob for this target. Defaults to
        # compliant.
        service_timestamps_configured=True,
        # Genuine: satisfied when no ingress rule allows unrestricted
        # (0.0.0.0/0 / ::/0) exposure on a remote-management port (SSH,
        # Telnet, RDP) -- our stand-in for restricting VTY access.
        vty_access_class_configured=not _any_management_port_open(security_group),
        # N/A: defaults to compliant.
        banner_motd_configured=True,
        # N/A: defaults to compliant.
        banner_exec_configured=True,
    )


def parse_aws_security_group_identity(text: str) -> DeviceIdentity:
    """Reads the metadata JSON dump (GroupId/OwnerId/Region/VpcId/
    Description) uploaded as this device's "version info" and returns the
    cloud-native identity fields -- there is no model/serial/OS version for
    a security group, so those stay None."""
    data: dict[str, Any] = json.loads(text)
    security_group = _extract_security_group(data)
    return DeviceIdentity(
        model=None,
        serial_number=None,
        os_version=None,
        resource_id=security_group.get("GroupId"),
        account=security_group.get("OwnerId"),
        region=security_group.get("Region"),
    )

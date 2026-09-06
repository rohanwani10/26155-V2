import json
from pathlib import Path

from app.facts import CiscoIosFacts
from app.vendor_aws_security_groups import (
    AwsSecurityGroupFacts,
    parse_aws_security_group_facts,
    parse_aws_security_group_identity,
)
from app.vendors import _detect_aws_security_groups, _detect_cisco_ios

FIXTURES = Path(__file__).parent / "fixtures" / "aws_security_groups"
CISCO_FIXTURES = Path(__file__).parent / "fixtures" / "cisco_ios"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_facts_dataclass_has_exact_same_field_names_as_cisco_ios() -> None:
    # Hard requirement: evaluate.py looks fields up by fact_id from rules.py,
    # so a mismatch here would KeyError at evaluation time.
    assert {f.name for f in AwsSecurityGroupFacts.__dataclass_fields__.values()} == {
        f.name for f in CiscoIosFacts.__dataclass_fields__.values()
    }


def test_vulnerable_security_group_fails_the_genuinely_implemented_facts() -> None:
    facts = parse_aws_security_group_facts(_read("vulnerable_security_group.json"))

    assert facts.telnet_enabled is True  # TCP 23 open to 0.0.0.0/0
    assert facts.ssh_version_2 is False  # TCP 22 open to 0.0.0.0/0
    assert facts.http_server_enabled is True  # TCP 80 open to 0.0.0.0/0
    assert facts.logging_host_configured is False  # no active flow logs
    assert facts.logging_trap_configured is False  # no active flow logs
    assert facts.vty_access_class_configured is False  # mgmt port open to the world


def test_hardened_security_group_passes_the_genuinely_implemented_facts() -> None:
    facts = parse_aws_security_group_facts(_read("hardened_security_group.json"))

    assert facts.telnet_enabled is False
    assert facts.ssh_version_2 is True  # SSH restricted to a private CIDR
    assert facts.http_server_enabled is False  # only 443 open, not 80
    assert facts.logging_host_configured is True  # flow log ACTIVE
    assert facts.logging_trap_configured is True  # TrafficType ALL
    assert facts.vty_access_class_configured is True  # no mgmt port open to the world


def test_na_facts_default_to_a_harmless_pass() -> None:
    # For every fact this target has no analog for, the parser must emit
    # whatever value satisfies that fact's passes_when in rules.py -- on
    # both fixtures, since it's a target-level default, not data-dependent.
    from app.rules import CIS_CONTROLS

    genuinely_implemented = {
        "telnet_enabled",
        "ssh_version_2",
        "http_server_enabled",
        "logging_host_configured",
        "logging_trap_configured",
        "vty_access_class_configured",
    }
    passes_when_by_fact = {c.fact_id: c.passes_when for c in CIS_CONTROLS}

    for fixture in ("vulnerable_security_group.json", "hardened_security_group.json"):
        facts = parse_aws_security_group_facts(_read(fixture))
        for fact_id, value in vars(facts).items():
            if fact_id in genuinely_implemented:
                continue
            assert value == passes_when_by_fact[fact_id], f"{fact_id} in {fixture}"


def test_identity_reads_cloud_native_fields() -> None:
    identity = parse_aws_security_group_identity(_read("identity_metadata.json"))

    assert identity.resource_id == "sg-0f9e8d7c6b5a43210"
    assert identity.account == "123456789012"
    assert identity.region == "us-east-1"
    assert identity.model is None
    assert identity.serial_number is None
    assert identity.os_version is None


def test_detect_recognizes_aws_security_group_json() -> None:
    config = _read("vulnerable_security_group.json")
    version = _read("identity_metadata.json")
    assert _detect_aws_security_groups(config, version) is True


def test_detect_never_matches_cisco_fixtures_or_arbitrary_text() -> None:
    cisco_config = (CISCO_FIXTURES / "hardened_running_config.txt").read_text()
    cisco_version = (CISCO_FIXTURES / "version_output.txt").read_text()
    assert _detect_aws_security_groups(cisco_config, cisco_version) is False
    assert _detect_aws_security_groups("just some arbitrary text", "more text") is False

    aws_config = _read("vulnerable_security_group.json")
    aws_version = _read("identity_metadata.json")
    assert _detect_cisco_ios(aws_config, aws_version) is False


def test_permission_covering_all_protocols_counts_as_open_on_any_port() -> None:
    # IpProtocol "-1" (all traffic) with no FromPort/ToPort is valid AWS
    # shape and must be treated as covering every port, including 23.
    config = json.dumps(
        {
            "GroupId": "sg-allopen",
            "OwnerId": "111122223333",
            "IpPermissions": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            ],
            "FlowLogs": [],
        }
    )
    facts = parse_aws_security_group_facts(config)
    assert facts.telnet_enabled is True
    assert facts.ssh_version_2 is False

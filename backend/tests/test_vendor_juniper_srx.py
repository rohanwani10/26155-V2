from app.redaction import redact_config
from app.vendor_juniper_srx import (
    detect_juniper_srx,
    parse_juniper_srx_facts,
    parse_juniper_srx_version,
)


def test_detect_juniper_srx_from_version_dump():
    assert detect_juniper_srx("set system host-name x\n", "JUNOS Software Release [21.2R3]\n")


def test_detect_juniper_srx_does_not_match_cisco_or_unrelated_text():
    assert not detect_juniper_srx("hostname x\n", "Cisco IOS Software, Version 15.0\n")
    assert not detect_juniper_srx("garbage\n", "Acme WidgetOS, v1.0\n")


def test_root_authentication_plain_text_password_is_not_considered_strong():
    facts = parse_juniper_srx_facts(
        redact_config('set system root-authentication plain-text-password "hunter2"\n')
    )
    assert facts.enable_secret_strong is False


def test_root_authentication_encrypted_password_is_considered_strong():
    facts = parse_juniper_srx_facts(
        redact_config('set system root-authentication encrypted-password "$6$abc$def"\n')
    )
    assert facts.enable_secret_strong is True


def test_service_password_encryption_fails_when_any_plain_text_password_present():
    facts = parse_juniper_srx_facts(
        redact_config(
            'set system root-authentication encrypted-password "$6$abc$def"\n'
            'set system login user admin authentication plain-text-password "hunter2"\n'
        )
    )
    assert facts.service_password_encryption is False


def test_service_password_encryption_passes_when_all_secrets_encrypted():
    facts = parse_juniper_srx_facts(
        redact_config(
            'set system root-authentication encrypted-password "$6$abc$def"\n'
            'set system login user admin authentication encrypted-password "$6$xyz$123"\n'
        )
    )
    assert facts.service_password_encryption is True


def test_username_password_line_is_flagged():
    facts = parse_juniper_srx_facts(
        redact_config('set system login user admin authentication plain-text-password "x"\n')
    )
    assert facts.username_password_configured is True


def test_username_secret_line_is_not_flagged():
    facts = parse_juniper_srx_facts(
        redact_config('set system login user admin authentication encrypted-password "x"\n')
    )
    assert facts.username_password_configured is False


def test_no_username_lines_is_not_flagged():
    facts = parse_juniper_srx_facts(redact_config(""))
    assert facts.username_password_configured is False


def test_exec_timeout_zero_is_not_configured():
    facts = parse_juniper_srx_facts(redact_config("set system login idle-timeout 0\n"))
    assert facts.exec_timeout_configured is False


def test_exec_timeout_nonzero_is_configured():
    facts = parse_juniper_srx_facts(redact_config("set system login idle-timeout 10\n"))
    assert facts.exec_timeout_configured is True


def test_exec_timeout_missing_entirely_fails_safe():
    assert parse_juniper_srx_facts(redact_config("")).exec_timeout_configured is False


def test_min_password_length_below_threshold_fails():
    facts = parse_juniper_srx_facts(
        redact_config("set system login password minimum-length 4\n")
    )
    assert facts.min_password_length_configured is False


def test_min_password_length_at_threshold_passes():
    facts = parse_juniper_srx_facts(
        redact_config("set system login password minimum-length 8\n")
    )
    assert facts.min_password_length_configured is True


def test_ssh_authentication_retries_above_max_fails():
    config = "set system login retry-options tries-before-disconnect 5\n"
    assert parse_juniper_srx_facts(redact_config(config)).ssh_auth_retries_limited is False


def test_ssh_authentication_retries_at_max_passes():
    config = "set system login retry-options tries-before-disconnect 3\n"
    assert parse_juniper_srx_facts(redact_config(config)).ssh_auth_retries_limited is True


def test_login_block_for_requires_both_tries_and_lockout():
    config = "set system login retry-options tries-before-disconnect 3\n"
    assert parse_juniper_srx_facts(redact_config(config)).login_block_for_configured is False

    config += "set system login retry-options lockout-period 60\n"
    assert parse_juniper_srx_facts(redact_config(config)).login_block_for_configured is True


def test_logging_buffered_below_minimum_size_fails():
    config = "set system syslog file messages archive size 1k\n"
    assert parse_juniper_srx_facts(redact_config(config)).logging_buffered_configured is False


def test_logging_buffered_at_or_above_minimum_size_passes():
    config = "set system syslog file messages archive size 4096\n"
    assert parse_juniper_srx_facts(redact_config(config)).logging_buffered_configured is True

    config = "set system syslog file messages archive size 1m\n"
    assert parse_juniper_srx_facts(redact_config(config)).logging_buffered_configured is True


def test_logging_trap_severity_none_does_not_count():
    config = "set system syslog host 10.0.0.5 any none\n"
    assert parse_juniper_srx_facts(redact_config(config)).logging_trap_configured is False


def test_logging_trap_severity_configured_counts():
    config = "set system syslog host 10.0.0.5 any info\n"
    assert parse_juniper_srx_facts(redact_config(config)).logging_trap_configured is True


def test_insecure_services_default_to_disabled_when_unconfigured():
    # Unlike Cisco IOS (insecure legacy services default ON), the closest
    # real Junos equivalents for these facts all default OFF -- absent
    # config means the safer default, not a compliance gap.
    facts = parse_juniper_srx_facts(redact_config(""))
    assert facts.cdp_enabled is False
    assert facts.bootp_server_enabled is False
    assert facts.finger_service_enabled is False
    assert facts.tcp_small_servers_enabled is False
    assert facts.udp_small_servers_enabled is False
    assert facts.pad_service_enabled is False
    assert facts.ip_domain_lookup_enabled is False
    assert facts.http_server_enabled is False
    # IP source-route is the one exception: mirrors Cisco's fail-safe stance
    # (must be explicitly disabled), since Junos also defaults to accepting
    # source-routed packets unless told otherwise.
    assert facts.ip_source_route_enabled is True


def test_insecure_services_explicit_enable_is_recognized():
    config = (
        "set system services telnet\n"
        "set system services finger\n"
        "set system services xnm-clear-text\n"
        "set system services dhcp-local-server group g interface ge-0/0/0.0\n"
        "set system services ssh root-login allow\n"
        "set system services web-management http\n"
        "set protocols lldp interface all\n"
        "set forwarding-options helpers bootp server 10.0.0.9\n"
        "set system name-server 8.8.8.8\n"
    )
    facts = parse_juniper_srx_facts(redact_config(config))
    assert facts.telnet_enabled is True
    assert facts.finger_service_enabled is True
    assert facts.tcp_small_servers_enabled is True
    assert facts.udp_small_servers_enabled is True
    assert facts.pad_service_enabled is True
    assert facts.http_server_enabled is True
    assert facts.cdp_enabled is True
    assert facts.bootp_server_enabled is True
    assert facts.ip_domain_lookup_enabled is True


def test_https_web_management_does_not_count_as_http_server_enabled():
    config = "set system services web-management https system-generate-certificate\n"
    assert parse_juniper_srx_facts(redact_config(config)).http_server_enabled is False


def test_aaa_authentication_login_requires_authentication_order_and_server():
    config = redact_config("set system authentication-order [ tacplus password ]\n")
    facts = parse_juniper_srx_facts(config)
    assert facts.aaa_new_model is True
    assert facts.aaa_authentication_login_configured is False

    config = redact_config(
        "set system authentication-order [ tacplus password ]\n"
        'set system tacplus-server 10.0.0.7 secret "s3cret"\n'
    )
    assert parse_juniper_srx_facts(config).aaa_authentication_login_configured is True


def test_aaa_new_model_false_without_external_method_in_authentication_order():
    config = redact_config("set system authentication-order password\n")
    facts = parse_juniper_srx_facts(config)
    assert facts.aaa_new_model is False
    assert facts.aaa_authentication_login_configured is False


def test_aaa_authorization_exec_requires_remote_class_and_aaa_new_model():
    config = redact_config("set system login user remote class super-user\n")
    assert parse_juniper_srx_facts(config).aaa_authorization_exec_configured is False

    config = redact_config(
        "set system authentication-order [ tacplus password ]\n"
        "set system login user remote class super-user\n"
    )
    assert parse_juniper_srx_facts(config).aaa_authorization_exec_configured is True


def test_aaa_accounting_exec_requires_login_event_and_aaa_destination():
    config = redact_config(
        "set system authentication-order [ tacplus password ]\n"
        "set system accounting events [ login interactive-commands ]\n"
        "set system accounting destination tacplus\n"
    )
    assert parse_juniper_srx_facts(config).aaa_accounting_exec_configured is True

    config = redact_config(
        "set system authentication-order [ tacplus password ]\n"
        "set system accounting events [ interactive-commands ]\n"
        "set system accounting destination tacplus\n"
    )
    assert parse_juniper_srx_facts(config).aaa_accounting_exec_configured is False


def test_vty_access_class_requires_lo0_filter_with_source_address_term():
    config = redact_config(
        "set interfaces lo0 unit 0 family inet filter input PROTECT-RE\n"
    )
    assert parse_juniper_srx_facts(config).vty_access_class_configured is False

    config = redact_config(
        "set interfaces lo0 unit 0 family inet filter input PROTECT-RE\n"
        "set firewall filter PROTECT-RE term allow-mgmt from source-address 10.0.0.0/24\n"
    )
    assert parse_juniper_srx_facts(config).vty_access_class_configured is True


def test_banner_facts_are_split_across_message_and_announcement():
    config = redact_config('set system login message "pre-login notice"\n')
    facts = parse_juniper_srx_facts(config)
    assert facts.banner_configured is True
    assert facts.banner_motd_configured is True
    assert facts.banner_exec_configured is False

    config = redact_config('set system login announcement "post-login notice"\n')
    facts = parse_juniper_srx_facts(config)
    assert facts.banner_configured is True
    assert facts.banner_motd_configured is False
    assert facts.banner_exec_configured is True


def test_device_identity_is_parsed_from_version_and_hardware_dump():
    text = (
        "Hostname: srx-core1\n"
        "Model: srx340\n"
        "Junos: 21.2R3-S1.7\n"
        "\n"
        "Hardware inventory:\n"
        "Item             Version  Part number     Serial number     Description\n"
        "Chassis                                JN123456AABC      SRX340\n"
    )
    identity = parse_juniper_srx_version(text)
    assert identity.model == "srx340"
    assert identity.os_version == "21.2R3-S1.7"
    assert identity.serial_number == "JN123456AABC"

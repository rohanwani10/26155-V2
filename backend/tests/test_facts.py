from app.facts import parse_cisco_ios_facts
from app.redaction import redact_config


def test_enable_secret_type_0_is_not_considered_strong():
    facts = parse_cisco_ios_facts(redact_config("enable secret 0 mypassword\n"))
    assert facts.enable_secret_strong is False


def test_enable_secret_type_5_is_considered_strong():
    facts = parse_cisco_ios_facts(redact_config("enable secret 5 $1$abc$def\n"))
    assert facts.enable_secret_strong is True


def test_enable_secret_without_type_digit_defaults_to_strong():
    facts = parse_cisco_ios_facts(redact_config("enable secret hunter2\n"))
    assert facts.enable_secret_strong is True


def test_enable_password_alone_is_never_considered_strong():
    facts = parse_cisco_ios_facts(redact_config("enable password hunter2\n"))
    assert facts.enable_secret_strong is False


def test_exec_timeout_checks_console_line_too():
    config = redact_config(
        "line con 0\n exec-timeout 0 0\nline vty 0 4\n exec-timeout 10 0\n"
    )
    assert parse_cisco_ios_facts(config).exec_timeout_configured is False


def test_exec_timeout_requires_every_vty_range_to_be_configured():
    config = redact_config(
        "line con 0\n exec-timeout 5 0\n"
        "line vty 0 4\n exec-timeout 10 0\n"
        "line vty 5 15\n exec-timeout 0 0\n"
    )
    assert parse_cisco_ios_facts(config).exec_timeout_configured is False


def test_exec_timeout_single_argument_form_is_recognized():
    config = redact_config("line con 0\n exec-timeout 10\nline vty 0 4\n exec-timeout 10\n")
    assert parse_cisco_ios_facts(config).exec_timeout_configured is True


def test_exec_timeout_missing_entirely_fails_safe():
    config = redact_config("line con 0\nline vty 0 4\n login\n")
    assert parse_cisco_ios_facts(config).exec_timeout_configured is False


def test_exec_timeout_all_lines_configured_and_nonzero_passes():
    config = redact_config(
        "line con 0\n exec-timeout 5 0\n"
        "line vty 0 4\n exec-timeout 10 0\n"
        "line vty 5 15\n exec-timeout 15 0\n"
    )
    assert parse_cisco_ios_facts(config).exec_timeout_configured is True


def test_username_password_line_is_flagged():
    facts = parse_cisco_ios_facts(redact_config("username admin password 0 hunter2\n"))
    assert facts.username_password_configured is True


def test_username_secret_line_is_not_flagged():
    facts = parse_cisco_ios_facts(redact_config("username admin secret hunter2\n"))
    assert facts.username_password_configured is False


def test_no_username_lines_is_not_flagged():
    facts = parse_cisco_ios_facts(redact_config(""))
    assert facts.username_password_configured is False


def test_min_password_length_below_threshold_fails():
    facts = parse_cisco_ios_facts(redact_config("security passwords min-length 4\n"))
    assert facts.min_password_length_configured is False


def test_min_password_length_at_threshold_passes():
    facts = parse_cisco_ios_facts(redact_config("security passwords min-length 8\n"))
    assert facts.min_password_length_configured is True


def test_ssh_authentication_retries_above_max_fails():
    facts = parse_cisco_ios_facts(redact_config("ip ssh authentication-retries 5\n"))
    assert facts.ssh_auth_retries_limited is False


def test_ssh_authentication_retries_at_max_passes():
    facts = parse_cisco_ios_facts(redact_config("ip ssh authentication-retries 3\n"))
    assert facts.ssh_auth_retries_limited is True


def test_logging_buffered_below_minimum_size_fails():
    facts = parse_cisco_ios_facts(redact_config("logging buffered 1024\n"))
    assert facts.logging_buffered_configured is False


def test_logging_buffered_at_minimum_size_passes():
    facts = parse_cisco_ios_facts(redact_config("logging buffered 4096\n"))
    assert facts.logging_buffered_configured is True


def test_console_login_local_requires_every_console_block():
    config = redact_config("line con 0\n exec-timeout 5 0\n")
    assert parse_cisco_ios_facts(config).console_login_local_configured is False


def test_console_login_local_configured_passes():
    config = redact_config("line con 0\n login local\n")
    assert parse_cisco_ios_facts(config).console_login_local_configured is True


def test_vty_access_class_requires_every_vty_range():
    config = redact_config(
        "line vty 0 4\n access-class 10 in\n"
        "line vty 5 15\n exec-timeout 10 0\n"
    )
    assert parse_cisco_ios_facts(config).vty_access_class_configured is False


def test_vty_access_class_configured_on_every_range_passes():
    config = redact_config(
        "line vty 0 4\n access-class 10 in\n"
        "line vty 5 15\n access-class 10 in\n"
    )
    assert parse_cisco_ios_facts(config).vty_access_class_configured is True


def test_insecure_services_default_to_enabled_when_unconfigured():
    facts = parse_cisco_ios_facts(redact_config(""))
    assert facts.cdp_enabled is True
    assert facts.bootp_server_enabled is True
    assert facts.finger_service_enabled is True
    assert facts.tcp_small_servers_enabled is True
    assert facts.udp_small_servers_enabled is True
    assert facts.pad_service_enabled is True
    assert facts.ip_source_route_enabled is True
    assert facts.ip_domain_lookup_enabled is True
    assert facts.http_server_enabled is True


def test_vty_access_class_removal_is_not_mistaken_for_configured():
    config = redact_config("line vty 0 4\n no access-class 10 in\n")
    assert parse_cisco_ios_facts(config).vty_access_class_configured is False


def test_aaa_authentication_login_without_new_model_does_not_count():
    config = redact_config("aaa authentication login default local\n")
    facts = parse_cisco_ios_facts(config)
    assert facts.aaa_new_model is False
    assert facts.aaa_authentication_login_configured is False


def test_aaa_authentication_login_with_new_model_counts():
    config = redact_config("aaa new-model\naaa authentication login default local\n")
    assert parse_cisco_ios_facts(config).aaa_authentication_login_configured is True


def test_login_block_for_does_not_require_aaa_new_model():
    config = redact_config("login block-for 120 attempts 3 within 60\n")
    facts = parse_cisco_ios_facts(config)
    assert facts.aaa_new_model is False
    assert facts.login_block_for_configured is True


def test_console_login_authentication_method_list_counts_as_configured():
    config = redact_config("line con 0\n login authentication default\n")
    assert parse_cisco_ios_facts(config).console_login_local_configured is True


def test_insecure_services_explicit_disable_is_recognized():
    config = redact_config(
        "no cdp run\n"
        "no ip bootp server\n"
        "no service finger\n"
        "no service tcp-small-servers\n"
        "no service udp-small-servers\n"
        "no service pad\n"
        "no ip source-route\n"
        "no ip domain-lookup\n"
        "no ip http server\n"
    )
    facts = parse_cisco_ios_facts(config)
    assert facts.cdp_enabled is False
    assert facts.bootp_server_enabled is False
    assert facts.finger_service_enabled is False
    assert facts.tcp_small_servers_enabled is False
    assert facts.udp_small_servers_enabled is False
    assert facts.pad_service_enabled is False
    assert facts.ip_source_route_enabled is False
    assert facts.ip_domain_lookup_enabled is False
    assert facts.http_server_enabled is False

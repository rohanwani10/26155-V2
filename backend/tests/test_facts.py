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

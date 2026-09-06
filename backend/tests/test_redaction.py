from app.redaction import redact_config


def test_enable_password_is_redacted():
    config = "enable password SuperSecretEnablePW1\n"
    redacted = redact_config(config)
    assert "SuperSecretEnablePW1" not in redacted
    assert "<redacted:enable_password" in redacted


def test_enable_secret_is_redacted_but_type_is_preserved():
    config = "enable secret 9 $9$abcdefghij$fakehash\n"
    redacted = redact_config(config)
    assert "$9$abcdefghij$fakehash" not in redacted
    assert "type=9" in redacted


def test_line_password_is_redacted():
    config = "line vty 0 4\n password SuperSecretVtyPW1\n login\n"
    redacted = redact_config(config)
    assert "SuperSecretVtyPW1" not in redacted


def test_username_secret_is_redacted():
    config = "username admin secret 5 $1$abc$def\n"
    redacted = redact_config(config)
    assert "$1$abc$def" not in redacted


def test_custom_snmp_community_is_redacted_but_marked_custom():
    config = "snmp-server community MyCustomSecretString RO\n"
    redacted = redact_config(config)
    assert "MyCustomSecretString" not in redacted
    assert "value=custom" in redacted


def test_default_snmp_community_public_is_marked_as_default():
    config = "snmp-server community public RO\n"
    redacted = redact_config(config)
    assert "value=public" in redacted


def test_non_secret_lines_are_left_untouched():
    config = "hostname EdgeRouter1\nip ssh version 2\n"
    redacted = redact_config(config)
    assert redacted == config


def test_enable_secret_without_type_digit_is_redacted():
    config = "enable secret hunter2\n"
    redacted = redact_config(config)
    assert "hunter2" not in redacted
    assert "<redacted:enable_secret" in redacted


def test_enable_password_without_type_digit_is_redacted():
    config = "enable password hunter2\n"
    redacted = redact_config(config)
    assert "hunter2" not in redacted
    assert "<redacted:enable_password type=plaintext>" in redacted


def test_username_secret_with_privilege_clause_is_redacted():
    config = "username admin privilege 15 secret 5 $1$abc$hash\n"
    redacted = redact_config(config)
    assert "$1$abc$hash" not in redacted
    assert "<redacted:user_secret" in redacted


def test_username_password_with_privilege_clause_is_redacted():
    config = "username admin privilege 15 password 0 hunter2\n"
    redacted = redact_config(config)
    assert "hunter2" not in redacted
    assert "<redacted:user_password" in redacted

"""Redacts secret-shaped values out of raw vendor config text.

This runs immediately on ingestion, before anything else touches the config
-- the "normalization boundary" the spec describes. Downstream parsing,
storage, the LLM, the vector store, chat, and the PDF report all only ever
see the redacted text, never the original secret values. Where compliance
logic needs to know something about a secret without knowing the secret
itself (e.g. "is the enable secret hashed, and with what algorithm?"), the
placeholder preserves that as a type tag.
"""

import re
from collections.abc import Callable

Pattern = re.Pattern[str]
Replacer = Callable[[re.Match[str]], str]

DEFAULT_SNMP_COMMUNITIES = {"public", "private"}

# Cisco's type digit is optional on both `secret` and `password` forms (e.g.
# `enable secret hunter2` is valid, undigited syntax). When it's omitted,
# `secret` forms are hashed by IOS using its default algorithm (historically
# type 5); `password` forms are never hashed at all, so they default to
# plaintext.
_SECRET_DEFAULT_TYPE = "5"
_PASSWORD_DEFAULT_TYPE = "plaintext"


def _make_type_tagged_redactor(label: str, default_type: str) -> Replacer:
    def _redact(match: re.Match[str]) -> str:
        kind = match.group(2) or default_type
        type_part = f" {match.group(2)}" if match.group(2) else ""
        return f"{match.group(1)}{type_part} <redacted:{label} type={kind}>"

    return _redact


def _redact_snmp_community(match: re.Match[str]) -> str:
    community = match.group(2).lower()
    marker = community if community in DEFAULT_SNMP_COMMUNITIES else "custom"
    return f"{match.group(1)} <redacted:snmp_community value={marker}>"


# Order matters only in that more specific prefixes (enable secret, username
# ... secret/password) must exist as their own patterns; the generic line
# `password` pattern is anchored to line-start so it can never accidentally
# re-match text that starts with "enable" or "username" instead. The type
# digit is optional everywhere Cisco allows it to be optional; `username`
# forms also allow an intervening `privilege <N>` clause.
_REDACTION_RULES: list[tuple[Pattern, Replacer]] = [
    (
        re.compile(r"(enable secret)(?: (\d+))? (\S+)", re.IGNORECASE),
        _make_type_tagged_redactor("enable_secret", _SECRET_DEFAULT_TYPE),
    ),
    (
        re.compile(r"(enable password)(?: (\d+))? (\S+)", re.IGNORECASE),
        _make_type_tagged_redactor("enable_password", _PASSWORD_DEFAULT_TYPE),
    ),
    (
        re.compile(
            r"(username \S+(?: privilege \d+)? secret)(?: (\d+))? (\S+)",
            re.IGNORECASE,
        ),
        _make_type_tagged_redactor("user_secret", _SECRET_DEFAULT_TYPE),
    ),
    (
        re.compile(
            r"(username \S+(?: privilege \d+)? password)(?: (\d+))? (\S+)",
            re.IGNORECASE,
        ),
        _make_type_tagged_redactor("user_password", _PASSWORD_DEFAULT_TYPE),
    ),
    (
        re.compile(r"^(\s*password)(?: (\d+))? (\S+)", re.IGNORECASE | re.MULTILINE),
        _make_type_tagged_redactor("line_password", _PASSWORD_DEFAULT_TYPE),
    ),
    (
        re.compile(r"(snmp-server community) (\S+)", re.IGNORECASE),
        _redact_snmp_community,
    ),
]


def register_redaction_rule(pattern: Pattern, replacer: Replacer) -> None:
    """Lets a vendor module add its own secret-shaped patterns (Juniper/
    FortiGate/etc. all spell secrets differently) without editing the rule
    list above. Every rule runs on every upload regardless of vendor -- cheap,
    and safe since these patterns target vendor-specific keywords that don't
    collide with each other's syntax."""
    _REDACTION_RULES.append((pattern, replacer))


def redact_config(raw_text: str) -> str:
    redacted = raw_text
    for pattern, replacer in _REDACTION_RULES:
        redacted = pattern.sub(replacer, redacted)
    return redacted

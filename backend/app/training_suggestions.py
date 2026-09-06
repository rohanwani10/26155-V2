"""AI-assisted suggestions for the unknown-vendor training queue (ticket 09).

Read-only helper on top of ticket 08's training loop: given one queued,
still-unmapped config line, ask the LLM client to propose which fact_id in
the real CIS taxonomy (rules.py) it maps to and what boolean value it sets,
then adversarially verify that proposal before returning it. Nothing here
ever writes a rule -- the admin still confirms via the existing
POST /api/training/mappings (training.py), verbatim, edited, or ignored.

Both the propose and verify passes go through the same LlmClient.interpret/
verify seam chat.py already uses for its draft-then-verify pattern -- no
second client, no second model.
"""

import re
from collections.abc import Callable
from typing import Any

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends

from .llm import LlmClient
from .rules import CIS_CONTROLS
from .training import FACT_IDS, TrainingRuleStore

# fact_id -> human-readable title, for prompt context and the verify pass's
# "what does this fact mean" context. Falls back to the bare fact_id for any
# FACT_IDS entry rules.py doesn't (yet) have a Control for.
_TITLE_BY_FACT_ID = {c.fact_id: c.title for c in CIS_CONTROLS}

_PROPOSAL_FORMAT = (
    "Respond in exactly this three-line format and nothing else:\n"
    "FACT_ID: <one fact_id from the list above, exactly as spelled>\n"
    "VALUE: <true or false>\n"
    "RATIONALE: <one short sentence>"
)

# A small quantized model won't reliably produce perfect JSON, so the prompt
# asks for a simple line-based format instead and this regex-based parser
# reads it -- tolerant of extra whitespace/case, and of extra prose the model
# tacks on before/after the three lines we actually need.
_FACT_ID_RE = re.compile(r"FACT_ID:\s*([A-Za-z0-9_]+)", re.IGNORECASE)
_VALUE_RE = re.compile(r"VALUE:\s*(true|false)", re.IGNORECASE)
_RATIONALE_RE = re.compile(r"RATIONALE:\s*(.+)", re.IGNORECASE)


def _parse_proposal(text: str) -> tuple[str, bool, str] | None:
    """Parse the model's response into (fact_id, value, rationale), or None
    if it's unusable -- missing fields, or a fact_id outside the real
    taxonomy (e.g. a hallucinated category). Never raises."""
    fact_match = _FACT_ID_RE.search(text)
    value_match = _VALUE_RE.search(text)
    if fact_match is None or value_match is None:
        return None
    fact_id = fact_match.group(1)
    if fact_id not in FACT_IDS:
        return None
    value = value_match.group(1).lower() == "true"
    rationale_match = _RATIONALE_RE.search(text)
    rationale = rationale_match.group(1).strip() if rationale_match else ""
    return fact_id, value, rationale


def _format_existing_rules(rules: list[dict[str, Any]]) -> str:
    if not rules:
        return "none"
    return "; ".join(f"{r['line']!r} -> {r['fact_id']}={r['value']}" for r in rules)


def _build_interpret_prompt(vendor: str, line: str, existing_rules: list[dict[str, Any]]) -> str:
    taxonomy = "\n".join(
        f"- {fact_id}: {_TITLE_BY_FACT_ID.get(fact_id, fact_id)}"
        for fact_id in sorted(FACT_IDS)
    )
    return (
        "You are helping map one unrecognized network device configuration "
        "line to a security control category, for an admin to review.\n\n"
        f"Config line: {line}\n\n"
        "Available categories (fact_id: title) -- you must pick one fact_id "
        "from this exact list:\n"
        f"{taxonomy}\n\n"
        f"Existing confirmed rules for vendor '{vendor}': "
        f"{_format_existing_rules(existing_rules)}\n\n"
        "Propose which single category this line most likely controls, and "
        "whether the line enables (true) or disables (false) that "
        "control.\n\n" + _PROPOSAL_FORMAT
    )


def _build_verify_claim(vendor: str, line: str, fact_id: str, value: bool) -> tuple[str, str]:
    title = _TITLE_BY_FACT_ID.get(fact_id, fact_id)
    claim = (
        f"The config line {line!r} should be mapped to fact_id "
        f"'{fact_id}' ({title}) with value {value}."
    )
    context = f"Config line: {line}\nFact meaning: {fact_id} - {title}"
    return claim, context


def build_training_suggestions_router(
    require_session: Callable[..., bytes],
    rule_store: TrainingRuleStore,
    llm_client: LlmClient,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/training/suggestions")
    def get_training_suggestion(
        vendor: str, line: str, data_key: bytes = Depends(require_session)
    ) -> dict[str, Any]:
        line = line.strip()
        existing_rules = rule_store.list_for_vendor(
            vendor, decrypt=Fernet(data_key).decrypt
        )

        proposal = _parse_proposal(
            llm_client.interpret(_build_interpret_prompt(vendor, line, existing_rules))
        )
        if proposal is None:
            return {
                "vendor": vendor,
                "line": line,
                "fact_id": None,
                "value": None,
                "rationale": None,
                "verified": False,
                "error": "Could not parse a valid suggestion from the model.",
            }

        fact_id, value, rationale = proposal
        claim, context = _build_verify_claim(vendor, line, fact_id, value)
        if existing_rules:
            context += f"\nExisting confirmed rules for this vendor: {_format_existing_rules(existing_rules)}"
        verified = llm_client.verify(claim, context)

        return {
            "vendor": vendor,
            "line": line,
            "fact_id": fact_id,
            "value": value,
            "rationale": rationale,
            "verified": verified,
            "error": None,
        }

    return router

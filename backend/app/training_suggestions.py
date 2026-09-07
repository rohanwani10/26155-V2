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

Ticket 11 adds optional online enrichment, additively, ahead of the existing
suggestion call: try the vendor's known official doc URL(s) (from the
allowlist in doc_fetcher.py -- deliberately just "fetch the vendor's own
doc page(s) directly", not a search/crawl feature; see doc_fetcher.py and
this ticket's issue file for that scoping call), extract+verify a
doc-grounded candidate mapping, and if it verifies, promote it into
VendorKnowledgeStore *and* fold it into this same request's suggestion
context. Previously-promoted knowledge is also queried and folded in on
every request, fetch or no fetch, so it keeps paying off offline too. When
there's nothing to fetch or nothing promoted yet, every added value is
falsy/empty and the prompt built is byte-identical to ticket 09's original --
so the offline case is unchanged, exactly as the ticket requires.

Ticket 16 adds an embedding-similarity pre-check *ahead of everything else in
this file*, including the ticket 11 enrichment above: before any LLM call,
embed the queued line and query TrainingMappingStore (training_mapping_
store.py) -- a dedicated Chroma collection of previously-*confirmed*
mappings, scoped to this vendor -- for a close match. A close match returns
that confirmed mapping's fact_id/value directly, with no LLM call at all
(neither the propose/verify pass below nor ticket 11's doc-enrichment pass,
which itself calls the LLM). No close match falls through to the rest of
this file completely unchanged. The admin still confirms every suggestion
this file returns -- embedding-matched or LLM-derived -- via the existing
POST /api/training/mappings; this ticket only changes how the *suggestion*
is produced.
"""

import re
from collections.abc import Callable
from typing import Any

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends

from .doc_fetcher import DocFetcher, urls_for_vendor
from .llm import LlmClient
from .rules import CIS_CONTROLS
from .training import FACT_IDS, TrainingRuleStore
from .training_mapping_store import TrainingMappingStore
from .vendor_knowledge_store import VendorKnowledgeStore

# How much of a fetched doc page to ground the extraction prompt in -- a
# small quantized local model has a limited effective context window, so a
# whole HTML page isn't useful past the first chunk anyway.
_DOC_EXCERPT_CHARS = 2000

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


def _build_interpret_prompt(
    vendor: str,
    line: str,
    existing_rules: list[dict[str, Any]],
    doc_knowledge: str = "",
) -> str:
    taxonomy = "\n".join(
        f"- {fact_id}: {_TITLE_BY_FACT_ID.get(fact_id, fact_id)}"
        for fact_id in sorted(FACT_IDS)
    )
    prompt = (
        "You are helping map one unrecognized network device configuration "
        "line to a security control category, for an admin to review.\n\n"
        f"Config line: {line}\n\n"
        "Available categories (fact_id: title) -- you must pick one fact_id "
        "from this exact list:\n"
        f"{taxonomy}\n\n"
        f"Existing confirmed rules for vendor '{vendor}': "
        f"{_format_existing_rules(existing_rules)}\n\n"
    )
    # Additive (ticket 11): only present -- and only ever non-empty -- when
    # online enrichment found something, so the offline/no-enrichment prompt
    # is byte-identical to ticket 09's original.
    if doc_knowledge:
        prompt += f"Relevant vendor documentation knowledge: {doc_knowledge}\n\n"
    prompt += (
        "Propose which single category this line most likely controls, and "
        "whether the line enables (true) or disables (false) that "
        "control.\n\n" + _PROPOSAL_FORMAT
    )
    return prompt


def _build_doc_enrichment_prompt(vendor: str, line: str, doc_excerpt: str) -> str:
    taxonomy = "\n".join(
        f"- {fact_id}: {_TITLE_BY_FACT_ID.get(fact_id, fact_id)}"
        for fact_id in sorted(FACT_IDS)
    )
    return (
        "You are extracting a candidate security-control mapping for one "
        "unrecognized network device configuration line, grounded in an "
        f"excerpt of official '{vendor}' vendor documentation.\n\n"
        f"Config line: {line}\n\n"
        "Vendor documentation excerpt:\n"
        f"{doc_excerpt}\n\n"
        "Available categories (fact_id: title) -- you must pick one fact_id "
        "from this exact list:\n"
        f"{taxonomy}\n\n"
        "Based on the documentation excerpt, propose which single category "
        "this line most likely controls, and whether it enables (true) or "
        "disables (false) that control.\n\n" + _PROPOSAL_FORMAT
    )


def _build_verify_claim(vendor: str, line: str, fact_id: str, value: bool) -> tuple[str, str]:
    title = _TITLE_BY_FACT_ID.get(fact_id, fact_id)
    claim = (
        f"The config line {line!r} should be mapped to fact_id "
        f"'{fact_id}' ({title}) with value {value}."
    )
    context = f"Config line: {line}\nFact meaning: {fact_id} - {title}"
    return claim, context


def _enrich_from_docs(
    vendor: str,
    line: str,
    doc_fetcher: DocFetcher,
    knowledge_store: VendorKnowledgeStore,
    llm_client: LlmClient,
) -> str | None:
    """Try each of the vendor's allowlisted doc URLs (in order) until one
    fetches; on the first success, extract a doc-grounded candidate mapping
    and adversarially verify it against the fact model *before* trusting it
    for anything. Only a verified candidate is promoted into
    VendorKnowledgeStore; returns the promoted knowledge text (for folding
    into this same request's suggestion context) or None if nothing was
    fetched, nothing parsed, or verification failed -- silent in every case,
    same as the offline path this replaces nothing of."""
    for url in urls_for_vendor(vendor):
        doc_text = doc_fetcher.fetch(url)
        if doc_text is None:
            continue
        excerpt = doc_text[:_DOC_EXCERPT_CHARS]
        proposal = _parse_proposal(
            llm_client.interpret(_build_doc_enrichment_prompt(vendor, line, excerpt))
        )
        if proposal is None:
            continue
        fact_id, value, rationale = proposal
        claim, _ = _build_verify_claim(vendor, line, fact_id, value)
        verify_context = f"Vendor documentation excerpt:\n{excerpt}"
        if not llm_client.verify(claim, verify_context):
            continue
        knowledge_text = (
            f"Vendor documentation for {vendor!r} supports mapping config "
            f"line {line!r} to fact_id '{fact_id}' "
            f"({_TITLE_BY_FACT_ID.get(fact_id, fact_id)}) with value {value}. "
            f"{rationale}"
        )
        knowledge_store.promote(vendor, fact_id, knowledge_text, source_url=url)
        return knowledge_text
    return None


def build_training_suggestions_router(
    require_session: Callable[..., bytes],
    rule_store: TrainingRuleStore,
    llm_client: LlmClient,
    doc_fetcher: DocFetcher,
    knowledge_store: VendorKnowledgeStore,
    mapping_store: TrainingMappingStore,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/training/suggestions")
    def get_training_suggestion(
        vendor: str, line: str, data_key: bytes = Depends(require_session)
    ) -> dict[str, Any]:
        line = line.strip()

        # Ticket 16: embedding-similarity pre-check, ahead of everything
        # else including ticket 11's doc enrichment below -- both of those
        # call the LLM, this doesn't. A close match to a previously
        # confirmed mapping (this vendor only) is returned directly.
        close_match = mapping_store.find_close_match(vendor, line)
        if close_match is not None:
            return {
                "vendor": vendor,
                "line": line,
                "fact_id": close_match["fact_id"],
                "value": close_match["value"],
                "rationale": (
                    "Matched a previously confirmed mapping for "
                    f"{close_match['line']!r} (embedding similarity "
                    f"{close_match['similarity']:.2f})."
                ),
                "verified": True,
                "error": None,
                "doc_enrichment_used": False,
            }

        existing_rules = rule_store.list_for_vendor(
            vendor, decrypt=Fernet(data_key).decrypt
        )

        # Ticket 11: opportunistic online enrichment, additive ahead of the
        # existing propose/verify call below. Fully silent no-op when
        # offline or when the vendor has no allowlisted docs -- see
        # _enrich_from_docs and doc_fetcher.py.
        freshly_promoted = _enrich_from_docs(
            vendor, line, doc_fetcher, knowledge_store, llm_client
        )
        promoted_knowledge = knowledge_store.query(vendor, line, k=3)
        doc_knowledge = "; ".join(chunk["text"] for chunk in promoted_knowledge)

        proposal = _parse_proposal(
            llm_client.interpret(
                _build_interpret_prompt(vendor, line, existing_rules, doc_knowledge)
            )
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
                "doc_enrichment_used": freshly_promoted is not None,
            }

        fact_id, value, rationale = proposal
        claim, context = _build_verify_claim(vendor, line, fact_id, value)
        if existing_rules:
            context += f"\nExisting confirmed rules for this vendor: {_format_existing_rules(existing_rules)}"
        if doc_knowledge:
            context += f"\nPromoted vendor documentation knowledge: {doc_knowledge}"
        verified = llm_client.verify(claim, context)

        return {
            "vendor": vendor,
            "line": line,
            "fact_id": fact_id,
            "value": value,
            "rationale": rationale,
            "verified": verified,
            "error": None,
            "doc_enrichment_used": freshly_promoted is not None,
        }

    return router

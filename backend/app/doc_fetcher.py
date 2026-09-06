"""Allowlisted vendor-documentation fetching (ticket 11).

`data/vendor_doc_allowlist.json` maps a *registered* vendor name (see
vendors.py -- "cisco_ios", "juniper_srx", "aws_security_groups") to the
official documentation hostnames it's ever allowed to fetch from. A vendor
with no entry (any live-trained/unknown vendor, by definition) simply gets no
URLs and therefore no enrichment -- see training_suggestions.py.

Host matching is case-sensitive (a `URL.host in list` check) -- real-world DNS
hostnames from an admin-curated allowlist file are lowercase by convention,
so exact-match keeps the check trivial to read and audit; there's no
untrusted input on the allowlist side that could smuggle a case variant past
it.

`is_allowlisted_host` is the single choke point every fetch must pass
through: it checks a URL's host against the *union* of every vendor's
allowlisted hosts (not just one vendor), because `DocFetcher.fetch` -- mirror
of `LlmClient`'s Protocol-plus-fake pattern -- takes only a URL, no vendor
argument. Vendor scoping happens one layer up: `urls_for_vendor` is the only
place that ever turns "vendor X" into a URL, and it only ever emits URLs
built from that vendor's own allowlist entries. So in practice a fetch is
always vendor-scoped by construction; the host check inside HttpDocFetcher is
defense-in-depth against any other caller passing an arbitrary URL in.
"""

import json
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import httpx

_ALLOWLIST_PATH = Path(__file__).parent / "data" / "vendor_doc_allowlist.json"


def load_allowlist() -> dict[str, list[str]]:
    with open(_ALLOWLIST_PATH, encoding="utf-8") as f:
        data: dict[str, list[str]] = json.load(f)
    return data


def urls_for_vendor(vendor: str, allowlist: dict[str, list[str]] | None = None) -> list[str]:
    """The vendor's own official doc root URL(s) to try fetching directly --
    see training_suggestions.py's scoping note: this is "try the known
    URL(s)", not search or crawling. Unknown/untrained vendor -> []."""
    allowlist = load_allowlist() if allowlist is None else allowlist
    return [f"https://{host}/" for host in allowlist.get(vendor, [])]


def is_allowlisted_host(url: str, allowlist: dict[str, list[str]] | None = None) -> bool:
    """True iff `url`'s host is a listed doc host for *some* vendor. Case-
    sensitive host match (see module docstring). Malformed URLs / no host ->
    False, never an exception -- callers treat that the same as "not
    allowlisted"."""
    allowlist = load_allowlist() if allowlist is None else allowlist
    host = urlparse(url).hostname
    if not host:
        return False
    return any(host in hosts for hosts in allowlist.values())


class DocFetcher(Protocol):
    def fetch(self, url: str) -> str | None:
        """Page text for `url`, or None on any failure -- non-2xx, timeout,
        DNS/connection error, or a host that isn't allowlisted. Never
        raises."""
        ...


class HttpDocFetcher:
    """Real implementation, backed by httpx. Validates the target host
    against the allowlist *before* making any request (never fetches an
    unlisted host), and treats every httpx failure -- offline, timeout,
    non-2xx, DNS failure -- as "unavailable": returns None, never raises.
    This is what makes the offline path a silent no-op rather than an error
    (spec's "no error or blocking behavior when offline")."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def fetch(self, url: str) -> str | None:
        if not is_allowlisted_host(url):
            return None
        try:
            resp = httpx.get(url, timeout=self._timeout)
            resp.raise_for_status()
            return resp.text
        except httpx.HTTPError:
            return None


class FakeDocFetcher:
    """Deterministic, in-memory implementation for the main test suite --
    the only fetcher any test may use (see spec's testing decisions: no test
    may perform a real external network call). `response` is a plain
    settable attribute so a test can flip it to None to simulate offline
    mid-test. `fetched_urls` records every URL passed to fetch(), so a test
    can assert enrichment only ever tries a vendor's own allowlisted URL(s)."""

    def __init__(self, response: str | None = "Fake fetched vendor doc text.") -> None:
        self.response = response
        self.fetched_urls: list[str] = []

    def fetch(self, url: str) -> str | None:
        self.fetched_urls.append(url)
        return self.response

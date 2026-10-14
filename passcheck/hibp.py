"""Have I Been Pwned "Pwned Passwords" lookup using the k-anonymity range API.

Only the first 5 hex characters of the password's SHA-1 hash ever leave this machine.
The API answers with every hash suffix it knows for that prefix (hundreds of them),
and the match is made locally. See README.md for why this protects the password.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from typing import Callable

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
PREFIX_LENGTH = 5
USER_AGENT = "PassCheck-CLI"
TIMEOUT_SECONDS = 10

# Takes the 5-character hash prefix, returns the raw response body.
Fetcher = Callable[[str], str]


class HIBPError(Exception):
    """The breach check could not be completed (network failure, bad response, ...)."""


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(password: str) -> tuple[str, str]:
    """Return (prefix, suffix) of the uppercase SHA-1 hash. Only the prefix is ever sent."""
    digest = sha1_hex(password)
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def fetch_range(prefix: str) -> str:
    """Download all hash suffixes that share ``prefix``.

    ``Add-Padding`` asks the API to pad the response with fake entries (count 0) so that
    the response size does not hint at which prefix was requested.
    """
    if len(prefix) != PREFIX_LENGTH or any(c not in "0123456789ABCDEF" for c in prefix):
        raise ValueError("prefix must be exactly 5 uppercase hex characters")
    request = urllib.request.Request(
        API_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HIBPError(f"could not reach the Pwned Passwords API: {exc}") from exc


def parse_range(body: str) -> dict[str, int]:
    """Parse "SUFFIX:COUNT" lines into a dict. Padding entries (count 0) are dropped."""
    results: dict[str, int] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        suffix, sep, count = line.partition(":")
        if not sep:
            raise HIBPError(f"unexpected line in API response: {line!r}")
        try:
            value = int(count)
        except ValueError as exc:
            raise HIBPError(f"unexpected count in API response: {line!r}") from exc
        if value > 0:
            results[suffix.strip().upper()] = value
    return results


def pwned_count(password: str, fetcher: Fetcher = fetch_range) -> int:
    """Return how many times ``password`` appears in known breaches (0 if never seen)."""
    prefix, suffix = split_hash(password)
    return parse_range(fetcher(prefix)).get(suffix, 0)

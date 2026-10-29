"""Have I Been Pwned "Pwned Passwords" lookup using the k-anonymity range API.

Only the first 5 hex characters of the password's SHA-1 hash ever leave this machine.
The API answers with every hash suffix it knows for that prefix (hundreds of them),
and the match is made locally. See README.md for why this protects the password.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import urllib.error
import urllib.request
from typing import Callable

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
PREFIX_LENGTH = 5
SUFFIX_LENGTH = 35
USER_AGENT = "PassCheck-CLI"
TIMEOUT_SECONDS = 10
# A real (padded) response is roughly 30-40 KB. Anything far larger is not the API we
# expect, so refuse it rather than reading an unbounded body into memory.
MAX_RESPONSE_BYTES = 1024 * 1024

_PREFIX_RE = re.compile(rf"[0-9A-F]{{{PREFIX_LENGTH}}}")
_SUFFIX_RE = re.compile(rf"[0-9A-F]{{{SUFFIX_LENGTH}}}")

Fetcher = Callable[[str], str]
"""Takes the 5-character hash prefix and returns the raw response body."""


class HIBPError(Exception):
    """The breach check could not be completed (network failure, bad response, ...)."""


def sha1_hex(password: str) -> str:
    """Return the uppercase hex SHA-1 digest of ``password`` (UTF-8 encoded).

    SHA-1 is what the Pwned Passwords API indexes by. It is used here only as a lookup
    key, never to store or protect a password, hence ``usedforsecurity=False`` (which
    also keeps the call working on FIPS-restricted systems).
    """
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def split_hash(password: str) -> tuple[str, str]:
    """Return (prefix, suffix) of the uppercase SHA-1 hash. Only the prefix is ever sent."""
    digest = sha1_hex(password)
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def fetch_range(prefix: str) -> str:
    """Download all hash suffixes that share ``prefix``.

    ``Add-Padding`` asks the API to pad the response with fake entries (count 0) so that
    the response size does not hint at which prefix was requested.

    Raises:
        ValueError: ``prefix`` is not exactly 5 uppercase hex characters. This is the
            guard that stops anything more than the prefix from ever being sent.
        HIBPError: the request failed or the response was not usable.
    """
    if not _PREFIX_RE.fullmatch(prefix):
        raise ValueError("prefix must be exactly 5 uppercase hex characters")
    url = API_URL.format(prefix=prefix)
    # S310/B310 warn that urlopen also accepts file:// and custom schemes. The URL is built
    # from a fixed https:// constant and a validated hex prefix, and this check keeps it so.
    if not url.startswith("https://"):
        raise HIBPError(f"refusing to use non-HTTPS API URL {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Add-Padding": "true"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310  # nosec B310
            final_url = response.geturl()
            if not final_url.startswith("https://"):
                raise HIBPError(f"refusing non-HTTPS response from {final_url}")
            body: bytes = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise HIBPError(f"the Pwned Passwords API returned HTTP {exc.code} {exc.reason}") from exc
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise HIBPError(f"could not reach the Pwned Passwords API: {reason}") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise HIBPError("the Pwned Passwords API response was unexpectedly large")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HIBPError("the Pwned Passwords API response was not valid UTF-8") from exc


def parse_range(body: str) -> dict[str, int]:
    """Parse "SUFFIX:COUNT" lines into ``{SUFFIX: count}``.

    Padding entries (count 0) are dropped. Any line that is not a 35-character hex suffix
    followed by a non-negative count raises :class:`HIBPError`, so a corrupted or spoofed
    response is reported instead of silently producing a wrong answer.
    """
    results: dict[str, int] = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        suffix, sep, count = line.partition(":")
        suffix = suffix.strip().upper()
        if not sep or not _SUFFIX_RE.fullmatch(suffix):
            raise HIBPError(f"unexpected line in API response: {line[:80]!r}")
        try:
            value = int(count)
        except ValueError as exc:
            raise HIBPError(f"unexpected count in API response: {line[:80]!r}") from exc
        if value < 0:
            raise HIBPError(f"unexpected count in API response: {line[:80]!r}")
        if value > 0:
            results[suffix] = value
    return results


def pwned_count(password: str, fetcher: Fetcher = fetch_range) -> int:
    """Return how many times ``password`` appears in known breaches (0 if never seen).

    ``fetcher`` performs the network call; tests pass a fake one. It only ever receives
    the 5-character hash prefix.
    """
    prefix, suffix = split_hash(password)
    return parse_range(fetcher(prefix)).get(suffix, 0)

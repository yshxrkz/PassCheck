"""Offline password strength analysis.

Everything here runs locally: no network access, no logging of the password.

The entry point is :func:`analyze`, which runs the individual detectors
(``find_sequences``, ``find_keyboard_walks``, ``find_repeats``,
``common_password_match``), turns their results into :class:`Finding` objects,
computes a 0-100 score and builds prioritised advice.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Literal

MIN_LENGTH = 8
GOOD_LENGTH = 12
GREAT_LENGTH = 16

# Characters inside a detected pattern are worth this fraction of a "free" character
# when computing the effective length. Predictable runs add very little to the search
# space an attacker has to cover.
PATTERN_CHAR_WEIGHT = 0.25

# Scoring weights: up to 80 points for (effective) length, up to 20 for variety.
POINTS_PER_CHAR = 4
MAX_SCORED_LENGTH = 20
POINTS_PER_CLASS = 5
SINGLE_CLASS_PENALTY = 10
YEAR_PENALTY = 5
SHORT_PASSWORD_CAP = 30
COMMON_VARIANT_CAP = 15
PASSPHRASE_ADVICE_BELOW = 60

# QWERTY rows and the common column-wise walks ("1qaz2wsx"). The number row is left
# out on purpose: digit runs are already caught as numeric sequences.
KEYBOARD_ROWS = (
    "qwertyuiop[]",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",
    "qazwsxedcrfvtgbyhnujmikolp",
)
MIN_KEYBOARD_WALK = 4
MIN_SEQUENCE = 3
MIN_REPEAT = 3

YEAR_RE = re.compile(r"(19|20)\d{2}")

LEET_MAP = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "!": "i"}
)

LABELS = (
    (80, "Very strong"),
    (60, "Strong"),
    (40, "Fair"),
    (20, "Weak"),
    (0, "Very weak"),
)

CHARACTER_CLASSES = ("lowercase", "uppercase", "digits", "symbols")

FindingKind = Literal["sequence", "keyboard", "repeat", "year", "common", "common-variant", "short", "variety"]
CommonMatch = Literal["common", "common-variant"]
Span = tuple[int, int]


@dataclass
class Finding:
    """A weakness detected in the password.

    ``kind`` is a stable machine-readable identifier and ``message`` is for humans. The
    message never contains any part of the password, so it is safe to log. The matched
    substrings are kept separately in ``fragments``; callers decide whether to show them.
    """

    kind: FindingKind
    message: str
    fragments: tuple[str, ...] = ()


@dataclass
class StrengthReport:
    """The result of :func:`analyze`.

    Attributes:
        score: 0 (trivially guessable) to 100.
        label: Human-readable band for ``score``, e.g. "Strong".
        length: Number of characters.
        char_classes: Which of lowercase/uppercase/digits/symbols appear.
        findings: Detected weaknesses, in display order.
        advice: Suggestions, most important first. Never empty.
    """

    score: int
    label: str
    length: int
    char_classes: list[str]
    findings: list[Finding] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)

    @property
    def is_common(self) -> bool:
        """True if the password is, or is a light variation of, a common password."""
        return any(f.kind in ("common", "common-variant") for f in self.findings)


@lru_cache(maxsize=1)
def load_common_passwords() -> frozenset[str]:
    """Load the bundled common-password list (lowercased, comments and blanks skipped)."""
    text = resources.files("passcheck").joinpath("data/common_passwords.txt").read_text("utf-8")
    return frozenset(line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def character_classes(password: str) -> list[str]:
    """Return which character classes appear, in a fixed order.

    Anything that is not a letter or digit (spaces, punctuation, emoji...) counts as a symbol.
    """
    present = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() for c in password),
    }
    return [name for name in CHARACTER_CLASSES if present[name]]


def find_sequences(password: str, min_len: int = MIN_SEQUENCE) -> list[Span]:
    """Return (start, end) spans of ascending/descending runs like "abc", "123", "987"."""
    spans = []
    lowered = password.lower()
    i = 0
    while i < len(lowered) - 1:
        step = ord(lowered[i + 1]) - ord(lowered[i])
        if step in (1, -1) and _same_kind(lowered[i], lowered[i + 1]):
            j = i + 1
            while (
                j < len(lowered) - 1
                and ord(lowered[j + 1]) - ord(lowered[j]) == step
                and _same_kind(lowered[j], lowered[j + 1])
            ):
                j += 1
            if j - i + 1 >= min_len:
                spans.append((i, j + 1))
                i = j + 1
                continue
        i += 1
    return spans


def _same_kind(a: str, b: str) -> bool:
    """True if both characters are ASCII lowercase letters, or both are digits."""
    return (a in string.ascii_lowercase and b in string.ascii_lowercase) or (a.isdigit() and b.isdigit())


def find_keyboard_walks(password: str, min_len: int = MIN_KEYBOARD_WALK) -> list[Span]:
    """Return spans of adjacent-key runs such as "qwerty", "asdf" or "1qaz2wsx" (either direction)."""
    lowered = password.lower()
    spans: list[Span] = []
    i = 0
    while i <= len(lowered) - min_len:
        best = 0
        for row in KEYBOARD_ROWS:
            for line in (row, row[::-1]):
                best = max(best, _longest_prefix_in(lowered[i:], line, min_len))
        if best:
            spans.append((i, i + best))
            i += best
        else:
            i += 1
    return spans


def _longest_prefix_in(text: str, line: str, min_len: int) -> int:
    """Length of the longest prefix of ``text`` (at least ``min_len``) found in ``line``, else 0."""
    length = 0
    for n in range(min_len, len(text) + 1):
        if text[:n] in line:
            length = n
        else:
            break
    return length


def find_repeats(password: str) -> list[Span]:
    """Return spans of repeated characters ("aaa") or repeated chunks ("abcabc")."""
    spans = []
    for match in re.finditer(rf"(.)\1{{{MIN_REPEAT - 1},}}", password):
        spans.append(match.span())
    for match in re.finditer(r"(.{2,}?)\1+", password):
        if len(set(match.group(1))) > 1:
            spans.append(match.span())
    return spans


def common_password_match(password: str) -> CommonMatch | None:
    """Return "common" for an exact match, "common-variant" for a disguised one, else None.

    Variants are found by stripping leading/trailing digits and symbols ("Password123!")
    and undoing l33t-speak substitutions ("p4$$w0rd").
    """
    common = load_common_passwords()
    lowered = password.lower()
    if lowered in common:
        return "common"
    stripped = re.sub(r"[\d\W_]+$", "", re.sub(r"^[\d\W_]+", "", lowered))
    candidates = {
        stripped,
        lowered.translate(LEET_MAP),
        stripped.translate(LEET_MAP),
        re.sub(r"[\d\W_]+$", "", lowered.translate(LEET_MAP)),
    }
    if any(len(c) >= 4 and c in common for c in candidates):
        return "common-variant"
    return None


def _label_for(score: int) -> str:
    """Map a 0-100 score to its label."""
    for threshold, label in LABELS:
        if score >= threshold:
            return label
    return LABELS[-1][1]


def _fragments(password: str, spans: list[Span]) -> tuple[str, ...]:
    """Return the substrings covered by ``spans`` in order of appearance, de-duplicated."""
    return tuple(dict.fromkeys(password[start:end] for start, end in sorted(spans)))


@dataclass
class _Detection:
    """Intermediate result of running every detector over a password."""

    findings: list[Finding]
    pattern_chars: int
    has_patterns: bool
    has_year: bool
    common: CommonMatch | None


def _detect(password: str, classes: list[str]) -> _Detection:
    """Run all detectors and collect findings, in the order they are shown to the user."""
    findings: list[Finding] = []
    covered = [False] * len(password)

    pattern_checks: tuple[tuple[FindingKind, str, list[Span]], ...] = (
        ("sequence", "Contains a predictable sequence", find_sequences(password)),
        ("keyboard", "Contains a keyboard walk", find_keyboard_walks(password)),
        ("repeat", "Contains repeated characters", find_repeats(password)),
    )
    for kind, description, spans in pattern_checks:
        if spans:
            span_chars = len({k for start, end in spans for k in range(start, end)})
            message = f"{description} ({span_chars} characters)"
            findings.append(Finding(kind, message, _fragments(password, spans)))
            for start, end in spans:
                covered[start:end] = [True] * (end - start)

    has_year = YEAR_RE.search(password) is not None
    if has_year:
        findings.append(Finding("year", "Contains what looks like a year, which is easy to guess"))

    common = common_password_match(password)
    if common == "common":
        findings.append(Finding("common", "This is one of the most commonly used passwords"))
    elif common == "common-variant":
        findings.append(
            Finding("common-variant", "This is a common password with small changes (digits, symbols or l33t-speak)")
        )

    if len(password) < MIN_LENGTH:
        findings.append(Finding("short", f"Too short: {len(password)} characters (minimum {MIN_LENGTH})"))

    if len(classes) == 1:
        findings.append(Finding("variety", f"Uses only {classes[0]}"))

    return _Detection(
        findings=findings,
        pattern_chars=sum(covered),
        has_patterns=any(spans for _, _, spans in pattern_checks),
        has_year=has_year,
        common=common,
    )


def _score(length: int, classes: list[str], detection: _Detection) -> int:
    """Compute the 0-100 score.

    Up to 80 points come from the effective length, where characters inside a detected
    pattern count for only ``PATTERN_CHAR_WEIGHT`` of a character; up to 20 points come
    from character variety. Caps then apply for short and common passwords.
    """
    pattern_chars = detection.pattern_chars
    effective_length = (length - pattern_chars) + pattern_chars * PATTERN_CHAR_WEIGHT
    score = min(effective_length, MAX_SCORED_LENGTH) * POINTS_PER_CHAR + len(classes) * POINTS_PER_CLASS
    if len(classes) == 1:
        score -= SINGLE_CLASS_PENALTY
    if detection.has_year:
        score -= YEAR_PENALTY
    if length < MIN_LENGTH:
        score = min(score, SHORT_PASSWORD_CAP)
    if detection.common == "common":
        score = 0
    elif detection.common == "common-variant":
        score = min(score, COMMON_VARIANT_CAP)
    return round(max(0, min(100, score)))


def _advice(length: int, classes: list[str], detection: _Detection, score: int) -> list[str]:
    """Build advice, most important first. Always returns at least one item."""
    advice: list[str] = []
    if detection.common:
        advice.append("Don't use a common password or a lightly modified one; attackers try these first.")
    if length < GOOD_LENGTH:
        advice.append(f"Make it longer: aim for at least {GOOD_LENGTH} characters, ideally {GREAT_LENGTH}+.")
    if detection.has_patterns:
        advice.append("Avoid sequences, keyboard patterns and repeated characters.")
    if detection.has_year:
        advice.append("Avoid years, birthdays and other dates tied to you.")
    missing = [c for c in CHARACTER_CLASSES if c not in classes]
    if missing and length < GREAT_LENGTH:
        advice.append("Mix in more character types: " + ", ".join(missing) + ".")
    if score < PASSPHRASE_ADVICE_BELOW:
        advice.append("Consider a passphrase of 4+ random, unrelated words, or let a password manager generate one.")
    if not advice:
        advice.append("Looks good. Use it for one account only and store it in a password manager.")
    return advice


def analyze(password: str) -> StrengthReport:
    """Score a password from 0 to 100 and explain what drags it down."""
    length = len(password)
    classes = character_classes(password)
    detection = _detect(password, classes)
    score = _score(length, classes, detection)
    return StrengthReport(
        score=score,
        label=_label_for(score),
        length=length,
        char_classes=classes,
        findings=detection.findings,
        advice=_advice(length, classes, detection, score),
    )

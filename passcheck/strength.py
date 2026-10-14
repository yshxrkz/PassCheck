"""Offline password strength analysis.

Everything here runs locally: no network access, no logging of the password.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

MIN_LENGTH = 8
GOOD_LENGTH = 12
GREAT_LENGTH = 16

# Characters inside a detected pattern are worth this fraction of a "free" character
# when computing the effective length. Predictable runs add very little to the search
# space an attacker has to cover.
PATTERN_CHAR_WEIGHT = 0.25

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


@dataclass
class Finding:
    """A weakness detected in the password."""

    kind: str
    message: str


@dataclass
class StrengthReport:
    score: int
    label: str
    length: int
    char_classes: list[str]
    findings: list[Finding] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)

    @property
    def is_common(self) -> bool:
        return any(f.kind in ("common", "common-variant") for f in self.findings)


@lru_cache(maxsize=1)
def load_common_passwords() -> frozenset[str]:
    text = resources.files("passcheck").joinpath("data/common_passwords.txt").read_text("utf-8")
    return frozenset(
        line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


def character_classes(password: str) -> list[str]:
    classes = []
    if any(c.islower() for c in password):
        classes.append("lowercase")
    if any(c.isupper() for c in password):
        classes.append("uppercase")
    if any(c.isdigit() for c in password):
        classes.append("digits")
    if any(not c.isalnum() for c in password):
        classes.append("symbols")
    return classes


def find_sequences(password: str, min_len: int = MIN_SEQUENCE) -> list[tuple[int, int]]:
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
    return (a in string.ascii_lowercase and b in string.ascii_lowercase) or (a.isdigit() and b.isdigit())


def find_keyboard_walks(password: str, min_len: int = MIN_KEYBOARD_WALK) -> list[tuple[int, int]]:
    """Return spans of adjacent-key runs such as "qwerty", "asdf" or "1qaz2wsx" (either direction)."""
    lowered = password.lower()
    spans: list[tuple[int, int]] = []
    i = 0
    while i <= len(lowered) - min_len:
        best = 0
        for row in KEYBOARD_ROWS:
            for line in (row, row[::-1]):
                length = _longest_prefix_in(lowered[i:], line, min_len)
                best = max(best, length)
        if best:
            spans.append((i, i + best))
            i += best
        else:
            i += 1
    return spans


def _longest_prefix_in(text: str, line: str, min_len: int) -> int:
    length = 0
    for n in range(min_len, len(text) + 1):
        if text[:n] in line:
            length = n
        else:
            break
    return length


def find_repeats(password: str) -> list[tuple[int, int]]:
    """Return spans of repeated characters ("aaa") or repeated chunks ("abcabc")."""
    spans = []
    for match in re.finditer(r"(.)\1{%d,}" % (MIN_REPEAT - 1), password):
        spans.append(match.span())
    for match in re.finditer(r"(.{2,}?)\1+", password):
        if len(set(match.group(1))) > 1:
            spans.append(match.span())
    return spans


def common_password_match(password: str) -> str | None:
    """Return "common" for an exact match, "common-variant" for a disguised one, else None."""
    common = load_common_passwords()
    lowered = password.lower()
    if lowered in common:
        return "common"
    # Strip the decorations people bolt onto a weak base ("Password123!", "dragon2024").
    stripped = re.sub(r"[\d\W_]+$", "", re.sub(r"^[\d\W_]+", "", lowered))
    candidates = {stripped, lowered.translate(LEET_MAP), stripped.translate(LEET_MAP)}
    deleeted_core = re.sub(r"[\d\W_]+$", "", lowered.translate(LEET_MAP))
    candidates.add(deleeted_core)
    if any(len(c) >= 4 and c in common for c in candidates):
        return "common-variant"
    return None


def _label_for(score: int) -> str:
    for threshold, label in LABELS:
        if score >= threshold:
            return label
    return LABELS[-1][1]


def analyze(password: str) -> StrengthReport:
    """Score a password from 0 to 100 and explain what drags it down."""
    length = len(password)
    classes = character_classes(password)
    findings: list[Finding] = []
    advice: list[str] = []

    covered = [False] * length

    def mark(spans: list[tuple[int, int]]) -> None:
        for start, end in spans:
            for k in range(start, end):
                covered[k] = True

    sequences = find_sequences(password)
    if sequences:
        parts = ", ".join(repr(password[s:e]) for s, e in sequences)
        findings.append(Finding("sequence", f"Contains a predictable sequence: {parts}"))
        mark(sequences)

    walks = find_keyboard_walks(password)
    if walks:
        parts = ", ".join(repr(password[s:e]) for s, e in walks)
        findings.append(Finding("keyboard", f"Contains a keyboard walk: {parts}"))
        mark(walks)

    repeats = find_repeats(password)
    if repeats:
        parts = ", ".join(sorted({repr(password[s:e]) for s, e in repeats}))
        findings.append(Finding("repeat", f"Contains repeated characters: {parts}"))
        mark(repeats)

    if re.search(r"(19|20)\d{2}", password):
        findings.append(Finding("year", "Contains what looks like a year, which is easy to guess"))

    common = common_password_match(password)
    if common == "common":
        findings.append(Finding("common", "This is one of the most commonly used passwords"))
    elif common == "common-variant":
        findings.append(
            Finding("common-variant", "This is a common password with small changes (digits, symbols or l33t-speak)")
        )

    if length < MIN_LENGTH:
        findings.append(Finding("short", f"Too short: {length} characters (minimum {MIN_LENGTH})"))

    if len(classes) == 1:
        findings.append(Finding("variety", f"Uses only {classes[0]}"))

    # Score: effective length (up to 80 points) plus character variety (up to 20).
    pattern_chars = sum(covered)
    effective_length = (length - pattern_chars) + pattern_chars * PATTERN_CHAR_WEIGHT
    score = min(effective_length, 20) * 4 + len(classes) * 5
    if len(classes) == 1:
        score -= 10
    if any(f.kind == "year" for f in findings):
        score -= 5
    if length < MIN_LENGTH:
        score = min(score, 30)
    if common == "common":
        score = 0
    elif common == "common-variant":
        score = min(score, 15)
    score = int(round(max(0, min(100, score))))

    # Advice, most important first.
    if common:
        advice.append("Don't use a common password or a lightly modified one; attackers try these first.")
    if length < GOOD_LENGTH:
        advice.append(f"Make it longer: aim for at least {GOOD_LENGTH} characters, ideally {GREAT_LENGTH}+.")
    if sequences or walks or repeats:
        advice.append("Avoid sequences, keyboard patterns and repeated characters.")
    if any(f.kind == "year" for f in findings):
        advice.append("Avoid years, birthdays and other dates tied to you.")
    missing = [c for c in ("lowercase", "uppercase", "digits", "symbols") if c not in classes]
    if missing and length < GREAT_LENGTH:
        advice.append("Mix in more character types: " + ", ".join(missing) + ".")
    if score < 60:
        advice.append(
            "Consider a passphrase of 4+ random, unrelated words, or let a password manager generate one."
        )
    if not advice:
        advice.append("Looks good. Use it for one account only and store it in a password manager.")

    return StrengthReport(
        score=score,
        label=_label_for(score),
        length=length,
        char_classes=classes,
        findings=findings,
        advice=advice,
    )

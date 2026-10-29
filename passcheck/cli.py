"""Command-line interface for PassCheck."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TextIO

from . import __version__
from .hibp import Fetcher, HIBPError, fetch_range, pwned_count
from .strength import Finding, StrengthReport, analyze

EXIT_OK = 0
EXIT_WEAK = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130  # conventional 128 + SIGINT

DEFAULT_MIN_SCORE = 60
# Far longer than any real password. Analysis is roughly quadratic in length, so this
# also stops a huge piped input from hanging the tool.
MAX_PASSWORD_LENGTH = 1024


class UsageError(Exception):
    """Bad input from the user; reported as a one-line message with exit status 2."""


@dataclass
class CheckResult:
    """Everything the output functions need. Deliberately holds no copy of the password.

    Attributes:
        report: The offline strength analysis.
        breach_count: Times seen in breaches, or None if the check was not run or failed.
        breach_error: Why the breach check failed, if it did.
        passes: Score is at least --min-score and the password was not found in a breach.
    """

    report: StrengthReport
    breach_count: int | None
    breach_error: str | None
    passes: bool


def _score_arg(value: str) -> int:
    """argparse type for --min-score: an integer from 0 to 100."""
    try:
        score = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be an integer, got {value!r}") from None
    if not 0 <= score <= 100:
        raise argparse.ArgumentTypeError(f"must be between 0 and 100, got {score}")
    return score


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="passcheck",
        description=(
            "Check how strong a password is. By default you are prompted for the password "
            "(input is hidden), so it never lands in your shell history."
        ),
        epilog="Exit status: 0 = passes, 1 = weak or breached, 2 = usage error, 130 = interrupted.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read the password from the first line of standard input instead of prompting",
    )
    parser.add_argument(
        "--pwned",
        action="store_true",
        help=(
            "also check Have I Been Pwned's breach corpus (k-anonymity: only the first "
            "5 characters of the SHA-1 hash are sent)"
        ),
    )
    parser.add_argument(
        "--min-score",
        type=_score_arg,
        default=DEFAULT_MIN_SCORE,
        metavar="N",
        help=f"exit with status 1 if the score is below N, 0-100 (default: {DEFAULT_MIN_SCORE})",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument(
        "--reveal",
        action="store_true",
        help=(
            "show which parts of the password matched a pattern (e.g. '123'). Off by default "
            "so output can be logged without leaking pieces of the password"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def read_password(use_stdin: bool, stdin: TextIO) -> str:
    """Read the password from the first line of ``stdin`` or from a hidden prompt.

    Raises:
        UsageError: nothing was entered, or the password is longer than
            ``MAX_PASSWORD_LENGTH`` characters.
    """
    if use_stdin:
        # Bounded read: never pull an arbitrarily long line into memory.
        password = stdin.readline(MAX_PASSWORD_LENGTH + 2).rstrip("\r\n")
    else:
        try:
            password = getpass.getpass("Password: ")
        except EOFError:
            raise UsageError("no password given") from None
    if not password:
        raise UsageError("no password given")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise UsageError(f"password is longer than {MAX_PASSWORD_LENGTH} characters")
    return password


def check_password(password: str, min_score: int, pwned: bool, fetcher: Fetcher) -> CheckResult:
    """Run the offline analysis and, if requested, the breach check."""
    report = analyze(password)
    breach_count: int | None = None
    breach_error: str | None = None
    if pwned:
        try:
            breach_count = pwned_count(password, fetcher)
        except HIBPError as exc:
            breach_error = str(exc)
    passes = report.score >= min_score and not breach_count
    return CheckResult(report, breach_count, breach_error, passes)


def _finding_text(finding: Finding, reveal: bool) -> str:
    """Render a finding for the terminal, quoting the matched fragments only if asked to."""
    if reveal and finding.fragments:
        return f"{finding.message}: " + ", ".join(repr(f) for f in finding.fragments)
    return finding.message


def _finding_json(finding: Finding, reveal: bool) -> dict[str, object]:
    """Render a finding for --json output; ``fragments`` is present only with --reveal."""
    data: dict[str, object] = {"kind": finding.kind, "message": finding.message}
    if reveal:
        data["fragments"] = list(finding.fragments)
    return data


def _bar(score: int, width: int = 20) -> str:
    """Draw a text progress bar for a 0-100 score."""
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def render_json(result: CheckResult, reveal: bool, out: TextIO) -> None:
    """Write the result as a JSON document."""
    report = result.report
    count = result.breach_count
    payload = {
        "score": report.score,
        "label": report.label,
        "length": report.length,
        "character_classes": report.char_classes,
        "findings": [_finding_json(f, reveal) for f in report.findings],
        "advice": report.advice,
        "pwned": None if count is None else {"breached": count > 0, "count": count},
        "pwned_error": result.breach_error,
        "passes": result.passes,
    }
    json.dump(payload, out, indent=2)
    out.write("\n")


def render_text(result: CheckResult, pwned: bool, reveal: bool, out: TextIO) -> None:
    """Write the human-readable report."""
    report = result.report
    lines = [
        f"Score: {report.score}/100 {_bar(report.score)} {report.label}",
        f"Length: {report.length}   Character types: {', '.join(report.char_classes)}",
    ]
    if report.findings:
        lines += ["", "Issues found:"]
        lines += [f"  - {_finding_text(f, reveal)}" for f in report.findings]
    if pwned:
        lines += ["", "Breach check (Have I Been Pwned):"]
        if result.breach_error:
            lines.append(f"  ! Skipped: {result.breach_error}")
        elif result.breach_count:
            lines.append(f"  ! Seen {result.breach_count:,} times in known data breaches. Do not use this password.")
        else:
            lines.append("  Not found in any known breach.")
    lines += ["", "Advice:"]
    if result.breach_count:
        lines.append("  - This password is public knowledge to attackers; change it wherever you use it.")
    lines += [f"  - {tip}" for tip in report.advice]
    out.write("\n".join(lines) + "\n")


def main(
    argv: Sequence[str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    fetcher: Fetcher = fetch_range,
) -> int:
    """Run the CLI and return its exit status.

    The streams and ``fetcher`` can be replaced, which is how the tests run the CLI
    without a terminal or network access.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)

    try:
        password = read_password(args.stdin, stdin)
        result = check_password(password, args.min_score, args.pwned, fetcher)
        # Not needed past this point; don't keep a reference around longer than necessary.
        del password
        if args.json:
            render_json(result, args.reveal, stdout)
        else:
            render_text(result, args.pwned, args.reveal, stdout)
        stdout.flush()
    except UsageError as exc:
        print(f"passcheck: error: {exc}", file=stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\npasscheck: interrupted", file=stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # Output was piped into something that stopped reading (e.g. `| head`). Point stdout
        # at devnull so the interpreter's final flush doesn't raise a second time.
        if stdout is sys.stdout:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        return EXIT_ERROR

    if result.breach_error:
        print(f"passcheck: warning: breach check skipped: {result.breach_error}", file=stderr)
    return EXIT_OK if result.passes else EXIT_WEAK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

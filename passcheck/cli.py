"""Command-line interface for PassCheck."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from typing import Sequence, TextIO

from . import __version__
from .hibp import Fetcher, HIBPError, fetch_range, pwned_count
from .strength import analyze

EXIT_OK = 0
EXIT_WEAK = 1
EXIT_ERROR = 2

DEFAULT_MIN_SCORE = 60


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passcheck",
        description=(
            "Check how strong a password is. By default you are prompted for the password "
            "(input is hidden), so it never lands in your shell history."
        ),
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
        type=int,
        default=DEFAULT_MIN_SCORE,
        metavar="N",
        help=f"exit with status 1 if the score is below N (default: {DEFAULT_MIN_SCORE})",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def read_password(use_stdin: bool, stdin: TextIO) -> str:
    if use_stdin:
        line = stdin.readline()
        return line[:-1] if line.endswith("\n") else line
    return getpass.getpass("Password: ")


def _bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def main(
    argv: Sequence[str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    fetcher: Fetcher = fetch_range,
) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)

    try:
        password = read_password(args.stdin, stdin)
    except (EOFError, KeyboardInterrupt):
        print("\nNo password given.", file=stderr)
        return EXIT_ERROR
    if not password:
        print("No password given.", file=stderr)
        return EXIT_ERROR

    report = analyze(password)

    breach_count: int | None = None
    breach_error: str | None = None
    if args.pwned:
        try:
            breach_count = pwned_count(password, fetcher)
        except HIBPError as exc:
            breach_error = str(exc)

    # The password is not needed past this point; drop our reference to it.
    del password

    weak = report.score < args.min_score or bool(breach_count)

    if args.json:
        payload = {
            "score": report.score,
            "label": report.label,
            "length": report.length,
            "character_classes": report.char_classes,
            "findings": [{"kind": f.kind, "message": f.message} for f in report.findings],
            "advice": report.advice,
            "pwned": None if breach_count is None else {"breached": breach_count > 0, "count": breach_count},
            "pwned_error": breach_error,
            "passes": not weak,
        }
        json.dump(payload, stdout, indent=2)
        stdout.write("\n")
    else:
        print(f"Score: {report.score}/100 {_bar(report.score)} {report.label}", file=stdout)
        print(f"Length: {report.length}   Character types: {', '.join(report.char_classes)}", file=stdout)
        if report.findings:
            print("\nIssues found:", file=stdout)
            for finding in report.findings:
                print(f"  - {finding.message}", file=stdout)
        if args.pwned:
            print("\nBreach check (Have I Been Pwned):", file=stdout)
            if breach_error:
                print(f"  ! Skipped: {breach_error}", file=stdout)
            elif breach_count:
                print(
                    f"  ! Seen {breach_count:,} times in known data breaches. Do not use this password.",
                    file=stdout,
                )
            else:
                print("  Not found in any known breach.", file=stdout)
        print("\nAdvice:", file=stdout)
        if breach_count:
            print("  - This password is public knowledge to attackers; change it wherever you use it.", file=stdout)
        for tip in report.advice:
            print(f"  - {tip}", file=stdout)

    if breach_error:
        print(f"warning: breach check skipped: {breach_error}", file=stderr)

    return EXIT_WEAK if weak else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

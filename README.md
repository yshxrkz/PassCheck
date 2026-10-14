# PassCheck

A command-line password strength checker. It scores a password from 0 to 100, explains
what makes it weak, and gives advice on fixing it. It can also check the password against
the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) breach corpus **without
ever sending the password, or even its full hash, over the network**.

Pure Python standard library, no runtime dependencies. Requires Python 3.9+.

## Install

```bash
pip install .            # installs the `passcheck` command
# or run it in place without installing:
python -m passcheck
```

## Usage

```bash
passcheck                 # prompts for the password (input hidden)
passcheck --pwned         # also check Have I Been Pwned
passcheck --json          # machine-readable output
passcheck --min-score 80  # stricter pass/fail threshold (default 60)
printf '%s\n' "$PW" | passcheck --stdin   # read from stdin, e.g. in scripts
```

The password is deliberately **not** accepted as a command-line argument: arguments are
saved in shell history and visible to other users through `ps`.

Example:

```text
$ passcheck --pwned
Password:
Score: 15/100 [###-----------------] Very weak
Length: 12   Character types: lowercase, uppercase, digits, symbols

Issues found:
  - Contains a predictable sequence: '123'
  - This is a common password with small changes (digits, symbols or l33t-speak)

Breach check (Have I Been Pwned):
  ! Seen 295,389 times in known data breaches. Do not use this password.

Advice:
  - This password is public knowledge to attackers; change it wherever you use it.
  - Don't use a common password or a lightly modified one; attackers try these first.
  - Avoid sequences, keyboard patterns and repeated characters.
  - Consider a passphrase of 4+ random, unrelated words, or let a password manager generate one.
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Score is at or above `--min-score` and (with `--pwned`) the password was not found in a breach |
| 1 | Score is below `--min-score`, or the password was found in a breach |
| 2 | No password given |

If the breach check can't reach the API, PassCheck prints a warning and falls back to the
offline result instead of failing.

## What it checks

| Check | Examples | Effect |
|-------|----------|--------|
| Length | under 8 chars | score capped at 30; advice to reach 12–16+ |
| Character variety | lowercase, uppercase, digits, symbols | up to 20 points; one class only is penalised |
| Common passwords | `123456`, `letmein`, `iloveyou` | score 0 |
| Disguised common passwords | `Password123!`, `m0nk3y`, `dragon2024` | score capped at 15 |
| Sequences | `abc`, `123`, `987`, `xyz` | characters count for ¼ of their length |
| Keyboard walks | `qwerty`, `asdf`, `poiuy`, `1qaz2wsx` | characters count for ¼ of their length |
| Repeats | `aaa`, `abcabc` | characters count for ¼ of their length |
| Years | `1987`, `2024` | small penalty |

**Scoring.** Up to 80 points come from the *effective length* (4 points per character, up
to 20 characters), where characters inside a detected pattern only count for a quarter,
because an attacker's tools guess those patterns early. Up to 20 more points come from
character variety. Labels: 0–19 Very weak, 20–39 Weak, 40–59 Fair, 60–79 Strong,
80–100 Very strong.

This is a heuristic. It catches the common mistakes, but it can't know that a password is
your dog's name. Length and randomness matter most, so a password manager or a passphrase
of several random words is the best advice in nearly every case.

## The breach check and why k-anonymity protects you

Have I Been Pwned (HIBP) keeps a list of hundreds of millions of real passwords exposed in
data breaches. If yours is on it, attackers have it in their wordlists, however strong it
looks. The difficulty is checking the list without handing your password to anyone.

### What PassCheck sends

1. It hashes your password locally with SHA-1:
   `password` → `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. It sends **only the first 5 hex characters** of that hash:
   `GET https://api.pwnedpasswords.com/range/5BAA6`
3. HIBP replies with the remaining 35 characters of **every** breached hash that starts
   with `5BAA6`, usually 800–1,000 of them, each with a count:
   ```
   ...
   1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824
   ...
   ```
4. PassCheck looks for its own 35-character suffix in that list **on your machine**.

Your password, the full hash, and the 35-character suffix never leave your computer. The
test suite enforces this: `tests/test_hibp.py` intercepts the outgoing HTTP request and
fails if anything beyond the 5-character prefix appears in the URL or headers.

### Why the prefix gives nothing away

* **The prefix is shared by a crowd.** 5 hex characters allow only 16⁵ = 1,048,576
  prefixes. Every possible password falls into one of these buckets, so each bucket covers
  an enormous number of possible passwords and hundreds of known breached ones. The server
  learns which bucket you asked about, and that bucket is shared by far too many
  candidates to single out your password. This is what *k-anonymity* means: your query
  can't be told apart from those of at least *k* others. Here *k* is in the hundreds even
  counting breached passwords alone, and effectively unbounded counting every possible one.
* **The server never learns the answer.** The match happens locally, so HIBP can't tell
  whether your password was in the list, let alone which entry it was. The request looks
  exactly the same either way.
* **Response padding hides the bucket size.** PassCheck sends the `Add-Padding: true`
  header, so HIBP pads each response with dummy entries (count 0, ignored by PassCheck).
  Every response is then a similar size, and someone watching the encrypted traffic can't
  guess the prefix from how much data came back.
* **Nothing to steal in transit or at rest.** Even if the request were logged by HIBP, a
  proxy, or an attacker, a 5-character prefix can't be reversed into a password. It only
  narrows the search by a factor of about one million, which is negligible next to the
  size of the space of possible passwords.

Without k-anonymity, the alternative would be sending the full SHA-1 hash. That is nearly
as bad as sending the password: unsalted SHA-1 is fast to compute, so any password a human
would pick can be recovered from its hash with a dictionary attack in seconds.

What k-anonymity does *not* hide: that you (your IP address) made a request to HIBP at a
particular time. The breach check is off by default; it only runs with `--pwned`.

## Development

```bash
pip install -e '.[test]'
pytest            # or: python -m unittest
```

The tests never touch the network: the HTTP call is injected or mocked.

Layout:

```
passcheck/
  strength.py                  offline analysis and scoring
  hibp.py                      k-anonymity Pwned Passwords client
  cli.py                       argument parsing and output
  data/common_passwords.txt    common password list
tests/
```

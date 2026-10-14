import io
import json
import unittest
from unittest import mock

from passcheck import cli
from passcheck.hibp import HIBPError, split_hash

STRONG = "xK9#mQ2$vL7pR4!w"


def run(argv, password, fetcher=None):
    stdout, stderr = io.StringIO(), io.StringIO()
    kwargs = {"fetcher": fetcher} if fetcher else {}
    code = cli.main(["--stdin", *argv], stdin=io.StringIO(password + "\n"), stdout=stdout, stderr=stderr, **kwargs)
    return code, stdout.getvalue(), stderr.getvalue()


def no_network(prefix):
    raise AssertionError("network should not be used without --pwned")


class CliTests(unittest.TestCase):
    def test_weak_password_exit_code_and_output(self):
        code, out, _ = run([], "password", fetcher=no_network)
        self.assertEqual(code, cli.EXIT_WEAK)
        self.assertIn("Score: 0/100", out)
        self.assertIn("Advice:", out)

    def test_strong_password_passes(self):
        code, out, _ = run([], STRONG, fetcher=no_network)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Very strong", out)

    def test_password_never_echoed(self):
        _, out, err = run(["--json"], STRONG)
        self.assertNotIn(STRONG, out + err)

    def test_min_score(self):
        code, _, _ = run(["--min-score", "101"], STRONG)
        self.assertEqual(code, cli.EXIT_WEAK)
        code, _, _ = run(["--min-score", "0"], "password")
        self.assertEqual(code, cli.EXIT_OK)

    def test_json_output(self):
        code, out, _ = run(["--json"], "qwerty12")
        data = json.loads(out)
        self.assertEqual(code, cli.EXIT_WEAK)
        self.assertIn("keyboard", {f["kind"] for f in data["findings"]})
        self.assertIsNone(data["pwned"])
        self.assertFalse(data["passes"])

    def test_empty_password_is_an_error(self):
        code, _, err = run([], "")
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("No password", err)

    def test_prompts_with_getpass_by_default(self):
        with mock.patch("getpass.getpass", return_value=STRONG) as prompt:
            code = cli.main([], stdout=io.StringIO(), stderr=io.StringIO())
        prompt.assert_called_once()
        self.assertEqual(code, cli.EXIT_OK)


class CliPwnedTests(unittest.TestCase):
    def test_breached_strong_password_fails(self):
        prefix, suffix = split_hash(STRONG)
        seen = []

        def fetcher(p):
            seen.append(p)
            return f"{suffix}:42\n"

        code, out, _ = run(["--pwned"], STRONG, fetcher=fetcher)
        self.assertEqual(seen, [prefix])
        self.assertEqual(code, cli.EXIT_WEAK)
        self.assertIn("Seen 42 times", out)

    def test_not_breached(self):
        code, out, _ = run(["--pwned"], STRONG, fetcher=lambda p: "")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Not found in any known breach", out)

    def test_json_includes_breach_result(self):
        _, suffix = split_hash(STRONG)
        _, out, _ = run(["--pwned", "--json"], STRONG, fetcher=lambda p: f"{suffix}:5\n")
        self.assertEqual(json.loads(out)["pwned"], {"breached": True, "count": 5})

    def test_network_failure_is_a_warning_not_a_crash(self):
        def failing(prefix):
            raise HIBPError("offline")

        code, out, err = run(["--pwned"], STRONG, fetcher=failing)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Skipped", out)
        self.assertIn("warning", err)


if __name__ == "__main__":
    unittest.main()

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
        code, _, _ = run(["--min-score", "100"], STRONG)  # STRONG scores 84
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
        self.assertIn("no password given", err)

    def test_prompts_with_getpass_by_default(self):
        with mock.patch("getpass.getpass", return_value=STRONG) as prompt:
            code = cli.main([], stdout=io.StringIO(), stderr=io.StringIO())
        prompt.assert_called_once()
        self.assertEqual(code, cli.EXIT_OK)


class CliErrorHandlingTests(unittest.TestCase):
    def test_min_score_must_be_in_range(self):
        for bad in ("-1", "101", "abc"):
            with self.subTest(value=bad), mock.patch("sys.stderr", io.StringIO()) as err:
                with self.assertRaises(SystemExit) as ctx:
                    cli.main(["--stdin", "--min-score", bad], stdin=io.StringIO("x\n"))
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("--min-score", err.getvalue())

    def test_overlong_password_is_rejected(self):
        code, out, err = run([], "a" * (cli.MAX_PASSWORD_LENGTH + 1))
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("longer than", err)
        self.assertEqual(out, "")

    def test_huge_stdin_is_not_read_into_memory(self):
        stdin = io.StringIO("a" * 10_000_000)
        code = cli.main(["--stdin"], stdin=stdin, stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertLessEqual(stdin.tell(), cli.MAX_PASSWORD_LENGTH + 2)

    def test_password_at_max_length_is_accepted(self):
        code, _, err = run(["--min-score", "0"], "Zq8!" * (cli.MAX_PASSWORD_LENGTH // 4))
        self.assertEqual(code, cli.EXIT_OK, err)

    def test_windows_line_ending_is_stripped(self):
        _, out, _ = run(["--json"], STRONG + "\r")
        self.assertEqual(json.loads(out)["length"], len(STRONG))

    def test_getpass_eof_is_a_usage_error(self):
        err = io.StringIO()
        with mock.patch("getpass.getpass", side_effect=EOFError):
            code = cli.main([], stdout=io.StringIO(), stderr=err)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("no password given", err.getvalue())

    def test_ctrl_c_exits_130(self):
        err = io.StringIO()
        with mock.patch("getpass.getpass", side_effect=KeyboardInterrupt):
            code = cli.main([], stdout=io.StringIO(), stderr=err)
        self.assertEqual(code, cli.EXIT_INTERRUPTED)
        self.assertIn("interrupted", err.getvalue())

    def test_ctrl_c_during_breach_check_exits_130(self):
        def slow_fetcher(prefix):
            raise KeyboardInterrupt

        code, _, _ = run(["--pwned"], STRONG, fetcher=slow_fetcher)
        self.assertEqual(code, cli.EXIT_INTERRUPTED)

    def test_broken_pipe_is_handled_quietly(self):
        class ClosedPipe(io.StringIO):
            def write(self, text):
                raise BrokenPipeError

        err = io.StringIO()
        code = cli.main(["--stdin"], stdin=io.StringIO(STRONG + "\n"), stdout=ClosedPipe(), stderr=err)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(err.getvalue(), "")


class RedactionTests(unittest.TestCase):
    """Output must not leak pieces of the password unless --reveal is given."""

    PASSWORD = "Zebra789Quasar!qwerty"

    def test_text_output_hides_fragments(self):
        _, out, err = run([], self.PASSWORD)
        self.assertIn("predictable sequence (3 characters)", out)
        for fragment in ("789", "qwerty", "Zebra", "Quasar"):
            self.assertNotIn(fragment, out + err)

    def test_json_output_hides_fragments(self):
        _, out, _ = run(["--json"], self.PASSWORD)
        self.assertNotIn("789", out)
        self.assertNotIn("qwerty", out)
        self.assertNotIn("fragments", json.loads(out)["findings"][0])

    def test_reveal_shows_fragments(self):
        _, out, _ = run(["--reveal"], self.PASSWORD)
        self.assertIn("'789'", out)
        self.assertIn("'qwerty'", out)
        _, out, _ = run(["--json", "--reveal"], self.PASSWORD)
        fragments = {frag for f in json.loads(out)["findings"] for frag in f["fragments"]}
        self.assertEqual(fragments, {"789", "qwerty"})


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

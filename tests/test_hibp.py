import hashlib
import unittest
from unittest import mock

from passcheck import hibp

PASSWORD = "password"
# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
FULL_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
PREFIX, SUFFIX = FULL_HASH[:5], FULL_HASH[5:]


class FakeResponse:
    """Minimal stand-in for the object ``urllib.request.urlopen`` returns."""

    def __init__(self, body, url="https://api.pwnedpasswords.com/range/00000"):
        self.body = body
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def geturl(self):
        return self.url

    def read(self, amount=-1):
        return self.body if amount < 0 else self.body[:amount]


class RecordingFetcher:
    """Stand-in for the network call that remembers exactly what it was given."""

    def __init__(self, body):
        self.body = body
        self.calls = []

    def __call__(self, prefix):
        self.calls.append(prefix)
        return self.body


class HashingTests(unittest.TestCase):
    def test_sha1_is_uppercase_hex(self):
        self.assertEqual(hibp.sha1_hex(PASSWORD), FULL_HASH)

    def test_split_hash(self):
        self.assertEqual(hibp.split_hash(PASSWORD), (PREFIX, SUFFIX))

    def test_unicode_is_utf8_encoded(self):
        expected = hashlib.sha1("pässwörd".encode()).hexdigest().upper()
        self.assertEqual(hibp.sha1_hex("pässwörd"), expected)


class ParseRangeTests(unittest.TestCase):
    def test_parses_lines_and_drops_padding(self):
        body = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n\r\n"
        self.assertEqual(hibp.parse_range(body), {"0018A45C4D1DEF81644B54AB7F969B88D65": 10})

    def test_malformed_lines_raise(self):
        for body in (
            "garbage",
            f"{SUFFIX}:notanumber",
            f"{SUFFIX}:-1",
            "ABC:3",  # suffix too short
            f"{SUFFIX}X:3",  # suffix too long
            "Z" * 35 + ":3",  # not hex
        ):
            with self.subTest(body=body), self.assertRaises(hibp.HIBPError):
                hibp.parse_range(body)

    def test_error_message_is_truncated(self):
        with self.assertRaises(hibp.HIBPError) as ctx:
            hibp.parse_range("x" * 10_000)
        self.assertLess(len(str(ctx.exception)), 200)


class PwnedCountTests(unittest.TestCase):
    def test_found(self):
        fetcher = RecordingFetcher(f"0000000000000000000000000000000000A:3\n{SUFFIX}:9545824\n")
        self.assertEqual(hibp.pwned_count(PASSWORD, fetcher), 9545824)

    def test_suffix_match_is_case_insensitive(self):
        fetcher = RecordingFetcher(f"{SUFFIX.lower()}:7\n")
        self.assertEqual(hibp.pwned_count(PASSWORD, fetcher), 7)

    def test_not_found(self):
        fetcher = RecordingFetcher("0000000000000000000000000000000000A:3\n")
        self.assertEqual(hibp.pwned_count(PASSWORD, fetcher), 0)

    def test_padding_entry_for_our_suffix_counts_as_not_found(self):
        fetcher = RecordingFetcher(f"{SUFFIX}:0\n")
        self.assertEqual(hibp.pwned_count(PASSWORD, fetcher), 0)


class KAnonymityTests(unittest.TestCase):
    """The privacy guarantee: only a 5-character hash prefix may leave the machine."""

    def test_fetcher_only_receives_five_char_prefix(self):
        fetcher = RecordingFetcher("")
        hibp.pwned_count(PASSWORD, fetcher)
        self.assertEqual(fetcher.calls, [PREFIX])
        self.assertEqual(len(fetcher.calls[0]), 5)

    def test_http_request_contains_only_prefix(self):
        # Distinctive secret: "password" itself is a substring of "pwnedpasswords.com".
        secret = "Zebra-Quasar-8812"
        full_hash = hashlib.sha1(secret.encode()).hexdigest().upper()
        prefix, suffix = full_hash[:5], full_hash[5:]
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            return FakeResponse(f"{suffix}:1\n".encode())

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(hibp.pwned_count(secret), 1)

        request = captured["request"]
        self.assertEqual(request.full_url, f"https://api.pwnedpasswords.com/range/{prefix}")
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        everything_sent = request.full_url + repr(request.header_items())
        for leaked in (secret, secret.lower(), full_hash, suffix, full_hash.lower(), suffix.lower()):
            self.assertNotIn(leaked, everything_sent)
        self.assertEqual(request.get_header("Add-padding"), "true")

    def test_fetch_range_rejects_anything_but_a_prefix(self):
        for bad in (FULL_HASH, PASSWORD, "5baa6", "5BAA", "ZZZZZ"):
            with self.assertRaises(ValueError):
                hibp.fetch_range(bad)

    def test_network_error_becomes_hibp_error(self):
        import urllib.error

        offline = mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline"))
        with offline, self.assertRaises(hibp.HIBPError):
            hibp.pwned_count(PASSWORD)


def urlopen_returning(response=None, error=None):
    def fake_urlopen(request, timeout):
        if error is not None:
            raise error
        return response

    return mock.patch("urllib.request.urlopen", fake_urlopen)


class FetchRangeErrorTests(unittest.TestCase):
    """Every failure mode surfaces as HIBPError, never as a traceback or a wrong answer."""

    def assert_hibp_error(self, patcher, message_part):
        with patcher, self.assertRaises(hibp.HIBPError) as ctx:
            hibp.fetch_range(PREFIX)
        self.assertIn(message_part, str(ctx.exception))

    def test_http_error_status(self):
        import urllib.error

        error = urllib.error.HTTPError("https://x", 429, "Too Many Requests", {}, None)
        self.assert_hibp_error(urlopen_returning(error=error), "HTTP 429")

    def test_timeout(self):
        self.assert_hibp_error(urlopen_returning(error=TimeoutError("timed out")), "could not reach")

    def test_truncated_response(self):
        import http.client

        error = http.client.IncompleteRead(b"partial")
        self.assert_hibp_error(urlopen_returning(error=error), "could not reach")

    def test_oversized_response(self):
        body = b"A" * (hibp.MAX_RESPONSE_BYTES + 10)
        self.assert_hibp_error(urlopen_returning(FakeResponse(body)), "unexpectedly large")

    def test_non_utf8_response(self):
        self.assert_hibp_error(urlopen_returning(FakeResponse(b"\xff\xfe")), "UTF-8")

    def test_redirect_to_plain_http_is_refused(self):
        response = FakeResponse(b"", url="http://evil.example/range/5BAA6")
        self.assert_hibp_error(urlopen_returning(response), "non-HTTPS")

    def test_non_https_api_url_is_refused(self):
        with mock.patch.object(hibp, "API_URL", "file:///etc/passwd?{prefix}"), self.assertRaises(hibp.HIBPError):
            hibp.fetch_range(PREFIX)

    def test_success_returns_text(self):
        with urlopen_returning(FakeResponse(f"{SUFFIX}:3\r\n".encode())):
            self.assertEqual(hibp.fetch_range(PREFIX), f"{SUFFIX}:3\r\n")


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest
from unittest import mock

from passcheck import hibp

PASSWORD = "password"
# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
FULL_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
PREFIX, SUFFIX = FULL_HASH[:5], FULL_HASH[5:]


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
        expected = hashlib.sha1("pässwörd".encode("utf-8")).hexdigest().upper()
        self.assertEqual(hibp.sha1_hex("pässwörd"), expected)


class ParseRangeTests(unittest.TestCase):
    def test_parses_lines_and_drops_padding(self):
        body = "0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n\r\n"
        self.assertEqual(hibp.parse_range(body), {"0018A45C4D1DEF81644B54AB7F969B88D65": 10})

    def test_malformed_line_raises(self):
        with self.assertRaises(hibp.HIBPError):
            hibp.parse_range("garbage")
        with self.assertRaises(hibp.HIBPError):
            hibp.parse_range("ABC:notanumber")


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

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return f"{suffix}:1\n".encode()

        def fake_urlopen(request, timeout):
            captured["request"] = request
            return FakeResponse()

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

        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            with self.assertRaises(hibp.HIBPError):
                hibp.pwned_count(PASSWORD)


if __name__ == "__main__":
    unittest.main()

import unittest

from passcheck.strength import (
    analyze,
    character_classes,
    common_password_match,
    find_keyboard_walks,
    find_repeats,
    find_sequences,
)


def kinds(password):
    return {f.kind for f in analyze(password).findings}


class CharacterClassTests(unittest.TestCase):
    def test_detects_each_class(self):
        self.assertEqual(character_classes("aB3$"), ["lowercase", "uppercase", "digits", "symbols"])
        self.assertEqual(character_classes("abc"), ["lowercase"])
        self.assertEqual(character_classes("a b"), ["lowercase", "symbols"])


class PatternTests(unittest.TestCase):
    def test_ascending_and_descending_sequences(self):
        self.assertEqual(find_sequences("xx123yy"), [(2, 5)])
        self.assertEqual(find_sequences("987"), [(0, 3)])
        self.assertEqual(find_sequences("helloABCD"), [(5, 9)])

    def test_two_char_run_is_not_a_sequence(self):
        self.assertEqual(find_sequences("a12b"), [])

    def test_sequence_does_not_cross_letters_and_digits(self):
        # '9' -> ':' is +1 in ASCII but not a meaningful sequence.
        self.assertEqual(find_sequences("89:"), [])

    def test_keyboard_walks(self):
        self.assertTrue(find_keyboard_walks("myqwertypass"))
        self.assertTrue(find_keyboard_walks("ASDF"))
        self.assertTrue(find_keyboard_walks("poiuy"))  # reversed row
        self.assertTrue(find_keyboard_walks("1qaz2wsx"))  # column walk
        self.assertEqual(find_keyboard_walks("qwe"), [])  # too short
        self.assertEqual(find_keyboard_walks("horse"), [])

    def test_keyboard_walk_span_is_greedy(self):
        self.assertEqual(find_keyboard_walks("xqwertyuiox"), [(1, 10)])

    def test_repeats(self):
        self.assertTrue(find_repeats("baaab"))
        self.assertTrue(find_repeats("abcabc"))
        self.assertEqual(find_repeats("aab"), [])


class CommonPasswordTests(unittest.TestCase):
    def test_exact_match_is_case_insensitive(self):
        self.assertEqual(common_password_match("password"), "common")
        self.assertEqual(common_password_match("PASSWORD"), "common")

    def test_decorated_variants(self):
        self.assertEqual(common_password_match("Password123!"), "common-variant")
        self.assertEqual(common_password_match("dragon2024"), "common-variant")
        self.assertEqual(common_password_match("m0nk3y"), "common-variant")
        self.assertEqual(common_password_match("!!sunshine"), "common-variant")

    def test_uncommon_password(self):
        self.assertIsNone(common_password_match("vortex-lantern-quill"))


class ScoringTests(unittest.TestCase):
    def test_common_password_scores_zero(self):
        report = analyze("123456")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.label, "Very weak")
        self.assertTrue(report.is_common)

    def test_common_variant_is_capped(self):
        self.assertLessEqual(analyze("Password123!").score, 15)

    def test_short_password_is_capped(self):
        report = analyze("Xy7$")
        self.assertLessEqual(report.score, 30)
        self.assertIn("short", kinds("Xy7$"))

    def test_single_character_class_is_flagged(self):
        self.assertIn("variety", kinds("lowercaseonly"))

    def test_patterns_reduce_score(self):
        plain = analyze("Gk7$vRm2Lp9!").score
        walky = analyze("Gk7$qwerty9!").score
        self.assertLess(walky, plain)

    def test_year_is_flagged(self):
        self.assertIn("year", kinds("Rocket1987xx"))

    def test_strong_random_password(self):
        report = analyze("xK9#mQ2$vL7pR4!w")
        self.assertGreaterEqual(report.score, 80)
        self.assertEqual(report.label, "Very strong")
        self.assertEqual(report.findings, [])

    def test_long_passphrase_is_strong(self):
        report = analyze("correct horse battery staple")
        self.assertGreaterEqual(report.score, 80)

    def test_score_is_monotonic_with_length(self):
        self.assertLess(analyze("Gk7$vRm2").score, analyze("Gk7$vRm2Lp9!Wd").score)

    def test_score_bounds(self):
        for pw in ["", "a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Zq8!" * 20]:
            score = analyze(pw).score
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)

    def test_advice_always_present(self):
        self.assertTrue(analyze("password").advice)
        self.assertTrue(analyze("xK9#mQ2$vL7pR4!w").advice)

    def test_weak_password_gets_passphrase_advice(self):
        self.assertTrue(any("passphrase" in tip for tip in analyze("qwerty12").advice))

    def test_unicode_password(self):
        report = analyze("Ünïcødé-Pässwörd-✓")
        self.assertIn("symbols", report.char_classes)
        self.assertGreater(report.score, 60)


if __name__ == "__main__":
    unittest.main()

"""
Unit test suite for Password Strength Analyzer, Generator, and Cryptographic DB.
Run with: `python -m unittest discover -s tests`
"""

import os
import tempfile
import unittest
from src.analyzer import PasswordAnalyzer
from src.generator import PasswordGenerator
from src.database import PasswordHistoryDB


class TestPasswordStrengthAnalyzer(unittest.TestCase):

    def test_common_weak_password(self):
        result = PasswordAnalyzer.analyze("password123")
        self.assertLessEqual(result.score, 20)
        self.assertEqual(result.rating, "Very Weak")
        self.assertTrue(any("dictionary" in v.lower() for v in result.vulnerabilities))

    def test_short_password(self):
        result = PasswordAnalyzer.analyze("Ab1!")
        self.assertLess(result.score, 40)
        self.assertTrue(any("short" in v.lower() for v in result.vulnerabilities))

    def test_strong_password(self):
        result = PasswordAnalyzer.analyze("K9#mP2$vL8@nQ5!zR4")
        self.assertGreaterEqual(result.score, 85)
        self.assertEqual(result.rating, "Very Strong")
        self.assertTrue(result.has_lowercase)
        self.assertTrue(result.has_uppercase)
        self.assertTrue(result.has_digits)
        self.assertTrue(result.has_special)

    def test_sequence_detection(self):
        result = PasswordAnalyzer.analyze("Qwerty123!@#")
        self.assertTrue(any("sequential" in v.lower() for v in result.vulnerabilities))

    def test_generator_produces_strong_passwords(self):
        random_pw = PasswordGenerator.generate_random_password(18)
        self.assertEqual(len(random_pw), 18)
        res = PasswordAnalyzer.analyze(random_pw)
        self.assertGreaterEqual(res.score, 80)

    def test_database_salted_hash_and_reuse_prevention(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        try:
            db = PasswordHistoryDB(db_path)
            strong_pw = "Vanguard#Solar92! Prism"
            analysis = PasswordAnalyzer.analyze(strong_pw)

            # First registration should succeed
            ok1, msg1 = db.store_password("alice", strong_pw, analysis.pool_entropy_bits, analysis.score)
            self.assertTrue(ok1, msg1)

            # Reusing the exact same password for 'alice' must be blocked
            ok2, msg2 = db.store_password("alice", strong_pw, analysis.pool_entropy_bits, analysis.score)
            self.assertFalse(ok2)
            self.assertIn("reuse prevented", msg2.lower())

            # Different user 'bob' can still use it because salts & user scopes are isolated
            ok3, _ = db.store_password("bob", strong_pw, analysis.pool_entropy_bits, analysis.score)
            self.assertTrue(ok3)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)


if __name__ == "__main__":
    unittest.main()

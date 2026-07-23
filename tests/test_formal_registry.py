"""
Unit tests for formal-verifier auto-discovery. Only the registry wiring is
tested (which verifier names are discovered, ABC contract, unknown-name error).
The live solc/SMT verify path is NOT run.
"""

import unittest

from hawki.core.formal.base import Verifier
from hawki.core.formal.registry import get_verifier, list_verifiers


class TestFormalRegistry(unittest.TestCase):
    def test_builtin_verifiers_discovered(self):
        names = list_verifiers()
        # Filename-derived keys (module name lowered, underscores removed).
        self.assertIn("smtchecker", names)
        self.assertIn("hevm", names)

    def test_get_verifier_returns_instance(self):
        v = get_verifier("smtchecker")
        self.assertIsInstance(v, Verifier)
        # The engine value used on the CLI must resolve to a Verifier subclass.
        self.assertTrue(hasattr(v, "verify"))

    def test_unknown_verifier_raises(self):
        with self.assertRaises(ValueError):
            get_verifier("nonexistent-engine")


if __name__ == "__main__":
    unittest.main()

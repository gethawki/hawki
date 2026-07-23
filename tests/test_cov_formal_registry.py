# File: tests/test_cov_formal_registry.py
"""
Extra coverage for the formal-verifier registry: the lazy-discovery branch in
get_verifier/list_verifiers (empty cache triggers _discover) and the Verifier
ABC contract. Complements tests/test_formal_registry.py without duplicating it.
"""

import unittest
from pathlib import Path

from hawki.core.formal import registry
from hawki.core.formal.base import Verifier
from hawki.core.formal.smtchecker import SMTCheckerVerifier


class TestRegistryLazyDiscovery(unittest.TestCase):
    def setUp(self):
        # Snapshot and clear the module-level cache so the lazy _discover()
        # branch in get_verifier/list_verifiers is exercised, then restore.
        self._saved = dict(registry._VERIFIERS)
        registry._VERIFIERS.clear()
        self.addCleanup(lambda: registry._VERIFIERS.update(self._saved))

    def test_list_verifiers_triggers_discovery(self):
        registry._VERIFIERS.clear()
        names = registry.list_verifiers()
        self.assertIn("smtchecker", names)

    def test_get_verifier_triggers_discovery(self):
        registry._VERIFIERS.clear()
        v = registry.get_verifier("smtchecker")
        self.assertIsInstance(v, SMTCheckerVerifier)

    def test_unknown_lists_available_in_message(self):
        registry._VERIFIERS.clear()
        with self.assertRaises(ValueError) as ctx:
            registry.get_verifier("does-not-exist")
        self.assertIn("Available", str(ctx.exception))


class TestVerifierABC(unittest.TestCase):
    def test_cannot_instantiate_abstract(self):
        with self.assertRaises(TypeError):
            Verifier()

    def test_subclass_must_implement_verify(self):
        class Incomplete(Verifier):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_concrete_subclass_ok(self):
        class Concrete(Verifier):
            def verify(self, source_path: Path, contract_name: str = None):
                return []

        self.assertEqual(Concrete().verify(Path("x")), [])


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for RulePlanner: it drains attack scripts from a directory, skips
already-attempted signatures (unless force), and returns None when exhausted.
Uses a temp scripts dir and a fake in-memory store, so nothing hits the real
attack_scripts directory or any external service.
"""

import tempfile
import unittest
from pathlib import Path

from hawki.core.deep.planner.rule_planner import RulePlanner


class _FakeMemory:
    def __init__(self, attempted=None):
        self._attempted = set(attempted or [])

    def has_attempted(self, sig):
        return sig in self._attempted


class TestRulePlanner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        # Two real attack scripts plus an __init__.py that must be excluded.
        (self.dir / "reentrancy_attack.py").write_text("# attack\n")
        (self.dir / "overflow_attack.py").write_text("# attack\n")
        (self.dir / "__init__.py").write_text("")

    def tearDown(self):
        self.tmp.cleanup()

    def test_discovers_scripts_excluding_init(self):
        planner = RulePlanner(attack_scripts_dir=self.dir)
        names = {p.name for p in planner._script_paths}
        self.assertEqual(names, {"reentrancy_attack.py", "overflow_attack.py"})

    def test_next_attack_returns_unattempted(self):
        planner = RulePlanner(attack_scripts_dir=self.dir)
        plan = planner.next_attack(_FakeMemory(), goal="drain")
        self.assertIsNotNone(plan)
        self.assertEqual(plan.type, "rule")
        # The signature is the script filename (matches the memory dedupe key).
        self.assertTrue(plan.signature.endswith(".py"))
        self.assertIn(plan.rule_name, {"reentrancy_attack", "overflow_attack"})

    def test_skips_already_attempted(self):
        planner = RulePlanner(attack_scripts_dir=self.dir)
        # Mark every script as attempted -> planner is exhausted.
        sigs = [planner._generate_signature(p) for p in planner._script_paths]
        plan = planner.next_attack(_FakeMemory(attempted=sigs), goal="drain")
        self.assertIsNone(plan)

    def test_force_ignores_memory(self):
        planner = RulePlanner(attack_scripts_dir=self.dir)
        sigs = [planner._generate_signature(p) for p in planner._script_paths]
        plan = planner.next_attack(_FakeMemory(attempted=sigs), goal="drain", force=True)
        self.assertIsNotNone(plan)

    def test_missing_dir_yields_no_scripts(self):
        planner = RulePlanner(attack_scripts_dir=self.dir / "does_not_exist")
        self.assertEqual(planner._script_paths, [])
        self.assertIsNone(planner.next_attack(_FakeMemory(), goal="drain"))


if __name__ == "__main__":
    unittest.main()

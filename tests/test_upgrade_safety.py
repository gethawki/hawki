"""
Unit tests for upgrade-safety analysis. The storage-layout parser and
collision comparator are exercised directly (no solc). The end-to-end
check_upgrade_safety is exercised with the solc subprocess mocked out, so only
the pure regex-based proxy/initializer detection runs.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hawki.core.upgrade import safety
from hawki.core.upgrade.safety import (
    _base_name,
    _compare_layouts,
    _parse_storage_layouts,
    check_upgrade_safety,
)

# solc --storage-layout text output. Each contract's JSON must be on a single
# line, matching the compiler's actual layout format.
_LAYOUT_V1 = (
    "======= src/Logic.sol:LogicV1 =======\n"
    "Contract Storage Layout:\n"
    '{"storage": [{"slot": "0", "offset": 0, "type": "t_uint256", "label": "count"}], "types": {}}\n'
)
_LAYOUT_V2 = (
    "======= src/Logic.sol:LogicV2 =======\n"
    "Contract Storage Layout:\n"
    '{"storage": [{"slot": "0", "offset": 0, "type": "t_address", "label": "owner"}], "types": {}}\n'
)


class TestBaseName(unittest.TestCase):
    def test_version_stripping(self):
        self.assertEqual(_base_name("LogicV1"), "Logic")
        self.assertEqual(_base_name("LogicV2"), "Logic")
        self.assertEqual(_base_name("Vault"), "Vault")


class TestParseStorageLayouts(unittest.TestCase):
    def test_parses_slots(self):
        layouts = _parse_storage_layouts(_LAYOUT_V1)
        self.assertIn("LogicV1", layouts)
        slots = layouts["LogicV1"]["slots"]
        self.assertIn(0, slots)
        offset, var_type, label = slots[0][0]
        self.assertEqual((offset, var_type, label), (0, "t_uint256", "count"))

    def test_empty_output(self):
        self.assertEqual(_parse_storage_layouts(""), {})


class TestCompareLayouts(unittest.TestCase):
    def test_detects_slot_type_collision(self):
        layouts = _parse_storage_layouts(_LAYOUT_V1 + _LAYOUT_V2)
        findings = _compare_layouts(
            "LogicV1", layouts["LogicV1"], "LogicV2", layouts["LogicV2"]
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "High")
        self.assertIn("collision", findings[0]["title"].lower())

    def test_no_collision_when_identical(self):
        layouts = _parse_storage_layouts(_LAYOUT_V1 + _LAYOUT_V1.replace("LogicV1", "LogicV3"))
        findings = _compare_layouts(
            "LogicV1", layouts["LogicV1"], "LogicV3", layouts["LogicV3"]
        )
        self.assertEqual(findings, [])


class TestCheckUpgradeSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        # Patch out solc so only regex heuristics run (deterministic, offline).
        patcher = mock.patch.object(safety, "_run_storage_layout", return_value="")
        self.addCleanup(patcher.stop)
        patcher.start()

    def tearDown(self):
        self.tmp.cleanup()

    def test_detects_transparent_proxy(self):
        (self.repo / "Proxy.sol").write_text(
            "contract Proxy {\n"
            "    function upgradeTo(address newImpl) public {}\n"
            "}\n"
        )
        findings = check_upgrade_safety(self.repo)
        self.assertTrue(any("proxy pattern" in f["title"].lower() for f in findings))

    def test_detects_missing_initializer(self):
        (self.repo / "Vault.sol").write_text(
            "contract Vault is Initializable {\n"
            "    uint256 public x;\n"
            "}\n"
        )
        findings = check_upgrade_safety(self.repo)
        crit = [f for f in findings if f["severity"] == "Critical"]
        self.assertTrue(any("initializer" in f["title"].lower() for f in crit))

    def test_no_sol_files(self):
        self.assertEqual(check_upgrade_safety(self.repo), [])


if __name__ == "__main__":
    unittest.main()

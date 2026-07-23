# File: tests/test_cov_upgrade_safety.py
"""
Coverage for core.upgrade.safety: solc discovery (_find_solc), the
_run_storage_layout subprocess wrapper (mocked), storage-layout parse error
branches, the __gap heuristic, and the storage-layout-driven proxy/versioned
collision findings inside check_upgrade_safety (solc output mocked).
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hawki.core.upgrade import safety
from hawki.core.upgrade.safety import (
    _find_solc,
    _parse_storage_layouts,
    _run_storage_layout,
    check_upgrade_safety,
)


class TestFindSolc(unittest.TestCase):
    def test_found_on_path(self):
        with mock.patch.object(safety.shutil, "which", return_value="/usr/bin/solc"):
            self.assertEqual(_find_solc(), "/usr/bin/solc")

    def test_fallback_next_to_interpreter(self):
        with mock.patch.object(safety.shutil, "which", return_value=None):
            with mock.patch.object(safety.Path, "exists", return_value=True):
                with mock.patch.object(safety.os, "access", return_value=True):
                    result = _find_solc()
                    self.assertTrue(result.endswith("solc"))

    def test_not_found_anywhere(self):
        with mock.patch.object(safety.shutil, "which", return_value=None):
            with mock.patch.object(safety.Path, "exists", return_value=False):
                self.assertIsNone(_find_solc())


class TestRunStorageLayout(unittest.TestCase):
    def test_returns_empty_when_solc_missing(self):
        with mock.patch.object(safety, "_find_solc", return_value=None):
            self.assertEqual(_run_storage_layout([Path("a.sol")]), "")

    def test_returns_stdout_on_success(self):
        fake = mock.MagicMock()
        fake.returncode = 0
        fake.stdout = "LAYOUT"
        fake.stderr = ""
        with mock.patch.object(safety, "_find_solc", return_value="/usr/bin/solc"):
            with mock.patch.object(safety.subprocess, "run", return_value=fake):
                self.assertEqual(_run_storage_layout([Path("a.sol")]), "LAYOUT")

    def test_nonzero_returncode_still_returns_stdout(self):
        fake = mock.MagicMock()
        fake.returncode = 1
        fake.stdout = "LAYOUT_WITH_WARNINGS"
        fake.stderr = "warning: x"
        with mock.patch.object(safety, "_find_solc", return_value="/usr/bin/solc"):
            with mock.patch.object(safety.subprocess, "run", return_value=fake):
                self.assertEqual(_run_storage_layout([Path("a.sol")]), "LAYOUT_WITH_WARNINGS")

    def test_subprocess_exception_returns_empty(self):
        with mock.patch.object(safety, "_find_solc", return_value="/usr/bin/solc"):
            with mock.patch.object(safety.subprocess, "run", side_effect=OSError("boom")):
                self.assertEqual(_run_storage_layout([Path("a.sol")]), "")


class TestParseStorageLayoutsErrors(unittest.TestCase):
    def test_bad_json_section_skipped(self):
        out = (
            "======= src/A.sol:A =======\n"
            "Contract Storage Layout:\n"
            "{not valid json\n"
        )
        self.assertEqual(_parse_storage_layouts(out), {})

    def test_entry_missing_slot_skipped(self):
        out = (
            "======= src/A.sol:A =======\n"
            "Contract Storage Layout:\n"
            '{"storage": [{"offset": 0, "type": "t_uint256", "label": "x"}], "types": {}}\n'
        )
        layouts = _parse_storage_layouts(out)
        self.assertIn("A", layouts)
        self.assertEqual(layouts["A"]["slots"], {})


class TestGapHeuristic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.object(safety, "_run_storage_layout", return_value="")
        p.start()
        self.addCleanup(p.stop)

    def test_variable_after_gap_flagged(self):
        (self.repo / "Gapped.sol").write_text(
            "contract Gapped {\n"
            "    uint256[50] private __gap;\n"
            "    address newVar;\n"
            "}\n"
        )
        findings = check_upgrade_safety(self.repo)
        self.assertTrue(any("__gap" in f["title"] for f in findings))

    def test_gap_without_trailing_var_ok(self):
        (self.repo / "Gapped.sol").write_text(
            "contract Gapped {\n"
            "    address firstVar;\n"
            "    uint256[50] private __gap;\n"
            "}\n"
        )
        findings = check_upgrade_safety(self.repo)
        self.assertFalse(any("__gap" in f["title"] for f in findings))

    def test_unreadable_file_is_skipped(self):
        # Non-UTF8 bytes make read_text(encoding='utf-8') raise; the loop should
        # swallow it and continue rather than crash.
        (self.repo / "Bad.sol").write_bytes(b"\xff\xfe contract X { function f() external {} }")
        # Should not raise.
        self.assertIsInstance(check_upgrade_safety(self.repo), list)


class TestStorageLayoutFindings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_proxy_with_own_slots_flagged(self):
        (self.repo / "MyProxy.sol").write_text(
            "contract MyProxy {\n"
            "    function upgradeTo(address n) public {}\n"
            "    address owner;\n"
            "}\n"
        )
        layout = (
            "======= MyProxy.sol:MyProxy =======\n"
            "Contract Storage Layout:\n"
            '{"storage": [{"slot": "0", "offset": 0, "type": "t_address", "label": "owner"}], "types": {}}\n'
        )
        with mock.patch.object(safety, "_run_storage_layout", return_value=layout):
            findings = check_upgrade_safety(self.repo)
        self.assertTrue(
            any("proxy" in f["title"].lower() and "state variables" in f["title"].lower()
                for f in findings)
        )

    def test_empty_slot_contract_not_flagged_as_proxy(self):
        (self.repo / "SafeProxy.sol").write_text(
            "contract SafeProxy {\n"
            "    function upgradeTo(address n) public {}\n"
            "}\n"
        )
        # Layout reports the proxy but with no occupied slots (EIP-1967 style),
        # exercising the empty-slots continue branch.
        layout = (
            "======= SafeProxy.sol:SafeProxy =======\n"
            "Contract Storage Layout:\n"
            '{"storage": [], "types": {}}\n'
        )
        with mock.patch.object(safety, "_run_storage_layout", return_value=layout):
            findings = check_upgrade_safety(self.repo)
        self.assertFalse(
            any("declares state variables" in f["title"] for f in findings)
        )

    def test_versioned_collision_via_full_flow(self):
        (self.repo / "Logic.sol").write_text("contract LogicV1 {}\ncontract LogicV2 {}\n")
        layout = (
            "======= src/Logic.sol:LogicV1 =======\n"
            "Contract Storage Layout:\n"
            '{"storage": [{"slot": "0", "offset": 0, "type": "t_uint256", "label": "count"}], "types": {}}\n'
            "======= src/Logic.sol:LogicV2 =======\n"
            "Contract Storage Layout:\n"
            '{"storage": [{"slot": "0", "offset": 0, "type": "t_address", "label": "owner"}], "types": {}}\n'
        )
        with mock.patch.object(safety, "_run_storage_layout", return_value=layout):
            findings = check_upgrade_safety(self.repo)
        self.assertTrue(
            any("collision between" in f["title"].lower() for f in findings)
        )


if __name__ == "__main__":
    unittest.main()

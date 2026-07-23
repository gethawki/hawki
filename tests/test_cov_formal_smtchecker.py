# File: tests/test_cov_formal_smtchecker.py
"""
Coverage tests for the built-in SMTChecker verifier. The live solc subprocess
is fully mocked: we feed canned solc stdout/stderr and assert the parsed
findings, severities and line numbers. No solc binary is ever executed.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hawki.core.formal import smtchecker as smt
from hawki.core.formal.smtchecker import SMTCheckerVerifier


def _proc(stdout="", stderr="", returncode=0):
    m = mock.MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


class TestSMTCheckerNoSolc(unittest.TestCase):
    def test_solc_not_found_returns_info(self):
        with mock.patch.object(smt, "_find_solc", return_value=None):
            findings = SMTCheckerVerifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "solc not found")
        self.assertEqual(findings[0]["severity"], "Info")


class TestSMTCheckerParsing(unittest.TestCase):
    def setUp(self):
        self.solc_patch = mock.patch.object(smt, "_find_solc", return_value="/usr/bin/solc")
        self.solc_patch.start()
        self.addCleanup(self.solc_patch.stop)

    def _run(self, stdout="", stderr=""):
        with mock.patch.object(smt.subprocess, "run", return_value=_proc(stdout, stderr)):
            return SMTCheckerVerifier().verify(Path("/tmp/x.sol"))

    def test_assertion_warning_high_with_line(self):
        out = (
            "Warning: CHC: Assertion violation happens here.\n"
            " --> test.sol:12:5:\n"
            "   |\n"
            "12 |     assert(x > 0);\n"
        )
        findings = self._run(stdout=out)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["line"], 12)
        self.assertTrue(findings[0]["title"].startswith("SMTChecker:"))

    def test_overflow_warning_medium(self):
        out = (
            "Warning: CHC: Overflow (resulting value larger than max) happens here.\n"
            " --> test.sol:8:9:\n"
        )
        findings = self._run(stdout=out)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")
        self.assertEqual(findings[0]["line"], 8)

    def test_error_header_and_pop_low(self):
        # An "Error:" header for a pop-on-empty-array target -> Low severity.
        out = "Error: CHC: Empty array \"pop\" detected here.\n --> a.sol:3:1:\n"
        findings = self._run(stdout=out)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Low")
        self.assertEqual(findings[0]["line"], 3)

    def test_non_safety_warning_skipped(self):
        out = "Warning: SPDX license identifier not provided in source file.\n"
        findings = self._run(stdout=out)
        self.assertEqual(findings, [])

    def test_warning_without_location_line_zero(self):
        out = "Warning: CHC: Assertion violation might happen.\n(no pointer)\n"
        findings = self._run(stdout=out)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 0)

    def test_multiple_warnings(self):
        out = (
            "Warning: CHC: Assertion violation happens here.\n --> a.sol:1:1:\n"
            "Warning: CHC: Underflow happens here.\n --> a.sol:2:1:\n"
        )
        findings = self._run(stdout=out)
        self.assertEqual(len(findings), 2)
        sevs = {f["severity"] for f in findings}
        self.assertEqual(sevs, {"High", "Medium"})

    def test_no_solver_marker(self):
        err = "Warning: CHC analysis was not possible since no Horn solver was found.\n"
        findings = self._run(stderr=err)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "SMTChecker solver unavailable")

    def test_timeout_returns_info(self):
        with mock.patch.object(
            smt.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="solc", timeout=180),
        ):
            findings = SMTCheckerVerifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "SMTChecker timeout")

    def test_z3_lib_dir_added_to_env(self):
        # When a z3 lib dir is found, it is prepended to LD_LIBRARY_PATH passed
        # to the subprocess. Capture the env and assert.
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs.get("env", {}))
            return _proc(stdout="")

        with mock.patch.object(smt, "_z3_lib_dir", return_value="/fake/z3/lib"), \
             mock.patch.dict(os.environ, {"LD_LIBRARY_PATH": "/pre"}), \
             mock.patch.object(smt.subprocess, "run", side_effect=fake_run):
            SMTCheckerVerifier().verify(Path("/tmp/x.sol"))
        self.assertIn("/fake/z3/lib", captured["LD_LIBRARY_PATH"])
        self.assertIn("/pre", captured["LD_LIBRARY_PATH"])


class TestSMTCheckerHelpers(unittest.TestCase):
    def test_find_solc_from_path(self):
        with mock.patch.object(smt.shutil, "which", return_value="/usr/bin/solc"):
            self.assertEqual(smt._find_solc(), "/usr/bin/solc")

    def test_find_solc_next_to_interpreter(self):
        with tempfile.TemporaryDirectory() as d:
            fake_solc = Path(d) / "solc"
            fake_solc.write_text("#!/bin/sh\n")
            fake_solc.chmod(fake_solc.stat().st_mode | stat.S_IXUSR)
            fake_python = Path(d) / "python"
            with mock.patch.object(smt.shutil, "which", return_value=None), \
                 mock.patch.object(smt.sys, "executable", str(fake_python)):
                self.assertEqual(smt._find_solc(), str(fake_solc))

    def test_find_solc_none(self):
        with tempfile.TemporaryDirectory() as d:
            fake_python = Path(d) / "python"  # no solc sibling exists
            with mock.patch.object(smt.shutil, "which", return_value=None), \
                 mock.patch.object(smt.sys, "executable", str(fake_python)):
                self.assertIsNone(smt._find_solc())

    def test_z3_lib_dir_returns_str_or_none(self):
        result = smt._z3_lib_dir()
        self.assertTrue(result is None or isinstance(result, str))


if __name__ == "__main__":
    unittest.main()

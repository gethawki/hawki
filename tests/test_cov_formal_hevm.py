# File: tests/test_cov_formal_hevm.py
"""
Coverage tests for the optional hevm verifier. Both the "hevm not installed"
warning path and the full symbolic-execution path are exercised with solc/hevm
fully mocked (shutil.which + subprocess.run). No real binaries are invoked.
"""

import unittest
from pathlib import Path
from unittest import mock

from hawki.core.formal import hevm as hevm_mod
from hawki.core.formal.hevm import HevmVerifier


def _proc(stdout="", stderr="", returncode=0):
    m = mock.MagicMock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


class TestHevmNotInstalled(unittest.TestCase):
    def test_not_installed_emits_info(self):
        with mock.patch.object(hevm_mod.shutil, "which", return_value=None):
            findings = HevmVerifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "hevm not installed")
        self.assertEqual(findings[0]["severity"], "Info")


class TestHevmAvailable(unittest.TestCase):
    def _verifier(self):
        # Force availability regardless of the host having hevm.
        with mock.patch.object(hevm_mod.shutil, "which", return_value="/usr/bin/hevm"):
            v = HevmVerifier()
        v.available = True
        return v

    def test_compilation_failure(self):
        with mock.patch.object(hevm_mod, "_find_solc", return_value="/usr/bin/solc"), \
             mock.patch.object(hevm_mod.subprocess, "run",
                               return_value=_proc(stderr="boom", returncode=1)):
            findings = self._verifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(findings[0]["title"], "Compilation failed for hevm")

    def test_no_bytecode_extracted(self):
        with mock.patch.object(hevm_mod, "_find_solc", return_value="/usr/bin/solc"), \
             mock.patch.object(hevm_mod.subprocess, "run",
                               return_value=_proc(stdout="no binary section here")):
            findings = self._verifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(findings[0]["title"], "No bytecode found")

    def test_counterexample_high(self):
        compile_proc = _proc(stdout="Binary: 60016002")
        hevm_proc = _proc(stdout="Found a counterexample!")
        with mock.patch.object(hevm_mod, "_find_solc", return_value="/usr/bin/solc"), \
             mock.patch.object(hevm_mod.subprocess, "run",
                               side_effect=[compile_proc, hevm_proc]):
            findings = self._verifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Hevm found counterexample")
        self.assertEqual(findings[0]["severity"], "High")

    def test_all_proved_no_findings(self):
        compile_proc = _proc(stdout="Binary: 60016002")
        hevm_proc = _proc(stdout="All assertions proved safe")
        with mock.patch.object(hevm_mod, "_find_solc", return_value="/usr/bin/solc"), \
             mock.patch.object(hevm_mod.subprocess, "run",
                               side_effect=[compile_proc, hevm_proc]):
            findings = self._verifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(findings, [])

    def test_incomplete_analysis(self):
        compile_proc = _proc(stdout="Binary: 60016002")
        hevm_proc = _proc(stdout="ran out of gas or something")
        with mock.patch.object(hevm_mod, "_find_solc", return_value="/usr/bin/solc"), \
             mock.patch.object(hevm_mod.subprocess, "run",
                               side_effect=[compile_proc, hevm_proc]):
            findings = self._verifier().verify(Path("/tmp/x.sol"))
        self.assertEqual(findings[0]["title"], "Hevm analysis incomplete")


class TestHevmFindSolc(unittest.TestCase):
    def test_find_solc_from_path(self):
        with mock.patch.object(hevm_mod.shutil, "which", return_value="/usr/bin/solc"):
            self.assertEqual(hevm_mod._find_solc(), "/usr/bin/solc")

    def test_find_solc_none(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            fake_python = Path(d) / "python"
            with mock.patch.object(hevm_mod.shutil, "which", return_value=None), \
                 mock.patch.object(hevm_mod.sys, "executable", str(fake_python)):
                self.assertIsNone(hevm_mod._find_solc())


if __name__ == "__main__":
    unittest.main()

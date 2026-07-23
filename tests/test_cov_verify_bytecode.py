# File: tests/test_cov_verify_bytecode.py
"""
Coverage for core.verify.bytecode: the end-to-end verify_bytecode() flow with
web3 + solc fully mocked (no network, no compiler), plus the metadata-strip
fallback/error branches not hit by the existing pure-helper tests.
"""

import unittest
from pathlib import Path
from unittest import mock

from hawki.core.verify import bytecode as bc


class TestStripMetadataBranches(unittest.TestCase):
    def test_nonhex_length_bytes_returns_normalized(self):
        # Last 4 chars are not valid hex -> int() ValueError -> meta_len = -1,
        # and the 53-byte fallback does not apply, so the input is returned as-is.
        self.assertEqual(bc._strip_metadata("6080zzzz"), "6080zzzz")

    def test_fixed_53_byte_fallback(self):
        # Implausible length bytes (ffff) skip the length-aware branch, but the
        # 106-hex tail starting with "a264" triggers the fixed-block fallback.
        code = "60" * 30  # 60 hex chars of runtime code
        tail = "a264" + ("00" * 49) + "ffff"  # 4 + 98 + 4 = 106 hex chars
        self.assertEqual(len(tail), 106)
        stripped = bc._strip_metadata(code + tail)
        self.assertEqual(stripped, code)


def _fake_web3(is_connected=True, code_hex="0x6080604052"):
    """Build a MagicMock standing in for the Web3 class the module imports."""
    web3_cls = mock.MagicMock(name="Web3")
    inst = web3_cls.return_value
    inst.is_connected.return_value = is_connected
    web3_cls.to_checksum_address.side_effect = lambda a: a
    code_obj = mock.MagicMock()
    code_obj.hex.return_value = code_hex
    inst.eth.get_code.return_value = code_obj
    return web3_cls, inst


class TestVerifyBytecode(unittest.TestCase):
    def _patch(self, web3_cls, compiled=None, compile_exc=None):
        patches = [
            mock.patch.object(bc, "Web3", web3_cls),
            mock.patch.object(bc, "geth_poa_middleware", mock.MagicMock()),
        ]
        if compile_exc is not None:
            patches.append(mock.patch.object(bc, "_compile_source", side_effect=compile_exc))
        else:
            patches.append(mock.patch.object(bc, "_compile_source", return_value=compiled or {}))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_cannot_connect(self):
        web3_cls, _ = _fake_web3(is_connected=False)
        self._patch(web3_cls)
        res = bc.verify_bytecode("0xabc", "http://rpc", Path("/tmp"))
        self.assertFalse(res["success"])
        self.assertIn("Cannot connect", res["error"])

    def test_no_bytecode_at_address(self):
        web3_cls, _ = _fake_web3(code_hex="0x")
        self._patch(web3_cls, compiled={"X:Y": "6080"})
        res = bc.verify_bytecode("0xabc", "http://rpc", Path("/tmp"))
        self.assertIn("No bytecode found", res["error"])

    def test_no_compiled_bytecode(self):
        web3_cls, _ = _fake_web3()
        self._patch(web3_cls, compiled={})
        res = bc.verify_bytecode("0xabc", "http://rpc", Path("/tmp"))
        self.assertIn("No runtime bytecode", res["error"])

    def test_single_contract_autopick_match(self):
        onchain = "0x6080604052"
        web3_cls, _ = _fake_web3(code_hex=onchain)
        self._patch(web3_cls, compiled={"src/A.sol:A": "6080604052"})
        res = bc.verify_bytecode("0xabc", "http://rpc", Path("/tmp"), ignore_metadata=False)
        self.assertTrue(res["success"])
        self.assertTrue(res["match"])
        self.assertEqual(res["compiled"]["name"], "src/A.sol:A")

    def test_named_contract_mismatch(self):
        web3_cls, _ = _fake_web3(code_hex="0x6080604052")
        self._patch(web3_cls, compiled={"src/A.sol:A": "deadbeef"})
        res = bc.verify_bytecode(
            "0xabc", "http://rpc", Path("/tmp"), ignore_metadata=False, contract_name="A"
        )
        self.assertTrue(res["success"])
        self.assertFalse(res["match"])
        self.assertIn("Mismatch", res["diff_summary"])

    def test_named_contract_not_found(self):
        web3_cls, _ = _fake_web3()
        self._patch(web3_cls, compiled={"src/A.sol:A": "6080"})
        res = bc.verify_bytecode(
            "0xabc", "http://rpc", Path("/tmp"), contract_name="Nope"
        )
        self.assertIn("not found", res["error"])

    def test_multiple_contracts_without_name(self):
        web3_cls, _ = _fake_web3()
        self._patch(web3_cls, compiled={"a:A": "6080", "b:B": "6081"})
        res = bc.verify_bytecode("0xabc", "http://rpc", Path("/tmp"))
        self.assertIn("Multiple contracts", res["error"])

    def test_poa_middleware_inject_failure_is_ignored(self):
        onchain = "0x6080604052"
        web3_cls, inst = _fake_web3(code_hex=onchain)
        inst.middleware_onion.inject.side_effect = Exception("no middleware")
        self._patch(web3_cls, compiled={"src/A.sol:A": "6080604052"})
        res = bc.verify_bytecode("0xabc", "http://rpc", Path("/tmp"), ignore_metadata=False)
        # Inject failure is swallowed; verification still proceeds.
        self.assertTrue(res["success"])

    def test_exception_is_captured(self):
        web3_cls, inst = _fake_web3()
        inst.eth.get_code.side_effect = RuntimeError("boom")
        self._patch(web3_cls, compiled={"a:A": "6080"})
        res = bc.verify_bytecode("0xabc", "http://rpc", Path("/tmp"))
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "boom")


class TestCompileSource(unittest.TestCase):
    def test_no_sol_files_raises(self):
        with self.assertRaises(ValueError):
            bc._compile_source(Path("/nonexistent-hawki-dir-xyz"))

    def test_compile_parses_combined_json(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            (src / "A.sol").write_text("contract A {}")
            fake = mock.MagicMock()
            fake.returncode = 0
            fake.stdout = json.dumps({"contracts": {"A.sol:A": {"bin-runtime": "6080"}}})
            with mock.patch.object(bc.subprocess, "run", return_value=fake):
                out = bc._compile_source(src)
            self.assertEqual(out, {"A.sol:A": "6080"})

    def test_compile_failure_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            (src / "A.sol").write_text("contract A {}")
            fake = mock.MagicMock()
            fake.returncode = 1
            fake.stderr = "syntax error"
            with mock.patch.object(bc.subprocess, "run", return_value=fake):
                with self.assertRaises(RuntimeError):
                    bc._compile_source(src)


if __name__ == "__main__":
    unittest.main()

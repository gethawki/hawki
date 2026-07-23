"""
Unit tests for the pure bytecode comparison helpers in core.verify.bytecode:
normalization, CBOR metadata stripping, and the match/mismatch summary. The
live RPC + solc path (verify_bytecode) is intentionally NOT exercised.
"""

import unittest

from hawki.core.verify.bytecode import _normalize, _strip_metadata, compare_bytecode

# Runtime code followed by a well-formed CBOR metadata tail. The last two bytes
# ("0004") encode a 4-byte metadata block that begins with the CBOR map marker
# 0xa2, so length-aware stripping removes exactly the trailing 6 bytes.
CODE = "60806040"
META_A = "a2bbccdd0004"   # 4-byte metadata + 2 length bytes
META_B = "a2eeff110004"   # same length, different content
BC_A = CODE + META_A
BC_B = CODE + META_B


class TestNormalize(unittest.TestCase):
    def test_strips_prefix_and_lowercases(self):
        self.assertEqual(_normalize("0x60AB"), "60ab")
        self.assertEqual(_normalize("0X60ab"), "60ab")
        self.assertEqual(_normalize("  60AB  "), "60ab")

    def test_empty(self):
        self.assertEqual(_normalize(""), "")
        self.assertEqual(_normalize(None), "")


class TestStripMetadata(unittest.TestCase):
    def test_strips_length_aware_cbor_tail(self):
        self.assertEqual(_strip_metadata(BC_A), CODE)
        self.assertEqual(_strip_metadata(BC_B), CODE)

    def test_too_short_returns_normalized(self):
        self.assertEqual(_strip_metadata("ab"), "ab")


class TestCompareBytecode(unittest.TestCase):
    def test_exact_match(self):
        res = compare_bytecode(CODE, CODE, ignore_metadata=False)
        self.assertTrue(res["match"])
        self.assertIn("exactly", res["diff_summary"])

    def test_match_ignoring_metadata(self):
        # Different metadata, identical code -> match only when metadata ignored.
        res = compare_bytecode(BC_A, BC_B, ignore_metadata=True)
        self.assertTrue(res["match"])
        self.assertIn("metadata ignored", res["diff_summary"])

    def test_metadata_difference_is_mismatch_when_not_ignored(self):
        res = compare_bytecode(BC_A, BC_B, ignore_metadata=False)
        self.assertFalse(res["match"])

    def test_prefix_and_case_insensitive_match(self):
        res = compare_bytecode("0x60AB", "60ab", ignore_metadata=False)
        self.assertTrue(res["match"])

    def test_mismatch_reports_byte_offset(self):
        res = compare_bytecode("6080", "6081", ignore_metadata=False)
        self.assertFalse(res["match"])
        self.assertIn("offset 1", res["diff_summary"])


if __name__ == "__main__":
    unittest.main()

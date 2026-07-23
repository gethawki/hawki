# File: tests/test_cov_bytecode_analyzer.py
"""
Coverage for core.bytecode.analyzer.analyze_bytecode: dangerous-opcode
detection, PUSH immediate skipping, hex normalization, and error handling.
Pure function, no I/O.
"""

import unittest

from hawki.core.bytecode.analyzer import _iter_opcodes, analyze_bytecode


class TestIterOpcodes(unittest.TestCase):
    def test_push_immediate_skipped(self):
        # PUSH1 (0x60) + 0xff data, then STOP (0x00). The PUSH and its immediate
        # are consumed together and not yielded; only STOP at offset 2 remains.
        ops = list(_iter_opcodes(bytes([0x60, 0xFF, 0x00])))
        self.assertEqual(ops, [(2, 0x00)])


class TestAnalyzeBytecode(unittest.TestCase):
    def test_empty_returns_no_findings(self):
        self.assertEqual(analyze_bytecode(""), [])
        self.assertEqual(analyze_bytecode("a"), [])

    def test_invalid_hex_returns_no_findings(self):
        self.assertEqual(analyze_bytecode("zzzz"), [])

    def test_delegatecall_detected(self):
        findings = analyze_bytecode("f4")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIn("DELEGATECALL", f["title"])
        self.assertEqual(f["severity"], "High")
        self.assertEqual(f["line"], 0)

    def test_0x_prefix_stripped(self):
        findings = analyze_bytecode("0xff")  # SELFDESTRUCT
        self.assertTrue(any("SELFDESTRUCT" in f["title"] for f in findings))

    def test_push1_ff_is_not_selfdestruct(self):
        # 0x60 0xff = PUSH1 0xff -> the 0xff is data, must NOT be flagged.
        self.assertEqual(analyze_bytecode("60ff"), [])

    def test_multiple_positions_truncated_with_more(self):
        # Seven consecutive SELFDESTRUCT opcodes -> only first 5 shown + "(+2 more)".
        findings = analyze_bytecode("ff" * 7)
        sd = [f for f in findings if "SELFDESTRUCT" in f["title"]][0]
        self.assertIn("more", sd["description"])

    def test_mixed_opcodes(self):
        # CALL (f1, Medium) + CREATE2 (f5, Medium) + DELEGATECALL (f4, High).
        findings = analyze_bytecode("f1f5f4")
        titles = " ".join(f["title"] for f in findings)
        self.assertIn("CALL", titles)
        self.assertIn("CREATE2", titles)
        self.assertIn("DELEGATECALL", titles)
        severities = {f["severity"] for f in findings}
        self.assertEqual(severities, {"Medium", "High"})

    def test_finding_schema_fields(self):
        f = analyze_bytecode("f4")[0]
        for key in ("title", "severity", "description", "file", "line",
                    "vulnerable_snippet", "explanation", "impact", "ai_used"):
            self.assertIn(key, f)
        self.assertEqual(f["file"], "bytecode")
        self.assertFalse(f["ai_used"])


if __name__ == "__main__":
    unittest.main()

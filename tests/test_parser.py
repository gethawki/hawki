# --------------------
# File: tests/test_parser.py
# --------------------
"""
Unit tests for SolidityParser.
"""

import tempfile
import unittest
from pathlib import Path

from hawki.core.repo_intelligence.parser import SolidityParser


class TestParser(unittest.TestCase):
    def setUp(self):
        self.parser = SolidityParser()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sample_contract = """
pragma solidity ^0.8.0;
contract Test {
    uint public x;
    function set(uint _x) public { x = _x; }
}
"""
        self.contract_path = Path(self.temp_dir.name) / "Test.sol"
        with open(self.contract_path, "w") as f:
            f.write(self.sample_contract)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_file(self):
        result = self.parser.parse_file(self.contract_path)
        self.assertIsNotNone(result)
        self.assertEqual(len(result["contracts"]), 1)
        contract = result["contracts"][0]
        self.assertEqual(contract["name"], "Test")
        self.assertEqual(len(contract["functions"]), 1)
        func = contract["functions"][0]
        self.assertEqual(func["name"], "set")
        self.assertEqual(func["visibility"], "public")

if __name__ == "__main__":
    unittest.main()
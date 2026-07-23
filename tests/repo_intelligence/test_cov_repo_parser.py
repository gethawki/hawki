# --------------------
# File: tests/repo_intelligence/test_cov_repo_parser.py
# --------------------
"""
Coverage tests for SolidityParser (real tree-sitter, no mocks).

Only asserts behavior that the shipped tree-sitter-solidity grammar
reliably produces: contract names, function names + visibility, and
state variables. (Inheritance / modifier extraction is grammar-version
dependent and intentionally not asserted here.)
"""

import tempfile
import unittest
from pathlib import Path

from hawki.core.repo_intelligence.parser import SolidityParser


class TestParserCoverage(unittest.TestCase):
    def setUp(self):
        self.parser = SolidityParser()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name: str, src: str) -> Path:
        p = self.dir / name
        p.write_text(src)
        return p

    def test_empty_file_returns_empty_contracts(self):
        p = self._write("Empty.sol", "")
        result = self.parser.parse_file(p)
        self.assertIsNotNone(result)
        self.assertEqual(result["contracts"], [])
        self.assertEqual(result["source"], "")
        self.assertEqual(result["path"], str(p))

    def test_pragma_only_no_contracts(self):
        p = self._write("Pragma.sol", "pragma solidity ^0.8.0;\n")
        result = self.parser.parse_file(p)
        self.assertIsNotNone(result)
        self.assertEqual(result["contracts"], [])

    def test_missing_file_returns_none(self):
        result = self.parser.parse_file(self.dir / "does_not_exist.sol")
        self.assertIsNone(result)

    def test_multiple_contracts_with_imports(self):
        src = """
pragma solidity ^0.8.0;
import "./Other.sol";

contract Alpha {
    uint256 public alphaVar;
    function foo() public {}
}

contract Beta {
    address private owner;
    function bar() external {}
    function baz() internal {}
}
"""
        p = self._write("Multi.sol", src)
        result = self.parser.parse_file(p)
        self.assertIsNotNone(result)
        names = [c["name"] for c in result["contracts"]]
        self.assertIn("Alpha", names)
        self.assertIn("Beta", names)
        self.assertEqual(len(result["contracts"]), 2)

    def test_functions_names_and_visibility(self):
        src = """
pragma solidity ^0.8.0;
contract V {
    function pub() public {}
    function ext() external {}
    function intl() internal {}
    function priv() private {}
    function defaultVis() {}
}
"""
        p = self._write("V.sol", src)
        result = self.parser.parse_file(p)
        contract = result["contracts"][0]
        by_name = {f["name"]: f for f in contract["functions"]}
        self.assertEqual(by_name["pub"]["visibility"], "public")
        self.assertEqual(by_name["ext"]["visibility"], "external")
        self.assertEqual(by_name["intl"]["visibility"], "internal")
        self.assertEqual(by_name["priv"]["visibility"], "private")
        # No visibility keyword -> parser default is "internal"
        self.assertEqual(by_name["defaultVis"]["visibility"], "internal")
        # Every function carries the full shape keys.
        for f in contract["functions"]:
            self.assertIn("parameters", f)
            self.assertIn("modifiers", f)
            self.assertIn("state_mutability", f)
            self.assertIn("returns", f)

    def test_function_parameters_extracted(self):
        src = """
pragma solidity ^0.8.0;
contract P {
    function transfer(address to, uint256 amount) public {}
}
"""
        p = self._write("P.sol", src)
        result = self.parser.parse_file(p)
        func = result["contracts"][0]["functions"][0]
        params = {pr["name"]: pr["type"] for pr in func["parameters"]}
        self.assertEqual(params.get("to"), "address")
        self.assertEqual(params.get("amount"), "uint256")

    def test_state_variables_extracted(self):
        src = """
pragma solidity ^0.8.0;
contract S {
    uint256 public total;
    address private owner;
    bool internal flag;
}
"""
        p = self._write("S.sol", src)
        result = self.parser.parse_file(p)
        svars = {v["name"]: v for v in result["contracts"][0]["state_variables"]}
        self.assertEqual(svars["total"]["type"], "uint256")
        self.assertEqual(svars["total"]["visibility"], "public")
        self.assertEqual(svars["owner"]["type"], "address")
        self.assertEqual(svars["owner"]["visibility"], "private")
        self.assertIn("flag", svars)

    def test_parse_file_accepts_str_path(self):
        # parse_file opens via open(); a str path works as well as Path.
        p = self._write("Str.sol", "pragma solidity ^0.8.0;\ncontract C {}\n")
        result = self.parser.parse_file(str(p))
        self.assertIsNotNone(result)
        self.assertEqual(result["contracts"][0]["name"], "C")


if __name__ == "__main__":
    unittest.main()

# --------------------
# File: tests/static_rule_engine/test_new_rules_hygiene.py
# --------------------
"""
Indexer-driven liveness + no-false-positive tests for the six hygiene rules:
floating_pragma, outdated_solidity, deprecated_constructs, inline_assembly,
missing_event_admin and default_visibility. Each rule gets a real trigger run
through RepositoryIndexer (so the tests exercise the exact file-level dicts the
scan pipeline passes to rules) and a clean/modern snippet it must NOT fire on.
"""

import tempfile
from pathlib import Path

from hawki.core.repo_intelligence.indexer import RepositoryIndexer
from hawki.core.static_rule_engine.rules.default_visibility import DefaultVisibilityRule
from hawki.core.static_rule_engine.rules.deprecated_constructs import DeprecatedConstructsRule
from hawki.core.static_rule_engine.rules.floating_pragma import FloatingPragmaRule
from hawki.core.static_rule_engine.rules.inline_assembly import InlineAssemblyRule
from hawki.core.static_rule_engine.rules.missing_event_admin import MissingEventAdminRule
from hawki.core.static_rule_engine.rules.outdated_solidity import OutdatedSolidityRule


def _index(solidity_source: str):
    """Write a temp contract and return the indexer's file-level contract dicts."""
    tmp = tempfile.mkdtemp()
    Path(tmp, "T.sol").write_text(solidity_source)
    return RepositoryIndexer().index(tmp)["contracts"]


CLEAN_MODERN = """
pragma solidity 0.8.24;

contract Clean {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function timeLeft(uint256 deadline) public view returns (uint256) {
        return deadline - block.timestamp;
    }
}
"""


# ---------------------------------------------------------------------------
# floating_pragma
# ---------------------------------------------------------------------------

def test_floating_pragma_fires_on_caret_range():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T { uint256 public x; }
""")
    findings = FloatingPragmaRule().run_check(contracts)
    assert len(findings) == 1
    assert findings[0]["title"] == "Floating pragma"
    assert findings[0]["severity"] == "Low"


def test_floating_pragma_silent_on_exact_pin():
    assert FloatingPragmaRule().run_check(_index(CLEAN_MODERN)) == []


# ---------------------------------------------------------------------------
# outdated_solidity
# ---------------------------------------------------------------------------

def test_outdated_solidity_fires_on_pre_08_pragma():
    contracts = _index("""
pragma solidity ^0.6.12;
contract T { uint256 public x; }
""")
    findings = OutdatedSolidityRule().run_check(contracts)
    assert len(findings) == 1
    assert findings[0]["title"] == "Outdated Solidity version"


def test_outdated_solidity_silent_on_modern_pragma():
    assert OutdatedSolidityRule().run_check(_index(CLEAN_MODERN)) == []


# ---------------------------------------------------------------------------
# deprecated_constructs
# ---------------------------------------------------------------------------

def test_deprecated_constructs_fires_and_dedupes_per_keyword():
    contracts = _index("""
pragma solidity ^0.4.24;
contract T {
    uint256 public stamp;
    function bad(uint256 x) public {
        if (x == 0) throw;
        if (x == 1) throw;
        var y = sha3(abi.encodePacked(x));
        stamp = now;
    }
}
""")
    findings = DeprecatedConstructsRule().run_check(contracts)
    constructs = sorted(f["construct"] for f in findings)
    # throw appears twice but is deduped per (file, keyword).
    assert constructs == ["now", "sha3", "throw", "var"]


def test_deprecated_constructs_silent_on_clean_and_comments():
    contracts = _index("""
pragma solidity 0.8.24;
contract T {
    // legacy code used throw and sha3(...) and now
    string public note = "do it now, don't throw";
    uint256 public knownow; // identifier containing 'now'
    function ok() public view returns (uint256) { return block.timestamp; }
}
""")
    assert DeprecatedConstructsRule().run_check(contracts) == []


# ---------------------------------------------------------------------------
# inline_assembly
# ---------------------------------------------------------------------------

def test_inline_assembly_fires_per_block():
    contracts = _index("""
pragma solidity 0.8.24;
contract T {
    function size(address a) public view returns (uint256 s) {
        assembly { s := extcodesize(a) }
    }
    function chain() public view returns (uint256 id) {
        assembly { id := chainid() }
    }
}
""")
    findings = InlineAssemblyRule().run_check(contracts)
    assert len(findings) == 2
    assert all(f["severity"] == "Info" for f in findings)


def test_inline_assembly_silent_without_assembly():
    assert InlineAssemblyRule().run_check(_index(CLEAN_MODERN)) == []


# ---------------------------------------------------------------------------
# missing_event_admin
# ---------------------------------------------------------------------------

def test_missing_event_admin_fires_on_silent_owner_setter():
    contracts = _index("""
pragma solidity 0.8.24;
contract T {
    address public owner;
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }
}
""")
    findings = MissingEventAdminRule().run_check(contracts)
    assert len(findings) == 1
    assert findings[0]["title"] == "State change without event"
    assert findings[0]["function_name"] == "setOwner"


def test_missing_event_admin_silent_when_event_emitted():
    # CLEAN_MODERN's transferOwnership assigns owner but emits an event.
    assert MissingEventAdminRule().run_check(_index(CLEAN_MODERN)) == []


def test_missing_event_admin_silent_on_comparisons_and_internal():
    contracts = _index("""
pragma solidity 0.8.24;
contract T {
    address public owner;
    function isOwner() public view returns (bool) { return msg.sender == owner; }
    function _setOwner(address n) internal { owner = n; }
}
""")
    assert MissingEventAdminRule().run_check(contracts) == []


# ---------------------------------------------------------------------------
# default_visibility
# ---------------------------------------------------------------------------

def test_default_visibility_fires_on_pre_05_implicit_public():
    contracts = _index("""
pragma solidity ^0.4.24;
contract Wallet {
    address public owner;
    function initWallet(address o) { owner = o; }
    function safe(address o) internal { owner = o; }
}
""")
    findings = DefaultVisibilityRule().run_check(contracts)
    assert len(findings) == 1
    assert findings[0]["function_name"] == "initWallet"
    assert findings[0]["severity"] == "Medium"


def test_default_visibility_silent_on_modern_code():
    assert DefaultVisibilityRule().run_check(_index(CLEAN_MODERN)) == []


def test_default_visibility_silent_without_pragma():
    contracts = _index("contract T { function f() { } }")
    assert DefaultVisibilityRule().run_check(contracts) == []
# EOF: tests/static_rule_engine/test_new_rules_hygiene.py

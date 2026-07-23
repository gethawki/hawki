# File: tests/static_rule_engine/test_liveness_fixed.py
"""
Liveness tests for the six rules that used to be silently dead in production.

Each trigger contract is written to disk and indexed through the REAL
RepositoryIndexer, so the rules are exercised against the exact contract_data
shape the scan pipeline produces (file-level dicts with ``source`` and
functions nested under ``contracts``, no bodies, no modifiers). A shared
benign, production-like contract asserts none of the six rules false-positive.
"""

from hawki.core.repo_intelligence.indexer import RepositoryIndexer
from hawki.core.static_rule_engine.rules.approval_race import ApprovalRaceRule
from hawki.core.static_rule_engine.rules.centralized_owner import CentralizedOwnerRule
from hawki.core.static_rule_engine.rules.oracle_manipulation import OracleManipulationRule
from hawki.core.static_rule_engine.rules.unsafe_external_call import UnsafeExternalCallRule
from hawki.core.static_rule_engine.rules.visibility import VisibilityRule
from hawki.core.static_rule_engine.rules.zero_address_check import ZeroAddressCheckRule


def _index(tmp_path, source):
    """Write the contract and index it through the real pipeline indexer."""
    (tmp_path / "Target.sol").write_text(source)
    info = RepositoryIndexer().index(str(tmp_path))
    return info["contracts"]


# ----------------------------------------------------------------------
# triggers: each rule must fire through the real indexer output
# ----------------------------------------------------------------------
def test_unsafe_external_call_fires_via_indexer(tmp_path):
    cd = _index(tmp_path, (
        "pragma solidity ^0.8.0;\n"
        "contract Payout {\n"
        "    event Paid(address to, uint256 amount);\n"
        "    function pay(address to, uint256 amount) public {\n"
        "        (bool ok, ) = to.call{value: amount}(\"\");\n"
        "        emit Paid(to, amount);\n"
        "    }\n"
        "}\n"
    ))
    findings = UnsafeExternalCallRule().run_check(cd)
    assert len(findings) >= 1
    assert findings[0]["title"] == "External call before state update (reentrancy risk)"
    assert findings[0]["severity"] == "Critical"


def test_approval_race_fires_via_indexer(tmp_path):
    cd = _index(tmp_path, (
        "pragma solidity ^0.8.0;\n"
        "contract Token {\n"
        "    mapping(address => mapping(address => uint256)) public allowance;\n"
        "    function approve(address spender, uint256 amount) public returns (bool) {\n"
        "        allowance[msg.sender][spender] = amount;\n"
        "        return true;\n"
        "    }\n"
        "}\n"
    ))
    findings = ApprovalRaceRule().run_check(cd)
    assert len(findings) >= 1
    assert findings[0]["title"] == "ERC20 approval race condition"


def test_zero_address_check_fires_via_indexer(tmp_path):
    cd = _index(tmp_path, (
        "pragma solidity ^0.8.0;\n"
        "contract Registry {\n"
        "    address public treasury;\n"
        "    function setTreasury(address _treasury) public {\n"
        "        treasury = _treasury;\n"
        "    }\n"
        "}\n"
    ))
    findings = ZeroAddressCheckRule().run_check(cd)
    assert len(findings) >= 1
    assert findings[0]["title"] == "Missing zero-address check"


def test_centralized_owner_fires_via_indexer(tmp_path):
    cd = _index(tmp_path, (
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    address public owner;\n"
        "    uint256 fee;\n"
        "    bool paused;\n"
        "    modifier onlyOwner() { require(msg.sender == owner); _; }\n"
        "    function setFee(uint256 f) public onlyOwner { fee = f; }\n"
        "    function pause() public onlyOwner { paused = true; }\n"
        "    function sweep(address token) public onlyOwner { paused = false; }\n"
        "}\n"
    ))
    findings = CentralizedOwnerRule().run_check(cd)
    assert len(findings) >= 1
    assert findings[0]["title"] == "Centralized owner risk"


def test_visibility_fires_via_indexer(tmp_path):
    cd = _index(tmp_path, (
        "pragma solidity ^0.8.0;\n"
        "contract Hashing {\n"
        "    function _hashUser(address user) public pure returns (bytes32) {\n"
        "        return keccak256(abi.encodePacked(user));\n"
        "    }\n"
        "}\n"
    ))
    findings = VisibilityRule().run_check(cd)
    assert len(findings) >= 1
    assert findings[0]["title"] == "Public function that may be internal"


def test_oracle_manipulation_fires_via_indexer(tmp_path):
    cd = _index(tmp_path, (
        "pragma solidity ^0.8.0;\n"
        "interface IFeed { function latestAnswer() external view returns (int256); }\n"
        "contract Lender {\n"
        "    IFeed public feed;\n"
        "    function collateralValue(uint256 amount) public view returns (uint256) {\n"
        "        return amount * uint256(feed.latestAnswer());\n"
        "    }\n"
        "}\n"
    ))
    findings = OracleManipulationRule().run_check(cd)
    assert len(findings) >= 1
    assert findings[0]["title"] == "Potential oracle manipulation"


# ----------------------------------------------------------------------
# no false positives on a benign, production-like contract
# ----------------------------------------------------------------------
_BENIGN = (
    "pragma solidity ^0.8.0;\n"
    "contract StakingPool {\n"
    "    address public owner;\n"
    "    address public admin;\n"
    "    mapping(address => uint256) public balances;\n"
    "    modifier onlyOwner() { require(msg.sender == owner); _; }\n"
    "    function setAdmin(address _admin) public onlyOwner {\n"
    "        require(_admin != address(0), \"zero address\");\n"
    "        admin = _admin;\n"
    "    }\n"
    "    function withdraw(uint256 amount) public {\n"
    "        balances[msg.sender] -= amount;\n"
    "        (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
    "        require(ok, \"transfer failed\");\n"
    "    }\n"
    "    function _sync() internal {\n"
    "        balances[address(this)] = address(this).balance;\n"
    "    }\n"
    "}\n"
)


def test_no_false_positives_on_benign_contract(tmp_path):
    cd = _index(tmp_path, _BENIGN)
    assert UnsafeExternalCallRule().run_check(cd) == []
    assert ApprovalRaceRule().run_check(cd) == []
    assert ZeroAddressCheckRule().run_check(cd) == []
    assert CentralizedOwnerRule().run_check(cd) == []
    assert VisibilityRule().run_check(cd) == []
    assert OracleManipulationRule().run_check(cd) == []
# EOF: tests/static_rule_engine/test_liveness_fixed.py

# File: tests/static_rule_engine/test_fp_signatures.py
"""
False-positive regression tests for the signature/validation rules.

Each rule gets a pair of checks: a benign snippet modeled on audited
production code (PancakeSwap farms-pools) that must NOT fire, and a
vulnerable snippet that MUST still fire, so tightening a rule for
precision can never silently cost its recall.
"""

from hawki.core.static_rule_engine.rules.approval_race import ApprovalRaceRule
from hawki.core.static_rule_engine.rules.input_validation import InputValidationRule
from hawki.core.static_rule_engine.rules.permit_replay import PermitReplayRule
from hawki.core.static_rule_engine.rules.reused_nonce import ReusedNonceRule
from hawki.core.static_rule_engine.rules.signature_malleability import SignatureMalleabilityRule


def _cd(source):
    """Build a minimal contract_data list carrying source text."""
    return [{"path": "nonexistent_contract.sol", "source": source, "functions": []}]


# ----------------------------------------------------------------------
# input validation
# ----------------------------------------------------------------------
def test_input_validation_ignores_mapping_access():
    # Mapping lookups keyed by an address are not array indexing
    # (PancakeSwap SmartChef.pendingReward pattern).
    src = (
        "contract C {\n"
        "    mapping(address => UserInfo) public userInfo;\n"
        "    function pendingReward(address _user) external view returns (uint256) {\n"
        "        UserInfo storage user = userInfo[_user];\n"
        "        return user.amount;\n"
        "    }\n"
        "}"
    )
    assert InputValidationRule().run_check(_cd(src)) == []


def test_input_validation_ignores_nested_mapping_access():
    # Nested mapping declaration (MasterChef.userInfo pattern).
    src = (
        "contract C {\n"
        "    mapping(uint256 => mapping(address => UserInfo)) public userInfo;\n"
        "    function f(uint256 _pid, address _user) public {\n"
        "        UserInfo storage user = userInfo[_pid][_user];\n"
        "    }\n"
        "}"
    )
    assert InputValidationRule().run_check(_cd(src)) == []


def test_input_validation_ignores_mapping_write():
    # Assignment into a mapping element is a write, not an unchecked read
    # (Timelock.queueTransaction / WBNB.transferFrom patterns).
    src = (
        "contract C {\n"
        "    mapping(bytes32 => bool) public queuedTransactions;\n"
        "    mapping(address => uint256) public balanceOf;\n"
        "    function q(bytes32 txHash, address src, uint256 wad) public {\n"
        "        queuedTransactions[txHash] = true;\n"
        "        balanceOf[src] -= wad;\n"
        "    }\n"
        "}"
    )
    assert InputValidationRule().run_check(_cd(src)) == []


def test_input_validation_ignores_constant_index_and_comments():
    src = (
        "contract C {\n"
        "    // reads data[i] in a comment only\n"
        "    function f() public view returns (uint256) {\n"
        "        return data[MAX_ENTRIES];\n"
        "    }\n"
        "}"
    )
    assert InputValidationRule().run_check(_cd(src)) == []


def test_input_validation_still_fires_on_variable_index_read():
    # The canonical unvalidated read must keep firing.
    src = "contract C {\n    function f(uint i) public {\n        uint x = data[i];\n    }\n}"
    findings = InputValidationRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Possible missing input validation"
    assert findings[0]["severity"] == "High"


def test_input_validation_still_fires_on_array_state_variable():
    # A real dynamic array indexed by a caller-supplied id (MasterChef.poolInfo
    # pattern) is a legitimate candidate and must keep firing.
    src = (
        "contract C {\n"
        "    PoolInfo[] public poolInfo;\n"
        "    function set(uint256 _pid) public {\n"
        "        uint256 prev = poolInfo[_pid].allocPoint;\n"
        "    }\n"
        "}"
    )
    findings = InputValidationRule().run_check(_cd(src))
    assert len(findings) == 1


# ----------------------------------------------------------------------
# approval race
# ----------------------------------------------------------------------
def test_approval_race_no_fire_on_guarded_approve():
    cd = [{
        "path": "nonexistent_contract.sol",
        "functions": [{"name": "approve", "line": 3,
                       "body": "require(amount == 0 || allowance[msg.sender][spender] == 0);"}],
    }]
    assert ApprovalRaceRule().run_check(cd) == []


def test_approval_race_still_fires_on_bare_approve():
    cd = [{
        "path": "nonexistent_contract.sol",
        "functions": [{"name": "approve", "line": 3,
                       "body": "allowed[msg.sender][spender] = amount;"}],
    }]
    findings = ApprovalRaceRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "ERC20 approval race condition"


# ----------------------------------------------------------------------
# permit replay
# ----------------------------------------------------------------------
def test_permit_replay_no_fire_with_nonce_tracking():
    src = (
        "contract C {\n"
        "    mapping(address => uint256) public nonces;\n"
        "    function permit(address owner) public {\n"
        "        uint256 current = nonces[owner]++;\n"
        "    }\n"
        "}"
    )
    assert PermitReplayRule().run_check(_cd(src)) == []


def test_permit_replay_still_fires_without_nonce():
    src = "contract C {\n    function permit(address o, address s, uint v) public {\n    }\n}"
    findings = PermitReplayRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing nonce in permit (signature replay)"


# ----------------------------------------------------------------------
# reused nonce
# ----------------------------------------------------------------------
def test_reused_nonce_no_fire_with_nonce():
    src = (
        "contract C {\n"
        "    mapping(address => uint256) public nonce;\n"
        "    function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
        "        address a = ecrecover(h, v, r, s);\n"
        "    }\n"
        "}"
    )
    assert ReusedNonceRule().run_check(_cd(src)) == []


def test_reused_nonce_still_fires_without_nonce():
    src = "contract C {\n    function f() public {\n        address a = ecrecover(h, v, r, s);\n    }\n}"
    findings = ReusedNonceRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing nonce in signature verification"


# ----------------------------------------------------------------------
# signature malleability
# ----------------------------------------------------------------------
def test_signature_malleability_no_fire_with_ecdsa():
    src = (
        "contract C {\n"
        "    using ECDSA for bytes32;\n"
        "    function f(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {\n"
        "        address a = ecrecover(h, v, r, s);\n"
        "    }\n"
        "}"
    )
    assert SignatureMalleabilityRule().run_check(_cd(src)) == []


def test_signature_malleability_still_fires_without_ecdsa():
    src = "contract C {\n    function f() public {\n        address a = ecrecover(h, v, r, s);\n    }\n}"
    findings = SignatureMalleabilityRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Potential signature malleability"
# EOF: tests/static_rule_engine/test_fp_signatures.py

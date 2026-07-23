# File: tests/static_rule_engine/test_cov_rules_source.py
"""
Coverage tests for the source-text based static rules.

Each rule under hawki/core/static_rule_engine/rules is a pure function over a
`contract_data` list of dicts. The rules covered here scan the contract's
`source` text with regexes/substring checks. For every rule we feed one
contract crafted to TRIGGER the rule (asserting a finding with the expected
title/severity) and one clean contract (asserting no finding), so both the
match and the no-match branch of each rule body execute.

A non-existent `path` is used deliberately so BaseRule._create_finding falls
back to the rule-supplied snippet instead of reading a real file.
"""

from hawki.core.static_rule_engine.rules.blockhash_randomness import BlockhashRandomnessRule
from hawki.core.static_rule_engine.rules.delegatecall_misuse import DelegatecallMisuseRule
from hawki.core.static_rule_engine.rules.dos_revert import DoSRevertRule
from hawki.core.static_rule_engine.rules.flash_loan_manipulation import FlashLoanManipulationRule
from hawki.core.static_rule_engine.rules.front_running import FrontRunningRule
from hawki.core.static_rule_engine.rules.gas_griefing import GasGriefingRule
from hawki.core.static_rule_engine.rules.governance_vote_manipulation import GovernanceVoteManipulationRule
from hawki.core.static_rule_engine.rules.hardcoded_address import HardcodedAddressRule
from hawki.core.static_rule_engine.rules.input_validation import InputValidationRule
from hawki.core.static_rule_engine.rules.integer_overflow import IntegerOverflowRule
from hawki.core.static_rule_engine.rules.integer_overflow_unchecked import IntegerOverflowUncheckedRule
from hawki.core.static_rule_engine.rules.oracle_manipulation import OracleManipulationRule
from hawki.core.static_rule_engine.rules.permit_replay import PermitReplayRule
from hawki.core.static_rule_engine.rules.reused_nonce import ReusedNonceRule
from hawki.core.static_rule_engine.rules.signature_malleability import SignatureMalleabilityRule
from hawki.core.static_rule_engine.rules.timestamp_dependency import TimestampDependencyRule
from hawki.core.static_rule_engine.rules.tx_origin_auth import TxOriginAuthRule
from hawki.core.static_rule_engine.rules.tx_origin_dependency import TxOriginRule
from hawki.core.static_rule_engine.rules.unbounded_loop import UnboundedLoopRule
from hawki.core.static_rule_engine.rules.unchecked_send import UncheckedSendRule
from hawki.core.static_rule_engine.rules.uninitialized_storage import UninitializedStorageRule


def _cd(source):
    """Build a minimal contract_data list carrying source text."""
    return [{"path": "nonexistent_contract.sol", "source": source, "functions": []}]


CLEAN = "// SPDX-License-Identifier: MIT\ncontract Clean {\n    uint256 public value;\n}\n"


# ----------------------------------------------------------------------
# blockhash randomness
# ----------------------------------------------------------------------
def test_blockhash_randomness_triggers():
    src = "contract C {\n    function r() public view returns (uint) {\n        return uint(blockhash(block.number - 1));\n    }\n}"
    findings = BlockhashRandomnessRule().run_check(_cd(src))
    assert len(findings) >= 1
    assert findings[0]["title"] == "Insecure randomness via blockhash"
    assert findings[0]["severity"] == "High"


def test_blockhash_randomness_clean():
    assert BlockhashRandomnessRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# delegatecall misuse
# ----------------------------------------------------------------------
def test_delegatecall_misuse_triggers():
    src = "contract C {\n    function f(address t, bytes memory d) public {\n        t.delegatecall(d);\n    }\n}"
    findings = DelegatecallMisuseRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Unsafe delegatecall"
    assert findings[0]["severity"] == "Critical"


def test_delegatecall_misuse_clean():
    assert DelegatecallMisuseRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# dos revert (unchecked .call)
# ----------------------------------------------------------------------
def test_dos_revert_triggers():
    src = "contract C {\n    function f() public {\n        target.call(data);\n    }\n}"
    findings = DoSRevertRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Potential DoS via unchecked external call"
    assert findings[0]["severity"] == "High"


def test_dos_revert_clean():
    # A .call guarded by require should not be flagged.
    src = "contract C {\n    function f() public {\n        require(target.call(data));\n    }\n}"
    assert DoSRevertRule().run_check(_cd(src)) == []
    assert DoSRevertRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# flash loan manipulation
# ----------------------------------------------------------------------
def test_flash_loan_manipulation_triggers():
    src = "contract C {\n    function price() public view returns (uint) {\n        (uint r0, uint r1,) = pair.getReserves();\n        return r0 / r1;\n    }\n}"
    findings = FlashLoanManipulationRule().run_check(_cd(src))
    assert len(findings) >= 1
    assert findings[0]["title"] == "Potential flash loan manipulation"
    assert findings[0]["severity"] == "Critical"


def test_flash_loan_manipulation_clean():
    assert FlashLoanManipulationRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# front running
# ----------------------------------------------------------------------
def test_front_running_triggers():
    src = "contract C {\n    function f() public {\n        require(block.timestamp > start);\n        uint b = block.number;\n    }\n}"
    findings = FrontRunningRule().run_check(_cd(src))
    # Reported once per contract (deduped) rather than per occurrence.
    assert len(findings) == 1
    assert findings[0]["title"] == "Potential front-running via block.timestamp/number"
    assert findings[0]["severity"] == "Low"


def test_front_running_clean():
    assert FrontRunningRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# gas griefing (loop over .length)
# ----------------------------------------------------------------------
def test_gas_griefing_triggers():
    src = "contract C {\n    function f(uint[] memory a) public {\n        for (uint i = 0; i < a.length; i++) { sum += a[i]; }\n    }\n}"
    findings = GasGriefingRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Potential gas griefing (unbounded loop)"
    assert findings[0]["severity"] == "High"


def test_gas_griefing_clean():
    assert GasGriefingRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# governance vote manipulation
# ----------------------------------------------------------------------
def test_governance_vote_manipulation_triggers():
    src = "contract C {\n    function vote() public {\n        uint power = token.balanceOf(msg.sender);\n    }\n}"
    findings = GovernanceVoteManipulationRule().run_check(_cd(src))
    assert len(findings) >= 1
    assert findings[0]["title"] == "Governance vote manipulation via flash loan"
    assert findings[0]["severity"] == "Critical"


def test_governance_vote_manipulation_clean_with_snapshot():
    # balanceOf(msg.sender) present but snapshot mechanism present -> suppressed.
    src = "contract C {\n    function vote() public {\n        uint power = token.balanceOf(msg.sender);\n        getPastVotes(msg.sender, block.number - 1);\n    }\n}"
    assert GovernanceVoteManipulationRule().run_check(_cd(src)) == []
    assert GovernanceVoteManipulationRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# hardcoded address
# ----------------------------------------------------------------------
def test_hardcoded_address_triggers():
    src = "contract C {\n    address owner = 0x1234567890abcdef1234567890ABCDEF12345678;\n}"
    findings = HardcodedAddressRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Hardcoded address"
    assert findings[0]["severity"] == "Medium"


def test_hardcoded_address_clean():
    assert HardcodedAddressRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# input validation (array index without length/require)
# ----------------------------------------------------------------------
def test_input_validation_triggers():
    src = "contract C {\n    function f(uint i) public {\n        uint x = data[i];\n    }\n}"
    findings = InputValidationRule().run_check(_cd(src))
    assert len(findings) >= 1
    assert findings[0]["title"] == "Possible missing input validation"
    assert findings[0]["severity"] == "High"


def test_input_validation_clean():
    src = "contract C {\n    uint256 public value;\n}"
    assert InputValidationRule().run_check(_cd(src)) == []


# ----------------------------------------------------------------------
# integer overflow (arithmetic without SafeMath)
# ----------------------------------------------------------------------
def test_integer_overflow_triggers():
    src = "contract C {\n    function f() public {\n        uint x = a + b;\n    }\n}"
    findings = IntegerOverflowRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Potential integer overflow/underflow"
    assert findings[0]["severity"] == "Medium"


def test_integer_overflow_clean_with_safemath():
    # Arithmetic present but SafeMath in use -> suppressed. Avoid any +-*/ chars.
    src = "pragma solidity 0.8.0;\ncontract C {\n    using SafeMath for uint256;\n    uint256 public value;\n}"
    assert IntegerOverflowRule().run_check(_cd(src)) == []


# ----------------------------------------------------------------------
# integer overflow unchecked
# ----------------------------------------------------------------------
def test_integer_overflow_unchecked_triggers():
    src = "contract C {\n    function f() public {\n        unchecked { z = x + y; }\n    }\n}"
    findings = IntegerOverflowUncheckedRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Unchecked arithmetic may overflow"
    assert findings[0]["severity"] == "Critical"


def test_integer_overflow_unchecked_clean():
    # unchecked block without arithmetic ops.
    src = "contract C {\n    function f() public {\n        unchecked { z = readValue(); }\n    }\n}"
    assert IntegerOverflowUncheckedRule().run_check(_cd(src)) == []
    assert IntegerOverflowUncheckedRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# oracle manipulation
# ----------------------------------------------------------------------
def test_oracle_manipulation_triggers():
    src = "contract C {\n    function price() public view returns (uint) {\n        (uint r0,,) = pair.getReserves();\n        return r0;\n    }\n}"
    findings = OracleManipulationRule().run_check(_cd(src))
    assert len(findings) >= 1
    assert findings[0]["title"] == "Potential oracle manipulation"
    assert findings[0]["severity"] == "Critical"


def test_oracle_manipulation_clean():
    assert OracleManipulationRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# permit replay
# ----------------------------------------------------------------------
def test_permit_replay_triggers():
    src = "contract C {\n    function permit(address o, address s, uint v) public {\n        // no nonce tracking\n    }\n}"
    findings = PermitReplayRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing nonce in permit (signature replay)"
    assert findings[0]["severity"] == "Critical"


def test_permit_replay_clean():
    src = "contract C {\n    mapping(address => uint) public nonces;\n    function permit(address o) public {\n        uint nonce = nonces[o]++;\n    }\n}"
    assert PermitReplayRule().run_check(_cd(src)) == []
    assert PermitReplayRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# reused nonce (ecrecover without nonce)
# ----------------------------------------------------------------------
def test_reused_nonce_triggers():
    src = "contract C {\n    function f() public {\n        address a = ecrecover(h, v, r, s);\n    }\n}"
    findings = ReusedNonceRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing nonce in signature verification"
    assert findings[0]["severity"] == "High"


def test_reused_nonce_clean():
    src = "contract C {\n    uint public nonce;\n    function f() public {\n        address a = ecrecover(h, v, r, s);\n    }\n}"
    assert ReusedNonceRule().run_check(_cd(src)) == []
    assert ReusedNonceRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# signature malleability (ecrecover without ECDSA)
# ----------------------------------------------------------------------
def test_signature_malleability_triggers():
    src = "contract C {\n    function f() public {\n        address a = ecrecover(h, v, r, s);\n    }\n}"
    findings = SignatureMalleabilityRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Potential signature malleability"
    assert findings[0]["severity"] == "High"


def test_signature_malleability_clean():
    src = "contract C {\n    using ECDSA for bytes32;\n    function f() public {\n        address a = ecrecover(h, v, r, s);\n    }\n}"
    assert SignatureMalleabilityRule().run_check(_cd(src)) == []
    assert SignatureMalleabilityRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# timestamp dependency
# ----------------------------------------------------------------------
def test_timestamp_dependency_triggers():
    src = "contract C {\n    function f() public {\n        require(block.timestamp > deadline);\n    }\n}"
    findings = TimestampDependencyRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Timestamp dependency"
    assert findings[0]["severity"] == "Medium"


def test_timestamp_dependency_clean():
    assert TimestampDependencyRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# tx.origin auth (near require/if)
# ----------------------------------------------------------------------
def test_tx_origin_auth_triggers():
    src = "contract C {\n    function f() public {\n        require(tx.origin == owner, \"no\");\n    }\n}"
    findings = TxOriginAuthRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "tx.origin used for authentication"
    assert findings[0]["severity"] == "Critical"


def test_tx_origin_auth_clean():
    assert TxOriginAuthRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# tx.origin dependency (any use)
# ----------------------------------------------------------------------
def test_tx_origin_dependency_triggers():
    src = "contract C {\n    function f() public {\n        address a = tx.origin;\n    }\n}"
    findings = TxOriginRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Use of tx.origin for authentication"
    assert findings[0]["severity"] == "High"


def test_tx_origin_dependency_clean():
    assert TxOriginRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# unbounded loop
# ----------------------------------------------------------------------
def test_unbounded_loop_triggers():
    src = "contract C {\n    function f(uint[] memory a) public {\n        for (uint i = 0; i < a.length; i++) {}\n    }\n}"
    findings = UnboundedLoopRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Unbounded loop may cause gas exhaustion"
    assert findings[0]["severity"] == "High"


def test_unbounded_loop_clean():
    assert UnboundedLoopRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# unchecked send/transfer
# ----------------------------------------------------------------------
def test_unchecked_send_triggers():
    src = "contract C {\n    function f() public {\n        payable(msg.sender).transfer(amount);\n    }\n}"
    findings = UncheckedSendRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Unchecked send/transfer"
    assert findings[0]["severity"] == "Medium"


def test_unchecked_send_clean():
    src = "contract C {\n    function f() public {\n        require(payable(msg.sender).send(amount));\n    }\n}"
    assert UncheckedSendRule().run_check(_cd(src)) == []
    assert UncheckedSendRule().run_check(_cd(CLEAN)) == []


# ----------------------------------------------------------------------
# uninitialized storage pointer
# ----------------------------------------------------------------------
def test_uninitialized_storage_triggers():
    src = "contract C {\n    function f() public {\n        User storage user;\n    }\n}"
    findings = UninitializedStorageRule().run_check(_cd(src))
    assert len(findings) >= 1
    assert findings[0]["title"] == "Uninitialized storage pointer"
    assert findings[0]["severity"] == "High"


def test_uninitialized_storage_clean():
    assert UninitializedStorageRule().run_check(_cd(CLEAN)) == []

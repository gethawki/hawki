# --------------------
# File: tests/static_rule_engine/test_fp_defi.py
# --------------------
"""
False-positive regression tests against real-world DeFi patterns.

Per rule: assert the benign pattern (taken from production-grade code) does
NOT fire, and the genuinely vulnerable pattern STILL fires.
"""

from hawki.core.static_rule_engine.rules.blockhash_randomness import BlockhashRandomnessRule
from hawki.core.static_rule_engine.rules.hardcoded_address import HardcodedAddressRule
from hawki.core.static_rule_engine.rules.timestamp_dependency import TimestampDependencyRule
from hawki.core.static_rule_engine.rules.zero_address_check import ZeroAddressCheckRule


def _cd(source):
    return [{"path": "nonexistent_contract.sol", "source": source, "functions": []}]


# ----------------------------------------------------------------------
# timestamp dependency
# ----------------------------------------------------------------------
def test_timestamp_benign_storage_and_return_do_not_fire():
    # Benign accounting/stamping uses (MasterChef/Timelock style).
    src = (
        "contract Farm {\n"
        "    uint256 public lastRewardTime;\n"
        "    function update() external {\n"
        "        lastRewardTime = block.timestamp;\n"
        "    }\n"
        "    function getBlockTimestamp() internal view returns (uint) {\n"
        "        return block.timestamp;\n"
        "    }\n"
        "    // block.timestamp > deadline (comment must not fire)\n"
        "}"
    )
    assert TimestampDependencyRule().run_check(_cd(src)) == []


def test_timestamp_comparison_still_fires_once_per_contract():
    src = (
        "contract Auction {\n"
        "    function claim() external {\n"
        "        require(block.timestamp > deadline);\n"
        "        if (block.timestamp >= end) { finalize(); }\n"
        "    }\n"
        "}"
    )
    findings = TimestampDependencyRule().run_check(_cd(src))
    # Deduped to ONE finding per contract even with multiple comparisons.
    assert len(findings) == 1
    assert findings[0]["title"] == "Timestamp dependency"


# ----------------------------------------------------------------------
# blockhash randomness
# ----------------------------------------------------------------------
def test_blockhash_no_double_count_and_skips_comments():
    src = (
        "contract Lotto {\n"
        "    // blockhash( in a comment must not fire\n"
        "    function r() public view returns (uint) {\n"
        "        return uint(block.blockhash(block.number - 1));\n"
        "    }\n"
        "}"
    )
    findings = BlockhashRandomnessRule().run_check(_cd(src))
    # `block.blockhash(` used to match two patterns and double-count.
    assert len(findings) == 1
    assert findings[0]["title"] == "Insecure randomness via blockhash"


def test_blockhash_difficulty_and_prevrandao_still_fire():
    src = (
        "contract Lotto {\n"
        "    function r() public view returns (uint) {\n"
        "        return uint(keccak256(abi.encode(block.difficulty, block.prevrandao)));\n"
        "    }\n"
        "}"
    )
    findings = BlockhashRandomnessRule().run_check(_cd(src))
    assert len(findings) == 2


# ----------------------------------------------------------------------
# hardcoded address
# ----------------------------------------------------------------------
def test_hardcoded_address_skips_sentinels_and_comments():
    src = (
        "contract Vault {\n"
        "    // deployed at 0x1111111111111111111111111111111111111111\n"
        "    address constant ZERO = 0x0000000000000000000000000000000000000000;\n"
        "    address constant BURN = 0x000000000000000000000000000000000000dEaD;\n"
        "    address constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;\n"
        "    bytes32 constant HASH = 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563;\n"
        "}"
    )
    assert HardcodedAddressRule().run_check(_cd(src)) == []


def test_hardcoded_address_still_fires_and_dedupes_per_literal():
    src = (
        "contract Admin {\n"
        "    address owner = 0x1234567890abcdef1234567890ABCDEF12345678;\n"
        "    address backup = 0x1234567890abcdef1234567890ABCDEF12345678;\n"
        "    address other = 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B;\n"
        "}"
    )
    findings = HardcodedAddressRule().run_check(_cd(src))
    # Two distinct literals -> two findings (repeat of the first is deduped).
    assert len(findings) == 2
    assert findings[0]["title"] == "Hardcoded address"


# ----------------------------------------------------------------------
# zero-address check
# ----------------------------------------------------------------------
def test_zero_address_skips_interfaces_and_read_only_params():
    cd = [{
        "path": "nonexistent.sol",
        "functions": [
            # Interface/abstract declaration: no body.
            {"name": "transferOwnership", "line": 2,
             "parameters": [{"type": "address", "name": "newOwner"}],
             "body": ""},
            # Signature ends in `;` (declaration only).
            {"name": "setOperator", "line": 3,
             "parameters": [{"type": "address", "name": "op"}],
             "body": ";"},
            # Param is only read/compared, never stored or transferred.
            {"name": "isOwner", "line": 4,
             "parameters": [{"type": "address", "name": "who"}],
             "body": "return who == owner;"},
            # Properly guarded setter.
            {"name": "setOwner", "line": 5,
             "parameters": [{"type": "address", "name": "newOwner"}],
             "body": "require(newOwner != address(0)); owner = newOwner;"},
        ],
    }]
    assert ZeroAddressCheckRule().run_check(cd) == []


def test_zero_address_still_fires_on_unguarded_setter_once():
    cd = [{
        "path": "nonexistent.sol",
        "functions": [{
            "name": "setAdmins", "line": 3,
            "parameters": [
                {"type": "address", "name": "newOwner"},
                {"type": "address", "name": "newAdmin"},
            ],
            "body": "owner = newOwner; admin = newAdmin;",
        }],
    }]
    findings = ZeroAddressCheckRule().run_check(cd)
    # Deduped: one finding per function, not one per address parameter.
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing zero-address check"
    assert findings[0]["severity"] == "Medium"
# EOF: tests/static_rule_engine/test_fp_defi.py

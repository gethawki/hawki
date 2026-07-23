# File: tests/static_rule_engine/test_fp_calls.py
"""
False-positive regression tests for the "calls" cluster of static rules.

These rules used to fire on safe, audited production code (verified against the
PancakeSwap farms-pools corpus). For each tightened rule we assert BOTH:

  * it stays SILENT on a real production snippet that is not actually vulnerable
    (the demonstrable false positive we removed), and
  * it STILL fires on the genuine vulnerable pattern (recall is preserved).

Only unchecked_send and dos_revert were tightened; the other rules in the
cluster (integer_overflow_unchecked, unsafe_external_call, delegatecall_misuse,
gas_griefing, unbounded_loop) produced zero findings on the production corpus,
so there was no false positive to remove and they are intentionally not changed.
"""

from hawki.core.static_rule_engine.rules.dos_revert import DoSRevertRule
from hawki.core.static_rule_engine.rules.unchecked_send import UncheckedSendRule


def _cd(source):
    """Minimal contract_data list carrying only source text (path is fake so
    BaseRule falls back to the rule-supplied snippet)."""
    return [{"path": "nonexistent_contract.sol", "source": source, "functions": []}]


# ----------------------------------------------------------------------
# unchecked_send
# ----------------------------------------------------------------------
def test_unchecked_send_ignores_function_declaration():
    # WBNB.sol / BnbStaking.sol: an interface/function DEFINITION named
    # `transfer` is not a value transfer with a dropped return value.
    src = (
        "interface IBEP20 {\n"
        "    function transfer(address to, uint256 value) external returns (bool);\n"
        "}\n"
        "contract C {\n"
        "    function transfer(address dst, uint256 wad) public returns (bool) {\n"
        "        return true;\n"
        "    }\n"
        "}\n"
    )
    assert UncheckedSendRule().run_check(_cd(src)) == []


def test_unchecked_send_ignores_internal_helper_and_checked_assert():
    # `_transfer(...)` is an internal helper call, not `.transfer(...)`; and a
    # transfer wrapped in assert(...) IS checked (BnbStaking.sol:181).
    src = (
        "contract C {\n"
        "    function f(address to, uint256 v) internal {\n"
        "        _transfer(msg.sender, to, v);\n"
        "        assert(IWBNB(WBNB).transfer(address(this), v));\n"
        "    }\n"
        "}\n"
    )
    assert UncheckedSendRule().run_check(_cd(src)) == []


def test_unchecked_send_still_fires_on_real_transfer():
    # WBNB.sol:29 pattern: a genuine unchecked ETH transfer must still fire.
    src = (
        "contract C {\n"
        "    function withdraw(uint256 wad) public {\n"
        "        msg.sender.transfer(wad);\n"
        "    }\n"
        "}\n"
    )
    findings = UncheckedSendRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Unchecked send/transfer"


# ----------------------------------------------------------------------
# dos_revert
# ----------------------------------------------------------------------
def test_dos_revert_ignores_checked_low_level_call():
    # Timelock.sol:159 / BnbStaking.sol:190 pattern: the call result is captured
    # and required on the next line, and there is a commented-out variant. None
    # of these is an unchecked-DoS risk.
    src = (
        "contract C {\n"
        "    function exec(address target, bytes memory callData) public {\n"
        "        (bool success, bytes memory ret) = target.call(callData);\n"
        "        require(success, \"reverted\");\n"
        "        // (bool ok,) = target.call(new bytes(0));\n"
        "    }\n"
        "}\n"
    )
    assert DoSRevertRule().run_check(_cd(src)) == []


def test_dos_revert_still_fires_on_unchecked_call():
    # DAO.sol:302 pattern: a bare low-level call whose success is never inspected.
    src = (
        "contract C {\n"
        "    function f(address extraBalance) public {\n"
        "        extraBalance.call.value(msg.value)();\n"
        "        balances[msg.sender] += 1;\n"
        "    }\n"
        "}\n"
    )
    findings = DoSRevertRule().run_check(_cd(src))
    assert len(findings) == 1
    assert findings[0]["title"] == "Potential DoS via unchecked external call"

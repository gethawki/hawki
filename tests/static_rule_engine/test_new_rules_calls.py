# --------------------
# File: tests/static_rule_engine/test_new_rules_calls.py
# --------------------
"""Trigger + no-false-positive tests for the calls & assets rule cluster."""
import tempfile
from pathlib import Path

from hawki.core.repo_intelligence.indexer import RepositoryIndexer
from hawki.core.static_rule_engine.rules.arbitrary_external_call import ArbitraryExternalCallRule
from hawki.core.static_rule_engine.rules.costly_loop import CostlyLoopRule
from hawki.core.static_rule_engine.rules.erc20_unchecked_transfer import Erc20UncheckedTransferRule
from hawki.core.static_rule_engine.rules.locked_ether import LockedEtherRule
from hawki.core.static_rule_engine.rules.msg_value_in_loop import MsgValueInLoopRule
from hawki.core.static_rule_engine.rules.selfdestruct_usage import SelfdestructUsageRule
from hawki.core.static_rule_engine.rules.strict_balance_equality import StrictBalanceEqualityRule


def _cd(src):
    """Index a source string through the REAL pipeline (file-level dicts)."""
    idx = RepositoryIndexer()
    d = tempfile.mkdtemp()
    Path(d, "T.sol").write_text(src)
    info = idx.index(d)
    idx.cleanup()
    return info["contracts"]


def test_selfdestruct_triggers_and_clean():
    assert SelfdestructUsageRule().run_check(_cd(
        "contract C{ function k() public { selfdestruct(payable(msg.sender)); } }"))
    assert SelfdestructUsageRule().run_check(_cd(
        "contract C{ uint x; function k() public { x=1; } }")) == []


def test_arbitrary_external_call_triggers_and_clean():
    assert ArbitraryExternalCallRule().run_check(_cd(
        "contract C{ function f(address t,bytes memory d) public { (bool ok,)=t.call(d); } }"))
    # call to a fixed/known target (not a param) should not be flagged as arbitrary
    assert ArbitraryExternalCallRule().run_check(_cd(
        "contract C{ address fixedT; function f(bytes memory d) public { (bool ok,)=fixedT.call(d); } }")) == []


def test_erc20_unchecked_transfer_triggers_and_clean():
    assert Erc20UncheckedTransferRule().run_check(_cd(
        "contract C{ function f(address tok,address to,uint a) public { IERC20(tok).transfer(to,a); } }"))
    # a checked transfer must not fire
    assert Erc20UncheckedTransferRule().run_check(_cd(
        "contract C{ function f(address tok,address to,uint a) public { require(IERC20(tok).transfer(to,a)); } }")) == []


def test_locked_ether_triggers_and_clean():
    assert LockedEtherRule().run_check(_cd(
        "contract C{ uint x; receive() external payable { x+=msg.value; } }"))
    # has an outward path -> not locked
    assert LockedEtherRule().run_check(_cd(
        "contract C{ receive() external payable {} function out(address payable a) public { a.transfer(1); } }")) == []


def test_strict_balance_equality_triggers_and_clean():
    assert StrictBalanceEqualityRule().run_check(_cd(
        "contract C{ function f() public view returns(bool){ return address(this).balance == 0; } }"))
    assert StrictBalanceEqualityRule().run_check(_cd(
        "contract C{ function f() public view returns(bool){ return address(this).balance >= 0; } }")) == []


def test_costly_loop_triggers_and_clean():
    assert CostlyLoopRule().run_check(_cd(
        "contract C{ address[] u; function pay() public { for(uint i=0;i<u.length;i++){ payable(u[i]).transfer(1); } } }"))
    # a loop with no external call / push is fine
    assert CostlyLoopRule().run_check(_cd(
        "contract C{ uint s; function f(uint n) public { for(uint i=0;i<n;i++){ s+=i; } } }")) == []


def test_msg_value_in_loop_triggers_and_clean():
    assert MsgValueInLoopRule().run_check(_cd(
        "contract C{ address[] r; function d() public payable { for(uint i=0;i<r.length;i++){ payable(r[i]).transfer(msg.value); } } }"))
    assert MsgValueInLoopRule().run_check(_cd(
        "contract C{ function d() public payable { uint v=msg.value; require(v>0); } }")) == []

# EOF: tests/static_rule_engine/test_new_rules_calls.py

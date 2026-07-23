# --------------------
# File: tests/test_rule_liveness.py
# --------------------
"""No-dead-rules guarantee.

Every active static rule must produce at least one finding on a crafted
triggering contract when that contract is indexed through the REAL
``RepositoryIndexer`` and passed to the rule exactly as the scan pipeline passes
it (file-level dicts: ``{path, source, contracts:[{functions}]}``). A rule that
reads a shape the pipeline never provides (a bare ``functions`` key, a function
``body`` the parser does not emit, or a regex that never matches) is "dead" -- it
silently returns nothing in production even though its unit test may pass by
hand-crafting inputs. This test catches that.

Adding a new rule REQUIRES adding a liveness trigger below; a rule with no
trigger, or a trigger that fails to fire it, fails this test.
"""
import tempfile
from pathlib import Path

import pytest

from hawki.core.repo_intelligence.indexer import RepositoryIndexer
from hawki.core.static_rule_engine import RuleEngine

# module-stem -> a realistic, multi-line Solidity contract that must make the
# rule of that module fire at least once through the real indexer.
TRIGGERS = {
    "reentrancy": "contract C{\n mapping(address=>uint) b;\n function w() public {\n  (bool ok,)=msg.sender.call{value:b[msg.sender]}(\"\");\n  b[msg.sender]=0;\n }\n}",
    "unsafe_external_call": "contract C{\n function w(address a) public {\n  (bool ok,)=a.call(\"\");\n  uint x=1;\n }\n}",
    "approval_race": "contract C{\n mapping(address=>mapping(address=>uint)) allowed;\n function approve(address s,uint v) public returns(bool){\n  allowed[msg.sender][s]=v;\n  return true;\n }\n}",
    "zero_address_check": "contract C{\n address owner;\n function setOwner(address o) public {\n  owner=o;\n }\n}",
    "delegatecall_misuse": "contract C{\n function f(address t,bytes memory d) public {\n  (bool ok,)=t.delegatecall(d);\n }\n}",
    "tx_origin_auth": "contract C{\n address owner;\n function f() public {\n  require(tx.origin==owner);\n }\n}",
    "tx_origin_dependency": "contract C{\n address owner;\n function f() public {\n  require(tx.origin==owner);\n }\n}",
    "unchecked_send": "contract C{\n function w(uint a) public {\n  msg.sender.send(a);\n }\n}",
    "dos_revert": "contract C{\n function f(address a) public {\n  a.call(\"\");\n  uint y=2;\n }\n}",
    "integer_overflow": "pragma solidity ^0.6.0;\ncontract C{\n function f(uint a,uint b) public pure returns(uint){\n  return a+b;\n }\n}",
    "integer_overflow_unchecked": "pragma solidity ^0.8.0;\ncontract C{\n function f(uint x,uint y) public pure returns(uint z){\n  unchecked{ z=x+y; }\n }\n}",
    "blockhash_randomness": "contract C{\n function r() public view returns(uint){\n  return uint(blockhash(block.number-1));\n }\n}",
    "timestamp_dependency": "contract C{\n uint d;\n function f() public view returns(bool){\n  return block.timestamp>d;\n }\n}",
    "front_running": "contract C{\n function f() public view returns(uint){\n  return block.number;\n }\n}",
    "hardcoded_address": "contract C{\n address a=0x1234567890AbcdEF1234567890aBcdef12345678;\n}",
    "input_validation": "contract C{\n uint[] data;\n function f(uint i) public view returns(uint){\n  return data[i];\n }\n}",
    "unbounded_loop": "contract C{\n uint[] a;\n function f() public {\n  for(uint i=0;i<a.length;i++){ a[i]=i; }\n }\n}",
    "gas_griefing": "contract C{\n address[] u;\n function pay() public {\n  for(uint i=0;i<u.length;i++){ payable(u[i]).transfer(1); }\n }\n}",
    "centralized_owner": "contract C{\n address owner;\n modifier onlyOwner(){ require(msg.sender==owner); _; }\n function a() public onlyOwner{}\n function b() public onlyOwner{}\n function c() public onlyOwner{}\n function d() public onlyOwner{}\n}",
    "visibility": "contract C{\n uint x;\n function _helper() public returns(uint){\n  return x;\n }\n}",
    "missing_initializer": "contract C is Initializable {\n uint x;\n function setup() public {\n  x=1;\n }\n}",
    "upgrade_admin": "contract C{\n address admin;\n function setAdmin(address a) public {\n  admin=a;\n }\n}",
    "access_control_bypass": "contract C{\n address owner;\n function setOwner(address o) public {\n  owner=o;\n }\n}",
    "uninitialized_storage": "contract C{\n struct S{uint a;}\n function f() public {\n  S storage s;\n  s.a=1;\n }\n}",
    "flash_loan_manipulation": "contract C{\n function p() public view returns(uint){\n  (uint r0,uint r1,)=pair.getReserves();\n  return r0/r1;\n }\n}",
    "governance_vote_manipulation": "contract C{\n function vote() public {\n  uint power=token.balanceOf(msg.sender);\n  flashLoan(power);\n  govern(power);\n }\n}",
    "oracle_manipulation": "contract C{\n function price() public view returns(uint){\n  return oracle.latestAnswer();\n }\n}",
    "permit_replay": "contract C{\n function permit(address o,address s,uint v,uint8 vv,bytes32 r,bytes32 ss) public {\n  address rec=ecrecover(keccak256(abi.encode(o,s,v)),vv,r,ss);\n }\n}",
    "reused_nonce": "contract C{\n function claim(bytes32 h,uint8 v,bytes32 r,bytes32 s) public {\n  address a=ecrecover(h,v,r,s);\n }\n}",
    "signature_malleability": "contract C{\n function v(bytes32 h,uint8 x,bytes32 r,bytes32 s) public returns(address){\n  return ecrecover(h,x,r,s);\n }\n}",
    # --- calls & assets ---
    "selfdestruct_usage": "contract C{\n function k() public {\n  selfdestruct(payable(msg.sender));\n }\n}",
    "arbitrary_external_call": "contract C{\n function f(address t, bytes memory d) public {\n  (bool ok,)=t.call(d);\n }\n}",
    "erc20_unchecked_transfer": "contract C{\n function f(address tok,address to,uint a) public {\n  IERC20(tok).transfer(to,a);\n }\n}",
    "locked_ether": "contract C{\n uint x;\n receive() external payable {\n  x+=msg.value;\n }\n}",
    "strict_balance_equality": "contract C{\n function f() public view returns(bool){\n  return address(this).balance == 0;\n }\n}",
    "costly_loop": "contract C{\n address[] u;\n function pay() public {\n  for(uint i=0;i<u.length;i++){ payable(u[i]).transfer(1); }\n }\n}",
    "msg_value_in_loop": "contract C{\n address[] r;\n function d() public payable {\n  for(uint i=0;i<r.length;i++){ payable(r[i]).transfer(msg.value); }\n }\n}",
    # --- arithmetic & crypto ---
    "divide_before_multiply": "contract C{\n function f(uint t,uint s,uint m) public pure returns(uint){\n  return t / s * m;\n }\n}",
    "unsafe_downcast": "contract C{\n function f(uint256 a) public pure returns(uint32){\n  return uint32(a);\n }\n}",
    "weak_randomness_modulo": "contract C{\n function r() public view returns(uint){\n  return block.timestamp % 10;\n }\n}",
    "tx_gasprice_dependency": "contract C{\n function f() public view returns(uint){\n  return gasleft() * tx.gasprice;\n }\n}",
    "block_gaslimit_dependency": "contract C{\n function f() public view returns(uint){\n  return block.gaslimit / 21000;\n }\n}",
    "ecrecover_unchecked": "contract C{\n mapping(address=>uint) bal;\n function f(bytes32 h,uint8 v,bytes32 r,bytes32 s) public {\n  address signer=ecrecover(h,v,r,s);\n  bal[signer]+=1;\n }\n}",
    "array_length_assignment": "contract C{\n uint[] items;\n function pop() public {\n  items.length = items.length - 1;\n }\n}",
    # --- hygiene & config ---
    "floating_pragma": "pragma solidity ^0.8.0;\ncontract C{ uint x; }",
    "outdated_solidity": "pragma solidity ^0.6.12;\ncontract C{ uint x; }",
    "deprecated_constructs": "pragma solidity ^0.4.24;\ncontract C{\n function f() public {\n  if(msg.sender==address(0)) throw;\n }\n}",
    "inline_assembly": "contract C{\n function s(address a) public view returns(uint n){\n  assembly { n := extcodesize(a) }\n }\n}",
    "missing_event_admin": "contract C{\n address owner;\n function setOwner(address o) external {\n  owner=o;\n }\n}",
    "default_visibility": "pragma solidity ^0.4.24;\ncontract C{\n address owner;\n function initWallet(address o) {\n  owner=o;\n }\n}",
}


def _active_rule_stems():
    """Every auto-discovered rule's module stem (mirrors RuleEngine discovery)."""
    stems = []
    for rule in RuleEngine().rules:
        stems.append(rule.__class__.__module__.rsplit(".", 1)[-1])
    return sorted(set(stems))


ACTIVE_STEMS = _active_rule_stems()


def test_every_active_rule_has_a_liveness_trigger():
    """A new rule must ship with a liveness trigger, or this fails."""
    missing = [s for s in ACTIVE_STEMS if s not in TRIGGERS]
    assert not missing, f"rules with no liveness trigger (add one to TRIGGERS): {missing}"


@pytest.mark.parametrize("stem", ACTIVE_STEMS)
def test_rule_is_live_through_real_pipeline(stem):
    """The rule must fire >=1 on its trigger, indexed through RepositoryIndexer."""
    if stem not in TRIGGERS:
        pytest.skip(f"no trigger for {stem} (covered by the completeness test above)")
    rule = next(r for r in RuleEngine().rules
                if r.__class__.__module__.rsplit(".", 1)[-1] == stem)
    idx = RepositoryIndexer()
    with tempfile.TemporaryDirectory() as d:
        Path(d, "T.sol").write_text(TRIGGERS[stem])
        info = idx.index(d)
        findings = rule.run_check(info["contracts"])
    idx.cleanup()
    assert findings, f"rule '{stem}' is DEAD: 0 findings on its trigger via the real pipeline"

# EOF: tests/test_rule_liveness.py

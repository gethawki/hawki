# --------------------
# File: tests/static_rule_engine/test_new_rules_math.py
# --------------------
"""
Indexer-driven liveness + no-false-positive tests for the seven math/env rules:
divide_before_multiply, unsafe_downcast, weak_randomness_modulo,
tx_gasprice_dependency, block_gaslimit_dependency, ecrecover_unchecked,
array_length_assignment.

Each rule is exercised end-to-end through RepositoryIndexer so the tests prove
the rule fires on what the production scan pipeline actually feeds it
(file-level dicts with raw source, no parsed function bodies).
"""

import tempfile
from pathlib import Path

from hawki.core.repo_intelligence.indexer import RepositoryIndexer
from hawki.core.static_rule_engine.rules.array_length_assignment import (
    ArrayLengthAssignmentRule,
)
from hawki.core.static_rule_engine.rules.block_gaslimit_dependency import (
    BlockGaslimitDependencyRule,
)
from hawki.core.static_rule_engine.rules.divide_before_multiply import (
    DivideBeforeMultiplyRule,
)
from hawki.core.static_rule_engine.rules.ecrecover_unchecked import (
    EcrecoverUncheckedRule,
)
from hawki.core.static_rule_engine.rules.tx_gasprice_dependency import (
    TxGaspriceDependencyRule,
)
from hawki.core.static_rule_engine.rules.unsafe_downcast import UnsafeDowncastRule
from hawki.core.static_rule_engine.rules.weak_randomness_modulo import (
    WeakRandomnessModuloRule,
)


def _index(sol: str):
    """Write `sol` to a temp repo and return the indexer's contract_data list."""
    d = tempfile.mkdtemp()
    Path(d, "T.sol").write_text(sol)
    return RepositoryIndexer().index(d)["contracts"]


# ----------------------------------------------------------------------
# divide_before_multiply
# ----------------------------------------------------------------------

def test_divide_before_multiply_fires():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    function reward(uint256 total, uint256 shares, uint256 mult)
        public pure returns (uint256)
    {
        return total / shares * mult;
    }
}
""")
    findings = DivideBeforeMultiplyRule().run_check(contracts)
    assert len(findings) >= 1
    assert findings[0]["title"] == "Division before multiplication"
    assert findings[0]["severity"] == "Medium"


def test_divide_before_multiply_ignores_comments_and_safe_order():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    // a / b * c inside a comment must not fire
    /* neither x / y * z in a block comment */
    function reward(uint256 total, uint256 shares, uint256 mult)
        public pure returns (uint256)
    {
        return total * mult / shares;
    }
}
""")
    assert DivideBeforeMultiplyRule().run_check(contracts) == []


# ----------------------------------------------------------------------
# unsafe_downcast
# ----------------------------------------------------------------------

def test_unsafe_downcast_fires():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    function pack(uint256 amount) public pure returns (uint32) {
        return uint32(amount);
    }
}
""")
    findings = UnsafeDowncastRule().run_check(contracts)
    assert len(findings) >= 1
    assert findings[0]["title"] == "Unsafe integer downcast"


def test_unsafe_downcast_skips_literals_and_guarded_safe32():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    uint8 constant ONE = uint8(1);
    function safe32(uint256 n, string memory err)
        internal pure returns (uint32)
    {
        require(n < 2**32, err);
        return uint32(n);
    }
}
""")
    assert UnsafeDowncastRule().run_check(contracts) == []


# ----------------------------------------------------------------------
# weak_randomness_modulo
# ----------------------------------------------------------------------

def test_weak_randomness_modulo_fires():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    function draw(uint256 pot) public view returns (uint256) {
        return uint256(blockhash(block.number - 1)) % pot;
    }
}
""")
    findings = WeakRandomnessModuloRule().run_check(contracts)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "High"


def test_weak_randomness_modulo_needs_both_parts():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    uint256 public deadline;
    function set(uint256 d) public { deadline = block.timestamp + d; }
    function parity(uint256 x) public pure returns (uint256) { return x % 2; }
}
""")
    assert WeakRandomnessModuloRule().run_check(contracts) == []


# ----------------------------------------------------------------------
# tx_gasprice_dependency
# ----------------------------------------------------------------------

def test_tx_gasprice_dependency_fires():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    function refund(uint256 gasUsed) public view returns (uint256) {
        return gasUsed * tx.gasprice;
    }
}
""")
    findings = TxGaspriceDependencyRule().run_check(contracts)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "Low"


def test_tx_gasprice_dependency_ignores_comments():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    // tx.gasprice mentioned in a comment only
    function ping() public pure returns (bool) { return true; }
}
""")
    assert TxGaspriceDependencyRule().run_check(contracts) == []


# ----------------------------------------------------------------------
# block_gaslimit_dependency
# ----------------------------------------------------------------------

def test_block_gaslimit_dependency_fires():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    function batchSize() public view returns (uint256) {
        return block.gaslimit / 21000;
    }
}
""")
    findings = BlockGaslimitDependencyRule().run_check(contracts)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "Low"


def test_block_gaslimit_dependency_ignores_comments():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    // block.gaslimit mentioned in a comment only
    function ping() public pure returns (bool) { return true; }
}
""")
    assert BlockGaslimitDependencyRule().run_check(contracts) == []


# ----------------------------------------------------------------------
# ecrecover_unchecked
# ----------------------------------------------------------------------

def test_ecrecover_unchecked_fires():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) public balances;
    function claim(bytes32 d, uint8 v, bytes32 r, bytes32 s, uint256 a) public {
        address signer = ecrecover(d, v, r, s);
        balances[signer] += a;
    }
}
""")
    findings = EcrecoverUncheckedRule().run_check(contracts)
    assert len(findings) >= 1
    assert findings[0]["title"] == "ecrecover result not validated"


def test_ecrecover_checked_is_not_flagged():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    function recover(bytes32 d, uint8 v, bytes32 r, bytes32 s)
        public pure returns (address)
    {
        address signer = ecrecover(d, v, r, s);
        require(signer != address(0), "bad sig");
        return signer;
    }
}
""")
    assert EcrecoverUncheckedRule().run_check(contracts) == []


# ----------------------------------------------------------------------
# array_length_assignment
# ----------------------------------------------------------------------

def test_array_length_assignment_fires():
    contracts = _index("""
pragma solidity ^0.5.0;
contract T {
    uint256[] public items;
    function shrink() public {
        items.length = items.length - 1;
    }
}
""")
    findings = ArrayLengthAssignmentRule().run_check(contracts)
    assert len(findings) >= 1
    assert findings[0]["title"] == "Direct array length assignment"


def test_array_length_comparison_is_not_flagged():
    contracts = _index("""
pragma solidity ^0.8.0;
contract T {
    uint256[] public items;
    function check() public view returns (bool) {
        require(items.length <= 100);
        return items.length == 0;
    }
}
""")
    assert ArrayLengthAssignmentRule().run_check(contracts) == []


# ----------------------------------------------------------------------
# Production corpus: none of the seven rules may fire on PancakeSwap
# farms-pools (the no-false-positive gate).
# ----------------------------------------------------------------------

def test_no_false_positives_on_pancake_corpus():
    corpus = (
        Path(__file__).resolve().parents[1].parent
        / "demo/pancake-smart-contracts/projects/farms-pools/contracts"
    )
    if not corpus.is_dir():
        return  # corpus not present in this checkout
    contracts = RepositoryIndexer().index(str(corpus))["contracts"]
    for rule in (
        DivideBeforeMultiplyRule(),
        UnsafeDowncastRule(),
        WeakRandomnessModuloRule(),
        TxGaspriceDependencyRule(),
        BlockGaslimitDependencyRule(),
        EcrecoverUncheckedRule(),
        ArrayLengthAssignmentRule(),
    ):
        findings = rule.run_check(contracts)
        assert findings == [], (
            f"{type(rule).__name__} produced false positives: "
            f"{[(f['file'], f['line']) for f in findings]}"
        )
# EOF: tests/static_rule_engine/test_new_rules_math.py

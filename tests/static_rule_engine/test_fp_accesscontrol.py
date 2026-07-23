# File: tests/static_rule_engine/test_fp_accesscontrol.py
"""
False-positive regression tests for the access-control family of rules.

The tree-sitter parser does not extract modifier invocations and nests
functions under ``contracts`` in real scans, so these rules must detect
guards (onlyOwner-style modifiers, require(msg.sender == ...) checks,
if (msg.sender != ...) revert patterns) from the raw source text. Each rule
gets one guarded/production-shaped case that must NOT fire and one
unguarded/vulnerable case that MUST still fire.
"""

from hawki.core.static_rule_engine.rules.access_control_bypass import AccessControlBypassRule
from hawki.core.static_rule_engine.rules.centralized_owner import CentralizedOwnerRule
from hawki.core.static_rule_engine.rules.missing_initializer import MissingInitializerRule
from hawki.core.static_rule_engine.rules.tx_origin_auth import TxOriginAuthRule
from hawki.core.static_rule_engine.rules.tx_origin_dependency import TxOriginRule
from hawki.core.static_rule_engine.rules.upgrade_admin import UpgradeAdminRule
from hawki.core.static_rule_engine.rules.visibility import VisibilityRule


def _indexed(source, name, functions):
    """Build contract_data in the shape the RepositoryIndexer produces:
    file-level dict with functions nested under ``contracts``. Parsed
    functions carry empty ``modifiers`` (the parser never fills them) and
    no ``body``/``line`` fields."""
    return [{
        "path": "nonexistent_fp.sol",
        "source": source,
        "contracts": [{"name": name, "functions": functions}],
    }]


def _func(name, visibility="public", mutability="nonpayable"):
    return {
        "name": name,
        "parameters": [],
        "modifiers": [],  # parser gap: modifiers are never extracted
        "visibility": visibility,
        "state_mutability": mutability,
        "returns": [],
    }


# ----------------------------------------------------------------------
# access control bypass
# ----------------------------------------------------------------------
def test_access_control_bypass_ignores_source_guarded_function():
    # onlyOwner is present in the source but NOT in the parsed modifiers:
    # the exact production false positive seen on pancake SmartChef.
    source = (
        "contract SmartChef {\n"
        "    function emergencyRewardWithdraw(uint256 _amount) external onlyOwner {\n"
        "        rewardToken.safeTransfer(address(msg.sender), _amount);\n"
        "    }\n"
        "    function setOwner(address _o) external {\n"
        "        require(msg.sender == owner, 'not owner');\n"
        "        owner = _o;\n"
        "    }\n"
        "}\n"
    )
    cd = _indexed(source, "SmartChef", [
        _func("emergencyRewardWithdraw", visibility="external"),
        _func("setOwner", visibility="external"),
    ])
    assert AccessControlBypassRule().run_check(cd) == []


def test_access_control_bypass_ignores_user_scoped_withdraw():
    # WETH-style withdraw pays out the caller's own balance; not an
    # access-control issue even though it is unguarded.
    source = (
        "contract WBNB {\n"
        "    function withdraw(uint256 wad) public {\n"
        "        require(balanceOf[msg.sender] >= wad);\n"
        "        balanceOf[msg.sender] -= wad;\n"
        "        msg.sender.transfer(wad);\n"
        "    }\n"
        "}\n"
    )
    cd = _indexed(source, "WBNB", [_func("withdraw")])
    assert AccessControlBypassRule().run_check(cd) == []


def test_access_control_bypass_still_fires_on_unguarded_admin_function():
    source = (
        "contract Unprotected {\n"
        "    address private owner;\n"
        "    function changeOwner(address _newOwner) public {\n"
        "        owner = _newOwner;\n"
        "    }\n"
        "}\n"
    )
    cd = _indexed(source, "Unprotected", [_func("changeOwner")])
    findings = AccessControlBypassRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing access control on changeOwner"
    assert findings[0]["line"] == 3


def test_access_control_bypass_still_fires_on_drain_withdraw():
    source = (
        "contract Drainable {\n"
        "    function withdrawAll() public {\n"
        "        msg.sender.transfer(address(this).balance);\n"
        "    }\n"
        "}\n"
    )
    cd = _indexed(source, "Drainable", [_func("withdrawAll")])
    findings = AccessControlBypassRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["function_name"] == "withdrawAll"


def test_access_control_bypass_skips_interface_declarations():
    source = (
        "interface IWithdraw {\n"
        "    function withdraw(uint256 amount) external;\n"
        "}\n"
    )
    cd = _indexed(source, "IWithdraw", [_func("withdraw", visibility="external")])
    assert AccessControlBypassRule().run_check(cd) == []


# ----------------------------------------------------------------------
# upgrade admin
# ----------------------------------------------------------------------
def test_upgrade_admin_ignores_source_guarded_change():
    source = (
        "contract Timelock {\n"
        "    function setPendingAdmin(address pendingAdmin_) public {\n"
        "        require(msg.sender == address(this), 'Timelock only');\n"
        "        pendingAdmin = pendingAdmin_;\n"
        "    }\n"
        "    function setAdmin(address newAdmin) external onlyOwner {\n"
        "        admin = newAdmin;\n"
        "    }\n"
        "}\n"
    )
    cd = _indexed(source, "Timelock", [
        _func("setPendingAdmin"),
        _func("setAdmin", visibility="external"),
    ])
    assert UpgradeAdminRule().run_check(cd) == []


def test_upgrade_admin_still_fires_on_unguarded_change():
    source = (
        "contract Proxy {\n"
        "    function setAdmin(address newAdmin) public {\n"
        "        admin = newAdmin;\n"
        "    }\n"
        "}\n"
    )
    cd = _indexed(source, "Proxy", [_func("setAdmin")])
    findings = UpgradeAdminRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Unprotected upgrade admin change"


# ----------------------------------------------------------------------
# missing initializer
# ----------------------------------------------------------------------
def test_missing_initializer_ignores_contract_with_initializer_in_source():
    # dvd ShardsFeeVault/ClimberVault false positive: initializer modifier
    # exists in source but the parser never reports it.
    source = (
        "contract FeeVault is Initializable, Ownable {\n"
        "    constructor() {\n"
        "        _disableInitializers();\n"
        "    }\n"
        "    function initialize(address _owner) external initializer {\n"
        "        _initializeOwner(_owner);\n"
        "    }\n"
        "}\n"
    )
    cd = [{"path": "nonexistent_fp.sol", "source": source,
           "functions": [{"name": "initialize", "modifiers": []}]}]
    assert MissingInitializerRule().run_check(cd) == []


def test_missing_initializer_still_fires_when_truly_missing():
    source = (
        "contract Vault is UUPSUpgradeable {\n"
        "    function initialize(address admin) external {\n"
        "        _owner = admin;\n"
        "    }\n"
        "}\n"
    )
    cd = [{"path": "nonexistent_fp.sol", "source": source,
           "functions": [{"name": "initialize", "modifiers": []}]}]
    findings = MissingInitializerRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing initializer in upgradeable contract"


def test_missing_initializer_ignores_similarly_named_contract():
    # "SmartChefInitializable" as a contract NAME must not count as
    # inheriting from Initializable.
    source = (
        "contract SmartChefInitializable is Ownable {\n"
        "    function deposit(uint256 x) external {}\n"
        "}\n"
    )
    cd = [{"path": "nonexistent_fp.sol", "source": source, "functions": []}]
    assert MissingInitializerRule().run_check(cd) == []


# ----------------------------------------------------------------------
# centralized owner
# ----------------------------------------------------------------------
def test_centralized_owner_ignores_substring_owner_word():
    # "borrower" contains "owner" as a substring; word-boundary matching
    # must not treat it as an owner variable.
    cd = [{
        "path": "nonexistent_fp.sol",
        "source": "contract C {\n    address borrower;\n    function pause() public onlyOwner {}\n}",
        "functions": [{"name": "pause", "modifiers": ["onlyOwner"]}],
    }]
    assert CentralizedOwnerRule().run_check(cd) == []


def test_centralized_owner_still_fires_and_dedupes():
    cd = [{
        "path": "nonexistent_fp.sol",
        "source": "contract C {\n    address owner;\n    function pause() public onlyOwner {}\n    function unpause() public onlyOwner {}\n}",
        "functions": [
            {"name": "pause", "modifiers": ["onlyOwner"]},
            {"name": "unpause", "modifiers": ["onlyOwner"]},
        ],
    }]
    findings = CentralizedOwnerRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Centralized owner risk"


# ----------------------------------------------------------------------
# tx.origin auth
# ----------------------------------------------------------------------
def test_tx_origin_auth_ignores_eoa_check_and_comments():
    source = (
        "contract C {\n"
        "    function f() public {\n"
        "        // tx.origin would be dangerous here, so we require an EOA\n"
        "        require(msg.sender == tx.origin, 'no contracts');\n"
        "    }\n"
        "}\n"
    )
    cd = [{"path": "nonexistent_fp.sol", "source": source, "functions": []}]
    assert TxOriginAuthRule().run_check(cd) == []


def test_tx_origin_auth_still_fires_on_auth_use():
    source = (
        "contract C {\n"
        "    function f() public {\n"
        "        require(tx.origin == owner, 'no');\n"
        "        require(tx.origin == owner, 'same line count once');\n"
        "    }\n"
        "}\n"
    )
    cd = [{"path": "nonexistent_fp.sol", "source": source, "functions": []}]
    findings = TxOriginAuthRule().run_check(cd)
    assert len(findings) == 2  # one per line, deduped within a line
    assert findings[0]["title"] == "tx.origin used for authentication"


# ----------------------------------------------------------------------
# tx.origin dependency
# ----------------------------------------------------------------------
def test_tx_origin_dependency_ignores_comments_and_eoa_check():
    source = (
        "contract C {\n"
        "    /* never rely on tx.origin for auth */\n"
        "    function f() public {\n"
        "        if (msg.sender != tx.origin) revert NoContracts();\n"
        "    }\n"
        "}\n"
    )
    cd = [{"path": "nonexistent_fp.sol", "source": source, "functions": []}]
    assert TxOriginRule().run_check(cd) == []


def test_tx_origin_dependency_still_fires_on_real_use():
    source = (
        "contract C {\n"
        "    function f() public {\n"
        "        if (tx.origin != beneficiary) revert OriginNotBeneficiary();\n"
        "    }\n"
        "}\n"
    )
    cd = [{"path": "nonexistent_fp.sol", "source": source, "functions": []}]
    findings = TxOriginRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Use of tx.origin for authentication"


# ----------------------------------------------------------------------
# visibility
# ----------------------------------------------------------------------
def test_visibility_ignores_bodiless_declaration():
    source = (
        "abstract contract Base {\n"
        "    function _hook() public virtual;\n"
        "}\n"
    )
    cd = _indexed(source, "Base", [_func("_hook")])
    assert VisibilityRule().run_check(cd) == []


def test_visibility_still_fires_on_public_underscore_function():
    source = (
        "contract C {\n"
        "    function _mintTo(address to) public {\n"
        "        balances[to] += 1;\n"
        "    }\n"
        "}\n"
    )
    cd = _indexed(source, "C", [_func("_mintTo")])
    findings = VisibilityRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Public function that may be internal"
    assert findings[0]["line"] == 2

# File: tests/static_rule_engine/test_cov_rules_functions.py
"""
Coverage tests for static rules that operate on parsed `functions` metadata
(name / modifiers / visibility / body / parameters) rather than raw source.

Each rule gets a triggering contract_data (assert a finding + expected
title/severity) and a clean one (assert no finding), exercising both branches.
"""

from hawki.core.static_rule_engine.rules.access_control_bypass import AccessControlBypassRule
from hawki.core.static_rule_engine.rules.approval_race import ApprovalRaceRule
from hawki.core.static_rule_engine.rules.centralized_owner import CentralizedOwnerRule
from hawki.core.static_rule_engine.rules.reentrancy import ReentrancyRule
from hawki.core.static_rule_engine.rules.unsafe_external_call import UnsafeExternalCallRule
from hawki.core.static_rule_engine.rules.upgrade_admin import UpgradeAdminRule
from hawki.core.static_rule_engine.rules.visibility import VisibilityRule
from hawki.core.static_rule_engine.rules.zero_address_check import ZeroAddressCheckRule


# ----------------------------------------------------------------------
# access control bypass
# ----------------------------------------------------------------------
def test_access_control_bypass_triggers():
    cd = [{
        "path": "nonexistent.sol",
        "source": "contract C {\n    function withdraw() public {}\n}",
        "functions": [{"name": "withdraw", "visibility": "public", "modifiers": [], "body": "payable(msg.sender).transfer(1)"}],
    }]
    findings = AccessControlBypassRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing access control on withdraw"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["function_name"] == "withdraw"


def test_access_control_bypass_clean():
    cd = [{
        "path": "nonexistent.sol",
        "source": "contract C {\n    function withdraw() public onlyOwner {}\n}",
        "functions": [{"name": "withdraw", "visibility": "public", "modifiers": ["onlyOwner"], "body": ""}],
    }]
    assert AccessControlBypassRule().run_check(cd) == []
    # Non-sensitive function name is never flagged.
    cd2 = [{"path": "nonexistent.sol", "source": "", "functions": [{"name": "totalSupply", "modifiers": []}]}]
    assert AccessControlBypassRule().run_check(cd2) == []


# ----------------------------------------------------------------------
# approval race
# ----------------------------------------------------------------------
def test_approval_race_triggers():
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "approve", "line": 5, "body": "allowanceMap[msg.sender][s] = amount;"}]}]
    findings = ApprovalRaceRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "ERC20 approval race condition"
    # SWC-114 approve race is a well-known low-impact issue (present in most tokens).
    assert findings[0]["severity"] == "Low"


def test_approval_race_clean():
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "approve", "body": "require(allowance[msg.sender][s] == 0);"}]}]
    assert ApprovalRaceRule().run_check(cd) == []
    # No approve function at all.
    cd2 = [{"path": "nonexistent.sol", "functions": [{"name": "transfer", "body": ""}]}]
    assert ApprovalRaceRule().run_check(cd2) == []


# ----------------------------------------------------------------------
# centralized owner
# ----------------------------------------------------------------------
def test_centralized_owner_triggers():
    cd = [{
        "path": "nonexistent.sol",
        "source": "contract C {\n    address owner;\n    function pause() public onlyOwner {}\n}",
        "functions": [{"name": "pause", "modifiers": ["onlyOwner"]}],
    }]
    findings = CentralizedOwnerRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Centralized owner risk"
    assert findings[0]["severity"] == "Low"


def test_centralized_owner_clean():
    # Has owner var but no onlyOwner-guarded function -> not flagged.
    cd = [{
        "path": "nonexistent.sol",
        "source": "contract C {\n    address owner;\n    function pause() public {}\n}",
        "functions": [{"name": "pause", "modifiers": []}],
    }]
    assert CentralizedOwnerRule().run_check(cd) == []
    # No owner/admin at all.
    cd2 = [{"path": "nonexistent.sol", "source": "contract C {}", "functions": []}]
    assert CentralizedOwnerRule().run_check(cd2) == []


# ----------------------------------------------------------------------
# reentrancy (clean branch; trigger already covered in test_rules.py)
# ----------------------------------------------------------------------
def test_reentrancy_triggers():
    # Classic checks-effects-interactions violation: external .call then state write.
    src = (
        "contract C {\n"
        "  mapping(address => uint) bal;\n"
        "  function withdraw() public {\n"
        "    (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(\"\");\n"
        "    require(ok);\n"
        "    bal[msg.sender] = 0;\n"
        "  }\n"
        "}"
    )
    cd = [{"path": "V.sol", "source": src}]
    findings = ReentrancyRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["function_name"] == "withdraw"


def test_reentrancy_clean():
    # Fixed pattern (state written BEFORE the call) and a guarded function.
    src = (
        "contract C {\n"
        "  mapping(address => uint) bal;\n"
        "  function withdrawFixed() public {\n"
        "    uint amount = bal[msg.sender];\n"
        "    bal[msg.sender] = 0;\n"
        "    (bool ok, ) = msg.sender.call{value: amount}(\"\");\n"
        "    require(ok);\n"
        "  }\n"
        "  function guarded() public nonReentrant {\n"
        "    (bool ok, ) = msg.sender.call{value: 1}(\"\");\n"
        "    x = 0;\n"
        "  }\n"
        "}"
    )
    cd = [{"path": "V.sol", "source": src}]
    assert ReentrancyRule().run_check(cd) == []


# ----------------------------------------------------------------------
# unsafe external call (call then state write)
# ----------------------------------------------------------------------
def test_unsafe_external_call_triggers():
    body = "(bool ok, ) = msg.sender.call{value: amount}(\"\");\nbalances[msg.sender] = 0;"
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "withdraw", "line": 10, "body": body}]}]
    findings = UnsafeExternalCallRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "External call before state update (reentrancy risk)"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["function_name"] == "withdraw"


def test_unsafe_external_call_clean():
    # No external call in the body.
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "read", "line": 1, "body": "return balances[msg.sender];"}]}]
    assert UnsafeExternalCallRule().run_check(cd) == []
    # Call present but no assignment after it.
    cd2 = [{"path": "nonexistent.sol", "functions": [{"name": "ping", "line": 1, "body": "msg.sender.call(\"\");"}]}]
    assert UnsafeExternalCallRule().run_check(cd2) == []


# ----------------------------------------------------------------------
# upgrade admin
# ----------------------------------------------------------------------
def test_upgrade_admin_triggers_name():
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "changeAdmin", "line": 4, "modifiers": [], "body": ""}]}]
    findings = UpgradeAdminRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Unprotected upgrade admin change"
    assert findings[0]["severity"] == "Medium"


def test_upgrade_admin_triggers_body_assignment():
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "setup", "line": 4, "modifiers": [], "body": "admin = newAdmin;"}]}]
    findings = UpgradeAdminRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Admin variable assignment without access control"


def test_upgrade_admin_clean():
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "changeAdmin", "line": 4, "modifiers": ["onlyOwner"], "body": "require(msg.sender == owner); admin = newAdmin;"}]}]
    assert UpgradeAdminRule().run_check(cd) == []


# ----------------------------------------------------------------------
# visibility (public helper prefixed with underscore)
# ----------------------------------------------------------------------
def test_visibility_triggers():
    cd = [{"path": "nonexistent.sol", "functions": [{"name": "_helper", "visibility": "public", "line": 7}]}]
    findings = VisibilityRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Public function that may be internal"
    assert findings[0]["severity"] == "High"


def test_visibility_clean():
    cd = [{"path": "nonexistent.sol", "functions": [
        {"name": "_helper", "visibility": "internal", "line": 1},
        {"name": "transfer", "visibility": "public", "line": 2},
    ]}]
    assert VisibilityRule().run_check(cd) == []


# ----------------------------------------------------------------------
# zero address check
# ----------------------------------------------------------------------
def test_zero_address_check_triggers():
    cd = [{"path": "nonexistent.sol", "functions": [{
        "name": "setOwner", "line": 3,
        "parameters": [{"type": "address", "name": "newOwner"}],
        "body": "owner = newOwner;",
    }]}]
    findings = ZeroAddressCheckRule().run_check(cd)
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing zero-address check"
    assert findings[0]["severity"] == "Medium"


def test_zero_address_check_clean():
    cd = [{"path": "nonexistent.sol", "functions": [{
        "name": "setOwner", "line": 3,
        "parameters": [{"type": "address", "name": "newOwner"}],
        "body": "require(newOwner != address(0)); owner = newOwner;",
    }]}]
    assert ZeroAddressCheckRule().run_check(cd) == []
    # No address parameters -> nothing to check.
    cd2 = [{"path": "nonexistent.sol", "functions": [{"name": "setValue", "parameters": [{"type": "uint256", "name": "v"}], "body": ""}]}]
    assert ZeroAddressCheckRule().run_check(cd2) == []

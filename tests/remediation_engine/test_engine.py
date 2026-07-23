# --------------------
# File: tests/core/remediation_engine/test_engine.py
# --------------------
import json

import pytest

from hawki.core.remediation_engine import RemediationEngine


@pytest.fixture
def templates_dir(tmp_path):
    d = tmp_path / "templates"
    d.mkdir()
    # Create a sample template
    with open(d / "reentrancy.json", "w") as f:
        json.dump({"fix_snippet": "function {{function_name}}() nonReentrant {\n    // fix\n}"}, f)
    with open(d / "access_control.json", "w") as f:
        json.dump({"fix_snippet": "function {{function_name}}() onlyOwner {\n    // fix\n}"}, f)
    return d

def test_load_templates(templates_dir):
    engine = RemediationEngine(templates_dir=templates_dir)
    assert "reentrancy" in engine.templates
    assert "access_control" in engine.templates

def test_get_fix_with_known_rule(templates_dir):
    engine = RemediationEngine(templates_dir=templates_dir)
    finding = {"rule": "reentrancy", "function_name": "withdraw", "visibility": "public"}
    context = {"function_name": "withdraw", "visibility": "public"}
    fix = engine.get_fix(finding, context)
    assert "withdraw" in fix
    assert "nonReentrant" in fix

def test_get_fix_with_unknown_rule(templates_dir):
    engine = RemediationEngine(templates_dir=templates_dir)
    finding = {"rule": "unknown"}
    fix = engine.get_fix(finding, {})
    assert fix == "No specific fix snippet available. Review the code and apply secure patterns."

def test_placeholder_replacement(templates_dir):
    engine = RemediationEngine(templates_dir=templates_dir)
    # Add a template with multiple placeholders
    template = {
        "fix_snippet": "function {{func}}() {{vis}} {\n    require({{cond}});\n}"
    }
    engine.templates["custom"] = template
    finding = {"rule": "custom"}
    context = {"func": "foo", "vis": "public", "cond": "amount > 0"}
    fix = engine.get_fix(finding, context)
    assert "function foo() public" in fix
    assert "require(amount > 0);" in fix
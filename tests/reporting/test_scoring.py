# --------------------
# File: tests/core/reporting/test_scoring.py
# --------------------
from hawki.core.data_layer.reporting.scoring_engine import SecurityScoreEngine


def test_no_findings():
    engine = SecurityScoreEngine()
    result = engine.calculate([])
    assert result["score"] == 100
    assert result["classification"] == "Secure"

def test_single_critical():
    engine = SecurityScoreEngine()
    findings = [{"severity": "Critical"}]
    result = engine.calculate(findings)
    assert result["score"] == 85
    assert result["classification"] == "Minor Risk"

def test_mixed_severities():
    engine = SecurityScoreEngine()
    findings = [
        {"severity": "Critical"},
        {"severity": "High"},
        {"severity": "Medium"},
        {"severity": "Low"},
    ]
    result = engine.calculate(findings)
    # Deductions: 15+8+4+1 = 28, score = 72
    assert result["score"] == 72
    assert result["classification"] == "Moderate Risk"

def test_simulation_penalty():
    engine = SecurityScoreEngine()
    findings = [{"severity": "Critical"}]
    sandbox = [{"success": True}, {"success": True}]
    result = engine.calculate(findings, sandbox_results=sandbox)
    # Deductions: 15 + 2*5 = 25, score = 75
    assert result["score"] == 75
    assert result["classification"] == "Minor Risk"
    assert result["deductions"]["simulation_penalty"] == 2

def test_clamping():
    engine = SecurityScoreEngine()
    findings = [{"severity": "Critical"} for _ in range(10)]
    result = engine.calculate(findings)
    assert result["score"] == 0
    assert result["classification"] == "Critical Risk"

# EOF: tests/core/reporting/test_scoring.py
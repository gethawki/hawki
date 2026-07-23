# File: tests/static_rule_engine/test_cov_rules_engine.py
"""
Coverage tests for the RuleEngine and the shared BaseRule helpers
(normalize_severity, _create_finding, snippet extraction with real file
context, fragment cleaning) plus the engine's failing-rule branch.
"""


from hawki.core.static_rule_engine import RuleEngine
from hawki.core.static_rule_engine.rules import BaseRule, normalize_severity


# ----------------------------------------------------------------------
# normalize_severity
# ----------------------------------------------------------------------
def test_normalize_severity_aliases_and_unknown():
    assert normalize_severity("critical") == "Critical"
    assert normalize_severity("HIGH") == "High"
    assert normalize_severity("moderate") == "Medium"
    assert normalize_severity("informational") == "Info"
    assert normalize_severity("") == "Info"
    assert normalize_severity(None) == "Info"
    # Unknown value is Title-cased rather than dropped.
    assert normalize_severity("bogus") == "Bogus"


# ----------------------------------------------------------------------
# BaseRule._create_finding + snippet extraction
# ----------------------------------------------------------------------
class _Probe(BaseRule):
    severity = "High"

    def run_check(self, contract_data):
        return []


def test_create_finding_reads_real_file_context(tmp_path):
    sol = tmp_path / "Sample.sol"
    sol.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "contract Sample {\n"
        "    function random() public view returns (uint) {\n"
        "        return uint(blockhash(block.number - 1));\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    probe = _Probe()
    finding = probe._create_finding(
        title="test",
        file=str(sol),
        line=4,
        vulnerable_snippet="ignored fallback",
    )
    snippet = finding["vulnerable_snippet"]
    # Real context is line-numbered with a marker on the flagged line.
    assert "blockhash" in snippet
    assert ">" in snippet
    assert finding["severity"] == "High"
    assert finding["file"] == str(sol)
    assert finding["line"] == 4


def test_create_finding_falls_back_to_cleaned_fragment():
    probe = _Probe()
    finding = probe._create_finding(
        title="test",
        file="does_not_exist.sol",
        line=3,
        vulnerable_snippet="\n        uint x = 1;\n",
    )
    # No readable file -> the supplied fragment is cleaned (dedented/stripped).
    assert finding["vulnerable_snippet"] == "uint x = 1;"


def test_create_finding_snippet_unavailable_placeholder():
    probe = _Probe()
    finding = probe._create_finding(
        title="test",
        file="",
        line=0,
        vulnerable_snippet="",
    )
    assert finding["vulnerable_snippet"] == "// snippet unavailable"
    assert finding["file"] == "unknown"
    assert finding["line"] == "?"


def test_read_snippet_out_of_range_returns_none(tmp_path):
    sol = tmp_path / "Tiny.sol"
    sol.write_text("contract T {}\n", encoding="utf-8")
    probe = _Probe()
    # Line far beyond file length -> extraction returns None, fallback used.
    finding = probe._create_finding("t", str(sol), 999, "fallback snippet")
    assert finding["vulnerable_snippet"] == "fallback snippet"


# ----------------------------------------------------------------------
# RuleEngine
# ----------------------------------------------------------------------
def test_engine_discovers_many_rules():
    engine = RuleEngine()
    assert len(engine.rules) >= 25
    names = {r.__class__.__name__ for r in engine.rules}
    assert "ReentrancyRule" in names


def test_engine_run_all_full_pipeline():
    engine = RuleEngine()
    contract_data = [{
        "path": "nonexistent.sol",
        "source": "contract C {\n    function f() public {\n        address a = tx.origin;\n    }\n}",
        "functions": [{"name": "withdraw", "state_mutability": "payable", "modifiers": [], "line": 2, "visibility": "public"}],
    }]
    findings = engine.run_all(contract_data)
    assert len(findings) >= 1
    for f in findings:
        # run_all enriches every finding with these fields.
        assert "explanation" in f
        assert "impact" in f
        assert "fix_snippet" in f
        assert "rule" in f
        # rule id is class name minus "Rule", lowercased.
        assert f["rule"] == f["rule"].lower()


class _BoomRule(BaseRule):
    severity = "High"

    def run_check(self, contract_data):
        raise RuntimeError("boom")


def test_engine_swallows_failing_rule():
    engine = RuleEngine()
    engine.rules = [_BoomRule()]
    # A rule that raises must not crash run_all; it just yields no findings.
    assert engine.run_all([{"path": "x.sol"}]) == []

# File: tests/reporting/test_cov_report_generator.py
"""Coverage tests for ReportGeneratorV2 and ReportManager (data_layer).

These exercise the real Jinja2 rendering paths for md/html/json/immunefi,
the _build_context branches, and the static helpers _first_sentence /
_infer_cwe. matplotlib may or may not be installed; the assertions here do
not depend on charts actually being produced. pdfkit is patched so no real
PDF (or wkhtmltopdf) is ever invoked.
"""

import json
import types

import pytest

from hawki.core.data_layer.report_manager import ReportManager
from hawki.core.data_layer.reporting import report_generator_v2 as rgv2
from hawki.core.data_layer.reporting.report_generator_v2 import ReportGeneratorV2

# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------

def _scan_metadata(ai=False, sandbox=False):
    return {
        "mode": "full",
        "ai_enabled": ai,
        "sandbox_enabled": sandbox,
        "total_scanned_contracts": 3,
        "total_files": 5,
    }


def _repo_data(sandbox_results=None):
    data = {"path": "/tmp/repo", "type": "local"}
    if sandbox_results is not None:
        data["sandbox_results"] = sandbox_results
    return data


def _finding(**over):
    base = {
        "id": "F001",
        "title": "Reentrancy in withdraw()",
        "severity": "Critical",
        "file": "Vault.sol",
        "line": 42,
        "vulnerable_snippet": "msg.sender.call{value: amount}('');",
        "fix_snippet": "use checks-effects-interactions",
        "explanation": "The function makes an external call before updating state. This is bad.",
        "impact": "An attacker can drain all funds.",
    }
    base.update(over)
    return base


@pytest.fixture
def manager(tmp_path):
    return ReportManager(output_dir=tmp_path)


# --------------------------------------------------------------------------
# ReportManager.generate_report -- markdown (audit)
# --------------------------------------------------------------------------

def test_generate_markdown_basic(manager):
    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="md",
    )
    assert out.exists()
    text = out.read_text()
    assert out.suffix == ".md"
    assert "Hawk-i Audit Report" in text
    assert "Reentrancy in withdraw()" in text
    # severity table present
    assert "| Critical |" in text
    # security score line
    assert "/100" in text


def test_markdown_degradation_notes(manager):
    """AI + sandbox disabled -> the 'not performed' style notes appear."""
    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(ai=False, sandbox=False),
        output_format="md",
    )
    text = out.read_text()
    assert "AI reasoning was not enabled" in text
    assert "Exploit simulation was not executed" in text
    # Additional modules all absent -> their "not performed" branches
    assert "Not performed." in text          # bytecode
    assert "No vulnerable dependencies found" in text
    assert "No upgrade safety issues detected" in text
    assert "No formal verification issues found" in text
    assert "Deep agent not run." in text


def test_markdown_all_modules(manager):
    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(ai=True, sandbox=True),
        output_format="md",
        bytecode_result={
            "match": False,
            "onchain_hash": "0xabc",
            "compiled_hash": "0xdef",
            "diff_summary": "bytecode differs",
        },
        dependency_findings=[
            {"package": "openzeppelin", "installed_version": "4.0.0",
             "vulnerable_versions": "<4.4.0", "severity": "High"}
        ],
        upgrade_findings=[
            {"file": "Proxy.sol", "title": "storage collision", "severity": "High"}
        ],
        formal_findings=[
            {"title": "invariant broken", "severity": "Medium", "description": "x != y"}
        ],
        deep_agent_stats={
            "total_attempts": 10, "successful": 3, "rule_attempts": 6,
            "novel_attempts": 4, "novel_successes": 2,
        },
        deep_agent_timeline=[
            {"timestamp": "t0", "type": "rule", "name": "reentrancy", "success": True},
            {"timestamp": "t1", "type": "novel", "name": "flashloan", "success": False},
        ],
    )
    text = out.read_text()
    assert "bytecode differs" in text
    assert "openzeppelin" in text
    assert "storage collision" in text
    assert "invariant broken" in text
    assert "Hawk-i Deep Agent Campaign" in text
    assert "Total attempts:" in text
    assert 'reentrancy' in text  # timeline


# --------------------------------------------------------------------------
# HTML + JSON
# --------------------------------------------------------------------------

def test_generate_html(manager):
    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="html",
    )
    assert out.exists()
    assert out.suffix == ".html"
    text = out.read_text()
    assert "Reentrancy in withdraw()" in text


def test_generate_json(manager):
    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="json",
    )
    assert out.exists()
    assert out.suffix == ".json"
    data = json.loads(out.read_text())
    assert data["total_findings"] == 1
    assert data["findings"][0]["title"] == "Reentrancy in withdraw()"
    # cwe inferred from title
    assert data["findings"][0]["cwe_id"] == "841"
    # function extracted from "in withdraw("
    assert data["findings"][0]["function_name"] == "withdraw"
    assert "score" in data
    assert data["severity_counts"]["Critical"] == 1


def test_unsupported_format_raises(manager):
    with pytest.raises(ValueError):
        manager.generate_report(
            findings=[_finding()],
            repo_data=_repo_data(),
            scan_metadata=_scan_metadata(),
            output_format="xml",
        )


# --------------------------------------------------------------------------
# Immunefi style
# --------------------------------------------------------------------------

def test_immunefi_style(manager):
    out = manager.generate_report(
        findings=[_finding(exploit_steps=["step one", "step two"])],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="md",
        style="immunefi",
    )
    assert out.exists()
    assert "immunefi_report_" in out.name
    text = out.read_text()
    assert "Critical: Reentrancy in withdraw()" in text
    assert "Steps to Reproduce" in text
    assert "1. step one" in text
    assert "2. step two" in text
    # CWE reference for reentrancy (841) rendered
    assert "CWE-841" in text


def test_immunefi_forces_md(manager):
    """Immunefi + html requested -> forced to md, file still produced."""
    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="html",
        style="immunefi",
    )
    assert out.exists()
    assert out.suffix == ".md"


def test_immunefi_no_steps(manager):
    out = manager.generate_report(
        findings=[_finding(explanation="", impact="")],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="md",
        style="immunefi",
    )
    text = out.read_text()
    assert "No steps provided." in text


# --------------------------------------------------------------------------
# _build_context branch coverage (via json render)
# --------------------------------------------------------------------------

def test_context_empty_finding_defaults(manager):
    """A near-empty finding exercises all the fallback defaults."""
    out = manager.generate_report(
        findings=[{}],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="json",
    )
    f = json.loads(out.read_text())["findings"][0]
    assert f["id"] == "F001"                     # generated id
    assert f["title"] == "Unknown Issue"
    assert f["file"] == "unknown"
    assert f["line"] == "?"
    assert f["vulnerable_snippet"] == "// snippet unavailable"
    assert f["fix_snippet"] == "No fix provided."
    assert f["explanation"] == "No explanation available for this finding."
    assert f["summary"] == "No summary provided."
    assert f["impact"] == "No impact analysis available for this finding."
    assert f["cwe_id"] == "Unknown"
    assert f["function_name"] == ""


def test_context_explicit_function_name(manager):
    out = manager.generate_report(
        findings=[_finding(title="Some generic issue", function_name="doStuff")],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="json",
    )
    f = json.loads(out.read_text())["findings"][0]
    assert f["function_name"] == "doStuff"


def test_context_line_zero_falls_back(manager):
    out = manager.generate_report(
        findings=[_finding(line=0)],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="json",
    )
    f = json.loads(out.read_text())["findings"][0]
    assert f["line"] == "?"


def test_context_line_string_preserved(manager):
    out = manager.generate_report(
        findings=[_finding(line="L10")],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="json",
    )
    f = json.loads(out.read_text())["findings"][0]
    assert f["line"] == "L10"


# --------------------------------------------------------------------------
# Sandbox linking + simulation success rate
# --------------------------------------------------------------------------

def test_sandbox_linking_and_success_rate(manager):
    sandbox = [
        {
            "attack_name": "reentrancy_attack.py",
            "success": True,
            "before_balance": 100,
            "after_balance": 0,
            "gas_used": 21000,
            "transaction_hash": "0xhash",
            "logs": "drained",
        },
        {"attack_name": "overflow_attack.py", "success": False},
    ]
    out = manager.generate_report(
        findings=[_finding()],   # title contains "reentrancy"
        repo_data=_repo_data(sandbox_results=sandbox),
        scan_metadata=_scan_metadata(sandbox=True),
        output_format="json",
    )
    data = json.loads(out.read_text())
    assert data["simulation_success_rate"].startswith("1/2")
    steps = data["findings"][0]["exploit_steps"]
    assert any("Exploit succeeded using script" in s for s in steps)
    assert any("0xhash" in s for s in steps)


def test_empty_sandbox_no_rate(manager):
    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(sandbox_results=[]),
        scan_metadata=_scan_metadata(),
        output_format="json",
    )
    data = json.loads(out.read_text())
    assert data["simulation_success_rate"] is None


# --------------------------------------------------------------------------
# Static helpers
# --------------------------------------------------------------------------

def test_first_sentence_basic():
    assert ReportGeneratorV2._first_sentence("Hello world. More text.") == "Hello world."


def test_first_sentence_empty():
    assert ReportGeneratorV2._first_sentence("") == "No summary provided."
    assert ReportGeneratorV2._first_sentence(None) == "No summary provided."


def test_first_sentence_no_punctuation():
    assert ReportGeneratorV2._first_sentence("no terminator here") == "no terminator here"


def test_first_sentence_decimal_not_split():
    # "block.number" / decimals should not cut the sentence
    txt = "The value is 3.14 and block.number is used here as seed. Second."
    result = ReportGeneratorV2._first_sentence(txt)
    assert result == "The value is 3.14 and block.number is used here as seed."


def test_first_sentence_truncation():
    long = "word " * 60  # 300 chars, no terminator
    result = ReportGeneratorV2._first_sentence(long)
    assert len(result) <= 200
    assert result.endswith("...")


@pytest.mark.parametrize("title,cwe", [
    ("Reentrancy attack", "841"),
    ("Integer overflow found", "190"),
    ("Integer underflow found", "191"),
    ("unchecked send call", "252"),
    ("Unbounded loop gas", "400"),
    ("delegatecall to untrusted", "829"),
    ("front running risk", "362"),
    ("weak randomness", "330"),
    ("flash loan attack", "682"),
    ("price oracle manipulation", "20"),
    ("governance takeover", "284"),
    ("signature malleability", "347"),
    ("tx.origin auth", "477"),
    ("hardcoded secret", "798"),
    ("re-initialize bug", "665"),
    # "uninitialized" contains "initializ", so 665 matches first (824 is
    # effectively shadowed) -- assert the actual ordered behaviour.
    ("uninitialized proxy", "665"),
    ("function visibility", "710"),
    ("access control missing", "284"),
    ("onlyowner missing", "284"),
    ("selfdestruct reachable", "284"),
    ("something totally unrelated", "Unknown"),
    ("", "Unknown"),
])
def test_infer_cwe(title, cwe):
    gen = ReportGeneratorV2.__new__(ReportGeneratorV2)
    assert gen._infer_cwe(title) == cwe


# --------------------------------------------------------------------------
# ReportManager.save_findings + _count_severities
# --------------------------------------------------------------------------

def test_save_findings_basic(manager):
    findings = [_finding(severity="Critical"), _finding(severity="low")]
    out = manager.save_findings(findings, {"path": "/tmp/x", "contracts": ["a"]})
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["severity_counts"]["Critical"] == 1
    assert data["summary"]["severity_counts"]["Low"] == 1
    # contracts key stripped from repository section
    assert "contracts" not in data["repository"]


def test_save_findings_with_sandbox(manager):
    findings = [_finding()]
    repo = {
        "path": "/tmp/x",
        "sandbox_results": [{"success": True}, {"success": False}],
    }
    out = manager.save_findings(findings, repo)
    data = json.loads(out.read_text())
    assert data["summary"]["sandbox_scripts_run"] == 2
    assert data["summary"]["sandbox_successful"] == 1
    assert "sandbox_results" in data


def test_count_severities(manager):
    findings = [
        {"severity": "Critical"},
        {"severity": "critical"},
        {"severity": "High"},
        {"severity": None},          # -> Info
        {},                          # missing severity -> Info
    ]
    counts = manager._count_severities(findings)
    assert counts["Critical"] == 2
    assert counts["High"] == 1
    assert counts["Info"] == 2


# --------------------------------------------------------------------------
# PDF path (patched -- no real wkhtmltopdf)
# --------------------------------------------------------------------------

def test_pdf_render_patched(manager, monkeypatch):
    calls = {}

    def fake_from_file(html, pdf):
        calls["html"] = html
        calls["pdf"] = pdf
        # Simulate pdfkit writing the file
        with open(pdf, "w") as fh:
            fh.write("%PDF-1.4 fake")

    fake_pdfkit = types.SimpleNamespace(from_file=fake_from_file)
    monkeypatch.setattr(rgv2, "PDFKIT_AVAILABLE", True)
    monkeypatch.setattr(rgv2, "pdfkit", fake_pdfkit, raising=False)

    out = manager.generate_report(
        findings=[_finding()],
        repo_data=_repo_data(),
        scan_metadata=_scan_metadata(),
        output_format="pdf",
    )
    assert out.exists()
    assert out.suffix == ".pdf"
    assert calls["html"].endswith(".html")


def test_pdf_render_unavailable_raises(manager, monkeypatch):
    monkeypatch.setattr(rgv2, "PDFKIT_AVAILABLE", False)
    with pytest.raises(RuntimeError):
        manager.generate_report(
            findings=[_finding()],
            repo_data=_repo_data(),
            scan_metadata=_scan_metadata(),
            output_format="pdf",
        )


# --------------------------------------------------------------------------
# ReportGeneratorV2 constructor + default ReportManager dir
# --------------------------------------------------------------------------

def test_generator_creates_output_dir(tmp_path):
    target = tmp_path / "nested" / "reports"
    gen = ReportGeneratorV2(target)
    assert target.exists()
    assert gen.template_dir.name == "templates"

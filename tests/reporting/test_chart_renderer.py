# --------------------
# File: tests/reporting/test_chart_renderer.py
# --------------------
"""Tests for ChartRenderer: findings charts and deep-agent campaign charts.

matplotlib ships in the reports extra and is present in the test venv, so these
exercise the real render path (no mocking). If matplotlib were absent the
methods return [] by contract, which the empty-input cases below also assert.
"""
from hawki.core.data_layer.reporting.chart_renderer import (
    MATPLOTLIB_AVAILABLE,
    ChartRenderer,
)


def test_findings_charts_written_to_own_dir(tmp_path):
    renderer = ChartRenderer(tmp_path / "charts")
    findings = [
        {"severity": "Critical", "title": "Reentrancy in withdraw"},
        {"severity": "High", "title": "Reentrancy in claim"},
        {"severity": "Low", "title": "Missing input validation"},
    ]
    paths = renderer.generate_charts(findings)
    if not MATPLOTLIB_AVAILABLE:
        assert paths == []
        return
    names = sorted(p.name for p in paths)
    assert names == ["severity_pie.png", "type_bar.png"]
    for p in paths:
        assert p.parent.name == "charts"
        assert p.exists() and p.stat().st_size > 0


def test_no_findings_no_charts(tmp_path):
    renderer = ChartRenderer(tmp_path / "charts")
    assert renderer.generate_charts([]) == []


def test_deep_charts_from_campaign_stats(tmp_path):
    renderer = ChartRenderer(tmp_path / "charts")
    stats = {
        "total_attempts": 35,
        "successful": 3,
        "rule_attempts": 31,
        "novel_attempts": 4,
        "novel_successes": 3,
    }
    paths = renderer.generate_deep_charts(stats)
    if not MATPLOTLIB_AVAILABLE:
        assert paths == []
        return
    names = sorted(p.name for p in paths)
    # outcomes bar always; novel split pie because novel_attempts > 0
    assert names == ["deep_novel_split.png", "deep_outcomes.png"]
    for p in paths:
        assert p.parent.name == "charts"
        assert p.exists() and p.stat().st_size > 0


def test_deep_charts_rule_only_no_novel_split(tmp_path):
    renderer = ChartRenderer(tmp_path / "charts")
    stats = {
        "total_attempts": 5,
        "successful": 1,
        "rule_attempts": 5,
        "novel_attempts": 0,
        "novel_successes": 0,
    }
    paths = renderer.generate_deep_charts(stats)
    if not MATPLOTLIB_AVAILABLE:
        assert paths == []
        return
    # no novel attempts -> only the outcomes chart, no novel-split pie
    assert [p.name for p in paths] == ["deep_outcomes.png"]


def test_deep_charts_empty_stats(tmp_path):
    renderer = ChartRenderer(tmp_path / "charts")
    assert renderer.generate_deep_charts({}) == []
    assert renderer.generate_deep_charts({"total_attempts": 0}) == []

# EOF: tests/reporting/test_chart_renderer.py

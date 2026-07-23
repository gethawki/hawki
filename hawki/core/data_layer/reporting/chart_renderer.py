# --------------------
# File: hawki/core/data_layer/reporting/chart_renderer.py
# --------------------
"""
Chart Renderer - generates severity pie chart and vulnerability type bar chart.
Uses matplotlib if available; otherwise logs a warning and returns empty list.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    # Do not warn at import time: this module is imported for every CLI command,
    # so an unconditional notice here would print on unrelated commands. The
    # notice is emitted lazily below, only when charts are actually requested.
    # Logging is configured to write to stderr, so the notice never touches stdout.


class ChartRenderer:
    """Generates visual charts from findings data."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        # Tolerate an unwritable target (e.g. a Docker volume owned by another
        # uid): charts are optional, so defer failure to generate_charts, which
        # degrades to an empty list rather than crashing the whole report.
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(f"Could not create charts directory {self.output_dir}: {exc}. Charts disabled.")

    def _writable(self) -> bool:
        """True only if charts can actually be written to output_dir."""
        return self.output_dir.is_dir() and os.access(self.output_dir, os.W_OK)

    def generate_charts(self, findings: List[Dict[str, Any]]) -> List[Path]:
        """
        Create severity pie chart and vulnerability type bar chart.
        Returns list of paths to generated PNG images (empty if matplotlib unavailable).
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning(
                "matplotlib not installed. Chart generation disabled. "
                "Install the reports extra with 'pip install hawki[reports]' to enable charts."
            )
            return []

        if not findings:
            logger.debug("No findings to chart")
            return []

        if not self._writable():
            logger.warning(f"Charts directory {self.output_dir} is not writable. Charts disabled.")
            return []

        chart_paths = []

        # 1. Severity pie chart
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "Low").capitalize()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts:
            fig, ax = plt.subplots(figsize=(8, 6))
            colors = {"Critical": "#8B0000", "High": "#FF4500", "Medium": "#FFA500", "Low": "#32CD32"}
            wedges, texts, autotexts = ax.pie(
                severity_counts.values(),
                labels=severity_counts.keys(),
                autopct="%1.1f%%",
                colors=[colors.get(k, "#687F97") for k in severity_counts.keys()],
                textprops={"color": "white", "fontsize": 12},
            )
            ax.set_title("Findings by Severity", color="white", fontsize=16)
            plt.tight_layout()
            pie_path = self.output_dir / "severity_pie.png"
            plt.savefig(pie_path, facecolor="#0c0c0c", edgecolor="none")
            plt.close()
            chart_paths.append(pie_path)

        # 2. Vulnerability type bar chart (top 10)
        type_counts = {}
        for f in findings:
            vuln_type = f.get("title", "").split()[0] if f.get("title") else "Unknown"
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1

        if type_counts:
            sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            types, counts = zip(*sorted_types) if sorted_types else ([], [])

            fig, ax = plt.subplots(figsize=(10, 6))
            ax.set_facecolor("#0c0c0c")
            ax.bar(types, counts, color="#687F97")
            ax.set_xlabel("Vulnerability Type", color="white")
            ax.set_ylabel("Count", color="white")
            ax.set_title("Top Vulnerability Types", color="white", fontsize=16)
            ax.tick_params(axis="x", rotation=45, colors="white")
            ax.tick_params(axis="y", colors="white")
            for spine in ax.spines.values():
                spine.set_color("#77746C")
            plt.tight_layout()
            bar_path = self.output_dir / "type_bar.png"
            plt.savefig(bar_path, facecolor="#0c0c0c", edgecolor="none")
            plt.close()
            chart_paths.append(bar_path)

        return chart_paths

    def generate_deep_charts(self, deep_stats: Dict[str, Any]) -> List[Path]:
        """
        Create charts summarising a Deep agent campaign: an attempted-vs-landed
        bar chart split by planner (rule vs novel), and a pie of how the novel
        attacks the agent invented turned out. Derived purely from the campaign
        stats, so it is always valid even when the run produced no static
        findings. Returns list of PNG paths (empty if matplotlib unavailable or
        there is nothing to chart).
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning(
                "matplotlib not installed. Chart generation disabled. "
                "Install the reports extra with 'pip install hawki[reports]' to enable charts."
            )
            return []

        if not deep_stats:
            logger.debug("No deep agent stats to chart")
            return []

        if not self._writable():
            logger.warning(f"Charts directory {self.output_dir} is not writable. Charts disabled.")
            return []

        total = deep_stats.get("total_attempts", 0)
        rule = deep_stats.get("rule_attempts", 0)
        novel = deep_stats.get("novel_attempts", 0)
        novel_successes = deep_stats.get("novel_successes", 0)
        successful = deep_stats.get("successful", 0)
        rule_successes = max(successful - novel_successes, 0)

        if not total:
            return []

        chart_paths = []

        # 1. Attempted vs landed, grouped by planner.
        groups = ["Rule", "Novel"]
        attempted = [rule, novel]
        landed = [rule_successes, novel_successes]
        x = range(len(groups))
        width = 0.38

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.set_facecolor("#0c0c0c")
        ax.bar([i - width / 2 for i in x], attempted, width, label="Attempted", color="#687F97")
        ax.bar([i + width / 2 for i in x], landed, width, label="Landed", color="#986C67")
        ax.set_xticks(list(x))
        ax.set_xticklabels(groups)
        ax.set_ylabel("Attacks", color="white")
        ax.set_title("Deep Agent: attempted vs landed", color="white", fontsize=16)
        ax.tick_params(axis="x", colors="white")
        ax.tick_params(axis="y", colors="white")
        for spine in ax.spines.values():
            spine.set_color("#77746C")
        ax.legend(labelcolor="white", facecolor="#0c0c0c", edgecolor="#77746C")
        plt.tight_layout()
        outcomes_path = self.output_dir / "deep_outcomes.png"
        plt.savefig(outcomes_path, facecolor="#0c0c0c", edgecolor="none")
        plt.close()
        chart_paths.append(outcomes_path)

        # 2. How the invented novel attacks resolved.
        if novel:
            labels, sizes, colors = [], [], []
            if novel_successes:
                labels.append("Landed")
                sizes.append(novel_successes)
                colors.append("#986C67")
            novel_failures = max(novel - novel_successes, 0)
            if novel_failures:
                labels.append("Failed")
                sizes.append(novel_failures)
                colors.append("#3A4D5E")
            if sizes:
                fig, ax = plt.subplots(figsize=(8, 6))
                ax.pie(
                    sizes,
                    labels=labels,
                    autopct="%1.0f%%",
                    colors=colors,
                    textprops={"color": "white", "fontsize": 12},
                )
                ax.set_title("Novel attacks invented by the agent", color="white", fontsize=16)
                plt.tight_layout()
                split_path = self.output_dir / "deep_novel_split.png"
                plt.savefig(split_path, facecolor="#0c0c0c", edgecolor="none")
                plt.close()
                chart_paths.append(split_path)

        return chart_paths

# EOF: hawki/core/data_layer/reporting/chart_renderer.py
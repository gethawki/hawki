# File: hawki/core/data_layer/reporting/report_generator_v2.py
"""
Audit-Grade Report Generator v2 - v1.0.0 with full module support and Immunefi style.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .chart_renderer import ChartRenderer
from .scoring_engine import SecurityScoreEngine, normalize_severity

try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    logging.getLogger(__name__).warning("jinja2 not installed. HTML/Markdown reports disabled.")

try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

logger = logging.getLogger(__name__)


class ReportGeneratorV2:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scoring_engine = SecurityScoreEngine()
        self.chart_renderer = ChartRenderer(output_dir / "charts")
        self.template_dir = Path(__file__).parent / "templates"

    def generate(
        self,
        repo_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        scan_metadata: Dict[str, Any],
        output_format: str = "md",
        style: str = "audit",  # NEW: 'audit' or 'immunefi'
        # Additional module results
        bytecode_result: Optional[Dict[str, Any]] = None,
        dependency_findings: Optional[List[Dict[str, Any]]] = None,
        upgrade_findings: Optional[List[Dict[str, Any]]] = None,
        formal_findings: Optional[List[Dict[str, Any]]] = None,
        deep_agent_stats: Optional[Dict[str, Any]] = None,
        deep_agent_timeline: Optional[List[Dict[str, Any]]] = None,
    ) -> Path:
        """Generate a unified report with all available sections."""
        # Compute score with all modules
        score_result = self.scoring_engine.calculate(
            findings=findings,
            sandbox_results=repo_data.get("sandbox_results"),
            ai_enabled=scan_metadata.get("ai_enabled", False),
            bytecode_result=bytecode_result,
            dependency_findings=dependency_findings,
            upgrade_findings=upgrade_findings,
            formal_findings=formal_findings,
            deep_agent_stats=deep_agent_stats,
        )

        # Generate charts only if format supports images (and style is audit)
        chart_paths = []
        if output_format in ("md", "html", "pdf") and style == "audit":
            chart_paths = self.chart_renderer.generate_charts(findings)
            # Deep agent campaigns get their own charts (attempted-vs-landed and
            # the novel-attack split), so a deep run's report is not chartless
            # just because it produced no static findings.
            if deep_agent_stats:
                chart_paths = chart_paths + self.chart_renderer.generate_deep_charts(deep_agent_stats)

        context = self._build_context(
            repo_data, findings, scan_metadata, score_result, chart_paths,
            bytecode_result, dependency_findings, upgrade_findings,
            formal_findings, deep_agent_stats, deep_agent_timeline
        )

        # Render based on style and format
        if style == "immunefi":
            # Only Markdown is supported for Immunefi
            if output_format != "md":
                logger.warning("Immunefi style only supports Markdown. Forcing output_format='md'.")
                output_format = "md"
            return self._render_immunefi(context)

        if output_format == "json":
            return self._render_json(context)
        elif output_format == "md":
            return self._render_markdown(context)
        elif output_format == "html":
            return self._render_html(context)
        elif output_format == "pdf":
            return self._render_pdf(context)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _build_context(
        self,
        repo_data,
        findings,
        scan_metadata,
        score_result,
        chart_paths,
        bytecode_result,
        dependency_findings,
        upgrade_findings,
        formal_findings,
        deep_agent_stats,
        deep_agent_timeline,
    ) -> Dict[str, Any]:
        """Assemble all data for templates."""
        # Per-finding details with extra fields for Immunefi
        detailed_findings = []
        for idx, f in enumerate(findings, 1):
            # Extract function name from title or file (heuristic)
            function_name = f.get("function_name", "")
            if not function_name:
                # Try to extract from title
                match = re.search(r'in\s+(\w+)\s*\(', f.get("title", ""))
                if match:
                    function_name = match.group(1)

            # Build summary for Immunefi (first real sentence of explanation).
            explanation = (f.get("explanation") or "").strip()
            if explanation:
                summary = self._first_sentence(explanation)
            else:
                explanation = "No explanation available for this finding."
                summary = "No summary provided."

            impact = (f.get("impact") or "").strip() or "No impact analysis available for this finding."

            snippet = (f.get("vulnerable_snippet") or "").strip() or "// snippet unavailable"
            fix_snippet = (f.get("fix_snippet") or "").strip() or "No fix provided."

            # PoC code - use vulnerable snippet if available, else a placeholder
            poc_code = snippet if snippet else "// No PoC available."

            severity = normalize_severity(f.get("severity"))

            # Location: keep line usable in "file:line" even when unknown.
            file_loc = (f.get("file") or "").strip() or "unknown"
            line_raw = f.get("line")
            line_loc = line_raw if isinstance(line_raw, int) and line_raw > 0 else (line_raw or "?")

            detailed_findings.append({
                "id": f.get("id", f"F{idx:03d}"),
                "title": f.get("title") or "Unknown Issue",
                "severity": severity,
                "severity_class": severity.lower(),
                "file": file_loc,
                "line": line_loc,
                "vulnerable_snippet": snippet,
                "fix_snippet": fix_snippet,
                "explanation": explanation,
                "impact": impact,
                "exploit_steps": f.get("exploit_steps", []),
                "ai_used": f.get("ai_used", False),
                # Extra fields for Immunefi
                "function_name": function_name,
                "summary": summary,
                "poc_code": poc_code,
                "cwe_id": self._infer_cwe(f.get("title", "")),
            })

        # Severity counts (canonical Title case)
        severity_counts = {}
        for f in findings:
            sev = normalize_severity(f.get("severity"))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Sandbox linking
        sandbox_results = repo_data.get("sandbox_results", [])
        sim_success_rate = None
        if sandbox_results:
            total = len(sandbox_results)
            successful = sum(1 for r in sandbox_results if r.get("success"))
            sim_success_rate = f"{successful}/{total} ({successful/total*100:.1f}%)" if total else "N/A"
            for res in sandbox_results:
                if res.get("success"):
                    attack_name = res.get("attack_name", "").lower().replace("_attack", "").replace(".py", "")
                    for f in detailed_findings:
                        if attack_name in f["title"].lower() or attack_name in f.get("id", "").lower():
                            steps = [
                                f"Exploit succeeded using script: {res.get('attack_name')}",
                                f"Before balance: {res.get('before_balance', 'N/A')}",
                                f"After balance: {res.get('after_balance', 'N/A')}",
                                f"Gas used: {res.get('gas_used', 'N/A')}",
                                f"Transaction hash: {res.get('transaction_hash', 'N/A')}",
                                f"Logs: {res.get('logs', 'N/A')}"
                            ]
                            f["exploit_steps"] = steps
                            break

        chart_rel_paths = [p.name for p in chart_paths]

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "scan_metadata": scan_metadata,
            "repo_data": repo_data,
            "findings": detailed_findings,
            "score": score_result,
            "severity_counts": severity_counts,
            "simulation_success_rate": sim_success_rate,
            "chart_paths": chart_rel_paths,
            "total_findings": len(findings),
            # Additional module sections
            "bytecode_result": bytecode_result,
            "dependency_findings": dependency_findings or [],
            "upgrade_findings": upgrade_findings or [],
            "formal_findings": formal_findings or [],
            "deep_agent_stats": deep_agent_stats,
            "deep_agent_timeline": deep_agent_timeline or [],
        }

    def _render_immunefi(self, context: Dict[str, Any]) -> Path:
        """Render Immunefi-style bug bounty report."""
        if not JINJA2_AVAILABLE:
            raise RuntimeError("jinja2 required for Immunefi reports")
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(self.template_dir))
        template = env.get_template("immunefi_template.md")
        # Build a list of individual finding contexts
        findings_context = context.get("findings", [])
        rendered_parts = []
        for f in findings_context:
            steps = f.get("exploit_steps", [])
            steps_text = "\n".join(f"{i+1}. {step}" for i, step in enumerate(steps)) if steps else "No steps provided."
            f_context = {
                "severity": f.get("severity", "Low"),
                "title": f.get("title", "Unknown Issue"),
                "summary": f.get("summary", ""),
                "file": f.get("file", "unknown.sol"),
                "function_name": f.get("function_name", "Unknown"),
                "line": f.get("line", "?"),
                "steps_to_reproduce": steps_text,
                "poc_code": f.get("poc_code", "// No PoC available"),
                "impact": f.get("impact", "No impact analysis provided."),
                "fix_snippet": f.get("fix_snippet", "No fix provided."),
                "cwe_id": f.get("cwe_id", "Unknown"),
            }
            rendered = template.render(f_context)
            rendered_parts.append(rendered)
        full_report = "\n\n---\n\n".join(rendered_parts)
        output_file = self.output_dir / f"immunefi_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        with open(output_file, "w") as f:
            f.write(full_report)
        logger.info(f"Immunefi report saved to {output_file}")
        return output_file

    @staticmethod
    def _first_sentence(text: str) -> str:
        """Return the first real sentence of `text` for a one-line summary.

        Splits on sentence punctuation only when followed by whitespace or the
        end of the string, so member access (block.number) and decimals do not
        cut the summary short. Caps the length so the summary stays a single
        readable line.
        """
        text = (text or "").strip()
        if not text:
            return "No summary provided."
        match = re.search(r"[.!?](?:\s|$)", text)
        sentence = text[: match.start() + 1].strip() if match else text
        if len(sentence) > 200:
            sentence = sentence[:197].rstrip() + "..."
        return sentence

    def _infer_cwe(self, title: str) -> str:
        """Infer a CWE ID from a finding title so Immunefi references resolve.

        Ordered longest/most-specific first; the first substring match wins.
        """
        mappings = [
            ("reentrancy", "841"),
            ("integer overflow", "190"),
            ("integer underflow", "191"),
            ("overflow", "190"),
            ("underflow", "191"),
            ("arithmetic", "190"),
            ("input validation", "20"),
            ("unchecked send", "252"),
            ("unchecked", "252"),
            ("unbounded loop", "400"),
            ("gas griefing", "400"),
            ("gas exhaustion", "400"),
            ("gas", "400"),
            ("denial of service", "400"),
            ("dos", "400"),
            ("delegatecall", "829"),
            ("front", "362"),
            ("timestamp", "829"),
            ("randomness", "330"),
            ("blockhash", "330"),
            ("flash loan", "682"),
            ("oracle", "20"),
            ("governance", "284"),
            ("signature malleability", "347"),
            ("signature", "347"),
            ("nonce", "347"),
            ("permit", "347"),
            ("replay", "347"),
            ("tx.origin", "477"),
            ("hardcoded", "798"),
            ("initializ", "665"),
            ("uninitialized", "824"),
            ("visibility", "710"),
            ("access control", "284"),
            ("owner", "284"),
            ("selfdestruct", "284"),
        ]
        lower = (title or "").lower()
        for key, cwe in mappings:
            if key in lower:
                return cwe
        return "Unknown"

    def _render_json(self, context: Dict[str, Any]) -> Path:
        output_file = self.output_dir / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, "w") as f:
            json.dump(context, f, indent=2)
        logger.info(f"JSON report saved to {output_file}")
        return output_file

    def _render_markdown(self, context: Dict[str, Any]) -> Path:
        if not JINJA2_AVAILABLE:
            raise RuntimeError("jinja2 required for Markdown reports")
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(self.template_dir))
        template = env.get_template("markdown_template.md")
        rendered = template.render(context)
        output_file = self.output_dir / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        with open(output_file, "w") as f:
            f.write(rendered)
        logger.info(f"Markdown report saved to {output_file}")
        return output_file

    def _render_html(self, context: Dict[str, Any]) -> Path:
        if not JINJA2_AVAILABLE:
            raise RuntimeError("jinja2 required for HTML reports")
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(self.template_dir))
        template = env.get_template("html_template.html")
        rendered = template.render(context)
        output_file = self.output_dir / f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        with open(output_file, "w") as f:
            f.write(rendered)
        logger.info(f"HTML report saved to {output_file}")
        return output_file

    def _render_pdf(self, context: Dict[str, Any]) -> Path:
        if not PDFKIT_AVAILABLE:
            raise RuntimeError("pdfkit required for PDF reports")
        html_file = self._render_html(context)
        pdf_file = html_file.with_suffix(".pdf")
        pdfkit.from_file(str(html_file), str(pdf_file))
        logger.info(f"PDF report saved to {pdf_file}")
        return pdf_file

# EOF
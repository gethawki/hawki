# File: hawki/core/exporters/structured_exporter.py
"""
Structured JSON exporter for scan results.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from .base import Exporter


class StructuredExporter(Exporter):
    """Export scan results as structured JSON."""

    @property
    def name(self) -> str:
        return "structured"

    @property
    def description(self) -> str:
        return "Structured JSON export with all findings, exploits, and metadata"

    def export(self, context: Dict[str, Any], output_path: Path) -> Path:
        """
        Export to structured JSON format.
        """
        # Build the export schema
        export_data = self._build_export_data(context)

        # Write to file
        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        return output_path

    def _build_export_data(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Build the structured export schema."""
        repo_data = context.get("repo_data", {})
        findings = context.get("findings", [])
        score = context.get("score", {})
        scan_metadata = context.get("scan_metadata", {})
        dependency_findings = context.get("dependency_findings", [])

        # Extract target metadata
        target = {}
        if repo_data.get("type") == "deployed":
            target = {
                "type": "deployed",
                "address": repo_data.get("address"),
                "chain": repo_data.get("chain"),
                "chain_id": repo_data.get("chain_id"),
                "rpc_url": repo_data.get("rpc_url"),
                "bytecode_length": repo_data.get("bytecode_length"),
                "source_available": repo_data.get("source_available", False),
                "verified_source": repo_data.get("verified_source", False),
                "etherscan_url": repo_data.get("etherscan_url"),
            }
        else:
            target = {
                "type": repo_data.get("type", "unknown"),
                "path": repo_data.get("path"),
                "url": repo_data.get("url"),
            }

        # Build findings list
        export_findings = []
        for f in findings:
            export_finding = {
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", "Low"),
                "file": f.get("file", ""),
                "line": f.get("line", 0),
                "vulnerable_snippet": f.get("vulnerable_snippet", ""),
                "fix_snippet": f.get("fix_snippet", ""),
                "explanation": f.get("explanation", ""),
                "impact": f.get("impact", ""),
                "exploit_steps": f.get("exploit_steps", []),
                "ai_used": f.get("ai_used", False),
            }
            export_findings.append(export_finding)

        # Extract exploit data from findings
        exploit_data = []
        for f in findings:
            if f.get("exploit_steps"):
                exploit_data.append({
                    "finding_id": f.get("id", ""),
                    "title": f.get("title", ""),
                    "steps": f.get("exploit_steps", []),
                    "poc_code": f.get("vulnerable_snippet", ""),
                    "poc_format": "solidity",
                })

        return {
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "metadata": {
                "scan_metadata": scan_metadata,
                "target": target,
            },
            "findings": export_findings,
            "exploits": exploit_data,
            "score": {
                "score": score.get("score", 0),
                "classification": score.get("classification", "Unknown"),
                "deductions": score.get("deductions", {}),
            },
            "dependencies": dependency_findings,
        }
# EOF

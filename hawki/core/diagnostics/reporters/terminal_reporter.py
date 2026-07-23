# File: hawki/core/diagnostics/reporters/terminal_reporter.py
"""
Terminal reporter for doctor output.
"""

from typing import Any, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

class TerminalReporter:
    """Render doctor results in a rich terminal format."""

    def report(self, summary: Dict[str, Any]) -> None:
        status = summary.get("status", "unknown")
        critical = summary.get("critical", 0)
        warnings = summary.get("warnings", 0)
        passed = summary.get("passed", 0)
        total = summary.get("total", 0)
        checks = summary.get("checks", [])

        # Header
        console.print()
        console.print(Panel.fit(
            Text("🦅 Hawk-i Health Check", style="bold cyan"),
            border_style="cyan"
        ))

        # Summary bar
        if status == "critical":
            status_color = "red"
            status_text = "CRITICAL"
        elif status == "warning":
            status_color = "yellow"
            status_text = "WARNING"
        else:
            status_color = "green"
            status_text = "PASS"

        console.print(f"Status: [{status_color}]{status_text}[/{status_color}]")
        console.print(f"Checks: {passed} passed, {warnings} warnings, {critical} critical, {total} total")
        console.print()

        # Detail table
        table = Table(show_header=True, header_style="bold")
        table.add_column("Check", style="cyan", width=25)
        table.add_column("Status", style="bold", width=10)
        table.add_column("Message", width=40)
        table.add_column("Fix", style="dim", width=30)

        for check in checks:
            status = check.get("status", "unknown")
            if status == "pass":
                status_display = "✅ PASS"
            elif status == "fail":
                status_display = "❌ FAIL"
            elif status == "warn":
                status_display = "⚠️ WARN"
            else:
                status_display = "⏭ SKIP"

            table.add_row(
                check.get("name", "unknown"),
                status_display,
                check.get("message", ""),
                check.get("fix", "") or "",
            )

        console.print(table)

        # Footer
        if status == "critical":
            console.print()
            console.print("[red]Critical failures found. Please fix the issues above before scanning.[/red]")
            console.print("[yellow]Run 'hawki doctor' again after fixing issues.[/yellow]")
        elif status == "warning":
            console.print()
            console.print("[yellow]Warnings found. Some features may work but with reduced functionality.[/yellow]")

        console.print()
        console.print("[dim]Run 'hawki doctor --help' for options.[/dim]")
# EOF

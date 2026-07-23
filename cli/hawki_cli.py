# File: cli/hawki_cli.py
"""
Hawk-i command-line interface with extension features.
Includes: scan, deep, verify, deps, upgrade, prove, registry, export, metrics, report, score, monitor, doctor.
"""

import argparse
import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path

# Rich imports
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.traceback import install

install()

sys.path.insert(0, str(Path(__file__).parent.parent))

from hawki import __version__ as HAWKI_VERSION  # noqa: E402

# ReasoningAgent is imported lazily inside scan_command (only when --ai is set) so that
# lightweight commands do not pay litellm's import cost.
from hawki.core.data_layer.report_manager import ReportManager  # noqa: E402
from hawki.core.deps import scan_dependencies, update_db  # noqa: E402
from hawki.core.exploit_sandbox.sandbox_manager import SandboxManager  # noqa: E402
from hawki.core.exporters import get_exporter, list_exporters  # noqa: E402

# Deep-agent classes are imported lazily inside scan_command and deep_command so that
# lightweight commands do not pay the litellm import cost pulled in by the deep package.
from hawki.core.registry import ContractRegistry  # noqa: E402
from hawki.core.repo_intelligence.indexer import RepositoryIndexer  # noqa: E402
from hawki.core.static_rule_engine import RuleEngine  # noqa: E402
from hawki.core.telemetry import MetricsStore  # noqa: E402

JINJA2_AVAILABLE = importlib.util.find_spec("jinja2") is not None
MATPLOTLIB_AVAILABLE = importlib.util.find_spec("matplotlib") is not None
PDFKIT_AVAILABLE = importlib.util.find_spec("pdfkit") is not None

console = Console()

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ============================================================================
# DOCTOR COMMAND
# ============================================================================

def doctor_command(args):
    """Run the health check command."""
    from hawki.core.diagnostics import Doctor

    config = {}
    # Load config if exists
    config_path = Path.home() / ".hawki" / "config.yaml"
    if config_path.exists():
        try:
            import yaml
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            pass

    doctor = Doctor(config=config)
    summary = doctor.run_sync(
        skip_rpc=args.skip_rpc,
        skip_ai=args.skip_ai,
        verbose=args.verbose,
        fix=args.fix,
    )

    if args.format == "json":
        # Emit raw JSON via a plain writer so Rich does not reflow long lines
        # or interpret bracketed content as markup (which corrupts the output).
        print(doctor.report_json(summary))
    else:
        doctor.report_terminal(summary)

    # Exit with non-zero code if critical
    if summary.get("status") == "critical":
        sys.exit(1)
    else:
        sys.exit(0)


# ============================================================================
# SCAN COMMAND
# ============================================================================

def scan_command(args):
    logger = logging.getLogger(__name__)

    # --all is a convenience switch for the additional static modules.
    if getattr(args, "all", False):
        args.check_deps = True
        args.upgrade_safety = True
        args.prove = True

    # Run doctor if requested
    if args.doctor:
        from hawki.core.diagnostics import Doctor
        console.print("[cyan]Running pre-flight health check...[/cyan]")
        doctor = Doctor()
        summary = doctor.run_sync()
        if summary.get("status") == "critical":
            console.print("[red]Critical failures found. Aborting scan.[/red]")
            console.print("[yellow]Run 'hawki doctor' to diagnose and fix issues.[/yellow]")
            sys.exit(1)
        console.print("[green]Health check passed.[/green]")

    indexer = RepositoryIndexer()
    engine = RuleEngine()
    try:
        report_mgr = ReportManager(output_dir=args.output_dir)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    if args.address:
        registry = ContractRegistry()
        if not args.force_scan and registry.is_scanned(args.address, args.chain or "ethereum", days=30):
            console.print(f"[yellow]Contract {args.address} was scanned within the last 30 days.[/yellow]")
            console.print("[yellow]Use --force-scan to override or --skip-known to ignore this check.[/yellow]")
            if args.skip_known:
                console.print("[green]--skip-known set, proceeding anyway.[/green]")
            else:
                console.print("[red]Scan aborted. Use --force-scan to proceed.[/red]")
                sys.exit(0)

    ai_agent = None
    if args.ai:
        console.log("[cyan]AI analysis enabled[/cyan]")
        from hawki.core.ai_engine.reasoning_agent import ReasoningAgent
        ai_agent = ReasoningAgent(orchestrator=None)
        if args.ai_model or args.api_key:
            from hawki.core.ai_engine.llm_orchestrator import LLMOrchestrator
            ai_agent.orchestrator = LLMOrchestrator(model=args.ai_model, api_key=args.api_key)

    if args.format in ("html", "pdf") and not JINJA2_AVAILABLE:
        console.print("[red]HTML/PDF reports require jinja2. Install with 'pip install hawki[reports]'[/red]")
        sys.exit(1)
    if args.format == "pdf" and not PDFKIT_AVAILABLE:
        console.print("[red]PDF reports require the pdf extra and the wkhtmltopdf system binary.[/red]")
        console.print("[yellow]Install the extra with 'pip install hawki[pdf]' and install wkhtmltopdf from https://wkhtmltopdf.org/downloads.html (or your OS package manager, e.g. 'apt install wkhtmltopdf').[/yellow]")
        sys.exit(1)

    try:
        if args.address:
            console.print(f"[bold green]Scanning deployed contract:[/bold green] {args.address} on {args.chain or 'ethereum'}")
        else:
            console.print(f"[bold green]Scanning target:[/bold green] {args.target}")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Fetching contract data...", total=1)
            if args.address:
                repo_data = indexer.from_contract(
                    address=args.address,
                    rpc_url=args.rpc_url,
                    source_path=Path(args.source) if args.source else None,
                    chain=args.chain or "ethereum",
                    explorer_api_key=args.explorer_key,
                )
            else:
                repo_data = indexer.index(args.target)
            progress.update(task, advance=1)

            total_files = len([p for p in Path(repo_data["path"]).rglob("*.sol")]) if repo_data.get("path") else 1
            total_contracts = sum(len(c.get("contracts", [])) for c in repo_data.get("contracts", []))

            static_findings = []
            ai_findings = []
            bytecode_findings = repo_data.get("bytecode_findings", [])

            if repo_data.get("contracts"):
                task = progress.add_task(f"[cyan]Running {len(engine.rules)} static rules...", total=1)
                static_findings = engine.run_all(repo_data["contracts"])
                progress.update(task, advance=1)

                if ai_agent:
                    task = progress.add_task("[cyan]Running AI reasoning...", total=1)
                    ai_findings = ai_agent.analyse_contracts(repo_data["contracts"])
                    progress.update(task, advance=1)
            else:
                if args.ai:
                    console.print("[yellow]No source code available, skipping AI reasoning.[/yellow]")
                console.print("[yellow]Performing bytecode analysis only.[/yellow]")

            all_findings = static_findings + ai_findings + bytecode_findings

            # Sandbox is disabled for deployed contracts
            sandbox_results = []
            docker_available = False
            if args.sandbox:
                if args.address:
                    console.print("[yellow]Sandbox simulation is not supported for deployed contracts.[/yellow]")
                else:
                    task = progress.add_task("[cyan]Starting exploit simulation sandbox...", total=1)
                    repo_path = Path(repo_data["path"]) if repo_data["type"] == "remote" else Path(repo_data["path"])
                    sandbox = SandboxManager(repo_path)
                    sandbox_results = sandbox.run_all()
                    progress.update(task, advance=1)
                    repo_data["sandbox_results"] = sandbox_results
                    docker_available = True

            dep_findings = []
            if args.check_deps and not args.address:
                task = progress.add_task("[cyan]Scanning dependencies...", total=1)
                repo_path = Path(repo_data["path"]) if repo_data["type"] == "remote" else Path(repo_data["path"])
                dep_findings = scan_dependencies(repo_path)
                progress.update(task, advance=1)

        # --- Additional v1.0.0 security modules (opt-in) ---
        # Findings from upgrade-safety and formal verification are merged into
        # all_findings so they flow into the report and the security score.
        def _normalize_finding(f):
            f.setdefault("file", "-")
            f.setdefault("line", 0)
            f.setdefault("severity", "Medium")
            f.setdefault("vulnerable_snippet", "")
            return f

        # Dedicated per-module results also flow into the report as their own
        # sections and carry their own scoring penalties (on top of the generic
        # severity weight the same findings get in the flat list).
        bytecode_result = None
        upgrade_findings_list = None
        formal_findings_list = None
        deep_agent_stats = None
        deep_agent_timeline = None

        if getattr(args, "upgrade_safety", False) and not args.address:
            from hawki.core.upgrade import check_upgrade_safety
            console.print("[cyan]Running upgrade safety checks...[/cyan]")
            try:
                up_findings = [_normalize_finding(f) for f in check_upgrade_safety(Path(repo_data["path"]))]
                all_findings.extend(up_findings)
                upgrade_findings_list = up_findings
                console.print(f"[cyan]Upgrade safety findings:[/cyan] {len(up_findings)}")
            except Exception as e:
                console.print(f"[yellow]Upgrade safety check failed: {e}[/yellow]")

        if getattr(args, "prove", False) and not args.address:
            from hawki.core.formal.registry import get_verifier
            console.print(f"[cyan]Running {args.prove_engine} formal verification...[/cyan]")
            try:
                verifier = get_verifier(args.prove_engine)
                pv_findings = [_normalize_finding(f) for f in verifier.verify(Path(repo_data["path"]), contract_name=None)]
                all_findings.extend(pv_findings)
                formal_findings_list = pv_findings
                console.print(f"[cyan]Formal verification findings:[/cyan] {len(pv_findings)}")
            except Exception as e:
                console.print(f"[yellow]Formal verification failed: {e}[/yellow]")

        if getattr(args, "verify", False):
            if not (args.address and args.rpc_url and args.source):
                console.print("[yellow]--verify requires --address, --rpc-url and --source. Skipping bytecode verification.[/yellow]")
            else:
                from hawki.core.verify import verify_bytecode
                console.print("[cyan]Verifying on-chain bytecode against source...[/cyan]")
                try:
                    vres = verify_bytecode(
                        address=args.address,
                        rpc_url=args.rpc_url,
                        source_path=Path(args.source),
                        ignore_metadata=True,
                        contract_name=None,
                    )
                    if vres.get("success"):
                        # Feed the dedicated Bytecode Verification report section
                        # and the one-time mismatch penalty.
                        bytecode_result = {
                            "match": vres.get("match", True),
                            "onchain_hash": (vres.get("onchain") or {}).get("hash", ""),
                            "compiled_hash": (vres.get("compiled") or {}).get("hash", ""),
                            "diff_summary": vres.get("diff_summary", ""),
                        }
                    if vres.get("success") and not vres.get("match"):
                        all_findings.append(_normalize_finding({
                            "title": "Deployed bytecode does not match source",
                            "severity": "High",
                            "file": args.source,
                            "explanation": vres.get("diff_summary", "On-chain bytecode differs from the compiled source."),
                            "rule": "bytecode_verification",
                        }))
                        console.print("[red]Bytecode mismatch recorded as a finding.[/red]")
                    elif vres.get("success"):
                        console.print("[green]Bytecode matches source.[/green]")
                    else:
                        console.print(f"[yellow]Bytecode verification failed: {vres.get('error')}[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]Bytecode verification failed: {e}[/yellow]")

        scan_metadata = {
            "ai_enabled": args.ai,
            "sandbox_enabled": args.sandbox,
            "docker_available": docker_available,
            "total_scanned_contracts": total_contracts,
            "total_files": total_files,
            "mode": "minimal",
            "version": HAWKI_VERSION,
            "target_type": "deployed" if args.address else "repository",
            "source_available": repo_data.get("source_available", False),
            "verified_source": repo_data.get("verified_source", False),
        }
        if args.ai and args.sandbox:
            scan_metadata["mode"] = "full"
        elif args.ai:
            scan_metadata["mode"] = "enhanced"
        else:
            scan_metadata["mode"] = "minimal"

        if args.address:
            registry = ContractRegistry()
            registry.add(
                address=args.address,
                chain=args.chain or "ethereum",
                repo_hash=repo_data.get("path", ""),
                findings_count=len(all_findings)
            )

        # Deep agent runs as a bounded adjunct campaign whose results feed this
        # scan's report and score. It uses an isolated memory so the stats and
        # timeline reflect only this run, not accumulated history.
        if getattr(args, "deep", False) and not args.address:
            console.print("[cyan]Launching Deep agent (bounded budget)...[/cyan]")
            try:
                import tempfile

                from hawki.core.deep import (
                    BudgetManager,
                    DeepOrchestrator,
                    HybridPlanner,
                    LLMPlanner,
                    NovelExecutor,
                    RuleExecutor,
                    RulePlanner,
                    SQLiteStore,
                )
                deep_goal = args.deep_goal or "Find and exploit vulnerabilities to drain or manipulate funds."
                budget = BudgetManager(max_attempts=args.deep_budget_attempts, max_tokens=args.deep_budget_tokens)
                rule_planner = RulePlanner()
                llm_planner = None
                if args.ai_model and args.api_key:
                    llm_planner = LLMPlanner(model=args.ai_model, api_key=args.api_key)
                    deep_executor = NovelExecutor(llm_model=args.ai_model, llm_api_key=args.api_key, poc_format="foundry")
                else:
                    deep_executor = RuleExecutor()
                planner = HybridPlanner(rule_planner, llm_planner)
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as _dbf:
                    deep_mem = SQLiteStore(db_path=Path(_dbf.name))
                orchestrator = DeepOrchestrator(
                    repo_path=Path(repo_data["path"]),
                    goal=deep_goal,
                    memory=deep_mem,
                    planner=planner,
                    executor=deep_executor,
                    budget=budget,
                    force=False,
                    continuous=False,
                    interval=60,
                    code_only=args.code_only,
                    target_contract=None,
                )
                asyncio.run(orchestrator.run())
                deep_agent_stats = deep_mem.get_stats()
                _attempts = deep_mem.get_all()
                deep_agent_stats["novel_successes"] = sum(
                    1 for a in _attempts if a.get("attack_type") == "novel" and a.get("success")
                )
                deep_agent_timeline = [
                    {
                        "timestamp": a.get("timestamp", ""),
                        "type": a.get("attack_type", "rule"),
                        "name": (a.get("parameters") or {}).get("name") or a.get("rule_name") or a.get("novel_description") or "attack",
                        "success": a.get("success", False),
                    }
                    for a in _attempts
                ]
            except Exception as e:
                console.print(f"[yellow]Deep agent run failed: {e}[/yellow]")
        elif getattr(args, "deep", False) and args.address:
            console.print("[yellow]Deep agent is not supported for deployed-contract scans. Skipping.[/yellow]")

        report_kwargs = {
            "findings": all_findings,
            "repo_data": repo_data,
            "scan_metadata": scan_metadata,
            "dependency_findings": dep_findings if args.check_deps else None,
            "bytecode_result": bytecode_result,
            "upgrade_findings": upgrade_findings_list,
            "formal_findings": formal_findings_list,
            "deep_agent_stats": deep_agent_stats,
            "deep_agent_timeline": deep_agent_timeline,
        }
        style = getattr(args, 'style', 'audit')
        if args.format:
            report_path = report_mgr.generate_report(
                **report_kwargs,
                output_format=args.format,
                style=style,
            )
        else:
            report_path = report_mgr.save_findings(all_findings, repo_data)

        console.print(f"[bold green]Scan complete.[/bold green] Total findings: {len(all_findings)}")
        if args.address and not repo_data.get("source_available"):
            console.print("[yellow]Note: Limited analysis due to missing source code.[/yellow]")
            console.print("[yellow]Provide source with --source or an explorer API key for full analysis.[/yellow]")
        if dep_findings:
            console.print(f"[yellow]Dependency vulnerabilities: {len(dep_findings)}[/yellow]")
        console.print(f"[cyan]Report saved to:[/cyan] {report_path}")

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        console.print_exception()
        sys.exit(1)
    finally:
        indexer.cleanup()


# ============================================================================
# OTHER COMMANDS (monitor, report, score, metrics, deep, verify, deps, upgrade, prove)
# ============================================================================

def monitor_command(args):
    from hawki.core.monitoring import Monitor
    config = {}
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
    else:
        if args.target:
            config = {
                "repocommitwatcher": {
                    "repo_path": args.target,
                    "branch": args.branch or "main"
                }
            }
        if args.contract_address:
            config["deployedcontractwatcher"] = {
                "rpc_url": args.rpc_url or "http://localhost:8545",
                "contract_address": args.contract_address
            }

    monitor = Monitor(
        watcher_configs=config,
        state_dir=args.state_dir,
        alert_log_file=args.alert_log
    )
    interval = args.interval or 60
    console.print("[cyan]Monitoring started. Press Ctrl+C to stop.[/cyan]")
    try:
        monitor.run_forever(interval_seconds=interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped by user.[/yellow]")
        sys.exit(0)


def report_command(args):
    from hawki.core.data_layer.report_manager import ReportManager
    report_mgr = ReportManager(output_dir=args.output_dir)

    input_path = args.input
    if not input_path:
        # Scans write findings JSON to ./hawki_reports/ by default. Look there
        # first (or an explicit --output-dir), then fall back to the cwd.
        search_dirs = []
        if args.output_dir:
            search_dirs.append(Path(args.output_dir))
        search_dirs.append(Path.cwd() / "hawki_reports")
        search_dirs.append(Path.cwd())

        report_files = []
        for directory in search_dirs:
            if directory.exists():
                found = sorted(directory.glob("report_*.json"), key=lambda p: p.stat().st_mtime)
                if found:
                    report_files = found
                    break

        if not report_files:
            console.print("[red]No findings file specified and no previous scan found.[/red]")
            sys.exit(1)
        input_path = report_files[-1]
        console.print(f"[cyan]Using latest findings file:[/cyan] {input_path}")

    try:
        with open(input_path) as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to load findings file {input_path}: {e}[/red]")
        sys.exit(1)

    findings = data.get("findings", [])
    repo_data = data.get("repository", {"path": "unknown", "type": "unknown"})
    if "sandbox_results" in data:
        repo_data["sandbox_results"] = data["sandbox_results"]

    scan_metadata = {
        "ai_enabled": False,
        "sandbox_enabled": "sandbox_results" in data,
        "docker_available": False,
        "total_scanned_contracts": len(repo_data.get("contracts", [])),
        "total_files": 0,
        "mode": "unknown"
    }

    output_format = args.format or "md"
    style = args.style if hasattr(args, 'style') else "audit"
    report_path = report_mgr.generate_report(
        findings=findings,
        repo_data=repo_data,
        scan_metadata=scan_metadata,
        output_format=output_format,
        style=style,
    )
    console.print(f"[green]Report saved to:[/green] {report_path}")


def score_command(args):
    from hawki.core.data_layer.reporting.scoring_engine import SecurityScoreEngine

    input_path = args.input
    if not input_path:
        console.print("[red]No findings file specified.[/red]")
        sys.exit(1)

    try:
        with open(input_path) as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]Failed to load findings file {input_path}: {e}[/red]")
        sys.exit(1)

    findings = data.get("findings", [])
    sandbox_results = data.get("sandbox_results")

    engine = SecurityScoreEngine()
    score_result = engine.calculate(
        findings=findings,
        sandbox_results=sandbox_results,
        ai_enabled=False,
    )

    table = Table(title="Security Score", show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Score", f"{score_result['score']}/100")
    table.add_row("Classification", score_result['classification'])
    if args.verbose:
        for key, value in score_result['deductions'].items():
            table.add_row(key, str(value))
    console.print(table)


def metrics_command(args):
    store = MetricsStore()

    if getattr(args, "clear", False):
        existing = store.get_all()
        if not existing:
            console.print("[yellow]No telemetry data to clear.[/yellow]")
            return
        console.print(f"[yellow]This will permanently delete {len(existing)} local telemetry record(s) at {store.path}.[/yellow]")
        confirm = console.input("[bold]Delete local telemetry data? [y/N]: [/bold]").strip().lower()
        if confirm in ("y", "yes"):
            store.clear()
            console.print("[green]Local telemetry data cleared.[/green]")
        else:
            console.print("[cyan]Aborted. No data was deleted.[/cyan]")
        return

    all_metrics = store.get_all()
    if not all_metrics:
        console.print("[yellow]No telemetry data recorded yet.[/yellow]")
        return

    total_scans = len(all_metrics)
    total_findings = sum(sum(m["findings"].values()) for m in all_metrics)
    critical = sum(m["findings"].get("Critical", 0) for m in all_metrics)
    high = sum(m["findings"].get("High", 0) for m in all_metrics)
    medium = sum(m["findings"].get("Medium", 0) for m in all_metrics)
    low = sum(m["findings"].get("Low", 0) for m in all_metrics)

    table = Table(title="Telemetry Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Total scans", str(total_scans))
    table.add_row("Total findings", str(total_findings))
    table.add_row("Critical", str(critical))
    table.add_row("High", str(high))
    table.add_row("Medium", str(medium))
    table.add_row("Low", str(low))
    console.print(table)

    if args.verbose:
        console.print("\n[bold]Detailed records:[/bold]")
        for m in all_metrics:
            console.print(f"  {m['timestamp']} - mode: {m['mode']}, findings: {m['findings']}")


def deep_command(args):
    from hawki.core.deep import (
        BudgetManager,
        DeepOrchestrator,
        HybridPlanner,
        JSONStore,
        LLMPlanner,
        NovelExecutor,
        RuleExecutor,
        RulePlanner,
        SQLiteStore,
    )

    # Run doctor if requested
    if args.doctor:
        from hawki.core.diagnostics import Doctor
        console.print("[cyan]Running pre-flight health check...[/cyan]")
        doctor = Doctor()
        summary = doctor.run_sync()
        if summary.get("status") == "critical":
            console.print("[red]Critical failures found. Aborting deep agent.[/red]")
            console.print("[yellow]Run 'hawki doctor' to diagnose and fix issues.[/yellow]")
            sys.exit(1)
        console.print("[green]Health check passed.[/green]")

    if args.goal_file:
        try:
            with open(args.goal_file) as f:
                goal = f.read().strip()
        except Exception as e:
            console.print(f"[red]Failed to read goal file: {e}[/red]")
            sys.exit(1)
    else:
        goal = args.goal

    # Memory store
    memory_path = Path(args.memory_path) if getattr(args, "memory_path", None) else None
    if args.memory == "json":
        memory = JSONStore(file_path=memory_path) if memory_path else JSONStore()
    else:
        memory = SQLiteStore(db_path=memory_path) if memory_path else SQLiteStore()

    # Budget
    budget = BudgetManager(max_attempts=args.budget_attempts, max_tokens=args.budget_tokens)

    # Planners
    rule_planner = RulePlanner()
    llm_planner = None
    executor = None
    if args.llm_provider and args.llm_model:
        model = f"{args.llm_provider}/{args.llm_model}" if "/" not in args.llm_model else args.llm_model
        llm_planner = LLMPlanner(model=model, api_key=args.llm_key)
        executor = NovelExecutor(llm_model=model, llm_api_key=args.llm_key, poc_format=args.poc_format)
    else:
        executor = RuleExecutor()
    planner = HybridPlanner(rule_planner, llm_planner)

    orchestrator = DeepOrchestrator(
        repo_path=Path(args.target),
        goal=goal,
        memory=memory,
        planner=planner,
        executor=executor,
        budget=budget,
        force=args.force,
        continuous=args.continuous,
        interval=args.interval,
        code_only=args.code_only,
        target_contract=args.target_contract,
    )
    asyncio.run(orchestrator.run())

    # Emit a unified report (with campaign charts) for the run. Continuous mode
    # never terminates, so it is skipped there. A reporting failure must never
    # mask a completed campaign, so it is best-effort.
    if not args.continuous:
        try:
            stats = memory.get_stats()
            attempts = memory.get_all()
            stats["novel_successes"] = sum(
                1 for a in attempts
                if a.get("attack_type") == "novel" and a.get("success")
            )
            timeline = []
            for a in attempts:
                if a.get("attack_type") == "novel":
                    name = (a.get("parameters") or {}).get("name") or a.get("novel_description") or "novel attack"
                else:
                    name = a.get("rule_name") or "rule attack"
                timeline.append({
                    "timestamp": a.get("timestamp", ""),
                    "type": a.get("attack_type", "rule"),
                    "name": name,
                    "success": a.get("success", False),
                })
            report_mgr = ReportManager(output_dir=getattr(args, "output_dir", None))
            scan_metadata = {
                "mode": "deep",
                "ai_enabled": llm_planner is not None,
                "sandbox_enabled": not args.code_only,
                "total_scanned_contracts": 0,
                "total_files": 0,
            }
            report_kwargs = dict(
                findings=[],
                repo_data={},
                scan_metadata=scan_metadata,
                style="audit",
                deep_agent_stats=stats,
                deep_agent_timeline=timeline,
            )
            md_path = report_mgr.generate_report(output_format="md", **report_kwargs)
            html_path = report_mgr.generate_report(output_format="html", **report_kwargs)
            console.print(f"[cyan]Deep report saved to:[/cyan] {md_path}")
            console.print(f"[cyan]Deep report (HTML) saved to:[/cyan] {html_path}")
        except Exception as exc:
            console.print(f"[dim]Report generation skipped: {exc}[/dim]")


def verify_command(args):
    from hawki.core.verify import verify_bytecode
    with console.status("[cyan]Verifying bytecode...[/cyan]"):
        result = verify_bytecode(
            address=args.address,
            rpc_url=args.rpc_url,
            source_path=Path(args.source),
            ignore_metadata=args.ignore_metadata,
            contract_name=args.contract,
        )
    if not result["success"]:
        console.print(f"[red]Verification failed: {result['error']}[/red]")
        return
    if result["match"]:
        console.print("[green]✓ Bytecode matches![/green]")
    else:
        console.print("[red]✗ Bytecode mismatch![/red]")
    console.print(f"  Onchain: {result['onchain']['hash']} (length {result['onchain']['length']} bytes)")
    console.print(f"  Compiled: {result['compiled']['name']} -> {result['compiled']['hash']} (length {result['compiled']['length']} bytes)")
    console.print(f"  Summary: {result['diff_summary']}")


def deps_command(args):
    from hawki.core.deps import scan_dependencies
    if args.update_db:
        try:
            with console.status("[cyan]Updating vulnerability database...[/cyan]"):
                update_db()
            console.print("[green]Database updated.[/green]")
        except Exception as exc:
            console.print(f"[red]Could not update the vulnerability database: {exc}[/red]")
            console.print("[dim]The bundled database is still in place; scans continue to work.[/dim]")
            return 1
        return
    with console.status("[cyan]Scanning dependencies...[/cyan]"):
        findings = scan_dependencies(Path(args.target))
    if not findings:
        console.print("[green]No vulnerable dependencies found.[/green]")
        return
    table = Table(title="Vulnerable Dependencies")
    table.add_column("Package", style="cyan")
    table.add_column("Installed", style="yellow")
    table.add_column("Vulnerable Versions", style="red")
    table.add_column("Severity", style="bold")
    table.add_column("File", style="dim")
    for f in findings:
        table.add_row(f["package"], f["installed_version"], f["vulnerable_versions"], f["severity"], f.get("file", ""))
    console.print(table)


def upgrade_command(args):
    from hawki.core.upgrade import check_upgrade_safety
    with console.status("[cyan]Checking upgrade safety...[/cyan]"):
        findings = check_upgrade_safety(Path(args.target))
    if not findings:
        console.print("[green]No upgrade safety issues detected.[/green]")
        return
    table = Table(title="Upgrade Safety Findings")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="dim")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="bold")
    for f in findings:
        table.add_row(f["file"], str(f.get("line", "?")), f["title"], f["severity"])
    console.print(table)


def prove_command(args):
    from hawki.core.formal.registry import get_verifier
    try:
        verifier = get_verifier(args.engine)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return
    with console.status(f"[cyan]Running {args.engine} formal verification...[/cyan]"):
        findings = verifier.verify(Path(args.target), contract_name=args.contract)
    if not findings:
        console.print("[green]No formal verification issues found.[/green]")
        return
    table = Table(title="Formal Verification Findings")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Description", style="dim")
    for f in findings:
        table.add_row(f["title"], f["severity"], f["description"][:100])
    console.print(table)


# ============================================================================
# REGISTRY COMMANDS
# ============================================================================

def registry_command(args):
    registry = ContractRegistry()
    if args.action == "list":
        entries = registry.list_entries()
        if not entries:
            console.print("[yellow]No contracts in registry.[/yellow]")
            return
        table = Table(title="Scanned Contracts Registry")
        table.add_column("Address", style="cyan")
        table.add_column("Chain", style="yellow")
        table.add_column("First Scanned", style="dim")
        table.add_column("Last Scanned", style="dim")
        table.add_column("Scan Count", style="white")
        table.add_column("Findings", style="white")
        for e in entries:
            table.add_row(
                e["address"][:10] + "...",
                e["chain"],
                e["first_scanned"][:10],
                e["last_scanned"][:10],
                str(e["scan_count"]),
                str(e["findings_count"])
            )
        console.print(table)
    elif args.action == "clear":
        registry.clear()
        console.print("[green]Registry cleared.[/green]")
    elif args.action == "show":
        if not args.address:
            console.print("[red]Please provide --address for show action.[/red]")
            return
        entry = registry.get_entry(args.address, args.chain or "ethereum")
        if entry:
            console.print("[bold]Contract Entry:[/bold]")
            for key, value in entry.items():
                console.print(f"  {key}: {value}")
        else:
            console.print(f"[yellow]No entry found for {args.address} on {args.chain or 'ethereum'}.[/yellow]")


# ============================================================================
# EXPORT COMMAND
# ============================================================================

def export_command(args):
    """Export findings to a structured format."""

    input_path = args.input
    if not input_path.exists():
        console.print(f"[red]File not found: {input_path}[/red]")
        sys.exit(1)

    with open(input_path) as f:
        data = json.load(f)

    # Build context
    context = {
        "repo_data": data.get("repository", {}),
        "findings": data.get("findings", []),
        "score": data.get("score", {}),
        "scan_metadata": data.get("scan_metadata", {}),
        "dependency_findings": data.get("dependency_findings", []),
    }

    exporter = get_exporter(args.format)
    if not exporter:
        console.print(f"[red]Unknown export format: {args.format}. Available: {list_exporters()}[/red]")
        sys.exit(1)

    output_path = args.output or Path.cwd() / f"export_{args.format}.json"
    exporter.export(context, output_path)
    console.print(f"[green]Export saved to: {output_path}[/green]")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description=f"Hawk-i Security Scanner v{HAWKI_VERSION}")
    parser.add_argument(
        "--version",
        action="version",
        version=f"hawki {HAWKI_VERSION}",
        help="Show the Hawk-i version and exit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommands")

    # ===== SCAN =====
    scan_parser = subparsers.add_parser("scan", help="Perform a one-time scan")
    scan_parser.add_argument("target", nargs="?", help="Local directory path or Git repository URL")
    scan_parser.add_argument("--address", help="Deployed contract address (instead of repo)")
    scan_parser.add_argument("--chain", default="ethereum", help="Blockchain chain (ethereum, polygon, arbitrum, etc.)")
    scan_parser.add_argument("--rpc-url", help="RPC URL for deployed contract scanning")
    scan_parser.add_argument("--source", help="Path to source repository (for deployed contract)")
    scan_parser.add_argument("-v", "--verbose", action="store_true")
    scan_parser.add_argument("-o", "--output-dir", type=Path, help="Directory to store reports")
    scan_parser.add_argument("--ai", action="store_true", help="Enable AI analysis")
    scan_parser.add_argument("--ai-model", help="LLM model (e.g., gemini/gemini-1.5-flash)")
    scan_parser.add_argument("--api-key", help="API key for the LLM")
    scan_parser.add_argument("--sandbox", action="store_true", help="Run exploit simulation sandbox")
    scan_parser.add_argument("--format", choices=["md", "json", "html", "pdf"], default=None,
                             help="Output report format")
    scan_parser.add_argument("--check-deps", action="store_true", help="Run dependency scanning")
    scan_parser.add_argument("--all", action="store_true",
                             help="Run all additional security modules (deps, upgrade safety, formal verification)")
    scan_parser.add_argument("--verify", action="store_true",
                             help="Verify on-chain bytecode against source (requires --address, --rpc-url and --source)")
    scan_parser.add_argument("--upgrade-safety", action="store_true", help="Run upgrade safety checks")
    scan_parser.add_argument("--prove", action="store_true", help="Run formal verification")
    scan_parser.add_argument("--prove-engine", choices=["smtchecker", "hevm"], default="smtchecker",
                             help="Formal verification engine (default: smtchecker)")
    scan_parser.add_argument("--deep", action="store_true",
                             help="Run the Deep agent with a bounded budget after the scan")
    scan_parser.add_argument("--deep-goal", help="Goal for the Deep agent (used with --deep)")
    scan_parser.add_argument("--deep-budget-attempts", type=int, default=5,
                             help="Max attack attempts for the Deep agent (default: 5)")
    scan_parser.add_argument("--deep-budget-tokens", type=int, default=10000,
                             help="Max estimated LLM tokens for the Deep agent (default: 10000)")
    scan_parser.add_argument("--code-only", action="store_true",
                             help="Deep agent code-only mode (skip live sandbox execution)")
    scan_parser.add_argument("--skip-known", action="store_true", help="Skip if scanned within last 30 days")
    scan_parser.add_argument("--force-scan", action="store_true", help="Force scan even if recently scanned")
    scan_parser.add_argument("--explorer-key", help="API key for block explorer (Etherscan, Polygonscan, etc.)")
    scan_parser.add_argument("--style", choices=["audit", "immunefi"], default="audit",
                             help="Report style (audit or immunefi)")
    scan_parser.add_argument("--doctor", action="store_true", help="Run pre-flight health check before scanning")
    scan_parser.set_defaults(func=scan_command)

    # ===== DEEP =====
    deep_parser = subparsers.add_parser("deep", help="Autonomous deep exploit agent")
    deep_parser.add_argument("target", help="Local directory path or Git repository URL")
    deep_parser.add_argument("--goal", required=True, help="Attack goal (e.g., 'drain funds')")
    deep_parser.add_argument("--goal-file", type=Path, help="Text file with goal description (overrides --goal)")
    deep_parser.add_argument("--budget-attempts", type=int, help="Maximum number of attack attempts")
    deep_parser.add_argument("--budget-tokens", type=int, help="Maximum estimated LLM tokens")
    deep_parser.add_argument("--memory", choices=["sqlite", "json"], default="sqlite", help="Memory backend")
    deep_parser.add_argument("--memory-path", type=Path,
                             help="Custom path for the memory store (default: ~/.hawki/deep_memory.db or .jsonl)")
    deep_parser.add_argument("--force", action="store_true", help="Re-attempt previously tried attacks")
    deep_parser.add_argument("--continuous", action="store_true", help="Run continuously, watching for changes")
    deep_parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds (continuous mode)")
    deep_parser.add_argument("--code-only", action="store_true", help="Skip live execution, only LLM reasoning")
    deep_parser.add_argument("--target-contract", help="Focus on a specific contract name")
    deep_parser.add_argument("--poc-format", choices=["hardhat", "foundry"], default="foundry",
                             help="PoC format (foundry is self-contained and runs offline; hardhat emits a standalone ethers script)")
    deep_parser.add_argument("--llm-provider", help="LLM provider (openai, anthropic, gemini, etc.)")
    deep_parser.add_argument("--llm-model", help="Model name")
    deep_parser.add_argument("--llm-key", help="API key")
    deep_parser.add_argument("--skip-known", action="store_true", help="Skip if scanned within last 30 days")
    deep_parser.add_argument("--force-scan", action="store_true", help="Force scan even if recently scanned")
    deep_parser.add_argument("--doctor", action="store_true", help="Run pre-flight health check before deep agent")
    deep_parser.set_defaults(func=deep_command)

    # ===== VERIFY =====
    verify_parser = subparsers.add_parser("verify", help="Verify on-chain bytecode against source")
    verify_parser.add_argument("address", help="Contract address")
    verify_parser.add_argument("--source", required=True, help="Path to source repository")
    verify_parser.add_argument("--rpc-url", default="http://localhost:8545", help="RPC URL")
    verify_parser.add_argument("--contract", help="Contract name (if multiple)")
    verify_parser.add_argument("--ignore-metadata", action="store_true", help="Ignore CBOR metadata")
    verify_parser.set_defaults(func=verify_command)

    # ===== DEPS =====
    deps_parser = subparsers.add_parser("deps", help="Scan dependencies for known vulnerabilities")
    deps_parser.add_argument("target", help="Repository path")
    deps_parser.add_argument("--update-db", action="store_true", help="Update vulnerability database")
    deps_parser.set_defaults(func=deps_command)

    # ===== UPGRADE =====
    upgrade_parser = subparsers.add_parser("upgrade", help="Check upgrade safety")
    upgrade_parser.add_argument("target", help="Repository path")
    upgrade_parser.set_defaults(func=upgrade_command)

    # ===== PROVE =====
    prove_parser = subparsers.add_parser("prove", help="Run formal verification")
    prove_parser.add_argument("target", help="Repository path")
    prove_parser.add_argument("--engine", choices=["smtchecker", "hevm"], default="smtchecker", help="Verification engine")
    prove_parser.add_argument("--contract", help="Contract name (optional)")
    prove_parser.set_defaults(func=prove_command)

    # ===== REGISTRY =====
    registry_parser = subparsers.add_parser("registry", help="Manage contract registry")
    registry_parser.add_argument("action", choices=["list", "clear", "show"], help="Action to perform")
    registry_parser.add_argument("--address", help="Contract address (for show action)")
    registry_parser.add_argument("--chain", default="ethereum", help="Chain (for show action)")
    registry_parser.set_defaults(func=registry_command)

    # ===== REPORT =====
    report_parser = subparsers.add_parser("report", help="Generate a report from existing findings")
    report_parser.add_argument("-i", "--input", type=Path, help="Findings JSON file")
    report_parser.add_argument("-o", "--output-dir", type=Path, help="Output directory for report")
    report_parser.add_argument("-f", "--format", choices=["md", "json", "html", "pdf"], default="md")
    report_parser.add_argument("--style", choices=["audit", "immunefi"], default="audit",
                               help="Report style (audit or immunefi)")
    report_parser.set_defaults(func=report_command)

    # ===== SCORE =====
    score_parser = subparsers.add_parser("score", help="Calculate security score from findings file")
    score_parser.add_argument("input", type=Path, help="Findings JSON file")
    score_parser.add_argument("-v", "--verbose", action="store_true", help="Show deduction details")
    score_parser.set_defaults(func=score_command)

    # ===== METRICS =====
    metrics_parser = subparsers.add_parser("metrics", help="Display local telemetry stats")
    metrics_parser.add_argument("-v", "--verbose", action="store_true")
    metrics_parser.add_argument("--clear", action="store_true",
                                help="Delete all local telemetry data (asks for confirmation)")
    metrics_parser.set_defaults(func=metrics_command)

    # ===== MONITOR =====
    monitor_parser = subparsers.add_parser("monitor", help="Continuously monitor targets")
    monitor_parser.add_argument("target", nargs="?", help="Local Git repository path")
    monitor_parser.add_argument("-v", "--verbose", action="store_true")
    monitor_parser.add_argument("-c", "--config", type=Path, help="JSON configuration file")
    monitor_parser.add_argument("--state-dir", type=Path, help="Directory for watcher state")
    monitor_parser.add_argument("--alert-log", type=Path, help="File to append alerts")
    monitor_parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds")
    monitor_parser.add_argument("--branch", help="Git branch to monitor")
    monitor_parser.add_argument("--contract-address", help="Ethereum contract address to monitor")
    monitor_parser.add_argument("--rpc-url", help="RPC URL for contract monitoring")
    monitor_parser.set_defaults(func=monitor_command)

    # ===== EXPORT =====
    export_parser = subparsers.add_parser("export", help="Export findings to a structured format")
    export_parser.add_argument("--input", type=Path, required=True, help="Findings JSON file")
    export_parser.add_argument("--format", choices=["structured"], default="structured",
                               help="Export format (currently only 'structured' is supported)")
    export_parser.add_argument("--output", type=Path, help="Output file path (default: export_structured.json)")
    export_parser.set_defaults(func=export_command)

    # ===== DOCTOR =====
    doctor_parser = subparsers.add_parser("doctor", help="Pre-flight health check")
    doctor_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    doctor_parser.add_argument("--fix", action="store_true", help="Auto-repair trivial issues")
    doctor_parser.add_argument("--format", choices=["terminal", "json"], default="terminal",
                               help="Output format (terminal or json)")
    doctor_parser.add_argument("--skip-rpc", action="store_true", help="Skip RPC connectivity checks")
    doctor_parser.add_argument("--skip-ai", action="store_true", help="Skip AI provider checks")
    doctor_parser.set_defaults(func=doctor_command)

    args = parser.parse_args()
    setup_logging(getattr(args, 'verbose', False))
    args.func(args)

if __name__ == "__main__":
    main()
# 🦅 Hawk-i

**Holistic Analysis for Web3 Kode and Infrastructure**
*Open-source, privacy-first security intelligence for smart contracts*

[![PyPI version](https://img.shields.io/pypi/v/hawki)](https://pypi.org/project/hawki/)
[![PyPI - Downloads](https://img.shields.io/pypi/dw/hawki)](https://pypi.org/project/hawki/)
[![Docker Pulls](https://img.shields.io/docker/pulls/levichinecherem/hawki)](https://hub.docker.com/r/levichinecherem/hawki)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Contributors](https://img.shields.io/github/contributors/gethawki/hawki)](https://github.com/gethawki/hawki/graphs/contributors)
[![Discussions](https://img.shields.io/github/discussions/gethawki/hawki)](https://github.com/gethawki/hawki/discussions)

---

## 📖 Table of Contents

- [What is Hawk-i?](#-what-is-hawk-i)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Operational Modes](#-operational-modes)
- [Advanced Usage](#-advanced-usage)
  - [Audit-Grade Reporting](#audit-grade-reporting)
  - [Security Score](#security-score)
  - [Guided Remediation](#guided-remediation)
  - [Hawk-i Deep, the Autonomous Agent](#hawk-i-deep-the-autonomous-agent)
  - [Bytecode Verification and Deployed-Contract Scanning](#bytecode-verification-and-deployed-contract-scanning)
  - [Dependency Scanning](#dependency-scanning)
  - [Upgrade Safety Checks](#upgrade-safety-checks)
  - [Formal Verification](#formal-verification)
  - [hawki doctor, the Pre-Flight Health Check](#hawki-doctor-the-pre-flight-health-check)
  - [hawki export, Structured Export](#hawki-export-structured-export)
  - [Contract Registry](#contract-registry)
  - [Local Metrics](#local-metrics)
  - [CLI Reference](#cli-reference)
  - [CI/CD Integration](#cicd-integration)
  - [Ecosystem Integrations](#ecosystem-integrations)
- [Demo Suite](#-demo-suite)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgements](#-acknowledgements)
- [Roadmap](#-roadmap)
- [Contact](#-contact)

---

## 🦅 What is Hawk-i?

Hawk-i is an **open-source security intelligence platform** for Web3 smart contracts. It goes beyond a simple scanner into a complete audit-grade system that **detects, simulates, scores, and helps fix vulnerabilities**, all while respecting your privacy.

**v1.0.0** introduces a **fully autonomous deep-exploit agent** (`hawki deep`) that invents novel attacks, remembers every attempt, and respects your budget. It also adds **bytecode verification**, **dependency scanning**, **upgrade safety checks**, **pluggable formal verification**, **deployed-contract scanning**, **Immunefi-style reports**, **Foundry PoC support**, **structured export**, a **contract registry**, and the **`hawki doctor` pre-flight health check**.

**Key differentiators:**
- **Hybrid analysis:** static rules plus AI reasoning plus live exploit simulation plus an autonomous agent.
- **Professional reporting:** executive summaries, risk scores, charts, and per-finding remediation.
- **Privacy by design:** runs locally; no code is sent to external servers (AI uses your own API keys). No telemetry is sent anywhere.
- **Extensible:** drop-in rules, attack scripts, memory backends, and report styles.

---

## ✨ Features

### Core Capabilities
- **🔍 Repository Intelligence:** parse and index Solidity files from local folders or remote Git repos (GitHub, GitLab, etc.).
- **📦 Static Rule Engine:** 50 source-level rules covering reentrancy, access control, integer overflow, oracle manipulation, unchecked calls, weak randomness, upgrade safety, code hygiene and more, with an extensible auto-discovery system. Every rule is guarded by a liveness test that proves it actually fires through the real scan pipeline, so the ruleset never carries dead rules.
- **🧠 AI Reasoning:** use LLMs (Gemini, OpenAI, Anthropic, local models via LiteLLM) to uncover logic flaws, economic exploits, and governance risks that static analysis misses.
- **💣 Exploit Simulation Sandbox:** deploy contracts in an isolated Docker environment and run attack scripts to validate vulnerabilities.
- **⏱️ Continuous Monitoring:** watch repositories and deployed contracts for changes and get alerts via file or console.

### v1.0.0, Autonomous Security Intelligence
- **🤖 Hawk-i Deep:** an autonomous agent that:
  - Starts with **30+ rule-based attacks**
  - Invents **novel attack vectors** using an LLM (your own API key)
  - Remembers every attempt via **pluggable memory** (SQLite or JSON)
  - Respects **dual budget limits** (attempts and estimated token usage)
  - Runs **continuously**, reacting to repository changes
  - Supports **Foundry PoC generation** (`--poc-format foundry`)
  - Can **focus on a specific contract** (`--target-contract`)
- **🔐 Bytecode Verification:** compare on-chain bytecode against compiled source.
- **📦 Dependency Scanning:** detect vulnerable library versions from multiple manifests (`package.json`, `foundry.toml`, `hardhat.config.js`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.toml`).
- **🔄 Upgrade Safety Checks:** identify proxy patterns (Transparent, UUPS, Beacon), storage collisions, and initialization risks.
- **✅ Pluggable Formal Verification:** built-in SMTChecker and optional Hevm support; add your own verifiers.
- **🌐 Deployed-Contract Scanning:** scan a contract by address across seven EVM mainnets plus Sepolia and a local chain.
- **📝 Immunefi-Style Reports:** generate ready-to-submit bug reports with `hawki report --style immunefi`.
- **📤 Structured Export:** export findings to JSON for CI/CD and toolchain integration with `hawki export`.
- **🩺 Pre-Flight Health Check:** run `hawki doctor` to validate your environment in under 5 seconds.
- **📋 Contract Registry:** track scanned contracts to avoid duplicates with `hawki registry`.
- **🧹 No Monetization:** all commercial telemetry has been removed. The software is 100% free and open source; enterprise support and services are sold separately.

---

## 🚀 Quick Start

### Installation

**Option 1: Install from PyPI (recommended)**
```bash
pip install hawki
```
Optional extras pull in report dependencies: `pip install "hawki[reports]"` (HTML and charts) or `pip install "hawki[all]"`.

**Option 2: Use Docker**
```bash
docker pull levichinecherem/hawki:latest
# Mount your project as the working directory and run as your own user so the
# report (written to ./hawki_reports) lands back on the host with the right
# ownership.
docker run --rm --user $(id -u):$(id -g) -v $(pwd):/work -w /work levichinecherem/hawki scan . --format html
```

**Option 3: Install from source**
```bash
git clone https://github.com/gethawki/hawki.git
cd hawki
pip install -e .
```

Check the installed version at any time:
```bash
hawki --version
```

### Basic Scan
```bash
hawki scan /path/to/your/project
```
This runs the static rules and writes a JSON report to `./hawki_reports/`. For a formatted audit report, add `--format`.

### Pre-Flight Health Check
```bash
hawki doctor
```
Validates your environment in under 5 seconds. Run it before your first scan to catch configuration issues early.

### Full Audit with AI and Sandbox
```bash
# Scan with AI reasoning and the exploit sandbox
hawki scan /path --ai --ai-model openai/gpt-4 --api-key YOUR_KEY --sandbox --format html
```

### Deep Autonomous Agent
```bash
# Invents novel attacks against your contracts
hawki deep /path --goal "drain funds" --budget-attempts 50 --llm-provider openai --llm-model gpt-4
```

### Scan a Deployed Contract
```bash
hawki scan --address 0x1234... --chain ethereum --rpc-url https://eth.llamarpc.com --explorer-key YOUR_KEY
```

### Additional Security Modules
```bash
# Bytecode verification
hawki verify 0x1234... --source ./contracts --rpc-url https://rpc.example

# Dependency scanning
hawki deps ./my-project

# Upgrade safety
hawki upgrade ./my-upgradeable-contract

# Formal verification
hawki prove ./contracts --engine smtchecker

# Immunefi-style bug report from a findings file
hawki report --input ./hawki_reports/report_latest.json --style immunefi --format md

# Export to structured JSON
hawki export --input ./hawki_reports/report_latest.json --output export.json

# Contract registry
hawki registry list
```

### Generate a Report from a Previous Scan
```bash
hawki report --input ./hawki_reports/report_latest.json --format html
```
If `--input` is omitted, Hawk-i uses the most recent `report_*.json` in `./hawki_reports/`.

### View a Security Score
```bash
hawki score ./hawki_reports/report_latest.json
```

### Show Local Metrics
```bash
hawki metrics
```

### Monitor a Repository
```bash
hawki monitor /path/to/repo --interval 60 --alert-log alerts.txt
```

---

## ⚙️ Operational Modes

`hawki scan` adapts to your environment and privacy needs:

| Mode | Static Rules | AI | Sandbox | Docker Required | How to Enable |
|------|--------------|----|---------|-----------------|----------------|
| **Minimal** | ✅ | ❌ | ❌ | ❌ | `hawki scan .` |
| **Enhanced** | ✅ | ✅ | ❌ | ❌ | `hawki scan . --ai` |
| **Full Audit** | ✅ | ✅ | ✅ | ✅ | `hawki scan . --ai --sandbox` |

Reports indicate which mode was used and adapt their content accordingly.

The **Deep Agent** is a separate autonomous command rather than a scan mode. Run it with `hawki deep <target> --goal "..."`. It has its own budget, memory, and sandbox lifecycle. See [Hawk-i Deep](#hawk-i-deep-the-autonomous-agent).

---

## 🔧 Advanced Usage

### Audit-Grade Reporting

`hawki scan` with `--format` generates a report using the Audit-Grade Report System (ARS v2). Reports include:

- **Executive Summary:** total contracts, severity counts, security score, risk classification, and the mode used.
- **Vulnerability Breakdown:** severity chart and type chart, with a fallback table.
- **Per-Finding Details:** title, severity, file and line, vulnerable code, recommended fix, explanation, impact, and exploit steps (when the sandbox reproduced the issue).
- **Simulation Metrics:** success rate, balance deltas, gas used (when `--sandbox` is set).
- **Immunefi Style:** use `--style immunefi` for ready-to-submit bug bounty reports.

Formats: Markdown, JSON, HTML, and PDF. HTML and charts need the `reports` extra; PDF additionally needs a wkhtmltopdf binary (`pip install "hawki[pdf]"`).

> **Note on scope:** `hawki scan` runs static rules, AI, and the sandbox by default, and can fold in the extra modules with flags. `--check-deps` (dependencies), `--upgrade-safety` (proxy upgrade checks), and `--prove` (formal verification) merge their findings into the single scan report and score; `--verify` (against a deployed `--address`) records a bytecode mismatch as a High finding; `--all` turns on deps, upgrade, and prove together. `--deep` launches the Deep agent as a bounded adjunct campaign that prints its own summary and records to its own memory rather than merging into the scan report. Each module is also available as its own subcommand (`hawki verify`, `hawki deps`, `hawki upgrade`, `hawki prove`, `hawki deep`) when you want to run it on its own.

### Security Score

The security score is a deterministic **0 to 100** number computed as:

- Base: 100
- Deductions per finding:
  - Critical: -15
  - High: -8
  - Medium: -4
  - Low: -1
- With the sandbox enabled: an additional penalty per successfully reproduced exploit.

The scoring engine can also apply extended penalties (bytecode mismatch, dependency with a known exploit, upgrade storage collision, novel-attack success) when the corresponding module results are supplied to it.

**Risk Bands:**

| Score | Classification |
|-------|----------------|
| 90 to 100 | Secure |
| 75 to 89 | Minor Risk |
| 50 to 74 | Moderate Risk |
| 25 to 49 | High Risk |
| 0 to 24 | Critical Risk |

Use `hawki score <findings.json>` to see the score without generating a full report.

### Guided Remediation

Every finding includes a `fix_snippet` populated by the Remediation Engine, which uses templates and AST context to generate accurate fixes. For example, a reentrancy finding includes:

```solidity
// Vulnerable code
function withdraw() external {
    uint amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] = 0;
}

// Recommended fix
function withdraw() external nonReentrant {
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

### Hawk-i Deep, the Autonomous Agent

Hawk-i Deep continuously probes your smart contracts for vulnerabilities. It starts with 30+ predefined attack scripts, and once those are exhausted it invents novel attacks using an LLM, executes them in a sandbox, and remembers every attempt.

**Basic usage:**
```bash
hawki deep /path/to/repo --goal "drain funds" --budget-attempts 50
```

Both the `target` and `--goal` are required. For the full flag reference and examples, see [docs/deep_agent.md](docs/deep_agent.md).

**Key flags:**

| Flag | Description |
|------|-------------|
| `--goal` | Natural language attack objective (required) |
| `--goal-file` | Text file containing the goal (overrides `--goal`) |
| `--budget-attempts N` | Stop after N attack attempts |
| `--budget-tokens M` | Stop after estimated token usage exceeds M |
| `--memory {sqlite,json}` | Memory backend (default: sqlite) |
| `--force` | Re-attempt previously tried attacks |
| `--continuous` | Run continuously, re-scanning for changes |
| `--interval` | Polling interval in seconds (continuous mode) |
| `--code-only` | Skip live execution, LLM reasoning only |
| `--target-contract` | Focus on a specific contract name |
| `--poc-format {hardhat,foundry}` | PoC format (default: hardhat) |
| `--llm-provider` | `openai`, `anthropic`, `gemini`, or other LiteLLM providers |
| `--llm-model` | Model name (for example `gpt-4`) |
| `--llm-key` | API key (or set the provider env var) |
| `--doctor` | Run a pre-flight health check first |
| `--skip-known` | Skip if scanned within the last 30 days |
| `--force-scan` | Override `--skip-known` |

**Memory backends:** SQLite (default, `~/.hawki/deep_memory.db`) or JSON (`~/.hawki/deep_memory.jsonl`). Switch with `--memory json`. Paths are fixed under `~/.hawki/`.

### Bytecode Verification and Deployed-Contract Scanning

Compare on-chain bytecode against locally compiled source:

```bash
hawki verify 0x1234567890abcdef1234567890abcdef12345678 \
  --source ./contracts \
  --rpc-url https://mainnet.infura.io/v3/YOUR_KEY \
  --ignore-metadata
```

Output indicates match or mismatch, the compared hashes, and a diff summary.

You can also scan a deployed contract directly by address:

```bash
hawki scan --address 0x1234567890abcdef1234567890abcdef12345678 \
  --chain ethereum \
  --rpc-url https://eth.llamarpc.com \
  --source ./contracts \
  --explorer-key YOUR_ETHERSCAN_KEY
```

Hawk-i fetches bytecode from the RPC endpoint, attempts to fetch verified source from the block explorer, runs static rules (and AI with `--ai`) when source is available, and falls back to bytecode opcode analysis when it is not.

**Chain support** (via `--chain`): `ethereum`, `polygon`, `arbitrum`, `optimism`, `base`, `bnb`, `avalanche`, `sepolia`, and `local`. See [docs/chains.md](docs/chains.md) for chain IDs, default RPCs, and explorer APIs.

### Dependency Scanning

Checks `package.json`, `foundry.toml`, `hardhat.config.js`, `yarn.lock`, `pnpm-lock.yaml`, and `Cargo.toml` for known vulnerable library versions.

```bash
hawki deps ./my-project
```

To refresh the vulnerability database (the target path is still required):
```bash
hawki deps ./my-project --update-db
```

You can also fold dependency checks into a repository scan with `hawki scan ./repo --check-deps`.

### Upgrade Safety Checks

Detects proxy patterns (Transparent, UUPS, Beacon) and flags storage collisions or missing initializers.

```bash
hawki upgrade ./my-upgradeable-contract
```

Heuristics look for `delegatecall`, `upgradeTo`, and storage layout via `solc --storage-layout`, and warn when an upgradeable contract has no initializer.

### Formal Verification

Runs the Solidity SMTChecker (`solc --model-checker`) or `hevm`.

```bash
hawki prove ./contracts --engine smtchecker
```

The default engine is `smtchecker`, which requires `solc` on your PATH. If `hevm` is installed, use `--engine hevm`. Narrow the analysis to one contract with `--contract NAME`.

### hawki doctor, the Pre-Flight Health Check

`hawki doctor` validates your Hawk-i environment in under 5 seconds:

- **System dependencies:** `forge`, `solc`, `git`, `python3`
- **AI provider connectivity:** OpenAI and Anthropic API keys
- **RPC and network health:** ping configured RPCs, validate chainId, measure latency
- **Configuration and storage:** validate `~/.hawki/config.yaml`, check permissions
- **Optional security tools:** detect `slither`, `mythril`, `hevm`
- **Budget and limits:** validate deep agent budget settings

**Options:**

| Flag | Description |
| :--- | :--- |
| `--verbose` | Show detailed output |
| `--fix` | Auto-repair trivial issues |
| `--format {terminal,json}` | Output format (use `json` for CI/CD) |
| `--skip-rpc` | Skip RPC checks |
| `--skip-ai` | Skip AI provider checks |

`hawki scan --doctor` and `hawki deep --doctor` run the health check first and abort on critical failures. See [docs/doctor.md](docs/doctor.md).

### hawki export, Structured Export

Export findings to a structured JSON format for toolchain integration:

```bash
hawki export --input ./hawki_reports/report_latest.json --output export.json
```

The envelope includes target metadata, all findings with full details, exploit code, attack sequences, the security score, and dependency findings. Only the `structured` format is currently supported. See [docs/export.md](docs/export.md) for the complete schema.

### Contract Registry

Track scanned contracts to avoid duplicates:

```bash
hawki registry list        # Show all scanned contracts
hawki registry clear       # Clear the registry
hawki registry show --address 0x123 --chain ethereum  # Show details
```

When scanning a deployed contract with `hawki scan --address`, the contract is automatically recorded in `~/.hawki/scanned_registry.json`. Use `--skip-known` to skip a contract scanned in the last 30 days, or `--force-scan` to override.

### Local Metrics

Hawk-i keeps anonymous usage statistics **locally only**, with no network export. View your own stats with:

```bash
hawki metrics
```

Data is stored in `~/.hawki/metrics.json` and includes scan timestamp (day only), mode, whether AI and sandbox were enabled, findings per severity, and platform. No metrics are sent to any external server; the old HTTP telemetry exporter was removed in v1.0.0.

### CLI Reference

The main command is `hawki`. Available subcommands:

| Subcommand | Description |
|------------|-------------|
| `scan` | Perform a one-time security scan. |
| `deep` | Run the autonomous deep-exploit agent. |
| `verify` | Verify on-chain bytecode against source. |
| `deps` | Scan dependencies for known vulnerabilities. |
| `upgrade` | Check upgrade safety of contracts. |
| `prove` | Run formal verification (SMTChecker or Hevm). |
| `registry` | Manage the contract registry. |
| `report` | Generate a report from existing findings. |
| `score` | Calculate the security score from a findings file. |
| `metrics` | Display local usage statistics. |
| `monitor` | Continuously monitor a repository or contract. |
| `export` | Export findings to structured JSON. |
| `doctor` | Pre-flight health check. |

**`hawki scan` options:**
```
hawki scan <target> [options]
  --address ADDR                Deployed contract address (instead of a repo)
  --chain CHAIN                 Blockchain chain (ethereum, polygon, etc.)
  --rpc-url URL                 RPC URL for deployed-contract scanning
  --source PATH                 Path to source repository (for deployed contract)
  -v, --verbose                 Enable debug logging
  -o, --output-dir DIR          Report output directory (default: ./hawki_reports)
  --ai                          Enable AI reasoning
  --ai-model MODEL              LLM model (for example openai/gpt-4)
  --api-key KEY                 API key for the LLM
  --sandbox                     Run exploit simulation (requires Docker)
  --format {md,json,html,pdf}   Output report format
  --check-deps                  Run dependency scanning (merged into the report)
  --upgrade-safety              Run proxy upgrade-safety checks (merged into the report)
  --prove                       Run formal verification (merged into the report)
  --prove-engine ENGINE         Formal engine (default: smtchecker)
  --verify                      Verify deployed bytecode against source (with --address)
  --all                         Enable dependency, upgrade-safety, and formal checks together
  --deep                        Run the Deep agent as a bounded adjunct campaign
  --deep-goal TEXT              Goal for the adjunct Deep campaign
  --deep-budget-attempts N      Attempt budget for the adjunct Deep campaign
  --deep-budget-tokens N        Token budget for the adjunct Deep campaign
  --skip-known                  Skip if scanned within the last 30 days
  --force-scan                  Force scan even if recently scanned
  --explorer-key KEY            Block explorer API key
  --style {audit,immunefi}      Report style (default: audit)
  --doctor                      Run a pre-flight health check first
```

**`hawki verify` options:**
```
hawki verify ADDRESS --source PATH [--rpc-url URL] [--contract NAME] [--ignore-metadata]
```

**`hawki deps` options:**
```
hawki deps TARGET [--update-db]
```

**`hawki upgrade` options:**
```
hawki upgrade TARGET
```

**`hawki prove` options:**
```
hawki prove TARGET [--engine {smtchecker,hevm}] [--contract NAME]
```

**`hawki doctor` options:**
```
hawki doctor [--verbose] [--fix] [--format {terminal,json}] [--skip-rpc] [--skip-ai]
```

**`hawki export` options:**
```
hawki export --input INPUT.json [--output OUTPUT.json] [--format structured]
```

**`hawki registry` options:**
```
hawki registry {list,clear,show} [--address ADDR] [--chain CHAIN]
```

**`hawki report` options:**
```
hawki report [-i INPUT.json] [-o OUTPUT_DIR] [-f {md,json,html,pdf}] [--style {audit,immunefi}]
```

**`hawki score` options:**
```
hawki score INPUT.json [-v]
```

For the full flag list of any subcommand, run `hawki <subcommand> --help`.

### CI/CD Integration

Hawk-i ships `scripts/ci_pipeline.py`, which auto-detects GitHub Actions or GitLab CI and formats output accordingly. The script exits with a non-zero code when high-severity findings are present, so it can fail a pipeline.

**GitHub Actions example (`.github/workflows/hawki.yml`):**
```yaml
name: Hawk-i Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Hawk-i
        run: pip install hawki
      - name: Health check
        run: hawki doctor --format json --skip-rpc --skip-ai
      - name: Run scan
        run: hawki scan . --format json
      - name: Export findings for tooling
        run: hawki export --input ./hawki_reports/report_*.json --output export.json
```

For continuous monitoring, run `hawki deep --continuous` or `hawki monitor` on a long-running server.

### Ecosystem Integrations

Use `scripts/deploy_helpers.py` to integrate with popular development tools.

```bash
# Foundry
python scripts/deploy_helpers.py foundry /path/to/forge-project --ai

# Hardhat
python scripts/deploy_helpers.py hardhat /path/to/hardhat-project

# Remix
python scripts/deploy_helpers.py remix /path/to/remix-workspace

# Generate a human-readable audit report
python scripts/deploy_helpers.py readme /path/to/report.json --output AUDIT.md
```

---

## 🧪 Demo Suite

A dedicated demo suite of intentionally vulnerable contracts helps you understand Hawk-i's capabilities and test your contributions. It contains 35 Solidity fixtures under `demo/contracts/`, covering reentrancy, access control, delegatecall misuse, oracle manipulation, flash-loan attacks, governance manipulation, signature replay, integer overflow, and more.

### Manual Demo

```bash
cd demo
npm install               # install Hardhat dependencies
npx hardhat node          # start a local chain (keep this terminal open)

# In a second terminal:
npx hardhat run scripts/deploy.js --network localhost

# In a third terminal:
hawki scan . --format html
hawki deep . --goal "drain funds" --budget-attempts 5 --llm-provider openai --llm-model gpt-4
```

See the [demo README](demo/README.md) for detailed instructions and expected output.

---

## 📁 Project Structure

```
hawki/
├── core/
│   ├── repo_intelligence/     # Repo cloning and Solidity parsing
│   ├── static_rule_engine/    # Static analysis and dynamic rule loading (30+ rules)
│   ├── ai_engine/             # LLM orchestration and prompt management
│   ├── exploit_sandbox/       # Docker-based exploit simulation
│   ├── deep/                  # Hawk-i Deep autonomous agent
│   ├── verify/                # Bytecode verification
│   ├── deps/                  # Dependency scanning
│   ├── upgrade/               # Upgrade safety checks
│   ├── formal/                # Pluggable formal verification
│   ├── diagnostics/           # Pre-flight health check
│   ├── exporters/             # Structured export
│   ├── registry/              # Contract registry
│   ├── remediation_engine/    # Context-aware fix snippet generation
│   ├── telemetry/             # Local-only metrics (no network export)
│   ├── monitoring/            # Continuous monitoring and alerts
│   └── data_layer/            # Report generation (ARS v2) and persistence
cli/                           # Command-line interface (outside the hawki package)
scripts/                       # CI/CD and integration helpers
docker/                        # Dockerfile and compose
demo/                          # Vulnerable contracts for testing
tests/                         # Unit tests
docs/                          # Documentation
├── doctor.md                  # Health check guide
├── chains.md                  # Multi-chain support
├── deep_agent.md              # Deep agent guide
├── verification.md            # Verification and security modules
├── export.md                  # Structured export guide
└── enterprise.md              # Self-hosting and services
pyproject.toml                 # Package metadata
CONTRIBUTING.md                # Contribution guidelines
CHANGELOG.md                   # Release notes
README.md                      # This file
```

---

## 🤝 Contributing

Contributions are welcome, whether you are fixing a bug, adding a rule, improving the deep agent, or writing documentation. Please read the [Contributing Guidelines](CONTRIBUTING.md) to get started.

---

## 📄 License

Hawk-i is released under the [MIT License](LICENSE).

---

## 🙏 Acknowledgements

Hawk-i builds on excellent open-source projects:

- [tree-sitter](https://tree-sitter.github.io/) and [tree-sitter-solidity](https://github.com/tree-sitter/tree-sitter-solidity) for parsing.
- [LiteLLM](https://github.com/BerriAI/litellm) for unified LLM access.
- [Docker](https://www.docker.com/) for sandboxing.
- [Web3.py](https://web3py.readthedocs.io/) for blockchain interaction.
- [GitPython](https://gitpython.readthedocs.io/) for repository handling.
- [matplotlib](https://matplotlib.org/) for chart generation (optional).
- [Jinja2](https://jinja.palletsprojects.com/) for templated reports.

Special thanks to all contributors and the Web3 security community.

---

## 🛣️ Roadmap

- [x] **Phase 1:** repository intelligence and static rule engine
- [x] **Phase 2:** AI reasoning with LiteLLM
- [x] **Phase 3:** exploit simulation sandbox
- [x] **Phase 4:** continuous monitoring and alerts
- [x] **Phase 5:** CI/CD and ecosystem integrations
- [x] **Phase 6:** deployment (PyPI, Docker, CLI)
- [x] **Phase 7, v0.7.0:** Intelligence and Reporting Upgrade (ARS v2, 30 rules, score, remediation)
- [x] **Phase 8, v1.0.0:** Autonomous Security Intelligence
  - Hawk-i Deep (novel attack generation, memory, budget, continuous mode, Foundry PoC, target-contract)
  - Bytecode verification, dependency scanning, upgrade safety, formal verification
  - Deployed-contract scanning (multi-chain, explorer integration, bytecode analysis)
  - Immunefi-style reports
  - Structured export (`hawki export`)
  - Pre-flight health check (`hawki doctor`)
  - Contract registry (`hawki registry`)
  - Removal of all commercial telemetry
- [ ] **Phase 9:** unified reporting that folds all module results into a single `hawki scan` run
- [ ] **Phase 10:** dashboard and real-time visualisation

---

## 📬 Contact and Support

- **Issues:** [GitHub Issues](https://github.com/gethawki/hawki/issues)
- **Discussions:** [GitHub Discussions](https://github.com/gethawki/hawki/discussions)
- **LinkedIn:** [0xSemantic](https://linkedin.com/in/0xsemantic)
- **Medium:** [@0xSemantic](https://medium.com/@0xsemantic)
- **Twitter:** [@0xSemantic](https://twitter.com/0xSemantic)

Happy auditing, and may your contracts be bug-free. 🦅

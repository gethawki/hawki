# Changelog

## v1.0.0 (2026-07-15) - Autonomous Security Intelligence

### 🚀 New Features

#### Hawk-i Deep - Autonomous Exploit Agent
- **Novel Attack Generation** - After exhausting 30+ rule-based attacks, the agent invents entirely new attack vectors using an LLM (your own API key via LiteLLM).
- **Pluggable Memory** - Remembers every attack attempt with SQLite (default) or JSON backends; prevents repeating the same attack.
- **Dual Budget Control** - Stop based on attack attempts (`--budget-attempts`) and/or estimated token usage (`--budget-tokens`).
- **Continuous Mode** - Run indefinitely (`--continuous`) and react to repository changes (resets rule memory on new commits).
- **Target-Specific Scanning** - Focus on a single contract (`--target-contract`) to reduce noise and speed up analysis.
- **Foundry PoC Support** - Generate exploit proof-of-concept in Foundry (Solidity) format (`--poc-format foundry`) alongside Hardhat (JavaScript).

#### Additional Security Modules
- **Bytecode Verification** (`hawki verify`) - Compare on-chain bytecode against compiled source with metadata stripping and detailed diff output.
- **Dependency Scanning** (`hawki deps`) - Detect vulnerable library versions from `package.json`, `foundry.toml`, `yarn.lock`, `pnpm-lock.yaml`, and `Cargo.toml` with full semver support and auto-updateable vulnerability database.
- **Upgrade Safety Checks** (`hawki upgrade`) - Detect proxy patterns (Transparent, UUPS, Beacon), storage collisions via `solc --storage-layout`, and missing initializers.
- **Pluggable Formal Verification** (`hawki prove`) - Built-in SMTChecker (solc) and Hevm support; add your own verifiers.

#### Deployed Contract Scanning
- **Scan by Address** (`hawki scan --address`) - Scan deployed contracts on any EVM chain without cloning a repository.
- **Multi-Chain Support** - Nine EVM chains supported (Ethereum, Polygon, Arbitrum, Optimism, Base, BNB, Avalanche, Sepolia, and a local chain) with chain-specific explorer APIs.
- **Verified Source Fetching** - Automatically fetch verified source code from block explorers (Etherscan, Polygonscan, Arbiscan, etc.).
- **Bytecode Analysis** - When source is unavailable, analyze bytecode for dangerous opcodes (`DELEGATECALL`, `SELFDESTRUCT`, `CALLCODE`).

#### Reporting & Export
- **Immunefi-Style Reports** (`hawki report --style immunefi`) - Generate ready-to-submit bug bounty reports matching Immunefi's template.
- **Structured Export** (`hawki export`) - Export findings, exploit code, and transaction sequences to JSON for CI/CD and toolchain integration.
- **Extended Reporting and Scoring** - The report generator and scoring engine gained sections and penalties for bytecode, dependency, upgrade, formal, and deep-agent results, ready to be populated from those subcommands.

#### Developer & DevOps Tooling
- **Pre-Flight Health Check** (`hawki doctor`) - Validate your entire environment (system deps, AI providers, RPCs, config, optional tools, budget) in under 5 seconds with actionable fix suggestions.
- **Contract Registry** (`hawki registry`) - Track scanned contracts to avoid duplicates; auto-records deployed contract scans.
- **CLI Integration** - `hawki scan --doctor` and `hawki deep --doctor` run health checks before scanning; abort on critical failures.

### 🔧 Improvements

#### CLI
- Added `deep`, `verify`, `deps`, `upgrade`, `prove`, `doctor`, `export`, `registry` subcommands.
- `scan` now supports `--address`, `--chain`, `--rpc-url`, `--source`, `--explorer-key` for deployed contract scanning.
- `scan` supports `--check-deps` to run dependency scanning inline.
- `report` supports `--style` to choose between `audit` and `immunefi`.
- `deep` supports `--target-contract`, `--poc-format`, and `--doctor`.

#### Dependency Scanner
- Full semver support using `packaging.version` and `packaging.specifiers`.
- Expanded vulnerability database with entries for OpenZeppelin, forge-std, hardhat, ethers, web3, Uniswap, Aave, Balancer, SushiSwap, and more.
- Auto-update vulnerability database with `hawki deps --update-db`.

#### Memory System
- `clear_rule_attempts()` method to reset rule attack memory on repository changes (continuous mode).
- JSON and SQLite backends now fully interchangeable.

#### Scoring Engine
- Extended weights: bytecode mismatch (-20), dependency with known exploit (-10 per), upgrade storage collision (-15 per), novel attack success (-10 per).

#### Documentation
- Added comprehensive documentation: `docs/doctor.md`, `docs/chains.md`, `docs/export.md`, `docs/deep_agent.md`, `docs/verification.md`, `docs/enterprise.md`.
- Updated README with all v1.0.0 features.

### 🐛 Bug Fixes
- Fixed `NovelExecutor` to accept `poc_format` and pass it to `CodeGenerator`.
- Fixed sandbox support for Foundry tests (`run_foundry_test` method added).
- Fixed CLI imports for `NovelExecutor`, `LLMPlanner`, `HybridPlanner`.
- Removed unsupported `--address` flags from `deep` command.

### ⚠️ Breaking Changes
- **Telemetry exporter removed** - `--telemetry` flag is no longer available. Local metrics (`hawki metrics`) remain.
- Scripts using `--telemetry` will need to remove the flag.

### 📚 Documentation
- Full documentation for all new features.
- Multi-chain support documented in `docs/chains.md`.
- Pre-flight health check guide in `docs/doctor.md`.
- Structured export guide in `docs/export.md`.
- Enterprise deployment guide in `docs/enterprise.md`.

### 🙏 Thanks
- To all contributors and users who tested v0.7.0 and provided feedback.
- Special thanks to the Web3 security community for supporting open-source security infrastructure.

---

## v0.7.0 (2025-04-15) - Intelligence & Reporting Upgrade

### 🚀 New Features
- **Audit-Grade Reporting (ARS v2)** - Professional reports with executive summary, security score, charts, and per-finding remediation.
- **Security Score** - 0-100 deterministic score based on severity and exploit success.
- **Guided Remediation Engine** - Context-aware fix snippets for every vulnerability.
- **Opt-In Telemetry** - Anonymous usage metrics to measure ecosystem impact.
- **Expanded Vulnerability Library** - 30+ rules covering critical, high, and medium issues.
- **Sandbox Enhancements** - Attack scripts now return detailed metrics (balances, gas, tx hash) integrated into reports.

### 🔧 Improvements
- CLI now supports `report`, `score`, and `metrics` subcommands.
- PDF report generation (optional).
- Backward compatibility preserved - old scans still work.

### 📚 Documentation
- Updated README with telemetry info.
- Added two case studies (bZx and PancakeBunny) in `docs/case-studies/`.

### 🐛 Bug Fixes
- Various bug fixes and stability improvements.

### ⚠️ Breaking Changes
- None - all additions are backward compatible.

### 🙏 Thanks
- To all contributors and users.

---

## v0.6.0 (2025-04-01) - Core Development Complete

### 🚀 New Features
- **Repository Intelligence** - Local and remote repository cloning, Solidity parsing, contract indexing, dependency graph.
- **Static Rule Engine** - Dynamic rule discovery with 15+ built-in rules (reentrancy, access control, integer overflow, etc.).
- **AI Reasoning** - LiteLLM integration for Gemini, OpenAI, Anthropic, local models; dynamic prompt management.
- **Exploit Simulation Sandbox** - Dockerised environment with Hardhat/Anvil; auto-discovers attack scripts.
- **Continuous Monitoring** - Modular watchers (Git commits, deployed contracts).
- **CI/CD Integration** - GitHub Actions, GitLab CI with annotations and exit codes.
- **CLI** - Single `hawki` command with `scan`, `audit`, `simulate`, `watch`, `report`.

### 🔧 Improvements
- PyPI package (`pip install hawki`).
- Docker image (`docker pull levichinecherem/hawki`).
- Demo suite of 30 intentionally vulnerable contracts.
- Cross-platform compatibility (Linux, macOS, Windows).

### 📚 Documentation
- Complete README with quick start, examples, and API reference.
- Demo suite documentation.

---

## v0.5.0 (2025-03-15) - CI/CD & Ecosystem Integrations

### 🚀 New Features
- GitHub Actions and GitLab CI integration.
- Foundry, Hardhat, Remix helpers.
- Human-readable audit report generation.

---

## v0.4.0 (2025-03-01) - Monitoring & Alerts

### 🚀 New Features
- Modular watcher system for continuous monitoring.
- Git commit watcher and deployed contract watcher.
- Alert manager with file and console logging.

---

## v0.3.0 (2025-02-20) - Exploit Simulation Sandbox

### 🚀 New Features
- Docker-based sandbox for exploit simulation.
- Attack script discovery and execution.
- Reentrancy, access control, and other example attacks.

---

## v0.2.0 (2025-02-10) - AI Reasoning

### 🚀 New Features
- LiteLLM integration for AI reasoning.
- Dynamic prompt templates.
- Structured finding output from AI.

---

## v0.1.0 (2025-02-01) - Repository Intelligence + Static Rules

### 🚀 New Features
- Repository intelligence (local/remote cloning, parsing).
- Static rule engine with dynamic discovery.
- 10+ built-in rules.
- CLI and basic reporting.

---

## Legend

| Icon | Meaning |
|------|---------|
| 🚀 | New Feature |
| 🔧 | Improvement |
| 🐛 | Bug Fix |
| ⚠️ | Breaking Change |
| 📚 | Documentation |
| 🙏 | Thanks |
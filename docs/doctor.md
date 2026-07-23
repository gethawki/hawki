# `hawki doctor` - Pre-Flight Health Check

## Overview

Hawk-i relies on a chain of external tools (Foundry, solc), network services (RPC endpoints), AI providers, and local state. A single misconfiguration can turn a quick scan into a long debugging session.

`hawki doctor` runs a diagnostic of your Hawk-i environment in under 5 seconds, clearly showing what works, what does not, and how to fix it.

## What It Checks

| Category | Checks Performed |
| :--- | :--- |
| **System Dependencies** | Verifies `forge`, `solc`, `git`, and `python3` are installed and meet minimum versions. |
| **AI Provider Connectivity** | Tests API keys for OpenAI and Anthropic by pinging the models endpoint. |
| **RPC and Network Health** | Pings enabled RPC endpoints (Ethereum, Arbitrum, Polygon, etc.), validates `chainId`, fetches the latest block, and measures latency. |
| **Configuration and Storage** | Validates `~/.hawki/config.yaml` syntax and checks write permissions for `~/.hawki/`. |
| **Optional Security Tools** | Detects `slither`, `mythril`, and `hevm`. Warns if missing (non-critical). |
| **Budget and Limits** | Validates deep agent budget settings (`--budget-attempts`, `--budget-tokens`). |

## Usage

```bash
hawki doctor
```

## Options

| Flag | Description |
| :--- | :--- |
| `--verbose` | Show detailed output. |
| `--fix` | Auto-repair trivial issues (create missing directories, set permissions). |
| `--format {terminal,json}` | Output format. Use `json` for CI/CD integration. |
| `--skip-rpc` | Skip RPC connectivity checks. |
| `--skip-ai` | Skip AI provider connectivity checks. |

## Example Output

```text
+----------------------------------------------+
| Hawk-i Health Check                          |
+----------------------------------------------+

Status: WARNING
Checks: 4 passed, 2 warnings, 1 critical, 7 total

+-------------------+----------+------------------------------------+----------------------------------+
| Check             | Status   | Message                            | Fix                              |
+-------------------+----------+------------------------------------+----------------------------------+
| system_deps       | PASS     | All system dependencies found.     |                                  |
| rpc_networks      | FAIL     | RPC failures: polygon              | Check RPC URLs and connectivity. |
| ai_providers      | WARN     | Some AI providers failed: OpenAI   | Check your API keys.             |
| config_storage    | PASS     | Configuration and storage healthy. |                                  |
| optional_tools    | WARN     | Optional tools missing: slither    | pip install slither-analyzer     |
| budget_limits     | PASS     | Budget limits configured.          |                                  |
+-------------------+----------+------------------------------------+----------------------------------+

Warnings found. Some features may work with reduced functionality.
```

## Integration with Workflow

- **Pre-scan guard:** `hawki scan --doctor` and `hawki deep --doctor` run the health check first. If critical failures are detected, the run aborts.
- **CI/CD pipelines:** `hawki doctor --format json` emits JSON you can parse to decide whether to proceed with the build.

## Troubleshooting Reference

| Symptom | Likely Cause | Fix |
| :--- | :--- | :--- |
| `solc not found` | Solidity compiler not installed | Run `foundryup` or install solc separately (for example via solc-select). |
| `RPC 403 Forbidden` | API key missing or expired | Set the chain RPC env var or pass `--rpc-url`. |
| `OpenAI Connection Failed` | Invalid API key | Set the `OPENAI_API_KEY` env var. |
| `Registry SQLite locked` | Another Hawk-i process is running | Close other terminal sessions. |

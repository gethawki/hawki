# Hawk-i Deep - Autonomous Exploit Agent

Hawk-i Deep is a self-learning agent that probes your smart contracts for vulnerabilities. It starts with 30+ predefined attack scripts (for example reentrancy and access control). After exhausting those, it invents novel attacks using an LLM, executes them in a sandbox, and remembers every attempt.

## Basic Usage

```bash
hawki deep /path/to/repo --goal "drain funds" --budget-attempts 50
```

The `target` (a local path or Git URL) and `--goal` are both required.

## Command Line Options

| Flag | Description |
| :--- | :--- |
| `--goal` | Natural language attack objective (required, e.g. "become owner") |
| `--goal-file` | Path to a text file containing the goal (overrides `--goal`) |
| `--budget-attempts N` | Stop after N attack attempts |
| `--budget-tokens M` | Stop after estimated token usage exceeds M (chars/4) |
| `--memory {sqlite,json}` | Memory backend (default: sqlite) |
| `--force` | Re-attempt previously tried attacks |
| `--continuous` | Run continuously, re-scanning the repo for changes |
| `--interval` | Polling interval in seconds (continuous mode) |
| `--code-only` | Skip live execution, LLM reasoning only |
| `--target-contract` | Focus the agent on a specific contract name |
| `--poc-format {hardhat,foundry}` | PoC format (default: hardhat) |
| `--llm-provider` | `openai`, `anthropic`, `gemini`, or other LiteLLM providers |
| `--llm-model` | Model name (e.g. `gpt-4`) |
| `--llm-key` | API key (or set the provider's environment variable) |
| `--doctor` | Run a pre-flight health check before starting |
| `--skip-known` | Skip if the repo was scanned within the last 30 days |
| `--force-scan` | Override `--skip-known` and scan anyway |

Both budgets default to unlimited when not set. When both are supplied, the agent stops at whichever limit is reached first.

> **Note:** There is no `--address` flag on `hawki deep`. Use `hawki scan --address` for deployed-contract analysis. Memory paths are fixed under `~/.hawki/`; the backend is chosen with `--memory`, not a custom path.

## Examples

### Run with GPT-4, a token budget, and a Foundry PoC

```bash
hawki deep ./vulnerable-contract \
  --goal "steal all ETH" \
  --budget-attempts 20 \
  --budget-tokens 100000 \
  --llm-provider openai \
  --llm-model gpt-4 \
  --llm-key $OPENAI_API_KEY \
  --poc-format foundry
```

### Focus on a specific contract

```bash
hawki deep ./my-protocol \
  --goal "find any privilege escalation" \
  --target-contract Vault \
  --budget-attempts 50
```

### Continuous monitoring with a health check

```bash
hawki deep ./my-protocol \
  --goal "find any privilege escalation" \
  --continuous \
  --interval 120 \
  --doctor
```

When new commits are detected, the agent clears its memory of rule-based attacks (so they are re-tested) but retains its novel-attack history.

## Memory Backends

- **SQLite** (default): stores attempts in `~/.hawki/deep_memory.db`
- **JSON**: human-readable, stored in `~/.hawki/deep_memory.jsonl`

Switch with `--memory json`. The two backends are interchangeable.

## Novel Attack Generation

Once all predefined attack scripts are exhausted, the agent calls the LLM with:

- A repository AST summary (contracts, functions)
- Recent memory (the last attempts)
- The user goal

The LLM returns a plan (`name`, `description`, `steps`). The agent then generates an exploit script in either:

- **Hardhat** (JavaScript), the default, or
- **Foundry** (Solidity), with `--poc-format foundry`

The script is executed in the sandbox and all results are recorded.

## Budgeting

- `--budget-attempts`: a counter of attack attempts. Each attempt may include one or more LLM calls.
- `--budget-tokens`: estimated token usage using the heuristic `len(prompt + completion) / 4`.

The agent stops when the first configured limit is reached.

## Target-Specific Contract (`--target-contract`)

When `--target-contract` is provided, the agent:

- Filters the AST to only include the named contract
- Runs only the attack scripts relevant to it
- Deploys only that contract in the sandbox

This reduces noise and speeds up analysis for large codebases.

## Foundry PoC Support (`--poc-format foundry`)

The agent can generate the exploit PoC in Foundry (Solidity) format instead of Hardhat (JavaScript). Foundry tests are run with `forge test` inside the sandbox.

> **Note:** The sandbox Docker image must have Foundry installed. See [enterprise.md](enterprise.md) for Docker setup details.

## Troubleshooting

- **Docker not installed:** the sandbox requires Docker. Install Docker Engine or Docker Desktop.
- **LLM key missing:** set the appropriate environment variable (for example `OPENAI_API_KEY`) or pass `--llm-key`.
- **No attacks found:** make sure the repository contains Solidity files. For novel attacks, use a capable model.
- **Health check fails:** run `hawki doctor` to diagnose environment issues.

# Hawk-i Demo Suite: Intentionally Vulnerable Contracts

Welcome to the Hawk-i Demo Suite, a collection of Solidity smart contracts deliberately written with security flaws. The suite is designed to test, demonstrate, and validate Hawk-i's features:

- **Static Rule Engine:** detects known vulnerability patterns (50 rules, every one verified to actually fire through the real scan pipeline).
- **AI Reasoning:** uncovers subtle, logic-based issues using LLMs (Gemini, OpenAI, Anthropic, or local models via LiteLLM).
- **Exploit Simulation Sandbox:** attempts to exploit identified weaknesses in Docker and returns metrics.
- **Audit-Grade Reporting (ARS v2):** produces reports with an executive summary, a 0 to 100 security score, charts, and per-finding remediation snippets.
- **Guided Remediation Engine:** every finding includes a context-aware fix snippet.

Whether you are evaluating Hawk-i, sharpening your security skills, or preparing for a real engagement, this demo gives you a repeatable, self-contained environment.

---

## Real-code demos

Beyond the intentionally vulnerable fixtures below, this folder vendors four real,
third-party Solidity corpora that Hawk-i was run against, each with its scan
report saved under `<name>/hawki_report/`:

- **`not-so-smart-contracts/`** (Trail of Bits): the canonical catalog of classic
  Solidity bugs. 285 findings across the whole taxonomy.
- **`damn-vulnerable-defi/`** (The Red Guild): the offensive DeFi security wargame.
  136 findings, 22 Critical, including the unchecked-arithmetic clusters.
- **`pancake-smart-contracts/`** (PancakeSwap, BNB Chain): real, audited, deployed
  farming contracts. 41 findings, **0 Critical** and no false alarms, the honest
  low-severity notes you expect on mature production code.
- **`DeFiVulnLabs/`** (SunWeb3Sec): self-contained reproductions of real on-chain
  incidents. Used to prove the full pipeline end to end: a 50-rule sweep (285
  findings) plus the deep agent inventing and landing a live reentrancy drain on
  the `EtherStore` victim (attacker 1 ETH to 2 ETH in the sandbox). See
  `DeFiVulnLabs/deep_novel/REPORT.md`.

Each corpus is vendored under its own license; see the `DEMO_SOURCE.md` in each
folder for provenance.

---

## Table of Contents

- [Demo Suite Overview](#demo-suite-overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Walkthrough](#detailed-walkthrough)
- [The Contracts](#the-contracts)
- [How Hawk-i Detects Each Vulnerability](#how-hawk-i-detects-each-vulnerability)
- [Security Score Formula](#security-score-formula)
- [Extending the Demo](#extending-the-demo)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Demo Suite Overview

The demo lives in the `demo/` directory of the Hawk-i project. Its actual structure is:

```
demo/
├── contracts/          # 35 vulnerable Solidity fixtures
├── scripts/
│   └── deploy.js       # Compiles and deploys every fixture to a local chain
├── test/               # Reserved for Hardhat tests
├── hardhat.config.js   # Hardhat configuration
├── package.json        # Node dependencies
├── Dockerfile.demo     # One-shot containerised demo
└── README.md           # This file
```

The exploit attack scripts are not part of the demo directory. They ship inside the Hawk-i package at `hawki/core/exploit_sandbox/attack_scripts/` and are auto-discovered by the sandbox when you run `hawki scan . --sandbox`.

---

## Prerequisites

- **Python 3.9+** with `pip`
- **Node.js 16+** and `npm`
- **Hawk-i v1.0.0+** installed (see the [main README](../README.md) for options)
- **Git**
- **Docker** (optional, for exploit simulation and the deep agent sandbox)

---

## Quick Start

```bash
# 1. Clone the repository (if you have not already)
git clone https://github.com/gethawki/hawki.git
cd hawki

# 2. Install Hawk-i in editable mode
pip install -e .

# 3. Enter the demo directory and install Hardhat dependencies
cd demo
npm install

# 4. Start a local Hardhat chain (keep this terminal open)
npx hardhat node

# 5. In a second terminal, deploy the contracts
npx hardhat run scripts/deploy.js --network localhost

# 6. In a third terminal, run a scan
hawki scan . --format html
```

Static rules flag known vulnerabilities, and an HTML report is written to `./hawki_reports/`. Add `--ai` for LLM reasoning and `--sandbox` (with Docker running) for exploit simulation.

---

## Detailed Walkthrough

### Step 1: Set up the environment

```bash
# From the Hawk-i root directory
pip install -e .            # or: pip install hawki
cd demo
npm install
```

### Step 2: Deploy the contracts

Start a local chain in one terminal:

```bash
npx hardhat node
```

This launches a local Ethereum network at `http://127.0.0.1:8545`. Keep it running. In a second terminal, deploy:

```bash
npx hardhat run scripts/deploy.js --network localhost
```

The script compiles the fixtures and deploys them, printing each address. Example:

```
Deploying contracts...

ReentrancyDemo deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3
CrossFunctionReentrancy deployed to: 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
...

All contracts deployed.
```

The addresses change every time you restart the node.

### Step 3: Minimal scan (static rules only)

```bash
hawki scan .
```

Hawk-i indexes the Solidity files, loads every static rule, runs them against the contracts, and writes a JSON report to `./hawki_reports/`. Expect dozens of findings across the 35 fixtures, each with a severity, file location, and description.

### Step 4: Enhanced scan (with AI)

Set an API key for one of the supported providers and enable AI reasoning:

```bash
export OPENAI_API_KEY=sk-...
hawki scan . --ai --ai-model openai/gpt-4
```

Hawk-i performs the same static analysis and then sends contract context to the LLM, which may surface additional logic or economic issues. AI findings are merged with the static findings.

### Step 5: Full audit (AI plus sandbox)

```bash
hawki scan . --ai --sandbox --format html
```

With Docker running, the sandbox deploys the contracts in an ephemeral container and runs the matching attack scripts for exploitable findings, returning metrics such as balance deltas and gas used.

### Step 6: Run the deep agent

```bash
hawki deep . --goal "drain funds" --budget-attempts 5 --llm-provider openai --llm-model gpt-4
```

The deep agent runs rule-based attacks first and then, once those are exhausted, invents novel attack vectors with the LLM. See [docs/deep_agent.md](../docs/deep_agent.md).

### Step 7: Generate reports and scores

```bash
hawki report --input ./hawki_reports/report_latest.json --format html
hawki score ./hawki_reports/report_latest.json
```

If `--input` is omitted, `hawki report` uses the most recent `report_*.json` in `./hawki_reports/`.

---

## The Contracts

The 35 fixtures in `demo/contracts/` are a numbered set (01 to 30) plus five additional named examples. The exact filenames are:

| # | File | Focus |
|---|------|-------|
| 1 | `01_Reentrancy.sol` | Classic reentrancy |
| 2 | `02_CrossFunctionReentrancy.sol` | Cross-function reentrancy |
| 3 | `03_Delegatecall.sol` | Delegatecall to a user-supplied address |
| 4 | `04_Selfdestruct.sol` | Unprotected selfdestruct |
| 5 | `05_ProxyStorageCollision.sol` | Proxy storage collision |
| 6 | `06_MissingInitializer.sol` | Missing initializer (UUPS) |
| 7 | `07_AccessControlBypass.sol` | Access control bypass |
| 8 | `08_OracleManipulation.sol` | Oracle price manipulation |
| 9 | `09_FlashLoan.sol` | Flash-loan price manipulation |
| 10 | `10_GovernanceVote.sol` | Governance vote manipulation |
| 11 | `11_PermitReplay.sol` | Permit signature replay |
| 12 | `12_IntegerOverflowUnchecked.sol` | Integer overflow in an `unchecked` block |
| 13 | `13_TxOriginAuth.sol` | Authorization via `tx.origin` |
| 14 | `14_UnsafeExternalCall.sol` | Unsafe external call with state change after |
| 15 | `15_ApprovalRace.sol` | ERC20 approval race condition |
| 16 | `16_TimestampDependency.sol` | Timestamp dependency |
| 17 | `17_BlockhashRandomness.sol` | Blockhash used as randomness |
| 18 | `18_DoS.sol` | Denial of service via unexpected revert |
| 19 | `19_GasGriefing.sol` | Gas griefing |
| 20 | `20_UnboundedLoop.sol` | Unbounded loop (gas exhaustion) |
| 21 | `21_InputValidation.sol` | Improper input validation |
| 22 | `22_SignatureMalleability.sol` | Signature malleability |
| 23 | `23_ReusedNonce.sol` | Reused nonce in signatures |
| 24 | `24_UninitializedStorage.sol` | Uninitialized storage pointer |
| 25 | `25_Visibility.sol` | Improper function visibility |
| 26 | `26_HardcodedAddress.sol` | Hardcoded privileged address |
| 27 | `27_EventEmission.sol` | Missing event emission |
| 28 | `28_ZeroAddress.sol` | Missing zero-address check |
| 29 | `29_UpgradeAdmin.sol` | Improper upgrade admin transfer |
| 30 | `30_CentralizedOwner.sol` | Centralized owner risk |
| 31 | `AccessControlTest.sol` | Additional access-control example |
| 32 | `DelegateCallExample.sol` | Additional delegatecall example |
| 33 | `MysteryLogic.sol` | Subtle logic and rounding flaw (good AI target) |
| 34 | `ReentrancyDemo.sol` | Standalone reentrancy example |
| 35 | `VulnerableToken.sol` | Token with multiple issues |

The deployment script `scripts/deploy.js` references the contract names defined inside these files (for example `01_Reentrancy.sol` defines `contract ReentrancyDemo`).

---

## How Hawk-i Detects Each Vulnerability

Hawk-i uses a hybrid approach:

1. **Static rules:** pattern-based detection written in Python and stored in `hawki/core/static_rule_engine/rules/`. Each rule produces findings with a severity, explanation, and fix template.
2. **AI reasoning:** for complex logic flaws (economic attacks, governance manipulation, rounding errors), Hawk-i sends contract context to an LLM.
3. **Exploit simulation:** for exploitable findings, the sandbox runs a matching attack script from `hawki/core/exploit_sandbox/attack_scripts/`.
4. **Remediation engine:** after detection, the engine uses each rule's fix template plus AST context to produce a context-aware fix snippet.

---

## Security Score Formula

The score is deterministic:

```
base_score = 100
deductions = {"Critical": 15, "High": 8, "Medium": 4, "Low": 1}

score = base_score
for finding in findings:
    score -= deductions[finding["severity"]]

# With the sandbox enabled, each reproduced exploit adds a further penalty.

score = max(0, min(100, score))
```

| Score | Classification |
|-------|----------------|
| 90 to 100 | Secure |
| 75 to 89 | Minor Risk |
| 50 to 74 | Moderate Risk |
| 25 to 49 | High Risk |
| 0 to 24 | Critical Risk |

View the score directly with `hawki score ./hawki_reports/report_latest.json`.

---

## Extending the Demo

### Add a new vulnerable contract

1. Create a new `.sol` file in `demo/contracts/`.
2. Add its contract name to the `CONTRACT_NAMES` array in `scripts/deploy.js`.

### Add a matching attack script

Attack scripts live in the Hawk-i package, not the demo directory:

1. Create a `.py` file in `hawki/core/exploit_sandbox/attack_scripts/`.
2. Read the deployed addresses from the `CONTRACT_ADDRESSES` environment variable.
3. Print a JSON object as the last stdout line with `success`, `before_balance`, `after_balance`, `gas_used`, and optionally `transaction_hash` and `logs`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the naming convention that couples a rule, its remediation template, and its attack script.

---

## Troubleshooting

- **`ModuleNotFoundError: No module named 'hawki'`**: install Hawk-i (`pip list | grep hawki`) or run from the project root with `python -m cli.hawki_cli`.
- **Hardhat node connection refused**: make sure `npx hardhat node` is running and you pass `--network localhost` when deploying.
- **Sandbox fails with Docker errors**: verify Docker is installed and your user can run containers. On Linux you may need to be in the `docker` group.
- **AI analysis returns nothing**: check that a valid API key is set via `--api-key` or an environment variable.
- **PDF report generation fails**: install the optional dependencies (`pip install "hawki[pdf]"`) and a `wkhtmltopdf` binary. Without them, Hawk-i falls back to HTML or Markdown.

---

## License

This demo suite is part of the Hawk-i project and is licensed under the [MIT License](../LICENSE).

For questions or feedback, please [open an issue](https://github.com/gethawki/hawki/issues) on GitHub.

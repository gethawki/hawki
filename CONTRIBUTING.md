# Contributing to Hawk-i

First off, thank you for considering contributing to Hawk-i. Your help is essential for making this project better, whether you are fixing a bug, adding a new rule, improving documentation, or suggesting features.

We welcome contributions from everyone: seasoned Web3 developers, security researchers, and first-time open-source contributors. This guide will help you get started.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful, constructive, and considerate in all interactions.

---

## Getting Started

### 1. Fork and Clone

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/hawki.git
   cd hawki
   ```
3. Add the original repository as an upstream remote:
   ```bash
   git remote add upstream https://github.com/gethawki/hawki.git
   ```

### 2. Set Up the Development Environment

Hawk-i targets Python 3.9+. We recommend a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -e .            # Editable install
```

For report generation extras, install `pip install -e ".[reports]"` (HTML and charts) or `pip install -e ".[all]"` (adds PDF support).

If you plan to run the demo contracts or the exploit sandbox, you also need Node.js and Hardhat:

```bash
cd demo
npm install
```

### 3. Run the Tests

`pytest` is not part of the editable install, so install it first, then run the suite from the project root:

```bash
pip install pytest
python -m pytest
```

External services (Docker, LLM providers, network) are mocked in the test suite. There are no skip guards, so a test that reached a real service would fail rather than skip.

You can also run the linter (ruff ships with the dev environment):

```bash
ruff check .
ruff format .
```

---

## Development Workflow

1. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Make your changes** following the guidelines below.
3. **Write or update tests** to cover your changes.
4. **Run the tests** again to make sure they pass.
5. **Commit** with a clear message. We use [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat(rule): add reentrancy guard detection
   fix(parser): handle nested contract declarations
   docs(readme): update installation instructions
   ```
6. **Push to your fork** and open a Pull Request against `main`.

---

## Coding Standards

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use type hints for all function signatures.
- Write docstrings for modules, classes, and public methods.
- Keep functions small and focused.

### Solidity (demo contracts and fixtures)

- Follow the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html).
- Comment intentional vulnerabilities clearly (for example `// VULNERABILITY: reentrancy`).

### File Headers

Every file should begin with a short header comment describing its purpose. Example:

```python
# --------------------
# File: hawki/core/repo_intelligence/parser.py
# --------------------
"""
Solidity parser using tree-sitter.
Extracts contracts, functions, state variables, modifiers, and inheritance.
"""
```

---

## Extending Hawk-i (Auto-Discovery)

Most of Hawk-i is extended by dropping a file in the right directory. There is no central registry to edit, with one exception (exporters). Be aware that the discovery mechanism and the contract differ by directory:

| Directory | Discovery mechanism | What your file must provide |
|-----------|---------------------|-----------------------------|
| `hawki/core/static_rule_engine/rules/` | Module scan for `BaseRule` subclasses | Subclass `BaseRule`, implement `run_check(contract_data) -> List[dict]` |
| `hawki/core/formal/` | Module scan keyed by filename (the `--engine` value) | Subclass `Verifier`, implement `verify(...)` |
| `hawki/core/monitoring/watchers/` | Glob for `Watcher` subclasses | Subclass `Watcher`, implement `check()`; the config key is the class name lowercased |
| `hawki/core/ai_engine/prompt_templates/` | Glob for `*.json` (data, not code) | JSON with `system` and `user` keys, using `{single-brace}` placeholders |
| `hawki/core/remediation_engine/templates/` | Glob for `*.json`, keyed by filename stem | The stem is the rule id; JSON needs a `fix_snippet` using `{{double-brace}}` placeholders |
| `hawki/core/exploit_sandbox/attack_scripts/` | Glob for `*.py` (runtime protocol, no base class) | Read `CONTRACT_ADDRESSES` from the environment and print a JSON result as the last stdout line |
| `hawki/core/exporters/` | Hardcoded dictionary in `exporters/registry.py` | The one exception: you must edit the registry manually |

### The Name Coupling You Must Respect

For a vulnerability that has a rule, a remediation template, and an attack script, the names have to line up across all three directories. The convention is:

- Rule class `ReentrancyRule` produces the rule id `reentrancy` (class name minus `Rule`, lowercased).
- The remediation template is `remediation_engine/templates/reentrancy.json`.
- The attack script is `exploit_sandbox/attack_scripts/reentrancy_attack.py`.

Use `static_rule_engine/rules/reentrancy.py` as the canonical example.

---

## Adding a New Static Rule

Every rule provides detection logic plus explanation, impact, and fix templates so reports are complete even when AI is disabled.

1. Create a `.py` file in `hawki/core/static_rule_engine/rules/`.
2. Define a class that inherits from `BaseRule` (imported from the `rules` package).
3. Set the class attributes:
   - `severity`: one of `"Critical"`, `"High"`, `"Medium"`, `"Low"`, `"Info"` (severities are normalized to Title case across the platform).
   - `explanation_template`, `impact_template`, `fix_template`: strings; `fix_template` may contain placeholders.
4. Implement `run_check(self, contract_data)`. It returns a list of finding dictionaries. Each finding should include at least:
   - `title`, `severity`, `file`, `line`, `vulnerable_snippet`.
   - The `explanation`, `impact`, and `fix_snippet` fields are merged in automatically from the class attributes and the remediation engine.
5. Write a unit test in `tests/test_rules.py`.

Example skeleton:

```python
# --------------------
# File: hawki/core/static_rule_engine/rules/reentrancy.py
# --------------------
from typing import List, Dict, Any
from . import BaseRule

class ReentrancyRule(BaseRule):
    severity = "Critical"
    explanation_template = "This function makes an external call before updating state."
    impact_template = "An attacker can drain funds by recursively calling back before state updates."
    fix_template = "Apply the checks-effects-interactions pattern and add a nonReentrant modifier."

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        # ... detection logic ...
        return findings
```

---

## Adding a New Attack Script

Attack scripts are used by the exploit sandbox. They follow a runtime protocol; there is no base class to subclass.

1. Create a `.py` file in `hawki/core/exploit_sandbox/attack_scripts/`, named to match its rule id with an `_attack.py` suffix (for example `reentrancy_attack.py`).
2. The script runs inside a Docker container with a local chain at `http://localhost:8545` and the vulnerable contracts deployed. The deployed addresses are available in the `CONTRACT_ADDRESSES` environment variable as a JSON map of contract name to address.
3. The script must print a JSON object as the last line of stdout, with these fields:
   ```python
   {
       "success": bool,
       "before_balance": int,
       "after_balance": int,
       "gas_used": int,
       "transaction_hash": str,   # optional
       "logs": str                # optional
   }
   ```

`web3.py` is available in the sandbox image. Example skeleton:

```python
#!/usr/bin/env python3
import os, json
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
contract_addresses = json.loads(os.environ["CONTRACT_ADDRESSES"])

# ... perform the exploit and measure balances ...

result = {
    "success": True,
    "before_balance": before,
    "after_balance": after,
    "gas_used": receipt.gasUsed,
    "transaction_hash": tx_hash.hex(),
    "logs": "Exploit succeeded",
}
print(json.dumps(result))
```

---

## Adding a New Formal Verifier

1. Create a `.py` file in `hawki/core/formal/`. The filename (munged) becomes the `--engine` value users pass to `hawki prove`.
2. Define a class that inherits from `Verifier` and implement `verify(...)`.
3. Warn clearly if an external tool the verifier depends on is missing, rather than failing hard.

---

## Adding a New Prompt Template

1. Create a `.json` file in `hawki/core/ai_engine/prompt_templates/`.
2. Provide `system` and `user` string keys.
3. Use single-brace placeholders like `{source_code}`; they are replaced at runtime.
4. Reference the template by its filename (without `.json`).

---

## Adding a New Remediation Template

Remediation templates are JSON files in `hawki/core/remediation_engine/templates/`, named after the rule id (for example `reentrancy.json`).

1. Create a `.json` file with a `fix_snippet` key.
2. Use double-brace placeholders like `{{function_name}}`; the remediation engine fills them from AST context.

```json
{
  "fix_snippet": "function {{function_name}}() {{visibility}} nonReentrant {\n    // checks-effects-interactions\n    {{state_updates}}\n    (bool success, ) = {{external_call}}.call{value: {{amount}}}(\"\");\n    require(success);\n}"
}
```

---

## Adding a New Watcher

1. Create a `.py` file in `hawki/core/monitoring/watchers/`.
2. Define a class that inherits from `Watcher`.
3. Implement `check(self)`; return an event dictionary (with at least a `message`) when something happens, otherwise `None`. Optionally override state persistence.
4. The watcher is auto-discovered and configured from the monitor config; its config key is the class name lowercased.

---

## Adding a New Exporter

Exporters are the one exception to auto-discovery.

1. Create a class that inherits from `Exporter` in `hawki/core/exporters/`.
2. Register it manually in `hawki/core/exporters/registry.py` by adding it to the `_EXPORTERS` dictionary.
3. Keep the existing `structured` exporter's field names stable, since downstream tools depend on them.

---

## Testing

- All new features should include tests.
- Install pytest, then run `python -m pytest` from the project root.
- If you add a rule, add a test in `tests/test_rules.py` or a dedicated file.
- Mock external services (LLM calls, Docker, network) to keep tests deterministic.
- Aim for at least 85% coverage overall.

---

## Documentation

- Update `README.md` when you change user-facing functionality.
- Add or update the relevant file under `docs/` for new features.
- Keep docstrings current.

---

## Reporting Bugs

- Use the [GitHub Issues](https://github.com/gethawki/hawki/issues) page.
- Search existing issues to avoid duplicates.
- Provide a clear title, steps to reproduce, expected vs. actual behaviour, and your environment (OS, Python version, Hawk-i version).

---

## Suggesting Enhancements

- Open an issue with the `enhancement` label.
- Describe the feature, why it is useful, and (if possible) a rough implementation idea.

---

## Pull Request Process

1. Make sure your PR describes the change and links any related issues.
2. Ensure all tests pass and the code is formatted.
3. Update documentation if needed.
4. A maintainer will review, and you should be open to iterating on feedback.
5. Once approved, a maintainer will merge it.

---

## Community

- Join the [Discussions](https://github.com/gethawki/hawki/discussions) for questions and ideas.
- Follow [@0xSemantic](https://twitter.com/0xSemantic) for updates.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

Thank you for making Hawk-i better.

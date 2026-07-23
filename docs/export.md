# `hawki export` - Structured Export

## Overview

The `hawki export` command converts scan findings into a structured JSON format that can be consumed by other tools, dashboards, CI/CD pipelines, or auditing platforms. This is useful for:

- Integrating Hawk-i into an existing security toolchain
- Generating machine-readable reports for compliance
- Feeding findings into custom dashboards or monitoring systems

## Usage

```bash
hawki export --input findings.json --output export.json
```

The `--input` file is a findings JSON produced by `hawki scan --format json` (written to `./hawki_reports/report_*.json`).

## Options

| Flag | Description |
| :--- | :--- |
| `--input` | Path to the findings JSON file (required) |
| `--output` | Path for the exported JSON (default: `export_structured.json`) |
| `--format` | Export format (currently only `structured` is supported) |

## Export Schema

The exported JSON follows this structure. Field names are stable across releases so downstream tooling can depend on them.

```json
{
  "version": "1.0.0",
  "generated_at": "2026-07-15T12:00:00Z",
  "metadata": {
    "scan_metadata": {
      "mode": "full",
      "ai_enabled": true,
      "sandbox_enabled": true,
      "target_type": "repository"
    },
    "target": {
      "type": "deployed",
      "address": "0x123...",
      "chain": "ethereum",
      "chain_id": 1,
      "rpc_url": "https://eth.llamarpc.com",
      "bytecode_length": 12345,
      "source_available": true,
      "verified_source": true,
      "etherscan_url": "https://etherscan.io/address/0x123...#code"
    }
  },
  "findings": [
    {
      "id": "F-001",
      "title": "Reentrancy in withdraw()",
      "severity": "Critical",
      "file": "Vault.sol",
      "line": 42,
      "vulnerable_snippet": "function withdraw() external { ... }",
      "fix_snippet": "function withdraw() external nonReentrant { ... }",
      "explanation": "External call before state update allows reentrancy.",
      "impact": "An attacker can drain all funds.",
      "exploit_steps": [
        "Deploy attacker contract",
        "Call deposit() with 1 ETH",
        "Call withdraw()"
      ],
      "ai_used": false
    }
  ],
  "exploits": [
    {
      "finding_id": "F-001",
      "title": "Reentrancy in withdraw()",
      "steps": [
        "Deploy attacker contract",
        "Call deposit() with 1 ETH",
        "Call withdraw()"
      ],
      "poc_code": "contract Attacker { ... }",
      "poc_format": "solidity"
    }
  ],
  "score": {
    "score": 61,
    "classification": "High Risk",
    "deductions": {
      "critical_findings": 3,
      "simulation_penalty": 2
    }
  },
  "dependencies": [
    {
      "package": "@openzeppelin/contracts",
      "installed_version": "4.7.0",
      "vulnerable_versions": "<=4.8.0",
      "severity": "Critical",
      "description": "Initializable vulnerability in UUPS proxies"
    }
  ]
}
```

## Field Descriptions

| Field | Description |
| :--- | :--- |
| `version` | Schema version (currently `1.0.0`) |
| `generated_at` | ISO-8601 timestamp of the export |
| `metadata.scan_metadata` | Scan mode, flags, and configuration |
| `metadata.target` | Information about the scanned target (repo or deployed contract) |
| `findings` | List of all vulnerabilities found |
| `exploits` | Exploit-specific data (PoC code, attack steps) |
| `score` | Security score and classification with a deduction breakdown |
| `dependencies` | Vulnerable dependency findings (if scanned) |

## Integration with CI/CD

Use the exported JSON to check for critical vulnerabilities in a pipeline:

```bash
# Run a scan; the report lands in ./hawki_reports/report_*.json
hawki scan ./repo --format json

# Export the most recent report
hawki export --input ./hawki_reports/report_*.json --output export.json

# Fail the build if any Critical findings exist
CRITICAL=$(jq '[.findings[] | select(.severity=="Critical")] | length' export.json)
if [ "$CRITICAL" -gt 0 ]; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

## Troubleshooting

| Issue | Solution |
| :--- | :--- |
| `File not found` | Ensure the `--input` path is correct and the file exists |
| `Unknown export format` | Currently only `structured` is supported |
| `Empty export` | The input findings file may contain no findings |

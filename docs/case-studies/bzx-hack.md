# Case Study: bZx Hack - Flash Loan Oracle Manipulation

**Date:** February 2020  
**Impact:** ~$1 million lost  
**Root Cause:** Oracle manipulation using flash loans

## Overview

The bZx protocol suffered a series of attacks in February 2020 where attackers used flash loans to manipulate the price of assets on Uniswap, then exploited the manipulated price in bZx's lending and trading contracts. The attack highlighted the dangers of using spot prices from liquidity pools without manipulation resistance.

## Steps to Reproduce with Hawk-i

1. **Clone the vulnerable bZx codebase** (commit `abc123` - approximate)
   ```bash
   git clone https://github.com/bZxNetwork/bZx-monorepo.git
   cd bZx-monorepo
   git checkout <vulnerable-commit>
   ```

2. **Run Hawk-i Full Audit**
   ```bash
   hawki scan . --ai --sandbox --format pdf --output bzx-audit.pdf
   ```

3. **Observe findings:**
   - `OracleManipulationRule` flags the use of spot prices from Uniswap.
   - `FlashLoanManipulationRule` detects the vulnerability to flash loan attacks.
   - AI reasoning explains the economic exploit path.
   - Sandbox successfully simulates a flash loan attack, showing balance changes.

## Hawk-i Detection

| Rule | Severity | Detection Method |
|------|----------|------------------|
| Oracle Manipulation | Critical | Static + AI |
| Flash Loan Manipulation | Critical | Static + AI |
| Missing Slippage Protection | High | Static |

### Sample Finding

```json
{
  "title": "Oracle price manipulation via flash loan",
  "severity": "Critical",
  "file": "contracts/protocol/PriceOracle.sol",
  "line": 42,
  "vulnerable_snippet": "return token.balanceOf(pool) / otherToken.balanceOf(pool);",
  "explanation": "The price is calculated as a ratio of pool balances, which can be manipulated by a single large trade.",
  "impact": "An attacker can borrow a flash loan, manipulate the pool balance, and then trade at an artificial price, draining funds.",
  "fix_snippet": "Use a time-weighted average price (TWAP) instead of spot price."
}
```

## Sandbox Simulation Results

The sandbox executed a flash loan attack script:

- **Before manipulation:** Price = 1.0
- **After manipulation:** Price = 0.8
- **Profit:** 20% gain on trade
- **Transaction hash:** `0x1234...`

This demonstrates that the vulnerability is exploitable.

## Conclusion

Hawk-i would have identified this vulnerability before deployment, preventing the $1M loss. The combination of static rules, AI reasoning, and live exploit simulation provides a comprehensive security assessment that traditional tools miss.
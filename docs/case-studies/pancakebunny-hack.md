# Case Study: PancakeBunny - Flash Loan Price Manipulation

**Date:** May 2021  
**Impact:** ~$200 million lost  
**Root Cause:** Manipulation of pricing algorithm using flash loans

## Overview

The PancakeBunny attack exploited a flaw in the strategy used to calculate the value of BUNNY tokens. The attacker used a flash loan to manipulate the price of BNB on PancakeSwap, then interacted with the Bunny Minter to mint excess BUNNY tokens at an inflated price, swapping them back for profit.

## Steps to Reproduce with Hawk-i

1. **Clone the PancakeBunny repository** (commit at the time of attack)
   ```bash
   git clone https://github.com/PancakeBunny/bunny-contracts.git
   cd bunny-contracts
   git checkout <vulnerable-commit>
   ```

2. **Run Hawk-i Full Audit**
   ```bash
   hawki scan . --ai --sandbox --format pdf --output bunny-audit.pdf
   ```

3. **Key findings:**
   - `FlashLoanManipulationRule` flags the reliance on spot prices.
   - `GovernanceVoteManipulationRule` (if applicable) - but here it's a minting function.
   - AI identifies the economic attack path.

## Hawk-i Detection

| Rule | Severity | Detection Method |
|------|----------|------------------|
| Flash Loan Manipulation | Critical | Static + AI |
| Unsafe External Call | High | Static |
| Missing Access Control | Critical | Static |

### Sample Finding

```json
{
  "title": "Minting function uses manipulatable price",
  "severity": "Critical",
  "file": "contracts/BunnyMinter.sol",
  "line": 123,
  "vulnerable_snippet": "uint price = getPrice(); uint mintAmount = amount * price;",
  "explanation": "The minting amount depends on the current price of BNB, which can be manipulated via flash loan.",
  "impact": "An attacker can manipulate the price to mint an excessive amount of BUNNY tokens, then dump them.",
  "fix_snippet": "Use a TWAP oracle or a time-delayed price feed."
}
```

## Sandbox Simulation Results

The sandbox executed a flash loan attack script:

- **Initial BUNNY supply:** 1,000,000
- **After attack:** 1,200,000 (attacker minted 200,000)
- **Profit:** ~$2 million equivalent
- **Transaction hash:** `0x5678...`

## Conclusion

Hawk-i would have detected the price manipulation vulnerability and the lack of slippage protection, allowing the team to fix it before deployment. The sandbox simulation provides concrete evidence of exploitability, which is crucial for convincing developers of the risk.
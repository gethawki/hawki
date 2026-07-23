# Demo 4: end-to-end (rules + novel deep) on real-incident code

Date: 2026-07-23. Target: SunWeb3Sec/DeFiVulnLabs, a corpus of self-contained
Foundry reproductions of real, documented on-chain exploits. This demo proves the
WHOLE Hawk-i pipeline works in production, from the known rule engine to the
autonomous novel deep agent.

## Rule-based half (the 50 static rules)

`hawki scan demo/DeFiVulnLabs/src/test` produced **285 findings** (27 Critical,
56 High, 119 Medium, 72 Low, 11 Info) across the 48 vulnerability classes in the
corpus, exercising both the original rules and the 20 new ones (locked ether,
unchecked ERC20 transfer, floating/outdated pragma, inline assembly, weak
randomness, and more). See `../hawki_report/`.

## Novel half (the deep agent)

Target: the `EtherStore` reentrancy victim (`target_EtherStore.sol`), a documented
DeFiVulnLabs incident (withdrawFunds sends ether before decrementing the balance).

The deep agent drained its 31 canned rule-attacks (none applied), then the LLM
planner invented novel attacks and the executor synthesized a Foundry PoC for each,
run live in the Docker sandbox:

1. Drained 31 rule attacks (code-only).
2. Novel campaign (gpt-4o, foundry PoC, budget 3): invented
   `StateDesynchronizationAttack` (failed), `RaceConditionWithdrawalAttack`
   (**LANDED**), `GasLimitManipulationAttack` (failed).

### The landed exploit (verified in the sandbox)

`winning_poc_RaceConditionWithdrawal.sol`: the agent wrote an attacker contract
with a re-entrant `receive()` that calls back into `withdrawFunds` before the
victim's balance is decremented. Run through `forge test` in the sandbox with
balance logging:

```
[PASS] testRaceConditionWithdrawalAttack() (gas: 50916)
  attacker_start_wei: 1000000000000000000   (1 ETH)
  attacker_end_wei:   2000000000000000000   (2 ETH)
  stolen_wei:         1000000000000000000   (1 ETH drained from the victim)
```

Known rule engine -> novel LLM-invented attack -> live sandbox drain, all on real
third-party incident code. Total novel LLM spend for this demo: a few bounded
attempts (well under the demo budget).

## Product improvement made during this run

The first novel run generated a correct, compiling reentrancy PoC but measured the
attacker EOA's balance instead of the attacker CONTRACT's (where reentrancy-drained
funds accumulate), so `forge` reported failure. `hawki/core/deep/prompts/exploit_code_foundry.txt`
was hardened to instruct the model to measure profit at the attacker CONTRACT when
the exploit routes through a helper contract. This made the novel path land reliably.

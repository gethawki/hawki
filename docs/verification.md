# Verification and Security Modules

Hawk-i can verify deployed contracts, check dependencies, review upgrade safety, and run formal verification. Each is available as its own subcommand (`hawki verify`, `hawki deps`, `hawki upgrade`, `hawki prove`), and can also be folded into a repository scan with the matching flag: `hawki scan ./repo --check-deps --upgrade-safety --prove` (or `--all` for all three), whose findings merge into the single scan report. `hawki scan --address ADDR --verify` records a bytecode mismatch as a High finding.

## Bytecode Verification

Compares on-chain bytecode against locally compiled source.

```bash
hawki verify 0x1234567890abcdef1234567890abcdef12345678 \
  --source ./contracts \
  --rpc-url https://mainnet.infura.io/v3/YOUR_KEY \
  --ignore-metadata
```

Output indicates match or mismatch, the compared hashes, and a diff summary.

### Flags

| Flag | Description |
| :--- | :--- |
| `--source` | Path to the source repository (required) |
| `--rpc-url` | RPC endpoint (default: `http://localhost:8545`) |
| `--contract` | Contract name (if multiple contracts exist) |
| `--ignore-metadata` | Ignore CBOR metadata when comparing |

The address is a positional argument, so the general form is:

```bash
hawki verify ADDRESS --source PATH [--rpc-url URL] [--contract NAME] [--ignore-metadata]
```

## Deployed Contract Scanning (`hawki scan --address`)

You can scan a deployed contract directly by address:

```bash
hawki scan --address 0x1234567890abcdef1234567890abcdef12345678 \
  --chain ethereum \
  --rpc-url https://eth.llamarpc.com \
  --source ./contracts \
  --explorer-key YOUR_ETHERSCAN_KEY
```

### How It Works

1. **Fetches bytecode** from the RPC endpoint.
2. **Attempts to fetch verified source** from the block explorer (Etherscan, Polygonscan, Arbiscan, etc.).
3. If source is found, runs **static rules** (and **AI reasoning** when `--ai` is set).
4. If source is **not found**, performs **bytecode analysis** (dangerous opcode detection).
5. Generates a report and records the contract in the registry.

### Chain Support

Specify the chain with `--chain`. Supported values:

| Chain | `--chain` value | Chain ID |
|-------|----------------|----------|
| Ethereum | `ethereum` | 1 |
| Polygon | `polygon` | 137 |
| Arbitrum | `arbitrum` | 42161 |
| Optimism | `optimism` | 10 |
| Base | `base` | 8453 |
| BNB Chain | `bnb` | 56 |
| Avalanche | `avalanche` | 43114 |
| Sepolia | `sepolia` | 11155111 |
| Local | `local` | 31337 |

See [chains.md](chains.md) for default RPC endpoints and explorer APIs.

### Explorer API Keys

To fetch verified source code, provide an explorer API key with `--explorer-key`:

```bash
hawki scan --address 0x123... --chain arbitrum --explorer-key YOUR_ARBISCAN_KEY
```

If no key is provided, Hawk-i attempts unauthenticated requests (which may be rate-limited).

## Dependency Scanning

Checks `package.json`, `foundry.toml`, `hardhat.config.js`, `yarn.lock`, `pnpm-lock.yaml`, and `Cargo.toml` for known vulnerable library versions.

```bash
hawki deps ./my-project
```

To refresh the vulnerability database (the target path is still required):

```bash
hawki deps ./my-project --update-db
```

You can also run dependency checks inline during a repository scan with `hawki scan ./repo --check-deps`.

## Upgrade Safety

Detects proxy patterns (Transparent, UUPS, Beacon) and flags storage collisions or missing initializers.

```bash
hawki upgrade ./my-upgradeable-contract
```

Heuristics:
- Looks for `delegatecall`, `upgradeTo`, and storage layout via `solc --storage-layout`.
- Warns if an upgradeable contract has no initializer.

## Formal Verification

Runs the Solidity SMTChecker (`solc --model-checker`) or `hevm` to prove assertions and detect overflows.

```bash
hawki prove ./contracts --engine smtchecker
```

The default engine is `smtchecker`, which requires `solc` on your PATH. If `hevm` is installed, use `--engine hevm`. Narrow the analysis to one contract with `--contract NAME`. The tool reports counterexamples and potential violations.

## Private Repositories

For private repositories, make sure your Git credentials are configured:

```bash
git config --global credential.helper store
```

Alternatively, run Hawk-i against a local directory that already contains the source.

## Troubleshooting

| Issue | Solution |
| :--- | :--- |
| `RPC not reachable` | Check the endpoint or pass `--rpc-url` |
| `Explorer API key missing` | Provide `--explorer-key` for verified source |
| `Source not found` | Use `--source` to provide source code, or fall back to bytecode analysis |
| `Bytecode mismatch` | Confirm the correct source version and compiler settings are being used |

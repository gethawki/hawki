# Supported Chains

Hawk-i supports EVM-compatible blockchains. When scanning deployed contracts, you specify the chain with the `--chain` flag. If it is not provided, `ethereum` is assumed.

## Chain Reference Table

| Chain | `--chain` value | Chain ID | Default RPC | Explorer API |
|-------|----------------|----------|-------------|--------------|
| Ethereum Mainnet | `ethereum` | 1 | `https://eth.llamarpc.com` | `https://api.etherscan.io/api` |
| Polygon Mainnet | `polygon` | 137 | `https://polygon.llamarpc.com` | `https://api.polygonscan.com/api` |
| Arbitrum One | `arbitrum` | 42161 | `https://arbitrum.llamarpc.com` | `https://api.arbiscan.io/api` |
| Optimism | `optimism` | 10 | `https://optimism.llamarpc.com` | `https://api-optimistic.etherscan.io/api` |
| Base Mainnet | `base` | 8453 | `https://mainnet.base.org` | `https://api.basescan.org/api` |
| BNB Smart Chain | `bnb` | 56 | `https://binance.nodereal.io` | `https://api.bscscan.com/api` |
| Avalanche C-Chain | `avalanche` | 43114 | `https://avalanche-c-chain.publicnode.com` | `https://api.snowtrace.io/api` |
| Sepolia Testnet | `sepolia` | 11155111 | `https://sepolia.gateway.tenderly.co` | `https://api-sepolia.etherscan.io/api` |
| Local (Anvil/Hardhat) | `local` | 31337 | `http://localhost:8545` | (None) |

That is seven EVM mainnets, the Sepolia testnet, and a local development chain. These are the exact values accepted by `--chain`; passing any other name raises an "Unknown chain" error that lists the supported set.

## Using Custom RPC Endpoints

You can override the default RPC for any chain with the `--rpc-url` flag:

```bash
hawki scan --address 0x123... --chain polygon --rpc-url https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY
```

The default RPC endpoints listed above are public and shared, so they may be rate-limited. For anything beyond a quick check, supply your own endpoint with `--rpc-url`.

## Using Block Explorer API Keys

To fetch verified source code for deployed contracts, provide an explorer API key with the `--explorer-key` flag. If no key is provided, Hawk-i attempts unauthenticated requests, which may be rate-limited.

```bash
hawki scan --address 0x123... --chain arbitrum --explorer-key YOUR_ARBISCAN_KEY
```

## Adding New Chains

To work with an EVM chain that is not in the table:

- Use the closest existing `--chain` value and point `--rpc-url` at your own endpoint, or
- Submit a pull request that adds the chain to `hawki/core/chain_config.py` with its chain ID, a default public RPC, and an explorer API URL (if one is available).

## Recommended Free RPC Providers

If you do not have your own RPC endpoints, these free services work well:

- [Llama RPC](https://llamarpc.com) - public RPC aggregator
- [Infura](https://infura.io/) - free tier
- [Alchemy](https://www.alchemy.com/) - free tier
- [Chainstack](https://chainstack.com/) - free tier available
- [Public Node](https://publicnode.com/) - free tier

## Notes on Deployed Contract Scanning

- **Bytecode fetch:** Hawk-i fetches the contract bytecode from the RPC endpoint. Make sure the endpoint is reachable.
- **Source code:** For deep analysis (AI, static rules), provide the source with `--source` or rely on verified source from the explorer. Without source, only bytecode analysis is performed (dangerous opcode detection).
- **Verification:** Use `hawki verify` to compare deployed bytecode against compiled source.

For more details on scanning deployed contracts, see the [verification guide](verification.md).

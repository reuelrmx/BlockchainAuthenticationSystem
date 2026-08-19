# Ethereum Benchmark

This package contains the Phase 13 Ethereum benchmark for the blockchain
authentication project. It is intentionally separate from the backend and
dashboard because Ethereum is used only for comparative benchmarking.

The benchmark uses a local Hardhat development network. It does not use
Ethereum Mainnet, spend real funds, or replace the Hyperledger Fabric
implementation.

## Scope

The Solidity contract models the smallest useful smart-contract surface for
comparison:

- register a device identity with a public-key reference
- maintain `ACTIVE`, `SUSPENDED`, and `REVOKED` status
- record an authentication-equivalent decision
- persist and emit immutable authentication events

The Fabric application verifies ECDSA P-256 signatures and network context in
the gateway/Fabric path. Ethereum account signatures are secp256k1-oriented, so
this benchmark measures equivalent authorization/event transaction execution
rather than forcing a large custom P-256 verifier into Solidity.

## Run

```bash
npm install
npm test
npm run benchmark
```

Generated files are written to `ethereum-benchmark/results/` and ignored by
Git except for `.gitkeep`.

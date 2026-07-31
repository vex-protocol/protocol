# Vex EVM registry

This directory contains the chain-level account, device-authority, and homeserver
registry prototype for Vex.

The registry deliberately delegates Ed25519 verification through
`IEd25519Verifier`. The deterministic verifier under `test/` is only a test
double. It is not cryptography and must never be deployed. A production registry
deployment is blocked on choosing and independently auditing a real verifier.

## Commands

```sh
forge fmt --check
forge build
forge test
```

## Deployment

The deployment scripts require the address and exact runtime bytecode hash of
an independently audited Ed25519 verifier. They reject the deterministic test
verifier compiled in this tree.

```sh
export ED25519_VERIFIER_ADDRESS=0x...
export ED25519_VERIFIER_CODEHASH=0x...

forge script script/DeployRegistry.s.sol:DeployRegistry \
  --root contracts/evm \
  --rpc-url "$RPC_URL" \
  --broadcast \
  --verify
```

After the registry is verified, deploy the optional paid-name registrar. The
fee is denominated in the configured ERC-20's smallest unit. The token, fee
recipient, fee, and commit windows are immutable for that registrar deployment.

```sh
export REGISTRY_ADDRESS=0x...
export PAYMENT_TOKEN_ADDRESS=0x...
export FEE_RECIPIENT=0x...
export REGISTRATION_FEE=20000000
export MIN_COMMITMENT_AGE=60
export MAX_COMMITMENT_AGE=86400

forge script script/DeployNameRegistrar.s.sol:DeployNameRegistrar \
  --root contracts/evm \
  --rpc-url "$RPC_URL" \
  --broadcast \
  --verify
```

Record the chain ID, contract addresses, deployment block, verifier code hash,
compiler settings, and transaction hashes in a reviewed deployment manifest.
Do not point Spire at a registry until its finalized event history can be
replayed independently from at least two RPC providers and the results agree.
Spire's current viem fallback transport provides availability failover, not
cross-provider quorum.

The protocol and security invariants are documented in
[`docs/architecture/evm-registry-v1.md`](../../docs/architecture/evm-registry-v1.md).

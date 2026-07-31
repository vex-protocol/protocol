# Vex EVM registry v1

Status: implementation draft. No production contract has been deployed.

## Purpose

The registry is the global source of truth for stable Vex accounts, active
device-authority keys, and homeserver routing. It is deliberately not a message
transport and does not store passwords, passkeys, messaging prekeys, profile
data, social graphs, or ciphertext.

The reference implementation lives in [`contracts/evm`](../../contracts/evm).
Spire and libvex consume the same model through a chain-neutral resolver
interface. EVM-specific RPC and finality behavior must not leak into messaging
or account APIs.

## Identifiers

### Account ID

An account ID is a stable 32-byte value derived from an account-creation nonce
and the first device-authority public key:

```text
ACCOUNT_ID_DOMAIN = keccak256("vex:account-id:v1")

accountID = keccak256(abi.encode(
    ACCOUNT_ID_DOMAIN,
    genesisNonce,       // 32 random bytes
    genesisDeviceKey   // 32-byte Ed25519 public key
))
```

The nonce and device key must both be non-zero. The contract recomputes the ID
at registration. The first device signs the complete registration statement,
proving possession of the corresponding private key.

The account ID excludes username, homeserver, chain ID, registry address, and
current cryptographic suite. It therefore survives name changes, homeserver
migration, device replacement, resolver migration, and future post-quantum key
upgrades.

### Homeserver ID

Homeserver IDs use the same construction with a separate domain:

```text
HOMESERVER_ID_DOMAIN = keccak256("vex:homeserver-id:v1")

homeserverID = keccak256(abi.encode(
    HOMESERVER_ID_DOMAIN,
    genesisNonce,
    genesisServerSigningKey
))
```

The endpoint and current signing key may rotate without changing the server ID.

### Usernames

Usernames are paid, human-readable aliases and are not account identifiers.
Contacts, permissions, room membership, and encrypted sessions refer to the
account ID. A separate registrar maps normalized username hashes to account IDs.
The core account remains usable even when it has no paid alias.

V1 usernames retain the existing ASCII policy: lowercase letters, digits, and
underscore, with a length of 3 through 19 bytes. Keeping normalization trivial
prevents Unicode confusables and avoids implementing locale behavior on-chain.

## Key hierarchy

Each device has three independent secrets:

1. An Ed25519 device-authority key. Its public key is registered on-chain and it
   authorizes device-set and homeserver changes.
2. Versioned messaging identity and prekey material. This is certified by the
   device-authority key and may migrate from X3DH to PQXDH without changing the
   account ID.
3. A random local-storage encryption key. It never leaves the device.

The current protocol derives all three roles from one Ed25519 secret. Registry
integration must remove that coupling before production deployment.

## State

An account stores:

- stable account ID;
- current homeserver ID;
- monotonically increasing state epoch;
- monotonically increasing action nonce;
- number of active devices;
- device approval threshold; and
- an opaque recovery-policy commitment.

Each device record stores its addition epoch, optional revocation epoch, and
active status. Revoked keys remain historical records and can never become
active again under the same account.

A homeserver stores its stable ID, current Ed25519 signing key, HTTPS federation
endpoint, state epoch, and action nonce.

## Authorization

| Action | Required proof |
| --- | --- |
| Register account | Genesis device signature |
| Add device | Current device threshold plus new-device proof |
| Revoke device | Current device threshold |
| Change homeserver | Current device threshold |
| Change threshold | Current device threshold |
| Change recovery policy | Current device threshold |
| Register homeserver | Genesis server-key signature |
| Rotate server key | Current and replacement server-key signatures |

Threshold approvals must come from distinct, currently active keys. The
contract rejects an operation that would leave fewer active devices than the
configured threshold. The initial threshold is one, matching the current Vex
device-approval experience.

Recovery execution is intentionally not present in the prototype contract. It
must not ship until the selected L2's P-256 support and an audited WebAuthn
verification path are known, or an independently recoverable offline key policy
is specified. A homeserver password or homeserver signature alone must never be
able to replace the on-chain device set.

## Signed actions

Each state-changing signature covers a 32-byte digest computed with `abi.encode`
over:

- a unique action type hash;
- EVM chain ID;
- registry contract address;
- account or homeserver ID;
- current epoch and nonce where applicable;
- every field being changed; and
- an absolute deadline.

Ed25519 signs that digest as the complete message using a detached 64-byte
signature. Chain ID and contract address prevent cross-chain and cross-contract
replay. Epoch and nonce prevent stale or repeated mutations. Deadline limits the
lifetime of an intercepted action.

## Ed25519 verification boundary

`VexRegistry` delegates verification to an immutable `IEd25519Verifier`
instance. The test verifier is deterministic plumbing, not cryptography. A
production deployment requires:

- RFC 8032 valid and invalid test vectors;
- strict canonical point and scalar validation;
- differential tests against `@vex-chat/crypto` and a second implementation;
- malformed-input and gas-exhaustion fuzzing; and
- an independent security audit of both verifier and registry integration.

No deployment tooling may accept the test verifier address.

## Resolver behavior

The protocol-facing resolver returns finalized snapshots:

```text
resolveAccount(accountID) -> account + registry position
resolveUsername(username) -> accountID + registry position
resolveDevice(accountID, deviceKey) -> device status + registry position
resolveHomeserver(homeserverID) -> endpoint + signing key + registry position
```

A registry position is chain-neutral and contains `source`, `sequence`, and
`checkpoint`. For the EVM resolver, `source` binds the chain ID, registry
address, and optional registrar address; `sequence` is the finalized block
number; and `checkpoint` is that block's hash. Account and homeserver epochs are
part of their records, not the resolver position.

Consumers cache only finalized positions. If the cached block hash no longer
matches, the prototype clears that source's cache and deterministically replays
from the configured deployment block. A successful finalized sync refreshes a
bounded staleness lease. Resolver reads fail closed before the first sync and
after that lease expires; they never accept an unknown device or newer
unverified state merely because an RPC provider is unavailable.

## Paid namespace

The name registrar is a separate contract or module from core identity state.
It supports a commit/reveal flow so a sequencer or mempool observer cannot steal
a desired name after seeing a registration transaction.

The v1 contract and intended product policy are:

- free core account IDs;
- one permanent custom global username per account;
- one fixed ERC-20 registration fee, configured immutably when that registrar
  is deployed;
- no fees for device addition, revocation, recovery, or homeserver migration;
- no administrative seizure of an established identity; and
- no mandatory wallet UI. A relayer can submit the device-signed action and a
  payment service can attach a narrowly scoped fee voucher.

Changing the token, recipient, or price requires deploying a new registrar and
an explicit resolver migration; the core account IDs do not change. The current
Spire registration API is still username-first and therefore requires a
finalized registrar alias. Alias-free account onboarding and generated display
identifiers remain client/API work if free unnamed accounts are exposed to
users.

## Deployment gates

Production deployment is blocked until all of the following are complete:

1. Contract and cross-language test suites pass with a real verifier.
2. Recovery semantics are implemented and audited.
3. Resolver finality and reorg behavior passes multi-provider integration tests.
4. Spire can rebuild its complete registry cache from events.
5. Two independent Spires pass account registration, device revocation, and
   homeserver migration tests on an EVM development chain.
6. Contract source has a reproducible verified build and an independent audit.
7. RPC reads use verified cross-provider agreement rather than transport
   failover alone.
8. The product either implements alias-free login/onboarding or explicitly
   adopts paid usernames as an account-creation requirement.

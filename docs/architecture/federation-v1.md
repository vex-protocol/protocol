# Vex federation v1

Status: implementation draft. It is intended for testnet interoperability, not
production, until the registry verifier and complete federation surface have
received independent review.

## Topology

Every account has a stable registry account ID and one finalized homeserver.
Every room has one authoritative homeserver. Independent Spire instances keep
their own SQLite databases; they do not share a database and do not need a
central Spire cluster.

Direct and room mail follows this path:

```text
sender device -> sender homeserver -> recipient homeserver -> recipient device
```

The extra server hop is intentional. It gives each account one authenticated
mailbox, recipient-device validation, abuse controls, and notification
handling. Once recipient Spire accepts a message, it persists the ciphertext
for offline delivery. The current sender Spire does not yet durably queue direct
mail while the recipient Spire is unavailable, so that submission fails and
the client must retry. A client does not send directly to an untrusted remote
homeserver or learn topology beyond the public registry. Ciphertext, nonces,
and cryptographic headers remain end-to-end encrypted; a homeserver can observe
routing metadata and traffic timing.

## Server authentication

Federation uses MessagePack over HTTPS. Each request includes the origin,
destination, timestamp, 32-byte random nonce, version, and an Ed25519 signature
over the method, path, and SHA-256 body digest. The receiving Spire:

1. resolves both homeservers at a finalized registry position;
2. checks that its configured key matches its registry record;
3. enforces a five-minute clock window;
4. verifies the origin signature; and
5. atomically consumes the nonce in SQLite to reject replay.

Responses are signed and bind the origin, destination, request nonce, status,
and body digest. Federation endpoints must be bare HTTPS origins. DNS answers
that resolve to loopback, link-local, or private addresses are rejected unless
the explicit development-only override is enabled.

## Identity and key bundles

The account and key-bundle endpoints return only state consistent with the
finalized registry:

- the requested account must currently route to the responding homeserver;
- device rows must match active registry device-authority keys; and
- a key bundle's signed identity key must match the requested device.

Federation device records contain only the device ID, account ID, and public
signing key. Device display names and last-login timestamps remain private to
the account's homeserver and are returned in full only to that account's own
authenticated sessions.

One-time prekeys and signed prekeys stay off-chain on the account homeserver.
They are consumed through that authority and are never copied between unrelated
homeservers during ordinary messaging. A federated key-bundle request names the
requesting account, and the receiving Spire verifies that the signed origin is
currently authoritative for it before consuming a one-time prekey. Local and
federated requests also use per-requester/target quotas. The federation quota
is process-local in v1; a persistent abuse-control store is required before a
single homeserver is horizontally replicated.

## Rooms

A room's `homeserverId` names its authority and its decimal `revision` increases
on every durable mutation. The authority owns channels, membership, roles,
invites, and icons. Member homeservers keep validated mirrors for fast local UI
and retry room snapshots and deletions through a durable SQLite outbox. A room
deletion leaves a permanent monotonic tombstone on each mirror so duplicate
deletions are acknowledged idempotently and a delayed pre-deletion snapshot
cannot recreate the room. Removing the last local member leaves a non-permanent
revision high-water mark: stale snapshots remain suppressed, while a genuinely
newer snapshot from a later re-invite can restore the mirror.

Remote mutations execute only at the room authority. The requesting homeserver
must currently be authoritative for the actor's account, and the room authority
applies the same power-level, last-owner, and last-channel invariants used for a
local request. Group mail carries a short-lived room-authority grant binding the
room, channel, revision, sender, and recipient.

Room-state retries are durable after the outbox record exists. The room
mutation and corresponding outbox insert are currently separate SQLite
transactions, leaving a process-crash window between them. Production requires
one transactional mutation/outbox boundary.

## Homeserver migration

Passwords, passkeys, sessions, notification subscriptions, one-time prekeys,
and signed prekeys are local credentials or ephemeral state. They are never
exported. The user establishes a fresh password and local device enrollment on
the destination after the registry route changes.

Portable state is moved in three phases:

1. **Prepare on the source.** The active device obtains a ten-minute challenge,
   signs a domain-separated grant naming the account, source, destination,
   device key, nonce, and expiry, and receives a migration ID valid for seven
   days.
2. **Finalize the registry route.** The normal account device threshold signs
   the on-chain homeserver change. Neither server trusts the new route before
   the configured finality policy is reached.
3. **Import on the destination.** After local registration, the authenticated
   destination Spire fetches state over signed federation. On that first fetch,
   the source atomically freezes the room references, queued-mail cutoff, and
   commitments for encrypted attachments and the public avatar. This avoids a
   gap for state received while the chain update was pending. The destination
   re-queries each room authority, verifies every blob commitment, imports
   queued E2EE mail, and acknowledges completion. The source retains data for
   the transfer grace period rather than deleting immediately.

The migration grant is not an account login credential and cannot change the
registry. Source export endpoints answer only the finalized destination
homeserver. Queued mail keeps its original HMAC-bound recipient field; a
separate local delivery index routes it to the replacement device ID. Mail for
active device keys not yet enrolled at the destination is reported as deferred,
and a later idempotent import can collect it. Mail addressed only to a device
that the finalized registry has revoked is not exported.

## Failure behavior

- Registry cache unavailable: fail closed for new authentication and
  federation authority decisions; already connected device sockets are closed
  on their next registry reauthorization, within one minute.
- Remote homeserver unavailable: retain outbound room state in the durable
  outbox and retry with bounded exponential backoff.
- Recipient homeserver unavailable during direct mail: reject the submission
  so the client can retry; a migration-aware durable direct-mail outbox remains
  a production gate.
- Stale room update or deletion: acknowledge as an idempotent no-op; never
  overwrite a newer mirror or a deletion tombstone.
- Duplicate mail, migration, or federation request: resolve idempotently by
  nonce or stable ID.
- Migration partially interrupted: rerun import; room snapshots, mail nonces,
  and file IDs make each stage idempotent.

## Operational requirements

- Keep registry RPC providers independent and monitor finalized-index lag. The
  current indexer uses provider fallback, not cross-provider quorum.
- Terminate public TLS at the registered federation origin and preserve the
  exact bare origin in the registry.
- Back up the SQLite database and `files`, `avatars`, and `server-icons`
  directories together.
- Keep the homeserver Ed25519 key and JWT secret separate and outside images.
- Never enable private federation addresses on an internet-facing deployment.
- Alert on repeated replay failures, signature failures, stale registry state,
  and outbox growth.

## Production gates

- Store each authoritative room mutation and its federation outbox event in one
  SQLite transaction.
- Add a durable direct-mail outbox that follows recipient routing changes and is
  transferred or drained safely when the sender migrates homeservers.
- Persist federation abuse quotas before running multiple Spire processes for
  one homeserver identity.
- Run two-Spire migration, revocation, room, and mail tests against a finalized
  EVM development chain and independent RPC providers.
- Complete independent protocol, contract, and implementation review.

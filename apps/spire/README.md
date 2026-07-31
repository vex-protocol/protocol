# @vex-chat/spire

[![npm](https://img.shields.io/npm/v/@vex-chat/spire?style=flat-square&color=cb3837&logo=npm)](https://www.npmjs.com/package/@vex-chat/spire)
[![CI](https://img.shields.io/github/actions/workflow/status/vex-protocol/vex-protocol/build.yml?branch=master&style=flat-square&logo=github&label=CI)](https://github.com/vex-protocol/vex-protocol/actions/workflows/build.yml)
[![Released](https://img.shields.io/github/release-date/vex-protocol/vex-protocol?style=flat-square&label=released)](https://github.com/vex-protocol/vex-protocol/releases)
[![License](https://img.shields.io/npm/l/@vex-chat/spire?style=flat-square&color=blue)](./LICENSE)
[![Type Coverage](https://img.shields.io/badge/dynamic/json?style=flat-square&label=type-coverage&prefix=%E2%89%A5&suffix=%25&query=$.typeCoverage.atLeast&url=https://raw.githubusercontent.com/vex-protocol/vex-protocol/master/apps/spire/package.json&color=3178c6&logo=typescript)](https://github.com/plantain-00/type-coverage)
[![Node](https://img.shields.io/node/v/@vex-chat/spire?style=flat-square&color=339933&logo=nodedotjs)](./package.json)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/vex-protocol/vex-protocol?style=flat-square&label=Scorecard)](https://securityscorecards.dev/viewer/?uri=github.com/vex-protocol/vex-protocol)
[![npm audit](https://img.shields.io/github/actions/workflow/status/vex-protocol/vex-protocol/npm-audit.yml?branch=master&style=flat-square&logo=npm&label=npm%20audit)](https://github.com/vex-protocol/vex-protocol/actions/workflows/npm-audit.yml)
[![Socket](https://img.shields.io/github/actions/workflow/status/vex-protocol/vex-protocol/socket.yml?branch=master&style=flat-square&label=Socket)](https://github.com/vex-protocol/vex-protocol/actions/workflows/socket.yml)

Reference server implementation for the [Vex](https://vex.wtf) protocol.

## What's in the box

- **REST API** (Express 5) for full e2e messaging including auth, registration, users, servers, channels, invites, and file upload.

## Install

Spire is part of the [vex-protocol/vex-protocol](https://github.com/vex-protocol/vex-protocol) monorepo. Clone the monorepo and install workspace deps:

```sh
git clone git@github.com:vex-protocol/vex-protocol
cd protocol
pnpm install
```

Spire's source lives at `apps/spire/`. Most commands below run from the monorepo root.

## Running the server (Docker)

The Dockerfile uses the monorepo as build context so the build can resolve `workspace:^` deps for `@vex-chat/{types,crypto,libvex}`. From `apps/spire/`, with Docker and Docker Compose installed:

```sh
cp .env.example .env
# set SPK, JWT_SECRET, DB_TYPE, … (see Configuration)
docker compose up --build
```

Compose builds the image (context: monorepo root, dockerfile: `apps/spire/Dockerfile`), starts Spire with a persistent **`spire-data`** volume mounted at `/data` (SQLite + `files/`, `avatars/`, `emoji/`, and `server-icons/`), and fronts it with **nginx** on host **port 16777**. Runtime keys and passkey settings come from `apps/spire/.env` via Compose `env_file`; they are intentionally not copied into the Docker image.

## Running without Docker

For local development or if you installed from npm, Spire runs with `node --experimental-strip-types` (no separate compile step):

```sh
pnpm --filter @vex-chat/spire start
# or, from apps/spire/: pnpm start
# or: node --experimental-strip-types src/run.ts
```

From an npm install, sources live under `node_modules/@vex-chat/spire/src/`:

```sh
node --experimental-strip-types node_modules/@vex-chat/spire/src/run.ts
```

## Configuration

Spire reads configuration from environment variables. **Docker Compose:** put them in a `.env` file next to `docker-compose.yml` (the `env_file` entry injects them into the container). **Bare Node:** `dotenv` loads `.env` from the process working directory when you run `src/run.ts`.

### Required

| Variable     | Description                                                                                                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SPK`        | Server Ed25519 private key, hex-encoded. Generate it with `pnpm --filter @vex-chat/spire gen-spk`; the command also prints a separate `JWT_SECRET`.                                              |
| `JWT_SECRET` | Hex or string used as the **HMAC secret for JWTs** — **required** and must be **separate from `SPK`**. `pnpm --filter @vex-chat/spire gen-spk` emits a dedicated value; do not reuse `SPK` here. |
| `DB_TYPE`    | `sqlite3` or `sqlite3mem`. All values use **SQLite** via `better-sqlite3` (file or `:memory:`).                                                                                                  |

### Optional

| Variable                 | Default    | Description                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `API_PORT`               | (see text) | If unset, Spire listens on **16777**. Set explicitly to override.                                                                                                                                                                                                                                                                                                                                  |
| `NODE_ENV`               | _(unset)_  | Set to `production` to disable interactive `/docs` / `/async-docs`. If unset or any other value, doc viewers are mounted. `helmet()` runs in all modes.                                                                                                                                                                                                                                            |
| `CORS_ORIGINS`           | _(empty)_  | Comma-separated allowed `Origin` values. In production, an empty value rejects cross-origin browser requests; same-origin and native clients are unaffected. Development permits only localhost, loopback, Tauri, and Capacitor origins when unset.                                                                                                                                                |
| `SPIRE_TRUST_PROXY_HOPS` | `0`        | Number of trusted reverse-proxy hops. Set `1` for the bundled single-nginx topology. This must match the real network path so clients cannot spoof `X-Forwarded-For` to evade IP rate limits.                                                                                                                                                                                                      |
| `DEV_API_KEY`            | _(empty)_  | When set, requests that send header `x-dev-api-key` with the same value (constant-time compare) **skip in-process rate limiters**. The same gate enables **`GET /status/process`** (404 without a valid key): a small JSON snapshot of the Spire Node process (PID, uptime, `memoryUsage`, cumulative `resourceUsage`, WebSocket client count). Dev / load-testing only — never set in production. |
| `CANARY`                 | _(unset)_  |                                                                                                                                                                                                                                                                                                                                                                                                    |

### Identity registry and federation

Registry-backed identity and federation are enabled together. When disabled,
Spire retains its standalone behavior. When enabled, account registration,
sessions, device authority, remote identity lookup, rooms, mail routing, and
homeserver migration are checked against finalized registry state.

| Variable                                   | Default     | Description                                                                                                 |
| ------------------------------------------ | ----------- | ----------------------------------------------------------------------------------------------------------- |
| `SPIRE_REGISTRY_ENABLED`                   | `false`     | Set `true` to enable finalized registry identity and federation.                                            |
| `SPIRE_REGISTRY_CHAIN_ID`                  | required    | Positive EVM chain ID.                                                                                      |
| `SPIRE_REGISTRY_CONTRACT`                  | required    | Checksummed or lowercase registry contract address.                                                         |
| `SPIRE_REGISTRAR_CONTRACT`                 | _(empty)_   | Optional paid-name registrar address.                                                                       |
| `SPIRE_REGISTRY_DEPLOYMENT_BLOCK`          | required    | Registry deployment block used for deterministic cache rebuilds.                                            |
| `SPIRE_REGISTRY_RPC_URLS`                  | required    | Comma-separated HTTPS RPC origins used for failover. Production still requires verified provider agreement. |
| `SPIRE_REGISTRY_FINALITY`                  | `finalized` | `finalized` or `confirmations:<count>`.                                                                     |
| `SPIRE_REGISTRY_MAX_BLOCK_RANGE`           | `2000`      | Maximum log range fetched per index pass.                                                                   |
| `SPIRE_REGISTRY_POLL_INTERVAL_MS`          | `12000`     | Registry poll interval, at least 1000 ms.                                                                   |
| `SPIRE_REGISTRY_MAX_STALENESS_MS`          | `>=60000`   | Maximum time since a successful finalized sync before registry-authoritative operations fail closed.        |
| `SPIRE_HOMESERVER_ID`                      | required    | Canonical lowercase `0x`-prefixed 32-byte homeserver ID.                                                    |
| `SPIRE_FEDERATION_ALLOW_PRIVATE_ADDRESSES` | `false`     | Allows private/loopback federation DNS targets for local integration tests only. Never enable publicly.     |

The registered endpoint must be a bare HTTPS origin and its Ed25519 signing key
must match `SPK`. Until the first finalized cache position is available, and
whenever successful sync exceeds the configured staleness window, Spire fails
closed for registry-authoritative operations. Connected device sockets are
reauthorized against that state every minute. See
[federation v1](../../docs/architecture/federation-v1.md) and the
[EVM registry deployment gates](../../docs/architecture/evm-registry-v1.md).

### Passkeys / WebAuthn

The `/auth/passkey/*`, `/user/:id/passkeys/*`, and `/passkey/*` routes are gated on `SPIRE_PASSKEY_RP_ID` and `SPIRE_PASSKEY_ORIGINS`; without them those endpoints return `500 Passkeys are not configured`. Spire also serves the CLI WebAuthn bridge at `/cli/passkey`, which should be loaded from an origin listed in `SPIRE_PASSKEY_ORIGINS` so browser passkey ceremonies verify against the same RP config as native clients. See [`.env.example`](./.env.example) for the full set, including the optional `SPIRE_PASSKEY_IOS_APP_IDS`, `SPIRE_PASSKEY_ANDROID_PACKAGE`, and `SPIRE_PASSKEY_ANDROID_FINGERPRINTS` triple that makes spire serve the WebAuthn well-known association files (`/.well-known/apple-app-site-association`, `/.well-known/assetlinks.json`) directly. Those endpoints 404 when their env vars aren't set, so a non-passkey deployment is indistinguishable from one that hasn't enrolled an app.

The same `SPIRE_PASSKEY_ANDROID_FINGERPRINTS` value is reused by `getRpConfig()` to derive `android:apk-key-hash:<base64url>` entries, which it merges into the WebAuthn `expectedOrigin` allowlist. Native Android Credential Manager sets `clientDataJSON.origin` to that string instead of the RP host, so without those entries simplewebauthn rejects every native-Android assertion at the origin check (the mobile UI surfaces this as a generic "RP failed" error). Operators only have to publish the cert fingerprints; the base64url math is handled server-side.

For Docker Compose, place the passkey variables in `apps/spire/.env` beside `SPK` and `JWT_SECRET`; the compose file passes that env file into the `spire` container. Production should use the production RP host, Android package, and EAS signing-certificate fingerprint. Development should use its own host/package/fingerprint so the dev APK is not authorized by the production association file.

### Sample `.env`

```sh
# Run `pnpm --filter @vex-chat/spire gen-spk` and paste the two lines it prints (SPK + JWT_SECRET).
SPK=a1b2c3...
JWT_SECRET=d4e5f6...
DB_TYPE=sqlite
# CANARY=true
# API_PORT=        # unset = 16777 unless you override
NODE_ENV=production
```

## Development

From the monorepo root (or use `pnpm <script>` from `apps/spire/`):

```sh
pnpm install                                  # install workspace deps
pnpm --filter @vex-chat/spire build           # tsc (sanity check — runtime uses --experimental-strip-types)
pnpm --filter @vex-chat/spire lint            # eslint strictTypeChecked
pnpm --filter @vex-chat/spire lint:fix        # eslint --fix
pnpm --filter @vex-chat/spire test            # vitest run
```

Workspace-wide commands from root: `pnpm test`, `pnpm lint`, `pnpm format:check`, `pnpm -r build`.

See the root [AGENTS.md](../../AGENTS.md) and this package's [AGENTS.md](./AGENTS.md) for the release flow (changesets → publish via OIDC) and the rules for writing changesets.

Outside contributors should follow the root [CONTRIBUTING.md](../../CONTRIBUTING.md) (including the [CLA](../../CLA.md)).

## License

Open source default: **[AGPL-3.0](./LICENSE)** (full text; see `package.json` for SPDX). Commercial licenses from **Vex Heavy Industries LLC**: [**LICENSE-COMMERCIAL**](./LICENSE-COMMERCIAL), [**LICENSING.md**](./LICENSING.md), [vex.wtf](https://vex.wtf/licensing).

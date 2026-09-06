# Build context is the MONOREPO ROOT (see docker-compose.yml: context: ../..).
# This Dockerfile lives in apps/spire/ but operates on the whole workspace
# so it can resolve `workspace:^` deps for @vex-chat/{types,crypto,libvex}.

# Match .tool-versions in both stages: native addons must be built with the
# tested Node headers. Node 24.19+ introduced an ObjectWrap cleanup regression
# that crashes better-sqlite3 during startup (nodejs/node#65042).
FROM node:24.14.0-alpine AS node-base

# ── Build stage ──────────────────────────────────────────────────────────
FROM node-base AS build

# argon2 + better-sqlite3 compile native code via node-gyp.
RUN apk add --no-cache python3 make g++

# Pin pnpm to match root `packageManager` (pnpm@10.33.0). Use npm global
# install instead of `corepack prepare`: Corepack’s pnpm fetch often fails in
# CI/Docker (transient TLS/registry errors on :443) while `npm i -g` is stable.
RUN npm install -g pnpm@10.33.0

WORKDIR /repo
COPY . .

# Install spire's full dep graph (devDeps included so we can build).
# onlyBuiltDependencies (argon2, better-sqlite3, esbuild, msgpackr-extract)
# is honored — postinstall scripts run for those, ignored for the rest.
RUN pnpm install --filter @vex-chat/spire... --frozen-lockfile

# Build types -> crypto -> libvex (their `files: [...]` arrays include
# `dist/` and that's what consumers — including spire — actually import).
# Topo order is automatic with `pnpm -r build` on the filtered subset.
RUN pnpm --filter @vex-chat/spire^... build

# `pnpm deploy` produces a flat /out with a real node_modules (workspace
# siblings materialized as packages, not symlinks) + spire's `files: [...]`
# contents. Result looks like a standalone `npm install`'d project.
# --prod skips devDependencies. --legacy uses the older deploy semantics
# that ship the package's source via `files: [...]` rather than expecting
# a "publish" subdir.
RUN pnpm --filter @vex-chat/spire deploy --prod --legacy /out

# ── Runtime stage ────────────────────────────────────────────────────────
FROM node-base

# Healthcheck: deploy/spire-container-health.sh (Node + fetch; no extra apk packages)
RUN deluser --remove-home node \
 && addgroup -g 1000 spire && adduser -u 1000 -G spire -s /bin/sh -D spire

WORKDIR /app
COPY --from=build /out /app

# spire's package.json `files: [...]` doesn't include deploy/ (it's runtime
# helper scripts, not shipped on npm) — copy them in separately.
RUN mkdir -p /app/deploy
COPY --chown=spire:spire apps/spire/deploy/resolve-spire-listen-port.sh \
    apps/spire/deploy/spire-container-health.sh \
    /app/deploy/
RUN chmod +x /app/deploy/resolve-spire-listen-port.sh /app/deploy/spire-container-health.sh

# /data is the writable volume for SQLite DB + uploaded files.
# Spire creates files/, avatars/, emoji/ relative to CWD.
RUN mkdir -p /data/files /data/avatars /data/emoji && chown -R spire:spire /data

USER spire
WORKDIR /data

ENV NODE_ENV=production

# Spire binds 16777 unless API_PORT; see src/spireListenPort.ts
EXPOSE 16777

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["/bin/sh", "/app/deploy/spire-container-health.sh"]

ENTRYPOINT ["node", "--experimental-strip-types", "/app/src/run.ts"]

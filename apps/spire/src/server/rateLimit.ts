/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Request } from "express";

import { timingSafeEqual } from "node:crypto";

import rateLimit, { ipKeyGenerator } from "express-rate-limit";

/** HTTP header carrying the dev API key (must match {@link process.env.DEV_API_KEY}). */
export const DEV_API_KEY_HEADER = "x-dev-api-key";

interface HeaderReader {
    get(name: string): string | undefined;
}

export function devApiKeyMatches(req: HeaderReader): boolean {
    const configured = process.env["DEV_API_KEY"]?.trim() ?? "";
    if (configured.length === 0) {
        return false;
    }
    const presented = req.get(DEV_API_KEY_HEADER);
    if (!presented || presented.length !== configured.length) {
        return false;
    }
    try {
        return timingSafeEqual(
            Buffer.from(presented, "utf8"),
            Buffer.from(configured, "utf8"),
        );
    } catch {
        return false;
    }
}

/**
 * When `DEV_API_KEY` is set in the environment, any request whose
 * `x-dev-api-key` header matches (constant-time) skips all in-process rate
 * limiters. Dev / load-testing escape hatch only — never set in production.
 * (Future: first-class API keys with scopes may reuse this header name.)
 */
export function devApiKeySkipsRateLimits(req: HeaderReader): boolean {
    if (disableRateLimitsByEnv()) {
        return true;
    }
    return devApiKeyMatches(req);
}

function disableRateLimitsByEnv(): boolean {
    const raw = process.env["SPIRE_DISABLE_RATE_LIMITS"]?.trim().toLowerCase();
    return raw === "1" || raw === "true";
}

/**
 * Rate limiting middleware.
 *
 * The limiters below address CWE-307 (brute-force auth), CWE-400 / CWE-770
 * (unrestricted resource consumption), and OWASP API4:2023. The primary tiers
 * are:
 *
 * - `globalLimiter` — baseline per-IP limit across every route. Wide
 *   enough to not bother normal clients, tight enough to shield the
 *   server from a single-host flood.
 * - `authLimiter` — strict per-IP limit on auth endpoints (register,
 *   login, device challenge). `skipSuccessfulRequests` means only the
 *   failed attempts count, so a correct login doesn't eat the budget.
 * - `uploadLimiter` — upload-specific limit applied before multer,
 *   so multer never even parses a request that's over quota.
 * - `migrationLimiter` — per-account protection for migration challenge,
 *   preparation, and import work.
 *
 * IP-keyed limiters use `ipKeyGenerator` from `express-rate-limit@7.4+` to
 * bucket IPv4 and IPv4-mapped IPv6 correctly (CVE-2026-30827 — older
 * versions silently collapsed all IPv4-mapped IPv6 addresses into
 * one bucket, which let attackers bypass the limiter).
 *
 * `trust proxy` must match the real deployment topology (see Spire.ts) so
 * `req.ip` cannot be spoofed and does not collapse all traffic onto a proxy.
 */

/**
 * Bucket requests by the real client IP, IPv6-safe.
 *
 * `req.ip` reflects the explicitly configured proxy hop count. We still run it through
 * `ipKeyGenerator` so IPv4-mapped IPv6 (`::ffff:1.2.3.4`) doesn't
 * collide with unrelated IPv6 addresses in the same /56.
 */
const keyByIp = (req: Request): string => ipKeyGenerator(req.ip ?? "");

/**
 * Global per-IP limiter. Applied app-wide via `api.use(globalLimiter)`.
 *
 * 150,000 requests per 15 minutes per client IP. This leaves room for
 * high-throughput clients and algorithmic applications while still
 * putting a ceiling on runaway single-host traffic.
 */
export const globalLimiter = rateLimit({
    keyGenerator: keyByIp,
    legacyHeaders: false,
    limit: 150_000,
    skip: devApiKeySkipsRateLimits,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

/**
 * Strict auth endpoint limiter. Applied per-route to /auth, /register,
 * and /auth/device.
 *
 * 50 failed attempts per 15 minutes per IP. Successful logins don't
 * count (`skipSuccessfulRequests`), so a normal user doesn't lock
 * themselves out by fat-fingering a password once. Blocks brute force
 * (CWE-307) without harming UX.
 */
export const authLimiter = rateLimit({
    keyGenerator: keyByIp,
    legacyHeaders: false,
    limit: 50,
    skip: devApiKeySkipsRateLimits,
    skipSuccessfulRequests: true,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

/**
 * Cross-IP password defense. This account bucket complements the IP bucket so
 * a distributed password spray cannot make unlimited guesses at one account.
 */
export const accountAuthLimiter = rateLimit({
    keyGenerator: (req) => {
        const body: unknown = req.body;
        const username =
            typeof body === "object" &&
            body !== null &&
            "username" in body &&
            typeof body.username === "string"
                ? body.username.trim().toLowerCase().slice(0, 64)
                : "";
        return username.length > 0
            ? `account:${username}`
            : `invalid:${keyByIp(req)}`;
    },
    legacyHeaders: false,
    limit: 100,
    skip: devApiKeySkipsRateLimits,
    skipSuccessfulRequests: true,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

/**
 * Limit repeated password replacement attempts per authenticated account.
 * This is intentionally tighter than sign-in because each failed request has
 * already passed bearer/device validation and still consumes an Argon2 check.
 */
export const passwordUpdateLimiter = rateLimit({
    keyGenerator: (req) =>
        req.user?.userID
            ? `password:${req.user.userID}`
            : `invalid:${keyByIp(req)}`,
    legacyHeaders: false,
    limit: 10,
    skip: devApiKeySkipsRateLimits,
    skipSuccessfulRequests: true,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

/**
 * Migration operations can trigger signed federation requests and durable
 * imports. Keep their cost bounded per authenticated account while allowing a
 * user to retry a partially deferred import after enrolling another device.
 */
export const migrationLimiter = rateLimit({
    keyGenerator: (req) =>
        req.user?.userID
            ? `migration:${req.user.userID}`
            : `invalid:${keyByIp(req)}`,
    legacyHeaders: false,
    limit: 20,
    skip: devApiKeySkipsRateLimits,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

/**
 * Upload endpoint limiter. Applied per-route to /file and /avatar
 * POSTs, BEFORE multer parses the multipart body. Caps the number of
 * upload attempts per minute so an attacker can't force spire to
 * spend CPU/IO on repeated large-body parses.
 *
 * 200 uploads per minute per IP — generous for a chat client (rapid-
 * fire image attachments) but tight enough to shield the disk.
 */
export const uploadLimiter = rateLimit({
    keyGenerator: keyByIp,
    legacyHeaders: false,
    limit: 200,
    skip: devApiKeySkipsRateLimits,
    standardHeaders: "draft-7",
    windowMs: 60 * 1000,
});

/**
 * Key-bundle retrieval dispenses OTKs, so it gets its own tighter bucket keyed
 * by authenticated caller and target device. This makes OTK-drain attempts hit
 * a per-pair budget without penalizing unrelated senders.
 */
export const keyBundleLimiter = rateLimit({
    keyGenerator: (req) => {
        const caller =
            req.user?.userID ??
            ipKeyGenerator(req.ip ?? req.socket.remoteAddress ?? "");
        const target =
            typeof req.params["id"] === "string" ? req.params["id"] : "unknown";
        return `${caller}:${target}`;
    },
    legacyHeaders: false,
    limit: 30,
    skip: devApiKeySkipsRateLimits,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

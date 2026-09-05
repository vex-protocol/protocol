/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database } from "../Database.ts";
import type {
    AuthenticationResponseJSON,
    RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { Passkey } from "@vex-chat/types";

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import {
    PasskeyAuthFinishPayloadSchema,
    PasskeyAuthStartPayloadSchema,
    PasskeyRegistrationFinishPayloadSchema,
    PasskeyRegistrationStartPayloadSchema,
} from "@vex-chat/types";

import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { z } from "zod";

import { JWT_EXPIRY_PASSKEY } from "../Spire.ts";
import { signAuthJwt } from "../utils/authJwt.ts";

import {
    getPasskeyRpConfig,
    sanitizePasskeyTransports,
} from "./passkeyConfig.ts";
import { authLimiter } from "./rateLimit.ts";
import { censorUser, getParam, getUser } from "./utils.ts";
import { sendWireResponse } from "./wireResponse.ts";

import { protect, protectAnyAuth } from "./index.ts";

const REGISTRATION_TTL_MS = 5 * 60 * 1000; // 5 min
const AUTHENTICATION_TTL_MS = 5 * 60 * 1000;
const BROWSER_AUTHENTICATION_TTL_MS = 5 * 60 * 1000;
const BROWSER_REGISTRATION_TTL_MS = 5 * 60 * 1000;
// Cap each user's passkey count so a compromised JWT can't fill the
// table. WebAuthn-style apps typically allow ~20; we go conservative.
const MAX_PASSKEYS_PER_USER = 10;

type AuthenticationOptions = Awaited<
    ReturnType<typeof generateAuthenticationOptions>
>;

type BrowserAuthenticationStatus = "in_progress" | "pending" | "response_ready";
type BrowserRegistrationStatus = "failed" | "in_progress" | "pending";

interface PendingAuthentication {
    browserRequestID: string;
    challenge: string;
    createdAt: number;
    options: AuthenticationOptions;
    userID: string;
}

interface PendingBrowserAuthentication {
    authenticationRequestID: string;
    createdAt: number;
    response?: Record<string, unknown>;
    status: BrowserAuthenticationStatus;
    tokenDigest: Buffer;
}

interface PendingBrowserRegistration {
    challenge?: string;
    createdAt: number;
    deviceID: string;
    error?: string;
    name: string;
    registrationRequestID: string;
    status: BrowserRegistrationStatus;
    tokenDigest: Buffer;
    userID: string;
    username: string;
}

interface PendingRegistration {
    browserRequestID: string;
    challenge: string;
    createdAt: number;
    deviceID: string;
    name: string;
    userID: string;
}

const pendingRegistrations = new Map<string, PendingRegistration>();
const pendingAuthentications = new Map<string, PendingAuthentication>();
const pendingBrowserAuthentications = new Map<
    string,
    PendingBrowserAuthentication
>();
const pendingBrowserRegistrations = new Map<
    string,
    PendingBrowserRegistration
>();

const BrowserHandoffTokenSchema = z.object({
    token: z.string().min(32).max(256),
});
const BrowserAuthenticationFinishSchema = BrowserHandoffTokenSchema.extend({
    response: z.record(z.string(), z.unknown()),
});
const BrowserRegistrationFinishSchema = BrowserHandoffTokenSchema.extend({
    response: z.record(z.string(), z.unknown()),
});

function browserTokenDigest(token: string): Buffer {
    return createHash("sha256").update(token, "utf8").digest();
}

function browserTokenMatches(
    pending: { tokenDigest: Buffer },
    token: string,
): boolean {
    return timingSafeEqual(pending.tokenDigest, browserTokenDigest(token));
}

function createBrowserAuthentication(authenticationRequestID: string): {
    browserToken: string;
    expiresAt: string;
    requestID: string;
} {
    pruneBrowserAuthentications();
    const requestID = crypto.randomUUID();
    const browserToken = randomBytes(32).toString("base64url");
    const createdAt = Date.now();
    pendingBrowserAuthentications.set(requestID, {
        authenticationRequestID,
        createdAt,
        status: "pending",
        tokenDigest: browserTokenDigest(browserToken),
    });
    return {
        browserToken,
        expiresAt: new Date(
            createdAt + BROWSER_AUTHENTICATION_TTL_MS,
        ).toISOString(),
        requestID,
    };
}

function createBrowserRegistration(args: {
    deviceID: string;
    name: string;
    registrationRequestID: string;
    userID: string;
    username: string;
}): {
    browserToken: string;
    expiresAt: string;
    requestID: string;
} {
    pruneBrowserRegistrations();
    const requestID = crypto.randomUUID();
    const browserToken = randomBytes(32).toString("base64url");
    const createdAt = Date.now();
    pendingBrowserRegistrations.set(requestID, {
        createdAt,
        deviceID: args.deviceID,
        name: args.name,
        registrationRequestID: args.registrationRequestID,
        status: "pending",
        tokenDigest: browserTokenDigest(browserToken),
        userID: args.userID,
        username: args.username,
    });
    return {
        browserToken,
        expiresAt: new Date(
            createdAt + BROWSER_REGISTRATION_TTL_MS,
        ).toISOString(),
        requestID,
    };
}

function failBrowserRegistration(
    pending: PendingBrowserRegistration,
    error: string,
): void {
    delete pending.challenge;
    pending.error = error;
    pending.status = "failed";
}

function pruneAuthentications(nowMs = Date.now()): void {
    for (const [id, entry] of pendingAuthentications.entries()) {
        if (nowMs - entry.createdAt > AUTHENTICATION_TTL_MS) {
            pendingAuthentications.delete(id);
            pendingBrowserAuthentications.delete(entry.browserRequestID);
        }
    }
}

function pruneBrowserAuthentications(nowMs = Date.now()): void {
    for (const [id, entry] of pendingBrowserAuthentications.entries()) {
        if (nowMs - entry.createdAt > BROWSER_AUTHENTICATION_TTL_MS) {
            pendingBrowserAuthentications.delete(id);
        }
    }
}

function pruneBrowserRegistrations(nowMs = Date.now()): void {
    for (const [id, entry] of pendingBrowserRegistrations.entries()) {
        if (nowMs - entry.createdAt > BROWSER_REGISTRATION_TTL_MS) {
            pendingBrowserRegistrations.delete(id);
        }
    }
}

function pruneRegistrations(nowMs = Date.now()): void {
    for (const [id, entry] of pendingRegistrations.entries()) {
        if (nowMs - entry.createdAt > REGISTRATION_TTL_MS) {
            pendingRegistrations.delete(id);
        }
    }
}

/**
 * Issues a passkey-scoped JWT.
 *
 * Carries `scope: "passkey"` and the owning userID; deliberately
 * shorter-lived than an account or device JWT (5 min vs 1 hour) because a
 * passkey JWT grants destructive admin powers (delete a device,
 * approve an enrollment) without further user verification. Callers
 * re-do the WebAuthn ceremony when this expires.
 */
function signPasskeyToken(args: {
    passkeyID: string;
    user: ReturnType<typeof censorUser>;
}): string {
    return signAuthJwt(
        {
            passkey: { passkeyID: args.passkeyID },
            scope: "passkey" as const,
            user: args.user,
        },
        JWT_EXPIRY_PASSKEY,
    );
}

export const getPasskeyRouter = (db: Database) => {
    const router = express.Router();

    // ── Authenticated registration (an existing device adds a passkey) ──

    router.post(
        "/user/:id/passkeys/register/begin",
        protect,
        async (req, res) => {
            const userDetails = getUser(req);
            const userID = getParam(req, "id");
            if (userDetails.userID !== userID) {
                res.sendStatus(401);
                return;
            }
            const parsed = PasskeyRegistrationStartPayloadSchema.safeParse(
                req.body,
            );
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid registration payload",
                    issues: parsed.error.issues,
                });
                return;
            }

            if (!req.device || req.device.owner !== userID) {
                res.status(401).send({
                    error: "Adding a passkey requires an authenticated device.",
                });
                return;
            }
            const existing = await db.retrievePasskeysByUser(userID);
            if (existing.length >= MAX_PASSKEYS_PER_USER) {
                res.status(409).send({
                    error: `Each account is limited to ${MAX_PASSKEYS_PER_USER} passkeys.`,
                });
                return;
            }

            const { rpID, rpName } = getPasskeyRpConfig();
            // The userID we hand to the authenticator is the account
            // userID encoded as bytes; this scopes the credential to
            // the account so re-registering on the same authenticator
            // updates the existing credential instead of stacking.
            const userIDBytes = new TextEncoder().encode(userID);

            const options = await generateRegistrationOptions({
                attestationType: "none",
                authenticatorSelection: {
                    requireResidentKey: false,
                    residentKey: "preferred",
                    userVerification: "required",
                },
                excludeCredentials: [],
                rpID,
                rpName,
                userDisplayName: userDetails.username,
                userID: userIDBytes,
                userName: userDetails.username,
            });

            pruneRegistrations();
            const requestID = crypto.randomUUID();
            const browserHandoff = createBrowserRegistration({
                deviceID: req.device.deviceID,
                name: parsed.data.name,
                registrationRequestID: requestID,
                userID,
                username: userDetails.username,
            });
            pendingRegistrations.set(requestID, {
                browserRequestID: browserHandoff.requestID,
                challenge: options.challenge,
                createdAt: Date.now(),
                deviceID: req.device.deviceID,
                name: parsed.data.name,
                userID,
            });

            // PasskeyRegistrationOptions in @vex-chat/types uses a
            // looser interface than @simplewebauthn/server (so this
            // shared types package doesn't take a runtime dep on
            // SimpleWebAuthn). The wire shape is identical — both
            // sides hand the JSON straight to navigator.credentials.
            sendWireResponse(req, res, {
                // Older libvex releases preserve the opaque options object but
                // strip unknown top-level fields. Keep the handoff inside that
                // object so desktop can adopt the HTTPS bridge before its next
                // package bump; WebAuthn ignores unknown dictionary members.
                options: { ...options, vexBrowserHandoff: browserHandoff },
                requestID,
            });
        },
    );

    router.post(
        "/user/:id/passkeys/register/finish",
        protect,
        async (req, res) => {
            const userDetails = getUser(req);
            const userID = getParam(req, "id");
            if (userDetails.userID !== userID) {
                res.sendStatus(401);
                return;
            }

            const parsed = PasskeyRegistrationFinishPayloadSchema.safeParse(
                req.body,
            );
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid finish payload",
                    issues: parsed.error.issues,
                });
                return;
            }

            if (!req.device || req.device.owner !== userID) {
                res.status(401).send({
                    error: "Adding a passkey requires an authenticated device.",
                });
                return;
            }

            pruneRegistrations();
            const pending = pendingRegistrations.get(parsed.data.requestID);
            if (
                !pending ||
                pending.userID !== userID ||
                pending.deviceID !== req.device.deviceID
            ) {
                res.status(404).send({
                    error: "Registration request not found or expired.",
                });
                return;
            }
            // Single-use challenge: clear immediately so a replay can't
            // re-bind the credential to a second name.
            pendingRegistrations.delete(parsed.data.requestID);
            pendingBrowserRegistrations.delete(pending.browserRequestID);

            const { expectedOrigin, rpID } = getPasskeyRpConfig();

            let verification;
            try {
                // The browser's RegistrationResponseJSON is opaque to
                // spire — simplewebauthn does the full structural
                // decode + signature verification on this argument,
                // so the cast from a generic `Record<string, unknown>`
                // to the branded type is the trust boundary.
                const rawResponse = parsed.data.response as unknown;
                verification = await verifyRegistrationResponse({
                    expectedChallenge: pending.challenge,
                    expectedOrigin,
                    expectedRPID: rpID,
                    requireUserVerification: true,
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- structurally validated by simplewebauthn below
                    response: rawResponse as RegistrationResponseJSON,
                });
            } catch (err: unknown) {
                logWebAuthnFailure("registration", err);
                res.status(400).send({
                    error: "Passkey attestation could not be verified.",
                });
                return;
            }

            if (!verification.verified) {
                res.status(400).send({ error: "Passkey attestation failed." });
                return;
            }

            const credential = verification.registrationInfo.credential;

            const dupe = await db.retrievePasskeyByCredentialID(credential.id);
            if (dupe) {
                res.status(409).send({
                    error: "This authenticator is already registered.",
                });
                return;
            }

            const transports = sanitizePasskeyTransports(
                credential.transports ?? [],
            );

            // Re-check the per-user cap inside the finish step in case
            // a concurrent request just consumed the last available
            // slot. `MAX_PASSKEYS_PER_USER` is the source of truth.
            const after = await db.retrievePasskeysByUser(userID);
            if (after.length >= MAX_PASSKEYS_PER_USER) {
                res.status(409).send({
                    error: `Each account is limited to ${MAX_PASSKEYS_PER_USER} passkeys.`,
                });
                return;
            }

            const created = await db.createPasskey(
                userID,
                pending.name,
                credential.id,
                XUtils.encodeHex(credential.publicKey),
                // The COSE alg is reported back in `info.fmt`-adjacent
                // helpers, but `WebAuthnCredential` only carries the
                // public key; verifyAuthenticationResponse re-derives
                // the alg from the COSE_Key bytes. We persist a
                // best-effort algorithm hint as 0 when unavailable and
                // refuse no algorithms here — verification time is
                // where the real check happens.
                0,
                transports,
            );

            sendWireResponse(req, res, created);
        },
    );

    router.get("/user/:id/passkeys", protectAnyAuth, async (req, res) => {
        const userDetails = getUser(req);
        const userID = getParam(req, "id");
        if (userDetails.userID !== userID) {
            res.sendStatus(401);
            return;
        }
        const list: Passkey[] = await db.retrievePasskeysByUser(userID);
        sendWireResponse(req, res, list);
    });

    router.delete(
        "/user/:id/passkeys/:passkeyID",
        protect,
        async (req, res) => {
            const userDetails = getUser(req);
            const userID = getParam(req, "id");
            const passkeyID = getParam(req, "passkeyID");
            if (userDetails.userID !== userID) {
                res.sendStatus(401);
                return;
            }
            if (!req.device || req.device.owner !== userID) {
                res.status(401).send({
                    error: "Removing a passkey requires an authenticated device.",
                });
                return;
            }
            const row = await db.retrievePasskeyInternal(passkeyID);
            if (!row || row.userID !== userID) {
                res.sendStatus(404);
                return;
            }
            await db.deletePasskey(passkeyID);
            res.sendStatus(200);
        },
    );

    // ── Public passkey login ───────────────────────────────────────────

    router.post(
        "/auth/passkey/browser-registration/:requestID/begin",
        authLimiter,
        async (req, res) => {
            const parsed = BrowserHandoffTokenSchema.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).send({ error: "Invalid browser handoff." });
                return;
            }
            pruneBrowserRegistrations();
            const pending = pendingBrowserRegistrations.get(
                getParam(req, "requestID"),
            );
            if (!pending || !browserTokenMatches(pending, parsed.data.token)) {
                res.status(401).send({
                    error: "Browser handoff is invalid or expired.",
                });
                return;
            }
            if (pending.status === "failed") {
                res.status(409).send({
                    error:
                        pending.error ??
                        "Browser handoff has already completed.",
                });
                return;
            }
            const device = await db.retrieveDevice(pending.deviceID);
            if (!device || device.owner !== pending.userID) {
                failBrowserRegistration(
                    pending,
                    "The originating device is no longer approved.",
                );
                res.status(401).send({ error: pending.error });
                return;
            }
            const existing = await db.retrievePasskeysByUser(pending.userID);
            if (existing.length >= MAX_PASSKEYS_PER_USER) {
                failBrowserRegistration(
                    pending,
                    `Each account is limited to ${MAX_PASSKEYS_PER_USER} passkeys.`,
                );
                res.status(409).send({ error: pending.error });
                return;
            }
            // The browser and native challenges represent one user action.
            // Once the HTTPS path starts, the custom-origin path cannot also
            // finish and create a second credential.
            pendingRegistrations.delete(pending.registrationRequestID);

            const { rpID, rpName } = getPasskeyRpConfig();
            const options = await generateRegistrationOptions({
                attestationType: "none",
                authenticatorSelection: {
                    requireResidentKey: false,
                    residentKey: "preferred",
                    userVerification: "required",
                },
                excludeCredentials: [],
                rpID,
                rpName,
                userDisplayName: pending.username,
                userID: new TextEncoder().encode(pending.userID),
                userName: pending.username,
            });
            pending.challenge = options.challenge;
            delete pending.error;
            pending.status = "in_progress";
            sendWireResponse(req, res, { options });
        },
    );

    router.post(
        "/auth/passkey/browser-registration/:requestID/finish",
        authLimiter,
        async (req, res) => {
            const parsed = BrowserRegistrationFinishSchema.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).send({
                    error: "Invalid browser handoff response.",
                });
                return;
            }
            pruneBrowserRegistrations();
            const pending = pendingBrowserRegistrations.get(
                getParam(req, "requestID"),
            );
            if (!pending || !browserTokenMatches(pending, parsed.data.token)) {
                res.status(401).send({
                    error: "Browser handoff is invalid or expired.",
                });
                return;
            }
            if (pending.status !== "in_progress" || !pending.challenge) {
                res.status(409).send({
                    error: "Request a fresh passkey challenge and try again.",
                });
                return;
            }
            const challenge = pending.challenge;
            delete pending.challenge;

            const device = await db.retrieveDevice(pending.deviceID);
            if (!device || device.owner !== pending.userID) {
                failBrowserRegistration(
                    pending,
                    "The originating device is no longer approved.",
                );
                res.status(401).send({ error: pending.error });
                return;
            }

            const { expectedOrigin, rpID } = getPasskeyRpConfig();
            let verification;
            try {
                verification = await verifyRegistrationResponse({
                    expectedChallenge: challenge,
                    expectedOrigin,
                    expectedRPID: rpID,
                    requireUserVerification: true,
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- structurally validated by simplewebauthn below
                    response: parsed.data
                        .response as unknown as RegistrationResponseJSON,
                });
            } catch (err: unknown) {
                logWebAuthnFailure("browser registration", err);
                failBrowserRegistration(
                    pending,
                    "Passkey attestation could not be verified.",
                );
                res.status(400).send({ error: pending.error });
                return;
            }
            if (!verification.verified) {
                failBrowserRegistration(pending, "Passkey attestation failed.");
                res.status(400).send({ error: pending.error });
                return;
            }

            const credential = verification.registrationInfo.credential;
            const duplicate = await db.retrievePasskeyByCredentialID(
                credential.id,
            );
            if (duplicate) {
                failBrowserRegistration(
                    pending,
                    "This authenticator is already registered.",
                );
                res.status(409).send({ error: pending.error });
                return;
            }
            const existing = await db.retrievePasskeysByUser(pending.userID);
            if (existing.length >= MAX_PASSKEYS_PER_USER) {
                failBrowserRegistration(
                    pending,
                    `Each account is limited to ${MAX_PASSKEYS_PER_USER} passkeys.`,
                );
                res.status(409).send({ error: pending.error });
                return;
            }

            const created = await db.createPasskey(
                pending.userID,
                pending.name,
                credential.id,
                XUtils.encodeHex(credential.publicKey),
                0,
                sanitizePasskeyTransports(credential.transports ?? []),
            );
            pendingBrowserRegistrations.delete(getParam(req, "requestID"));
            sendWireResponse(req, res, created);
        },
    );

    router.post(
        "/auth/passkey/browser-authentication/:requestID/begin",
        authLimiter,
        (req, res) => {
            const parsed = BrowserHandoffTokenSchema.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).send({ error: "Invalid browser handoff." });
                return;
            }
            pruneAuthentications();
            pruneBrowserAuthentications();
            const browserRequestID = getParam(req, "requestID");
            const browserPending =
                pendingBrowserAuthentications.get(browserRequestID);
            if (
                !browserPending ||
                !browserTokenMatches(browserPending, parsed.data.token)
            ) {
                res.status(401).send({
                    error: "Browser handoff is invalid or expired.",
                });
                return;
            }
            const authenticationPending = pendingAuthentications.get(
                browserPending.authenticationRequestID,
            );
            if (!authenticationPending) {
                pendingBrowserAuthentications.delete(browserRequestID);
                res.status(401).send({
                    error: "Authentication request is invalid or expired.",
                });
                return;
            }
            if (browserPending.status === "response_ready") {
                res.status(409).send({
                    error: "This browser handoff has already completed.",
                });
                return;
            }
            browserPending.status = "in_progress";
            sendWireResponse(req, res, {
                options: authenticationPending.options,
            });
        },
    );

    router.post(
        "/auth/passkey/browser-authentication/:requestID/finish",
        authLimiter,
        (req, res) => {
            const parsed = BrowserAuthenticationFinishSchema.safeParse(
                req.body,
            );
            if (!parsed.success) {
                res.status(400).send({
                    error: "Invalid browser handoff response.",
                });
                return;
            }
            pruneAuthentications();
            pruneBrowserAuthentications();
            const browserRequestID = getParam(req, "requestID");
            const browserPending =
                pendingBrowserAuthentications.get(browserRequestID);
            if (
                !browserPending ||
                !browserTokenMatches(browserPending, parsed.data.token)
            ) {
                res.status(401).send({
                    error: "Browser handoff is invalid or expired.",
                });
                return;
            }
            if (
                browserPending.status !== "in_progress" ||
                !pendingAuthentications.has(
                    browserPending.authenticationRequestID,
                )
            ) {
                res.status(409).send({
                    error: "Request a fresh passkey challenge and try again.",
                });
                return;
            }
            browserPending.response = parsed.data.response;
            browserPending.status = "response_ready";
            sendWireResponse(req, res, { ok: true });
        },
    );

    router.post(
        "/auth/passkey/browser-authentication/:requestID/status",
        authLimiter,
        (req, res) => {
            const parsed = BrowserHandoffTokenSchema.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).send({ error: "Invalid browser handoff." });
                return;
            }
            pruneAuthentications();
            pruneBrowserAuthentications();
            const browserRequestID = getParam(req, "requestID");
            const browserPending =
                pendingBrowserAuthentications.get(browserRequestID);
            if (
                !browserPending ||
                !browserTokenMatches(browserPending, parsed.data.token)
            ) {
                res.status(401).send({
                    error: "Browser handoff is invalid or expired.",
                });
                return;
            }
            if (
                !pendingAuthentications.has(
                    browserPending.authenticationRequestID,
                )
            ) {
                pendingBrowserAuthentications.delete(browserRequestID);
                res.status(401).send({
                    error: "Authentication request is invalid or expired.",
                });
                return;
            }
            if (
                browserPending.status !== "response_ready" ||
                !browserPending.response
            ) {
                res.status(202).send({ status: browserPending.status });
                return;
            }
            sendWireResponse(req, res, {
                response: browserPending.response,
            });
        },
    );

    router.post("/auth/passkey/begin", authLimiter, async (req, res) => {
        const parsed = PasskeyAuthStartPayloadSchema.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid begin payload",
                issues: parsed.error.issues,
            });
            return;
        }

        const user = await db.retrieveUser(parsed.data.username);
        if (!user) {
            // Don't reveal whether the username exists — return a
            // generic 401 here. (Some flows return a generated stub
            // challenge for username-less / discoverable creds; not
            // implemented yet.)
            res.sendStatus(401);
            return;
        }

        const passkeys = await db.retrievePasskeysByUser(user.userID);
        if (passkeys.length === 0) {
            res.sendStatus(401);
            return;
        }

        const allowCredentials = await Promise.all(
            passkeys.map(async (pk) => {
                const internal = await db.retrievePasskeyInternal(pk.passkeyID);
                return {
                    id: internal?.credentialID ?? "",
                    transports: sanitizePasskeyTransports(pk.transports),
                    type: "public-key" as const,
                };
            }),
        );

        const { rpID } = getPasskeyRpConfig();

        const options = await generateAuthenticationOptions({
            allowCredentials: allowCredentials.filter((c) => c.id.length > 0),
            rpID,
            userVerification: "required",
        });

        pruneAuthentications();
        const requestID = crypto.randomUUID();
        const browserHandoff = createBrowserAuthentication(requestID);
        pendingAuthentications.set(requestID, {
            browserRequestID: browserHandoff.requestID,
            challenge: options.challenge,
            createdAt: Date.now(),
            options,
            userID: user.userID,
        });

        sendWireResponse(req, res, {
            options: { ...options, vexBrowserHandoff: browserHandoff },
            requestID,
        });
    });

    router.post("/auth/passkey/finish", authLimiter, async (req, res) => {
        const parsed = PasskeyAuthFinishPayloadSchema.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid finish payload",
                issues: parsed.error.issues,
            });
            return;
        }

        pruneAuthentications();
        const pending = pendingAuthentications.get(parsed.data.requestID);
        if (!pending) {
            res.status(401).send({
                error: "Authentication challenge not found or expired.",
            });
            return;
        }
        // Single-use.
        pendingAuthentications.delete(parsed.data.requestID);
        pendingBrowserAuthentications.delete(pending.browserRequestID);

        // The browser's AuthenticationResponseJSON is opaque to spire
        // — simplewebauthn does the structural decode + signature
        // verification. The cast from `Record<string, unknown>` to
        // the branded type is the trust boundary.
        const rawAssertion = parsed.data.response as unknown;
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- structurally validated by simplewebauthn below
        const assertion = rawAssertion as AuthenticationResponseJSON;
        const credentialID =
            typeof assertion.id === "string" ? assertion.id : "";
        if (!credentialID) {
            res.status(400).send({
                error: "Assertion is missing a credential id.",
            });
            return;
        }

        const passkeyRow = await db.retrievePasskeyByCredentialID(credentialID);
        if (!passkeyRow || passkeyRow.userID !== pending.userID) {
            res.status(401).send({
                error: "No matching passkey for this account.",
            });
            return;
        }

        const { expectedOrigin, rpID } = getPasskeyRpConfig();

        // Force `Uint8Array<ArrayBuffer>` (not `ArrayBufferLike`) so
        // simplewebauthn's strict generic accepts the buffer; the
        // raw decoded bytes are identical.
        const credentialPublicKey = new Uint8Array(
            XUtils.decodeHex(passkeyRow.publicKey),
        );

        let verification;
        try {
            verification = await verifyAuthenticationResponse({
                credential: {
                    counter: passkeyRow.signCount,
                    id: passkeyRow.credentialID,
                    publicKey: credentialPublicKey,
                    transports: sanitizePasskeyTransports(
                        passkeyRow.transports.split(","),
                    ),
                },
                expectedChallenge: pending.challenge,
                expectedOrigin,
                expectedRPID: rpID,
                requireUserVerification: true,
                response: assertion,
            });
        } catch (err: unknown) {
            logWebAuthnFailure("authentication", err);
            res.status(401).send({
                error: "Passkey assertion could not be verified.",
            });
            return;
        }

        if (!verification.verified) {
            res.status(401).send({ error: "Passkey assertion failed." });
            return;
        }

        // Counter should be strictly increasing per the WebAuthn spec.
        // FIDO authenticators that report 0 are excused (the spec says
        // 0→0 is legitimate when the authenticator has no counter).
        const newCounter = verification.authenticationInfo.newCounter;
        if (
            newCounter !== 0 &&
            passkeyRow.signCount !== 0 &&
            newCounter <= passkeyRow.signCount
        ) {
            res.status(401).send({
                error: "Authenticator counter regressed (possible cloned credential).",
            });
            return;
        }

        const counterUpdated = await db.markPasskeyUsed(
            passkeyRow.passkeyID,
            passkeyRow.signCount,
            newCounter,
        );
        if (!counterUpdated) {
            res.status(401).send({
                error: "Passkey assertion was already used.",
            });
            return;
        }

        const user = await db.retrieveUser(pending.userID);
        if (!user) {
            res.status(404).send({ error: "Account not found." });
            return;
        }
        const censored = censorUser(user);
        const token = signPasskeyToken({
            passkeyID: passkeyRow.passkeyID,
            user: censored,
        });
        sendWireResponse(req, res, {
            passkeyID: passkeyRow.passkeyID,
            token,
            user: censored,
        });
    });

    return router;
};

function logWebAuthnFailure(ceremony: string, err: unknown): void {
    const requestId = crypto.randomUUID();
    const message = err instanceof Error ? err.message : String(err);
    console.warn(
        `[spire] WebAuthn ${ceremony} verification failed requestId=${requestId} message=${message}`,
    );
}

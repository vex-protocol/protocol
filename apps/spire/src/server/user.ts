/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database } from "../Database.ts";
import type { FederationService } from "../federation/FederationService.ts";
import type {
    AuthenticatorTransportFuture,
    RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { Device, DevicePayload } from "@vex-chat/types";

import express from "express";

import { xRandomBytes } from "@vex-chat/crypto";
import { XUtils } from "@vex-chat/crypto";
import { DevicePayloadSchema, TokenScopes } from "@vex-chat/types";

import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { stringify } from "uuid";
import { z } from "zod/v4";

import { MAX_ACTIVE_DEVICES_PER_USER } from "../Database.ts";
import { FederationServiceError } from "../federation/FederationService.ts";
import { msgpack } from "../utils/msgpack.ts";
import { verifyDevicePayloadPreKeySignature } from "../utils/preKeySignature.ts";
import { spireXSignOpenAsync } from "../utils/spireXSignOpenAsync.ts";

import { AppError } from "./errors.ts";
import { publicPeerDevice } from "./publicDevice.ts";
import { censorUser, getParam, getUser } from "./utils.ts";
import { buildAndroidApkKeyHashOrigins } from "./wellKnown.ts";

import { protect } from "./index.ts";

const DEVICE_REQUEST_TTL_MS = 10 * 60 * 1000;
const PASSKEY_REGISTRATION_TTL_MS = 5 * 60 * 1000;
const RESOLVED_REQUEST_TTL_MS = 30 * 60 * 1000;
const MAX_PASSKEYS_PER_USER = 10;

interface DeviceEnrollmentRequest {
    approvedDeviceID?: string;
    challengeHex: string;
    createdAt: number;
    devicePayload: DevicePayload;
    error?: string;
    /**
     * When false, the enrolling client has not yet confirmed on their
     * screen — we must not call `notify` until `POST .../publish`.
     */
    ownerNotified?: boolean;
    passkeyRegistration?: PendingDevicePasskeyRegistration;
    /**
     * Set when the requesting device proved account ownership with a passkey
     * before asking the existing device cluster for membership approval.
     */
    requesterPasskeyID?: string;
    requestID: string;
    resolvedAt?: number;
    status: DeviceEnrollmentStatus;
    userID: string;
}

type DeviceEnrollmentStatus = "approved" | "expired" | "pending" | "rejected";

interface PendingDevicePasskeyRegistration {
    challenge: string;
    createdAt: number;
    name: string;
}

const approvePayloadSchema = z.object({
    signed: z.string().min(1),
});

const pollPendingApprovalSchema = z.object({
    signed: z.string().min(1),
});

const pendingPasskeyRegistrationStartSchema = z.object({
    name: z.string().min(1).max(255),
    signed: z.string().min(1),
});

const pendingPasskeyRegistrationFinishSchema = z.object({
    name: z.string().min(1).max(255),
    requestID: z.string().min(1),
    response: z.record(z.string(), z.unknown()),
    signed: z.string().min(1),
});

const deviceEnrollments = new Map<string, DeviceEnrollmentRequest>();

const KNOWN_TRANSPORTS = [
    "ble",
    "cable",
    "hybrid",
    "internal",
    "nfc",
    "smart-card",
    "usb",
] as const satisfies readonly AuthenticatorTransportFuture[];

type VerifiedPendingResult =
    | { error: string; issues?: z.core.$ZodIssue[]; ok: false; status: number }
    | { ok: true; pending: DeviceEnrollmentRequest };

export function createPendingDeviceEnrollmentRequest(
    userID: string,
    devicePayload: DevicePayload,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void,
    options?: {
        deferOwnerNotification?: boolean;
        requesterPasskeyID?: string;
    },
): {
    challenge: string;
    expiresAt: string;
    requestID: string;
    status: "pending_approval";
    userID: string;
} {
    pruneDeviceEnrollmentRequests();
    const requestID = crypto.randomUUID();
    const challengeHex = XUtils.encodeHex(xRandomBytes(32));
    const deferOwner = options?.deferOwnerNotification === true;
    const pending: DeviceEnrollmentRequest = {
        challengeHex,
        createdAt: Date.now(),
        devicePayload,
        requestID,
        ...(options?.requesterPasskeyID
            ? { requesterPasskeyID: options.requesterPasskeyID }
            : {}),
        status: "pending",
        userID,
        ...(deferOwner ? { ownerNotified: false } : { ownerNotified: true }),
    };
    deviceEnrollments.set(requestID, pending);
    if (!deferOwner) {
        notify(userID, "deviceRequest", crypto.randomUUID(), {
            requestID,
            status: "pending",
        });
    }
    // We include the existing user's `userID` so the new (still-
    // unauthenticated) device can fetch its public avatar from the
    // unauthenticated `/avatar/:userID` endpoint and surface an "is
    // this you?" confirmation before continuing with the approval
    // request. The userID is already implicit (the requester typed the
    // username and learned the account exists from this very response),
    // so returning it here doesn't expand the attack surface.
    return {
        challenge: challengeHex,
        expiresAt: new Date(
            pending.createdAt + DEVICE_REQUEST_TTL_MS,
        ).toISOString(),
        requestID,
        status: "pending_approval",
        userID,
    };
}

/**
 * Reusable approve/reject side of a pending device-enrollment
 * request. Lives here so both the device-authenticated router
 * (signs an approval challenge with the approving device's
 * Ed25519 key) and the passkey-authenticated router (relies on
 * the freshness of the passkey JWT instead) can share the same
 * state-machine + enrollment lifecycle.
 *
 * The device-auth caller is expected to have already verified the
 * approving device's signature before invoking this helper.
 */
export async function recoverDeviceEnrollmentRequest(args: {
    approvedByPasskeyID?: string;
    db: Database;
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void;
    requestID: string;
    userID: string;
}): Promise<
    | { device: Device; kind: "ok"; revokedDeviceIDs: string[] }
    | { error: string; kind: "err"; status: number }
> {
    pruneDeviceEnrollmentRequests();
    const pending = deviceEnrollments.get(args.requestID);
    if (!pending || pending.userID !== args.userID) {
        return { error: "Request not found.", kind: "err", status: 404 };
    }
    if (pending.status !== "pending") {
        return {
            error: "Request is not pending.",
            kind: "err",
            status: 409,
        };
    }
    if (Date.now() - pending.createdAt > DEVICE_REQUEST_TTL_MS) {
        pending.status = "expired";
        pending.resolvedAt = Date.now();
        pending.error = "Request expired.";
        deviceEnrollments.set(args.requestID, pending);
        return { error: "Request expired.", kind: "err", status: 410 };
    }

    try {
        const { device, revokedDeviceIDs } = await args.db.recoverDevice(
            args.userID,
            pending.devicePayload,
            args.approvedByPasskeyID
                ? { approvedByPasskeyID: args.approvedByPasskeyID }
                : undefined,
        );
        pending.status = "approved";
        pending.approvedDeviceID = device.deviceID;
        pending.resolvedAt = Date.now();
        deviceEnrollments.set(args.requestID, pending);
        args.notify(args.userID, "deviceRequest", crypto.randomUUID(), {
            requestID: args.requestID,
            status: "approved",
        });
        return { device, kind: "ok", revokedDeviceIDs };
    } catch {
        pending.status = "rejected";
        pending.error = "Could not recover device.";
        pending.resolvedAt = Date.now();
        deviceEnrollments.set(args.requestID, pending);
        args.notify(args.userID, "deviceRequest", crypto.randomUUID(), {
            requestID: args.requestID,
            status: "rejected",
        });
        return {
            error: "Could not recover device.",
            kind: "err",
            status: 470,
        };
    }
}

export async function resolveDeviceEnrollmentRequest(args: {
    action: "approve" | "reject";
    db: Database;
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void;
    requestID: string;
    userID: string;
}): Promise<
    | { device: Device; kind: "ok" }
    | { error: string; kind: "err"; status: number }
> {
    pruneDeviceEnrollmentRequests();
    const pending = deviceEnrollments.get(args.requestID);
    if (!pending || pending.userID !== args.userID) {
        return { error: "Request not found.", kind: "err", status: 404 };
    }
    if (pending.status !== "pending") {
        return {
            error: "Request is not pending.",
            kind: "err",
            status: 409,
        };
    }
    if (Date.now() - pending.createdAt > DEVICE_REQUEST_TTL_MS) {
        pending.status = "expired";
        pending.resolvedAt = Date.now();
        pending.error = "Request expired.";
        deviceEnrollments.set(args.requestID, pending);
        return { error: "Request expired.", kind: "err", status: 410 };
    }

    if (args.action === "reject") {
        pending.status = "rejected";
        pending.resolvedAt = Date.now();
        pending.error = "Rejected.";
        deviceEnrollments.set(args.requestID, pending);
        args.notify(args.userID, "deviceRequest", crypto.randomUUID(), {
            requestID: args.requestID,
            status: "rejected",
        });
        // Caller maps `kind: "ok"` without device to a 200; reuse the
        // ok shape with a placeholder device since the type insists
        // on one. The reject flow doesn't return a body, the caller
        // discards `device`.
        return {
            device: {
                deleted: false,
                deviceID: "",
                lastLogin: "",
                name: "",
                owner: args.userID,
                signKey: "",
            },
            kind: "ok",
        };
    }

    try {
        const device = await args.db.createDevice(
            args.userID,
            pending.devicePayload,
        );
        pending.status = "approved";
        pending.approvedDeviceID = device.deviceID;
        pending.resolvedAt = Date.now();
        deviceEnrollments.set(args.requestID, pending);
        args.notify(args.userID, "deviceRequest", crypto.randomUUID(), {
            requestID: args.requestID,
            status: "approved",
        });
        return { device, kind: "ok" };
    } catch {
        pending.status = "rejected";
        pending.error = "Could not create approved device.";
        pending.resolvedAt = Date.now();
        deviceEnrollments.set(args.requestID, pending);
        args.notify(args.userID, "deviceRequest", crypto.randomUUID(), {
            requestID: args.requestID,
            status: "rejected",
        });
        return {
            error: "Could not create approved device.",
            kind: "err",
            status: 470,
        };
    }
}

function buildApprovalChallenge(
    requestID: string,
    signKey: string,
): Uint8Array {
    return XUtils.decodeUTF8(`${requestID}:${signKey.toLowerCase()}`);
}

function getRpConfig(): {
    expectedOrigin: string[];
    rpID: string;
    rpName: string;
} {
    const rpID = process.env["SPIRE_PASSKEY_RP_ID"]?.trim();
    const originsRaw = process.env["SPIRE_PASSKEY_ORIGINS"]?.trim();
    if (!rpID) {
        throw new AppError(
            500,
            "Passkeys are not configured on this server (SPIRE_PASSKEY_RP_ID is unset).",
        );
    }
    if (!originsRaw) {
        throw new AppError(
            500,
            "Passkeys are not configured on this server (SPIRE_PASSKEY_ORIGINS is unset).",
        );
    }
    const explicitOrigins = originsRaw
        .split(",")
        .map((o) => o.trim())
        .filter((o) => o.length > 0);
    if (explicitOrigins.length === 0) {
        throw new AppError(500, "SPIRE_PASSKEY_ORIGINS is empty.");
    }
    const expectedOrigin = Array.from(
        new Set([...explicitOrigins, ...buildAndroidApkKeyHashOrigins()]),
    );
    return {
        expectedOrigin,
        rpID,
        rpName: process.env["SPIRE_PASSKEY_RP_NAME"]?.trim() || "Vex",
    };
}

function isKnownTransport(s: string): s is AuthenticatorTransportFuture {
    return (KNOWN_TRANSPORTS as readonly string[]).includes(s);
}

function pruneDeviceEnrollmentRequests(nowMs = Date.now()): void {
    for (const [requestID, req] of deviceEnrollments.entries()) {
        if (
            req.status === "pending" &&
            nowMs - req.createdAt > DEVICE_REQUEST_TTL_MS
        ) {
            req.status = "expired";
            req.resolvedAt = nowMs;
            deviceEnrollments.set(requestID, req);
            continue;
        }
        if (
            req.status !== "pending" &&
            req.resolvedAt !== undefined &&
            nowMs - req.resolvedAt > RESOLVED_REQUEST_TTL_MS
        ) {
            deviceEnrollments.delete(requestID);
        }
    }
}

function requestSummary(req: DeviceEnrollmentRequest): {
    approvedDeviceID?: string;
    createdAt: string;
    deviceName: string;
    error?: string;
    expiresAt: string;
    requestID: string;
    signKey: string;
    status: DeviceEnrollmentStatus;
    username?: string;
} {
    return {
        createdAt: new Date(req.createdAt).toISOString(),
        deviceName: req.devicePayload.deviceName,
        expiresAt: new Date(
            req.createdAt + DEVICE_REQUEST_TTL_MS,
        ).toISOString(),
        requestID: req.requestID,
        signKey: req.devicePayload.signKey,
        status: req.status,
        ...(req.devicePayload.username !== undefined
            ? { username: req.devicePayload.username }
            : {}),
        ...(req.approvedDeviceID !== undefined
            ? { approvedDeviceID: req.approvedDeviceID }
            : {}),
        ...(req.error !== undefined ? { error: req.error } : {}),
    };
}

function sanitizeTransports(input: string[]): AuthenticatorTransportFuture[] {
    return input.filter(isKnownTransport);
}

async function tryGetVerifiedPendingEnrollment(
    req: express.Request,
): Promise<VerifiedPendingResult> {
    const parsed = pollPendingApprovalSchema.safeParse(req.body);
    if (!parsed.success) {
        return {
            error: "Invalid poll payload",
            issues: parsed.error.issues,
            ok: false,
            status: 400,
        };
    }
    return tryGetVerifiedPendingEnrollmentForSigned(req, parsed.data.signed);
}

async function tryGetVerifiedPendingEnrollmentForSigned(
    req: express.Request,
    signed: string,
): Promise<VerifiedPendingResult> {
    const requestID = getParam(req, "requestID");
    const pending = deviceEnrollments.get(requestID);
    if (!pending) {
        return { error: "Not found.", ok: false, status: 404 };
    }
    const opened = await spireXSignOpenAsync(
        XUtils.decodeHex(signed),
        XUtils.decodeHex(pending.devicePayload.signKey),
    );
    if (!opened) {
        return { error: "Poll signature invalid.", ok: false, status: 401 };
    }
    const expected = XUtils.decodeHex(pending.challengeHex);
    if (!XUtils.bytesEqual(opened, expected)) {
        return { error: "Poll challenge mismatch.", ok: false, status: 401 };
    }
    return { ok: true, pending };
}

export const getUserRouter = (
    db: Database,
    tokenValidator: (key: string, scope: TokenScopes) => boolean,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void,
    disconnectDevices?: (deviceIDs: string[]) => void,
    federation?: FederationService,
) => {
    const router = express.Router();

    // Unauthenticated status poll for the *requesting* device on a pending
    // device-enrollment request. The new device cannot use the protected
    // `/:id/devices/requests/:requestID` endpoint because it has no token
    // until an existing device approves it. To prove possession of the
    // private signing key for the request, the device signs the random
    // challenge issued in the 202 register response with its secret key,
    // and we open it with the pending request's stored public signKey.
    //
    // This is registered before any `/:id/...` route so Express matches the
    // literal `/devices/requests/:requestID/poll` segment before the
    // `:id` placeholder.
    router.post("/devices/requests/:requestID/poll", async (req, res) => {
        pruneDeviceEnrollmentRequests();
        const v = await tryGetVerifiedPendingEnrollment(req);
        if (!v.ok) {
            if (v.status === 400) {
                res.status(400).json({
                    error: v.error,
                    ...(v.issues !== undefined ? { issues: v.issues } : {}),
                });
                return;
            }
            if (v.status === 404) {
                res.sendStatus(404);
                return;
            }
            res.status(v.status).send({ error: v.error });
            return;
        }
        res.send(msgpack.encode(requestSummary(v.pending)));
    });

    router.post(
        "/devices/requests/:requestID/passkeys/register/begin",
        async (req, res) => {
            pruneDeviceEnrollmentRequests();
            const parsed = pendingPasskeyRegistrationStartSchema.safeParse(
                req.body,
            );
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid registration payload",
                    issues: parsed.error.issues,
                });
                return;
            }
            const v = await tryGetVerifiedPendingEnrollmentForSigned(
                req,
                parsed.data.signed,
            );
            if (!v.ok) {
                if (v.status === 404) {
                    res.sendStatus(404);
                    return;
                }
                res.status(v.status).send({ error: v.error });
                return;
            }
            const { pending } = v;
            if (
                pending.status !== "approved" ||
                pending.approvedDeviceID === undefined
            ) {
                res.status(409).send({
                    error: "Device approval must complete before passkey setup.",
                });
                return;
            }
            const user = await db.retrieveUser(pending.userID);
            if (!user) {
                res.sendStatus(404);
                return;
            }
            const existing = await db.retrievePasskeysByUser(pending.userID);
            if (existing.length >= MAX_PASSKEYS_PER_USER) {
                res.status(409).send({
                    error: `Each account is limited to ${MAX_PASSKEYS_PER_USER} passkeys.`,
                });
                return;
            }

            const { rpID, rpName } = getRpConfig();
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
                userDisplayName: user.username,
                userID: new TextEncoder().encode(pending.userID),
                userName: user.username,
            });

            pending.passkeyRegistration = {
                challenge: options.challenge,
                createdAt: Date.now(),
                name: parsed.data.name,
            };
            deviceEnrollments.set(pending.requestID, pending);
            res.send(
                msgpack.encode({
                    options,
                    requestID: pending.requestID,
                }),
            );
        },
    );

    router.post(
        "/devices/requests/:requestID/passkeys/register/finish",
        async (req, res) => {
            pruneDeviceEnrollmentRequests();
            const parsed = pendingPasskeyRegistrationFinishSchema.safeParse(
                req.body,
            );
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid finish payload",
                    issues: parsed.error.issues,
                });
                return;
            }
            const requestID = getParam(req, "requestID");
            if (parsed.data.requestID !== requestID) {
                res.status(400).send({ error: "Request ID mismatch." });
                return;
            }
            const v = await tryGetVerifiedPendingEnrollmentForSigned(
                req,
                parsed.data.signed,
            );
            if (!v.ok) {
                if (v.status === 404) {
                    res.sendStatus(404);
                    return;
                }
                res.status(v.status).send({ error: v.error });
                return;
            }
            const { pending } = v;
            if (
                pending.status !== "approved" ||
                pending.approvedDeviceID === undefined
            ) {
                res.status(409).send({
                    error: "Device approval must complete before passkey setup.",
                });
                return;
            }
            const passkeyRegistration = pending.passkeyRegistration;
            if (!passkeyRegistration) {
                res.status(404).send({
                    error: "Passkey registration request not found or expired.",
                });
                return;
            }
            if (
                Date.now() - passkeyRegistration.createdAt >
                PASSKEY_REGISTRATION_TTL_MS
            ) {
                delete pending.passkeyRegistration;
                deviceEnrollments.set(pending.requestID, pending);
                res.status(410).send({
                    error: "Passkey registration request expired.",
                });
                return;
            }
            delete pending.passkeyRegistration;
            deviceEnrollments.set(pending.requestID, pending);

            const { expectedOrigin, rpID } = getRpConfig();
            let verification;
            try {
                verification = await verifyRegistrationResponse({
                    expectedChallenge: passkeyRegistration.challenge,
                    expectedOrigin,
                    expectedRPID: rpID,
                    requireUserVerification: true,
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- structurally validated by simplewebauthn below
                    response: parsed.data
                        .response as unknown as RegistrationResponseJSON,
                });
            } catch (err: unknown) {
                const requestId = crypto.randomUUID();
                const message =
                    err instanceof Error ? err.message : String(err);
                console.warn(
                    `[spire] pending-device WebAuthn registration failed requestId=${requestId} message=${message}`,
                );
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
            const existing = await db.retrievePasskeysByUser(pending.userID);
            if (existing.length >= MAX_PASSKEYS_PER_USER) {
                res.status(409).send({
                    error: `Each account is limited to ${MAX_PASSKEYS_PER_USER} passkeys.`,
                });
                return;
            }
            const created = await db.createPasskey(
                pending.userID,
                passkeyRegistration.name,
                credential.id,
                XUtils.encodeHex(credential.publicKey),
                0,
                sanitizeTransports(credential.transports ?? []),
            );
            res.send(msgpack.encode(created));
        },
    );

    /**
     * After the new device confirms "this account is mine" locally, call
     * this so existing signed-in devices receive the pending request
     * notification. Until then, the enrollment row exists for poll/abort
     * only — no owner push is sent.
     */
    router.post("/devices/requests/:requestID/publish", async (req, res) => {
        pruneDeviceEnrollmentRequests();
        const v = await tryGetVerifiedPendingEnrollment(req);
        if (!v.ok) {
            if (v.status === 400) {
                res.status(400).json({
                    error: v.error,
                    ...(v.issues !== undefined ? { issues: v.issues } : {}),
                });
                return;
            }
            if (v.status === 404) {
                res.sendStatus(404);
                return;
            }
            res.status(v.status).send({ error: v.error });
            return;
        }
        const { pending } = v;
        if (pending.ownerNotified !== false) {
            res.sendStatus(204);
            return;
        }
        notify(pending.userID, "deviceRequest", crypto.randomUUID(), {
            requestID: pending.requestID,
            status: "pending",
        });
        pending.ownerNotified = true;
        deviceEnrollments.set(pending.requestID, pending);
        res.sendStatus(200);
    });

    /** Drop an unpublished enrollment before any owner notification fires. */
    router.post("/devices/requests/:requestID/abort", async (req, res) => {
        pruneDeviceEnrollmentRequests();
        const v = await tryGetVerifiedPendingEnrollment(req);
        if (!v.ok) {
            if (v.status === 400) {
                res.status(400).json({
                    error: v.error,
                    ...(v.issues !== undefined ? { issues: v.issues } : {}),
                });
                return;
            }
            if (v.status === 404) {
                res.sendStatus(404);
                return;
            }
            res.status(v.status).send({ error: v.error });
            return;
        }
        const { pending } = v;
        if (pending.ownerNotified !== false) {
            res.status(409).send({
                error: "This request was already sent to your other devices.",
            });
            return;
        }
        deviceEnrollments.delete(pending.requestID);
        res.sendStatus(200);
    });

    router.get("/:id", protect, async (req, res) => {
        try {
            const id = getParam(req, "id");
            if (federation) {
                const user = (await federation.resolveAccount(id))?.user;
                return user
                    ? res.send(msgpack.encode(user))
                    : res.sendStatus(404);
            }
            const user = await db.retrieveUser(id);
            return user
                ? res.send(msgpack.encode(censorUser(user)))
                : res.sendStatus(404);
        } catch (error: unknown) {
            return sendFederationError(res, error);
        }
    });

    router.get("/:id/devices", protect, async (req, res) => {
        const id = getParam(req, "id");
        try {
            const authenticatedUser = getUser(req);
            if (id === authenticatedUser.userID) {
                const deviceList = await db.retrieveUserDeviceList([id]);
                return res.send(msgpack.encode(deviceList));
            }
            if (federation) {
                const devices = await federation.resolveDevices(id);
                if (!devices) return res.sendStatus(404);
                return res.send(msgpack.encode(devices.map(publicPeerDevice)));
            }
            const user = await db.retrieveUser(id);
            if (!user) {
                return res.sendStatus(404);
            }
            const deviceList = await db.retrieveUserDeviceList([id]);
            return res.send(msgpack.encode(deviceList.map(publicPeerDevice)));
        } catch (error: unknown) {
            return sendFederationError(res, error);
        }
    });

    router.get("/:id/permissions", protect, async (req, res) => {
        const userDetails = getUser(req);
        if (getParam(req, "id") !== userDetails.userID) {
            res.sendStatus(403);
            return;
        }
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "all",
        );
        res.send(msgpack.encode(permissions));
    });

    router.get("/:id/servers", protect, async (req, res) => {
        const userDetails = getUser(req);
        if (getParam(req, "id") !== userDetails.userID) {
            res.sendStatus(403);
            return;
        }
        const servers = await db.retrieveServers(userDetails.userID);
        res.send(msgpack.encode(servers));
    });

    router.get("/:id/servers/bootstrap", protect, async (req, res) => {
        const userDetails = getUser(req);
        if (getParam(req, "id") !== userDetails.userID) {
            res.sendStatus(403);
            return;
        }
        const payload = await db.retrieveServerChannelBootstrap(
            userDetails.userID,
        );
        res.send(msgpack.encode(payload));
    });

    router.delete("/:userID/devices/:deviceID", protect, async (req, res) => {
        const device = await db.retrieveDevice(getParam(req, "deviceID"));

        if (!device) {
            res.sendStatus(404);
            return;
        }
        const userDetails = getUser(req);
        const currentDevice = req.device;
        if (
            getParam(req, "userID") !== userDetails.userID ||
            userDetails.userID !== device.owner ||
            !currentDevice ||
            currentDevice.owner !== userDetails.userID
        ) {
            res.sendStatus(403);
            return;
        }
        const deviceList = await db.retrieveUserDeviceList([
            userDetails.userID,
        ]);
        if (deviceList.length === 1) {
            res.status(400).send({
                error: "You can't delete your last device.",
            });
            return;
        }

        await db.deleteDevice(device.deviceID);
        disconnectDevices?.([device.deviceID]);
        res.sendStatus(200);
    });

    router.post("/:id/devices", protect, async (req, res) => {
        pruneDeviceEnrollmentRequests();
        const userDetails = getUser(req);
        const parsed = DevicePayloadSchema.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid device payload",
                issues: parsed.error.issues,
            });
            return;
        }
        const deviceData = parsed.data;

        const token = await spireXSignOpenAsync(
            XUtils.decodeHex(deviceData.signed),
            XUtils.decodeHex(deviceData.signKey),
        );

        if (!token) {
            res.sendStatus(400);
            return;
        }

        if (userDetails.userID !== getParam(req, "id")) {
            res.sendStatus(401);
            return;
        }

        const existingBySignKey = await db.retrieveDevice(deviceData.signKey);
        if (existingBySignKey) {
            res.sendStatus(470);
            return;
        }

        if (tokenValidator(stringify(token), TokenScopes.Device)) {
            if (!(await verifyDevicePayloadPreKeySignature(deviceData))) {
                res.status(400).send({
                    error: "Signed prekey signature is invalid.",
                });
                return;
            }
            const userDevices = await db.retrieveUserDeviceList([
                userDetails.userID,
            ]);
            if (userDevices.length >= MAX_ACTIVE_DEVICES_PER_USER) {
                res.status(409).send({
                    error: `Each account is limited to ${String(MAX_ACTIVE_DEVICES_PER_USER)} active devices. Remove an old device before adding another.`,
                });
                return;
            }
            if (userDevices.length === 0) {
                try {
                    const device = await db.createDevice(
                        userDetails.userID,
                        deviceData,
                    );
                    res.send(msgpack.encode(device));
                    return;
                } catch (_err: unknown) {
                    // signkey already taken
                    res.sendStatus(470);
                    return;
                }
            }

            let requesterPasskeyID: string | undefined;
            if (req.passkey?.passkeyID) {
                const passkey = await db.retrievePasskeyInternal(
                    req.passkey.passkeyID,
                );
                if (!passkey || passkey.userID !== userDetails.userID) {
                    res.status(403).send({
                        error: "Passkey verification does not match this account.",
                    });
                    return;
                }
                requesterPasskeyID = req.passkey.passkeyID;
            }

            const pendingResponse = createPendingDeviceEnrollmentRequest(
                userDetails.userID,
                deviceData,
                notify,
                requesterPasskeyID ? { requesterPasskeyID } : undefined,
            );
            res.status(202).send(msgpack.encode(pendingResponse));
        } else {
            res.sendStatus(401);
        }
    });

    router.get("/:id/devices/requests", protect, (req, res) => {
        pruneDeviceEnrollmentRequests();
        const userDetails = getUser(req);
        const userID = getParam(req, "id");
        if (userDetails.userID !== userID) {
            res.sendStatus(401);
            return;
        }
        const requests: ReturnType<typeof requestSummary>[] = [];
        for (const reqItem of deviceEnrollments.values()) {
            if (reqItem.userID === userID) {
                requests.push(requestSummary(reqItem));
            }
        }
        requests.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        res.send(msgpack.encode(requests));
    });

    router.get("/:id/devices/requests/:requestID", protect, (req, res) => {
        pruneDeviceEnrollmentRequests();
        const userDetails = getUser(req);
        const userID = getParam(req, "id");
        if (userDetails.userID !== userID) {
            res.sendStatus(401);
            return;
        }
        const requestID = getParam(req, "requestID");
        const pending = deviceEnrollments.get(requestID);
        if (!pending || pending.userID !== userID) {
            res.sendStatus(404);
            return;
        }
        res.send(msgpack.encode(requestSummary(pending)));
    });

    router.post(
        "/:id/devices/requests/:requestID/approve",
        protect,
        async (req, res) => {
            pruneDeviceEnrollmentRequests();
            const userDetails = getUser(req);
            const userID = getParam(req, "id");
            if (userDetails.userID !== userID) {
                res.sendStatus(401);
                return;
            }
            const approverDevice = req.device;
            if (!approverDevice || approverDevice.owner !== userID) {
                res.status(401).send({
                    error: "Approve requires an authenticated existing device.",
                });
                return;
            }

            const parsedApprove = approvePayloadSchema.safeParse(req.body);
            if (!parsedApprove.success) {
                res.status(400).json({
                    error: "Invalid approval payload",
                    issues: parsedApprove.error.issues,
                });
                return;
            }

            const requestID = getParam(req, "requestID");
            const pending = deviceEnrollments.get(requestID);
            if (!pending || pending.userID !== userID) {
                res.sendStatus(404);
                return;
            }
            if (pending.status !== "pending") {
                res.status(409).send({ error: "Request is not pending." });
                return;
            }
            if (Date.now() - pending.createdAt > DEVICE_REQUEST_TTL_MS) {
                pending.status = "expired";
                pending.resolvedAt = Date.now();
                pending.error = "Request expired.";
                deviceEnrollments.set(requestID, pending);
                res.status(410).send({ error: "Request expired." });
                return;
            }

            if (approverDevice.signKey === pending.devicePayload.signKey) {
                res.status(400).send({
                    error: "Cannot self-approve with the requesting device key.",
                });
                return;
            }

            const approvedByPasskeyID = pending.requesterPasskeyID;
            if (approvedByPasskeyID) {
                const passkey =
                    await db.retrievePasskeyInternal(approvedByPasskeyID);
                if (!passkey || passkey.userID !== userID) {
                    res.status(403).send({
                        error: "Passkey verification does not match this account.",
                    });
                    return;
                }
            }

            const opened = await spireXSignOpenAsync(
                XUtils.decodeHex(parsedApprove.data.signed),
                XUtils.decodeHex(approverDevice.signKey),
            );
            if (!opened) {
                res.status(401).send({ error: "Approval signature invalid." });
                return;
            }

            const expected = buildApprovalChallenge(
                requestID,
                pending.devicePayload.signKey,
            );
            if (!XUtils.bytesEqual(opened, expected)) {
                res.status(401).send({ error: "Approval challenge mismatch." });
                return;
            }

            try {
                const device = await db.createDevice(
                    userID,
                    pending.devicePayload,
                    approvedByPasskeyID
                        ? {
                              approvedByDeviceID: approverDevice.deviceID,
                              approvedByPasskeyID,
                          }
                        : undefined,
                );
                pending.status = "approved";
                pending.approvedDeviceID = device.deviceID;
                pending.resolvedAt = Date.now();
                deviceEnrollments.set(requestID, pending);
                notify(userID, "deviceRequest", crypto.randomUUID(), {
                    requestID,
                    status: "approved",
                });
                res.send(msgpack.encode(device));
                return;
            } catch {
                pending.status = "rejected";
                pending.error = "Could not create approved device.";
                pending.resolvedAt = Date.now();
                deviceEnrollments.set(requestID, pending);
                notify(userID, "deviceRequest", crypto.randomUUID(), {
                    requestID,
                    status: "rejected",
                });
                res.sendStatus(470);
                return;
            }
        },
    );

    router.post(
        "/:id/devices/requests/:requestID/reject",
        protect,
        (req, res) => {
            pruneDeviceEnrollmentRequests();
            const userDetails = getUser(req);
            const userID = getParam(req, "id");
            if (userDetails.userID !== userID) {
                res.sendStatus(401);
                return;
            }
            const approverDevice = req.device;
            if (!approverDevice || approverDevice.owner !== userID) {
                res.status(401).send({
                    error: "Reject requires an authenticated existing device.",
                });
                return;
            }

            const requestID = getParam(req, "requestID");
            const pending = deviceEnrollments.get(requestID);
            if (!pending || pending.userID !== userID) {
                res.sendStatus(404);
                return;
            }
            if (pending.status !== "pending") {
                res.status(409).send({ error: "Request is not pending." });
                return;
            }

            pending.status = "rejected";
            pending.resolvedAt = Date.now();
            pending.error = "Rejected by existing device.";
            deviceEnrollments.set(requestID, pending);
            notify(userID, "deviceRequest", crypto.randomUUID(), {
                requestID,
                status: "rejected",
            });
            res.sendStatus(200);
        },
    );

    return router;
};

function sendFederationError(
    response: express.Response,
    error: unknown,
): express.Response {
    const status = error instanceof FederationServiceError ? error.status : 502;
    const message =
        error instanceof FederationServiceError
            ? error.message
            : "The authoritative homeserver could not be reached.";
    return response.status(status).json({ error: message });
}

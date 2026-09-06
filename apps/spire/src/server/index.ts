/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database } from "../Database.ts";
import type { Device, Emoji } from "@vex-chat/types";

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";

import express from "express";

import { type KeyPair, XUtils } from "@vex-chat/crypto";
import {
    MAX_FILE_UPLOAD_ENCODED_BODY_BYTES,
    PreKeysWSSchema,
    TokenScopes,
    UserSchema,
} from "@vex-chat/types";

import cors from "cors";
import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import helmet from "helmet";
import multer from "multer";
import parseDuration from "parse-duration";
import { stringify as uuidStringify } from "uuid";
import { z } from "zod/v4";

import { POWER_LEVELS } from "../ClientManager.ts";
import { JWT_EXPIRY } from "../Spire.ts";
import { signAuthJwt, verifyAuthJwt } from "../utils/authJwt.ts";
import { msgpack } from "../utils/msgpack.ts";
import { verifyPreKeyWsSignature } from "../utils/preKeySignature.ts";
import { spireXSignOpenAsync } from "../utils/spireXSignOpenAsync.ts";

import { getAvatarRouter } from "./avatar.ts";
import { getBillingRouter } from "./billing.ts";
import { getCliPasskeyPageRouter } from "./cliPasskeyPage.ts";
import { getEntitlementRouter } from "./entitlements.ts";
import { errorHandler } from "./errors.ts";
import { getFileRouter } from "./file.ts";
import { getInviteRouter } from "./invite.ts";
import { setupDocs } from "./openapi.ts";
import { getPasskeyRouter } from "./passkey.ts";
import { getPasskeyDeviceRouter } from "./passkeyDevices.ts";
import { getPasswordRouter } from "./password.ts";
import {
    canDeletePermission,
    hasAnyPermission,
    hasPermission,
    userHasPermission,
} from "./permissions.ts";
import { globalLimiter, keyBundleLimiter, uploadLimiter } from "./rateLimit.ts";
import { deleteServerIconFile, getServerIconRouter } from "./serverIcon.ts";
import { getUserRouter } from "./user.ts";
import { censorUser, getParam, getUser } from "./utils.ts";
import { getWellKnownRouter } from "./wellKnown.ts";

// expiry of regkeys
export const EXPIRY_TIME = 1000 * 60 * 5;

export const ALLOWED_IMAGE_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/apng",
    "image/avif",
    "image/webp",
];

// ── Zod schemas for trust-boundary validation ──────────────────────────
const invitePayload = z.object({
    duration: z.string().min(1).max(32),
    serverID: z.string().min(1).max(128),
});

const channelPayload = z.object({
    name: z.string().trim().min(1).max(100),
});

const serverUpdatePayload = z.object({
    name: z.string().trim().min(1).max(100),
});

const permissionRolePayload = z.object({
    powerLevel: z.union([z.literal(0), z.literal(50), z.literal(100)]),
});

const deviceListPayload = z.array(z.string().min(1).max(128)).max(256);

const connectPayload = z.object({
    signed: z.custom<Uint8Array>(
        (val) => val instanceof Uint8Array && val.byteLength <= 16_384,
    ),
});

const safePathParam = z.string().regex(/^[a-zA-Z0-9._-]+$/);

const emojiPayload = z.object({
    file: z.string().max(350_000).optional(),
    name: z.string().trim().min(1).max(64),
    signed: z.string().max(8192).optional(),
});
const emojiUpload = multer({
    limits: { fields: 3, files: 1, fileSize: 256_000, parts: 4 },
});

const DEVELOPMENT_CORS_ORIGINS: Array<RegExp | string> = [
    /^https?:\/\/localhost(?::\d{1,5})?$/,
    /^https?:\/\/127\.0\.0\.1(?::\d{1,5})?$/,
    /^https?:\/\/\[::1\](?::\d{1,5})?$/,
    "capacitor://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "tauri://localhost",
];

const jwtUserPayload = z.object({
    exp: z.number().optional(),
    scope: z.literal("user"),
    user: UserSchema,
});

const jwtDevicePayload = z.object({
    device: z.object({
        deleted: z.boolean(),
        deviceID: z.string(),
        lastLogin: z.string(),
        name: z.string(),
        owner: z.string(),
        signKey: z.string(),
    }),
    scope: z.literal("device"),
});

const jwtPasskeyPayload = z.object({
    passkey: z.object({
        passkeyID: z.string(),
    }),
    scope: z.literal("passkey"),
    user: UserSchema,
});

/** Extract Bearer token from Authorization header. */
function extractBearer(req: express.Request): null | string {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return null;
    return header.slice(7);
}

const checkAuth: express.RequestHandler = (req, _res, next) => {
    const token = extractBearer(req);
    if (token) {
        try {
            const result = verifyAuthJwt(token);
            // Passkey-scoped JWTs share the bearer slot with regular
            // user JWTs but carry a `scope: "passkey"` discriminator
            // and a `passkey` claim. Populate `req.passkey` and the
            // user (so route guards using `req.user` still pass) but
            // never `req.device`. The actual privilege gate lives at
            // the route level: passkey-only routes require
            // `req.passkey`, device-only routes require `req.device`.
            const passkeyParsed = jwtPasskeyPayload.safeParse(result);
            if (passkeyParsed.success) {
                req.user = passkeyParsed.data.user;
                req.passkey = passkeyParsed.data.passkey;
                req.bearerToken = token;
            } else {
                const parsed = jwtUserPayload.safeParse(result);
                if (parsed.success) {
                    req.user = parsed.data.user;
                    if (parsed.data.exp !== undefined) {
                        req.exp = parsed.data.exp;
                    }
                    req.bearerToken = token;
                }
            }
        } catch {
            // Token verification failed — continue without auth
        }
    }
    next();
};

export function createCheckDevice(
    db: Pick<Database, "retrieveDevice">,
): express.RequestHandler {
    return async (req, _res, next) => {
        const token = req.headers["x-device-token"];
        if (typeof token === "string" && token) {
            try {
                const result = verifyAuthJwt(token);
                const parsed = jwtDevicePayload.safeParse(result);
                if (parsed.success) {
                    const device = await currentTokenDevice(
                        db,
                        parsed.data.device,
                    );
                    if (
                        device &&
                        (!req.user || device.owner === req.user.userID)
                    ) {
                        req.device = device;
                    }
                }
            } catch {
                // Device token verification/revalidation failed — continue without device.
            }
        }
        next();
    };
}

/**
 * Revalidate the credential behind a passkey-scoped bearer on every request.
 * Passkey JWTs are short-lived, but removing a credential must revoke its
 * recovery and account-administration access immediately.
 */
export function createCheckPasskey(
    db: Pick<Database, "retrievePasskeyInternal">,
): express.RequestHandler {
    return async (req, _res, next) => {
        if (req.passkey) {
            const passkey = await db.retrievePasskeyInternal(
                req.passkey.passkeyID,
            );
            if (!passkey || !req.user || passkey.userID !== req.user.userID) {
                delete req.bearerToken;
                delete req.passkey;
                delete req.user;
            }
        }
        next();
    };
}

async function currentTokenDevice(
    db: Pick<Database, "retrieveDevice">,
    tokenDevice: Device,
): Promise<Device | null> {
    const device = await db.retrieveDevice(tokenDevice.deviceID);
    if (!device || device.signKey !== tokenDevice.signKey) {
        return null;
    }
    return device;
}

export const protect: express.RequestHandler = (req, res, next) => {
    if (!req.user || req.passkey) {
        res.sendStatus(401);
        return;
    }

    next();
};

/** Require either an approved device or a fresh passkey session. */
export const protectAnyAuth: express.RequestHandler = (req, res, next) => {
    if (!req.user || (!req.device && !req.passkey)) {
        res.sendStatus(401);
        return;
    }
    next();
};

/**
 * Restrict a route to passkey-scoped JWTs (used by the parallel
 * `/user/:id/passkey/devices/...` admin/recovery routes). A
 * passkey-authenticated caller can list devices, delete devices, and
 * recover or reject pending enrollments — and nothing else.
 */
export const protectPasskey: express.RequestHandler = (req, res, next) => {
    if (!req.user || !req.passkey) {
        res.sendStatus(401);
        return;
    }

    next();
};

export const msgpackParser: express.RequestHandler = (req, res, next) => {
    if (req.is("application/msgpack")) {
        try {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument -- Express req.body is any; decoded body is validated by route-level Zod schemas
            req.body = msgpack.decode(req.body);
        } catch {
            res.sendStatus(400);
            return;
        }
    }
    next();
};

const directories = ["files", "avatars", "emoji", "server-icons"];
for (const dir of directories) {
    fs.mkdirSync(dir, { recursive: true });
}

export const initApp = (
    api: express.Application,
    db: Database,
    tokenValidator: (key: string, scope: TokenScopes) => boolean,
    signKeys: KeyPair,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void,
    disconnectDevices?: (deviceIDs: string[]) => void,
) => {
    const notifyServerChange = async (
        serverID: string,
        additionalUserIDs: readonly string[] = [],
    ): Promise<void> => {
        const affectedUsers = await db.retrieveAffectedUsers(serverID);
        const userIDs = new Set([
            ...affectedUsers.map((user) => user.userID),
            ...additionalUserIDs,
        ]);
        for (const userID of userIDs) {
            notify(userID, "serverChange", crypto.randomUUID(), serverID);
        }
    };

    // INIT ROUTERS
    const userRouter = getUserRouter(
        db,
        tokenValidator,
        notify,
        disconnectDevices,
    );
    const fileRouter = getFileRouter(db);
    const avatarRouter = getAvatarRouter();
    const billingRouter = getBillingRouter(db, notify);
    const entitlementRouter = getEntitlementRouter(db, notify);
    const inviteRouter = getInviteRouter(db, tokenValidator, notify);
    const passkeyRouter = getPasskeyRouter(db);
    const passwordRouter = getPasswordRouter(db);
    const serverIconRouter = getServerIconRouter(db, notifyServerChange);
    const passkeyDeviceRouter = getPasskeyDeviceRouter(
        db,
        notify,
        disconnectDevices,
    );

    // MIDDLEWARE

    // WebAuthn well-known association files (AASA, assetlinks.json)
    // are served BEFORE the global rate limiter so periodic platform
    // fetches by Apple / Google CDNs are never 429'd. They 404 when
    // the relevant env vars aren't set, so this is a no-op for
    // deployments that haven't enrolled an app.
    api.use(getWellKnownRouter());

    // Global per-IP rate limit is the FIRST authenticated-path
    // middleware so a flooded source hits the limiter before Express
    // spends any cycles on body parsing, helmet, or auth. See
    // src/server/rateLimit.ts.
    api.use(globalLimiter);
    // Base64 expands a 25 MiB encrypted upload to about 33.4 MiB. Give only
    // the JSON fallback route enough room for that encoded payload and its
    // JSON/msgpack envelope; unrelated routes keep the tighter global cap.
    api.use(
        "/file/json",
        express.json({ limit: MAX_FILE_UPLOAD_ENCODED_BODY_BYTES }),
        express.raw({
            limit: MAX_FILE_UPLOAD_ENCODED_BODY_BYTES,
            type: "application/msgpack",
        }),
    );
    api.use(express.json({ limit: "20mb" }));
    api.use(
        express.raw({
            limit: "20mb",
            type: "application/msgpack",
        }),
    );

    // CORS before helmet/auth so browser preflight (OPTIONS) and PATCH get
    // Access-Control-* headers. Node clients ignore CORS; browsers do not.
    // Set `CORS_ORIGINS` to a comma-separated allowlist to restrict frontends.
    const corsRaw = process.env["CORS_ORIGINS"];
    const corsOrigins = corsRaw
        ? corsRaw
              .split(",")
              .map((o) => o.trim())
              .filter((o) => o.length > 0)
        : [];
    api.use(
        cors({
            credentials: true,
            methods: [
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
            ],
            origin:
                corsOrigins.length > 0
                    ? corsOrigins
                    : process.env["NODE_ENV"] === "production"
                      ? false
                      : DEVELOPMENT_CORS_ORIGINS,
        }),
    );

    api.use(helmet());

    // Browser bridge used by the CLI to run WebAuthn ceremonies at the same
    // origin/RP ID as the API host. The token is carried in the URL fragment,
    // so Spire never receives it when serving the page.
    api.use(getCliPasskeyPageRouter());

    api.use(msgpackParser);
    api.use(checkAuth);
    api.use(createCheckPasskey(db));
    api.use(createCheckDevice(db));

    api.get("/server/:id", protect, async (req, res) => {
        const serverID = getParam(req, "id");
        const userDetails = getUser(req);
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        if (!hasAnyPermission(permissions, serverID)) {
            return res.sendStatus(403);
        }
        const server = await db.retrieveServer(serverID);

        if (server) {
            return res.send(msgpack.encode(server));
        } else {
            return res.sendStatus(404);
        }
    });

    api.patch("/server/:id", protect, async (req, res) => {
        const parsed = serverUpdatePayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid server update",
                issues: parsed.error.issues,
            });
            return;
        }

        const serverID = getParam(req, "id");
        const permissions = await db.retrievePermissions(
            getUser(req).userID,
            "server",
        );
        if (!hasPermission(permissions, serverID, POWER_LEVELS.CREATE)) {
            res.sendStatus(403);
            return;
        }

        const server = await db.updateServer(serverID, parsed.data);
        if (!server) {
            res.sendStatus(404);
            return;
        }
        await notifyServerChange(serverID);
        res.send(msgpack.encode(server));
    });

    api.post("/servers", protect, async (req, res) => {
        const parsed = serverUpdatePayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid server",
                issues: parsed.error.issues,
            });
            return;
        }

        const server = await db.createServer(
            parsed.data.name,
            getUser(req).userID,
        );
        res.send(msgpack.encode(server));
    });

    // Compatibility route for clients released before server names moved into
    // the request body. New clients use POST /servers so Unicode names work.
    api.post("/server/:name", protect, async (req, res) => {
        const userDetails = getUser(req);
        const encodedName = getParam(req, "name");
        if (encodedName.length > 256) {
            res.sendStatus(400);
            return;
        }
        let decodedName: string;
        try {
            decodedName = atob(encodedName);
        } catch {
            res.sendStatus(400);
            return;
        }
        const parsedName = z
            .string()
            .trim()
            .min(1)
            .max(100)
            .safeParse(decodedName);
        if (!parsedName.success) {
            res.sendStatus(400);
            return;
        }

        const server = await db.createServer(
            parsedName.data,
            userDetails.userID,
        );
        res.send(msgpack.encode(server));
    });

    api.post("/server/:serverID/invites", protect, async (req, res) => {
        const userDetails = getUser(req);

        const parsedPayload = invitePayload.safeParse(req.body);
        if (!parsedPayload.success) {
            res.status(400).json({
                error: "Invalid invite payload",
                issues: parsedPayload.error.issues,
            });
            return;
        }
        const payload = parsedPayload.data;
        const serverEntry = await db.retrieveServer(getParam(req, "serverID"));

        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );

        if (
            !hasPermission(
                permissions,
                getParam(req, "serverID"),
                POWER_LEVELS.INVITE,
            )
        ) {
            res.sendStatus(401);
            return;
        }

        const duration = parseDuration(payload.duration, "ms");

        if (!duration) {
            res.sendStatus(400);
            return;
        }

        const expires = new Date(Date.now() + duration);

        const invite = await db.createInvite(
            crypto.randomUUID(),
            serverEntry.serverID,
            userDetails.userID,
            expires.toString(),
        );
        res.send(msgpack.encode(invite));
    });

    api.get("/server/:serverID/invites", protect, async (req, res) => {
        const userDetails = getUser(req);

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );

        if (
            !hasPermission(
                permissions,
                getParam(req, "serverID"),
                POWER_LEVELS.INVITE,
            )
        ) {
            res.sendStatus(401);
            return;
        }

        const inviteList = await db.retrieveServerInvites(
            getParam(req, "serverID"),
        );
        res.send(msgpack.encode(inviteList));
    });

    api.delete("/server/:id", protect, async (req, res) => {
        const userDetails = getUser(req);
        const serverID = getParam(req, "id");
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        if (hasPermission(permissions, serverID, POWER_LEVELS.DELETE)) {
            const server = await db.retrieveServer(serverID);
            if (!server) {
                res.sendStatus(404);
                return;
            }
            const affectedUsers = await db.retrieveAffectedUsers(serverID);
            await db.deleteServer(serverID);
            if (server.icon) await deleteServerIconFile(server.icon);
            await notifyServerChange(
                serverID,
                affectedUsers.map((user) => user.userID),
            );
            res.sendStatus(200);
            return;
        }
        res.sendStatus(403);
    });

    api.post("/server/:id/channels", protect, async (req, res) => {
        const userDetails = getUser(req);
        const serverID = getParam(req, "id");
        // resourceID is serverID
        const parsedBody = channelPayload.safeParse(req.body);
        if (!parsedBody.success) {
            res.status(400).json({
                error: "Invalid channel payload",
                issues: parsedBody.error.issues,
            });
            return;
        }
        const { name } = parsedBody.data;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        if (hasPermission(permissions, serverID, POWER_LEVELS.CREATE)) {
            const channel = await db.createChannel(name, serverID);
            res.send(msgpack.encode(channel));
            await notifyServerChange(serverID);
            return;
        }
        res.sendStatus(403);
    });

    api.get("/server/:id/channels", protect, async (req, res) => {
        const serverID = getParam(req, "id");
        const userDetails = getUser(req);
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        if (hasAnyPermission(permissions, serverID)) {
            const channels = await db.retrieveChannels(serverID);
            res.send(msgpack.encode(channels));
            return;
        }
        res.sendStatus(401);
    });

    api.get("/server/:serverID/emoji", protect, async (req, res) => {
        const serverID = getParam(req, "serverID");
        const permissions = await db.retrievePermissions(
            getUser(req).userID,
            "server",
        );
        if (!hasAnyPermission(permissions, serverID)) {
            res.sendStatus(403);
            return;
        }
        const rows = await db.retrieveEmojiList(serverID);
        res.send(msgpack.encode(rows));
    });

    api.get("/server/:serverID/permissions", protect, async (req, res) => {
        const userDetails = getUser(req);
        const serverID = getParam(req, "serverID");
        const permissions = await db.retrievePermissionsByResourceID(serverID);
        const canSee = permissions.some(
            (perm) => perm.userID === userDetails.userID,
        );
        if (!canSee) {
            res.sendStatus(401);
            return;
        }
        res.send(msgpack.encode(permissions));
    });

    api.patch("/channel/:id", protect, async (req, res) => {
        const parsed = channelPayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid channel update",
                issues: parsed.error.issues,
            });
            return;
        }

        const channelID = getParam(req, "id");
        const channel = await db.retrieveChannel(channelID);
        if (!channel) {
            res.sendStatus(404);
            return;
        }
        const permissions = await db.retrievePermissions(
            getUser(req).userID,
            "server",
        );
        if (
            !hasPermission(permissions, channel.serverID, POWER_LEVELS.DELETE)
        ) {
            res.sendStatus(403);
            return;
        }

        const updated = await db.updateChannel(channelID, parsed.data.name);
        if (!updated) {
            res.sendStatus(404);
            return;
        }
        await notifyServerChange(channel.serverID);
        res.send(msgpack.encode(updated));
    });

    api.delete("/channel/:id", protect, async (req, res) => {
        const channelID = getParam(req, "id");
        const userDetails = getUser(req);

        const channel = await db.retrieveChannel(channelID);

        if (!channel) {
            res.sendStatus(401);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        for (const permission of permissions) {
            if (
                permission.resourceID === channel.serverID &&
                permission.powerLevel >= POWER_LEVELS.DELETE
            ) {
                const deleted = await db.deleteChannelIfNotLast(channelID);
                if (!deleted) {
                    res.status(409).json({
                        error: "A server must have at least one channel.",
                    });
                    return;
                }
                await notifyServerChange(channel.serverID);
                res.sendStatus(200);
                return;
            }
        }
        res.sendStatus(403);
    });

    api.get("/channel/:id", protect, async (req, res) => {
        const channel = await db.retrieveChannel(getParam(req, "id"));

        if (channel) {
            const permissions = await db.retrievePermissions(
                getUser(req).userID,
                "server",
            );
            if (!hasAnyPermission(permissions, channel.serverID)) {
                return res.sendStatus(403);
            }
            return res.send(msgpack.encode(channel));
        } else {
            return res.sendStatus(404);
        }
    });

    api.patch("/permission/:permissionID", protect, async (req, res) => {
        const parsed = permissionRolePayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid role",
                issues: parsed.error.issues,
            });
            return;
        }

        const target = await db.retrievePermission(
            getParam(req, "permissionID"),
        );
        if (!target) {
            res.sendStatus(404);
            return;
        }
        if (target.resourceType !== "server") {
            res.sendStatus(400);
            return;
        }

        const actor = getUser(req);
        if (target.userID === actor.userID) {
            res.status(400).json({
                error: "Use another owner to change your role.",
            });
            return;
        }
        const actorPermissions = await db.retrievePermissions(
            actor.userID,
            "server",
        );
        if (!hasPermission(actorPermissions, target.resourceID, 100)) {
            res.sendStatus(403);
            return;
        }

        const updated = await db.updatePermissionPowerLevel(
            target.permissionID,
            parsed.data.powerLevel,
        );
        if (!updated) {
            res.sendStatus(404);
            return;
        }
        await notifyServerChange(target.resourceID);
        res.send(msgpack.encode(updated));
    });

    api.delete("/permission/:permissionID", protect, async (req, res) => {
        const permissionID = getParam(req, "permissionID");
        const userDetails = getUser(req);
        const permToDelete = await db.retrievePermission(permissionID);
        if (!permToDelete) {
            res.sendStatus(404);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            permToDelete.resourceType,
        );

        if (
            canDeletePermission(
                permissions,
                userDetails.userID,
                permToDelete,
                POWER_LEVELS.DELETE,
            )
        ) {
            if (
                permToDelete.resourceType === "server" &&
                permToDelete.powerLevel >= 100
            ) {
                const resourcePermissions =
                    await db.retrievePermissionsByResourceID(
                        permToDelete.resourceID,
                    );
                const hasAnotherOwner = resourcePermissions.some(
                    (permission) =>
                        permission.permissionID !== permToDelete.permissionID &&
                        permission.powerLevel >= 100,
                );
                if (!hasAnotherOwner) {
                    res.status(409).json({
                        error: "Delete the server instead of leaving it without an owner.",
                    });
                    return;
                }
            }
            await db.deletePermission(permToDelete.permissionID);
            if (permToDelete.resourceType === "server") {
                await notifyServerChange(permToDelete.resourceID, [
                    permToDelete.userID,
                ]);
            }
            res.sendStatus(200);
            return;
        }
        res.sendStatus(403);
    });

    api.post("/userList/:channelID", protect, async (req, res) => {
        const userDetails = getUser(req);
        const channelID = getParam(req, "channelID");

        const channel = await db.retrieveChannel(channelID);
        if (!channel) {
            res.sendStatus(404);
            return;
        }
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        for (const permission of permissions) {
            if (permission.resourceID === channel.serverID) {
                const groupMembers = await db.retrieveGroupMembers(channelID);
                res.send(
                    msgpack.encode(
                        groupMembers.map((user) => censorUser(user)),
                    ),
                );
                return;
            }
        }
        res.sendStatus(401);
    });

    api.post("/deviceList", protect, async (req, res) => {
        const parsed = deviceListPayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Expected array of user ID strings",
                issues: parsed.error.issues,
            });
            return;
        }
        const devices = await db.retrieveUserDeviceList(parsed.data);
        res.send(msgpack.encode(devices));
    });

    api.get("/device/:id", protect, async (req, res) => {
        const device = await db.retrieveDevice(getParam(req, "id"));

        if (device) {
            return res.send(msgpack.encode(device));
        } else {
            return res.sendStatus(404);
        }
    });

    api.post(
        "/device/:id/keyBundle",
        protect,
        keyBundleLimiter,
        async (req, res) => {
            try {
                const keyBundle = await db.getKeyBundle(getParam(req, "id"));
                if (keyBundle) {
                    res.send(msgpack.encode(keyBundle));
                } else {
                    res.sendStatus(404);
                }
            } catch {
                res.sendStatus(500);
            }
        },
    );

    api.post("/device/:id/mail", protect, async (req, res) => {
        const deviceDetails = req.device;
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }
        if (deviceDetails.deviceID !== getParam(req, "id")) {
            res.sendStatus(403);
            return;
        }
        const inbox = await db.retrieveMail(deviceDetails.deviceID);
        res.send(msgpack.encode(inbox));
    });

    api.post("/device/:id/connect", protect, async (req, res) => {
        const parsedBody = connectPayload.safeParse(req.body);
        if (!parsedBody.success) {
            res.status(400).json({
                error: "Invalid connect payload",
                issues: parsedBody.error.issues,
            });
            return;
        }
        const { signed } = parsedBody.data;
        const device = await db.retrieveDevice(getParam(req, "id"));
        if (!device) {
            res.sendStatus(404);
            return;
        }
        if (req.user?.userID !== device.owner) {
            res.sendStatus(401);
            return;
        }
        const regKey = await spireXSignOpenAsync(
            signed,
            XUtils.decodeHex(device.signKey),
        );
        if (
            regKey &&
            tokenValidator(uuidStringify(regKey), TokenScopes.Connect)
        ) {
            const token = signAuthJwt({ device, scope: "device" }, JWT_EXPIRY);

            res.send(msgpack.encode({ deviceToken: token }));
        } else {
            res.sendStatus(401);
        }
    });

    api.get("/device/:id/otk/count", protect, async (req, res) => {
        const deviceDetails = req.device;
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }
        if (deviceDetails.deviceID !== getParam(req, "id")) {
            res.sendStatus(403);
            return;
        }
        const count = await db.getOTKCount(deviceDetails.deviceID);
        res.send(msgpack.encode({ count }));
    });

    api.post("/device/:id/prekey", protect, async (req, res) => {
        const parsedPreKey = PreKeysWSSchema.safeParse(req.body);
        if (!parsedPreKey.success) {
            res.status(400).json({
                error: "Invalid prekey payload",
                issues: parsedPreKey.error.issues,
            });
            return;
        }

        const deviceID = getParam(req, "id");
        const device = await db.retrieveDevice(deviceID);
        const deviceDetails = req.device;
        if (!device) {
            res.sendStatus(404);
            return;
        }
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }
        if (
            deviceDetails.deviceID !== deviceID ||
            req.user?.userID !== device.owner
        ) {
            res.sendStatus(401);
            return;
        }

        const preKey = parsedPreKey.data;
        if (preKey.deviceID !== deviceID) {
            res.status(400).send({ error: "Prekey deviceID mismatch." });
            return;
        }
        if (
            !(await verifyPreKeyWsSignature(preKey, device.signKey, "signed"))
        ) {
            res.status(401).send({ error: "Prekey signature invalid." });
            return;
        }

        await db.replacePreKey(device.owner, deviceID, preKey);
        res.sendStatus(200);
    });

    api.post("/device/:id/otk", protect, async (req, res) => {
        const parsedOTKs = z.array(PreKeysWSSchema).safeParse(req.body);
        if (!parsedOTKs.success) {
            res.status(400).json({
                error: "Invalid OTK payload",
                issues: parsedOTKs.error.issues,
            });
            return;
        }
        const submittedOTKs = parsedOTKs.data;
        if (submittedOTKs.length === 0) {
            res.sendStatus(200);
            return;
        }

        const userDetails = getUser(req);
        const deviceDetails = req.device;

        const deviceID = getParam(req, "id");
        const otk = submittedOTKs[0];

        const device = await db.retrieveDevice(deviceID);
        if (!device || !otk) {
            res.sendStatus(404);
            return;
        }
        if (
            !deviceDetails ||
            deviceDetails.deviceID !== deviceID ||
            userDetails.userID !== device.owner
        ) {
            res.sendStatus(401);
            return;
        }
        for (const submittedOTK of submittedOTKs) {
            if (submittedOTK.deviceID !== deviceID) {
                res.status(400).send({ error: "OTK deviceID mismatch." });
                return;
            }
            if (
                !(await verifyPreKeyWsSignature(
                    submittedOTK,
                    device.signKey,
                    "one-time",
                ))
            ) {
                res.status(401).send({ error: "OTK signature invalid." });
                return;
            }
        }

        await db.saveOTK(userDetails.userID, deviceID, submittedOTKs);
        res.sendStatus(200);
    });

    api.get("/emoji/:emojiID/details", protect, async (req, res) => {
        const emoji = await db.retrieveEmoji(getParam(req, "emojiID"));
        if (!emoji) {
            res.sendStatus(404);
            return;
        }
        const permissions = await db.retrievePermissions(
            getUser(req).userID,
            "server",
        );
        if (!hasAnyPermission(permissions, emoji.owner)) {
            res.sendStatus(403);
            return;
        }
        res.send(msgpack.encode(emoji));
    });

    api.get("/emoji/:emojiID", protect, async (req, res) => {
        const safeId = safePathParam.safeParse(getParam(req, "emojiID"));
        if (!safeId.success) {
            res.sendStatus(400);
            return;
        }
        const emoji = await db.retrieveEmoji(safeId.data);
        if (!emoji) {
            res.sendStatus(404);
            return;
        }
        const permissions = await db.retrievePermissions(
            getUser(req).userID,
            "server",
        );
        if (!hasAnyPermission(permissions, emoji.owner)) {
            res.sendStatus(403);
            return;
        }
        const filePath = "./emoji/" + safeId.data;
        const typeDetails = await fileTypeFromFile(filePath).catch(() => null);
        if (!typeDetails) {
            res.sendStatus(404);
            return;
        }
        res.set("Content-type", typeDetails.mime);
        res.set("Cache-control", "public, max-age=31536000");

        const stream = fs.createReadStream(filePath);
        stream.on("error", (_err) => {
            // debugger: emoji stream read error
            res.sendStatus(500);
        });
        stream.pipe(res);
    });

    api.post(
        "/emoji/:serverID/json",
        uploadLimiter,
        protect,
        async (req, res) => {
            const parsedPayload = emojiPayload.safeParse(req.body);
            if (!parsedPayload.success) {
                res.status(400).json({
                    error: "Invalid emoji payload",
                    issues: parsedPayload.error.issues,
                });
                return;
            }
            const payload = parsedPayload.data;

            const userDetails = getUser(req);
            const device = req.device;

            if (!device) {
                res.sendStatus(401);
                return;
            }

            if (!payload.file) {
                res.sendStatus(400);
                return;
            }

            let buf: Buffer;
            try {
                buf = Buffer.from(XUtils.decodeBase64(payload.file));
            } catch {
                res.status(400).send({ error: "Emoji must be valid base64." });
                return;
            }
            const serverEntry = await db.retrieveServer(
                getParam(req, "serverID"),
            );

            const permissionList = await db.retrievePermissionsByResourceID(
                getParam(req, "serverID"),
            );

            if (
                !userHasPermission(
                    permissionList,
                    userDetails.userID,
                    POWER_LEVELS.EMOJI,
                )
            ) {
                res.sendStatus(401);
                return;
            }
            if (!serverEntry) {
                res.sendStatus(404);
                return;
            }
            if (!payload.name) {
                res.sendStatus(400);
                return;
            }
            if (Buffer.byteLength(buf) > 256000) {
                res.sendStatus(413);
                return;
            }

            const mimeType = await fileTypeFromBuffer(buf);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                        String(mimeType?.ext),
                });
                return;
            }

            const emoji: Emoji = {
                emojiID: crypto.randomUUID(),
                name: payload.name,
                owner: getParam(req, "serverID"),
            };

            await db.createEmoji(emoji);

            try {
                // write the file to disk
                await fsp.writeFile("emoji/" + emoji.emojiID, buf);
                res.send(msgpack.encode(emoji));
            } catch (_err: unknown) {
                // debugger: emoji write failed
                res.sendStatus(500);
            }
        },
    );

    api.post(
        "/emoji/:serverID",
        uploadLimiter,
        protect,
        emojiUpload.single("emoji"),
        async (req, res) => {
            const parsedPayload = emojiPayload.safeParse(req.body);
            if (!parsedPayload.success) {
                res.status(400).json({
                    error: "Invalid emoji payload",
                    issues: parsedPayload.error.issues,
                });
                return;
            }
            const payload = parsedPayload.data;
            const serverID = getParam(req, "serverID");
            if (typeof serverID !== "string") {
                res.sendStatus(400);
                return;
            }
            const serverEntry = await db.retrieveServer(serverID);
            const userDetails = getUser(req);
            const deviceDetails = req.device;
            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }

            const permissionList =
                await db.retrievePermissionsByResourceID(serverID);

            if (
                !userHasPermission(
                    permissionList,
                    userDetails.userID,
                    POWER_LEVELS.EMOJI,
                )
            ) {
                res.sendStatus(401);
                return;
            }

            if (!serverEntry) {
                res.sendStatus(404);
                return;
            }

            if (!payload.name) {
                res.sendStatus(400);
                return;
            }

            if (!req.file) {
                res.sendStatus(400);
                return;
            }

            if (Buffer.byteLength(req.file.buffer) > 256000) {
                res.sendStatus(413);
                return;
            }

            const mimeType = await fileTypeFromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                        String(mimeType?.ext),
                });
                return;
            }

            const emoji: Emoji = {
                emojiID: crypto.randomUUID(),
                name: payload.name,
                owner: serverID,
            };

            await db.createEmoji(emoji);

            try {
                // write the file to disk
                await fsp.writeFile("emoji/" + emoji.emojiID, req.file.buffer);
                res.send(msgpack.encode(emoji));
            } catch (_err: unknown) {
                // debugger: emoji write failed
                res.sendStatus(500);
            }
        },
    );

    // COMPLEX RESOURCES
    // Passkey routes are mounted at the root since they live under
    // both `/user/:id/passkeys/...` (registration / list / delete by
    // an authenticated device) and `/auth/passkey/...` (public
    // sign-in). The router itself defines the full path on each
    // route handler.
    api.use(billingRouter);
    api.use(entitlementRouter);
    api.use(passkeyRouter);
    api.use(passkeyDeviceRouter);
    api.use(passwordRouter);

    api.use("/user", userRouter);

    api.use("/file", fileRouter);

    api.use("/avatar", avatarRouter);

    api.use("/server-icon", serverIconRouter);

    api.use("/invite", inviteRouter);

    setupDocs(api);

    // Central error handler MUST be last. Handles both thrown AppErrors
    // (client-safe status + message) and programmer errors (generic 500
    // with full details logged server-side). See src/server/errors.ts
    // for the CWE mapping.
    api.use(errorHandler());
};

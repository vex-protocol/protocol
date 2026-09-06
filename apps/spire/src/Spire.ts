/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type {
    ActionToken,
    BaseMsg,
    Device,
    MailWS,
    User,
} from "@vex-chat/types";
import type { IncomingMessage, Server } from "http";

import { EventEmitter } from "events";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import { freemem, loadavg, totalmem } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import {
    type KeyPair,
    xRandomBytes,
    xSignKeyPairFromSecret,
} from "@vex-chat/crypto";
import {
    ACCOUNT_PASSWORD_MAX_LENGTH,
    MailWSSchema,
    RegistrationPayloadSchema,
    TokenScopes,
    UserSchema,
} from "@vex-chat/types";

import morgan from "morgan";
import { stringify as uuidStringify } from "uuid";
import { WebSocketServer } from "ws";
import { z } from "zod/v4";

import { CallManager } from "./CallManager.ts";
import { ClientManager, MAX_CLIENT_MESSAGE_BYTES } from "./ClientManager.ts";
import {
    Database,
    hashPasswordArgon2,
    MAX_ACTIVE_DEVICES_PER_USER,
    validateAccountPassword,
    verifyPassword,
} from "./Database.ts";
import { resolveIceServersFromEnv } from "./IceServers.ts";
import { NotificationService } from "./NotificationService.ts";
import { initApp, protect } from "./server/index.ts";
import {
    MailIngressValidationError,
    validateMailIngress,
} from "./server/mailIngress.ts";
import {
    accountAuthLimiter,
    authLimiter,
    devApiKeySkipsRateLimits,
} from "./server/rateLimit.ts";
import { createPendingDeviceEnrollmentRequest } from "./server/user.ts";
import { censorUser, getParam, getUser } from "./server/utils.ts";
import { resolveSpireListenPort } from "./spireListenPort.ts";
import { signAuthJwt, verifyAuthJwt } from "./utils/authJwt.ts";
import { msgpack } from "./utils/msgpack.ts";
import { verifyDevicePayloadPreKeySignature } from "./utils/preKeySignature.ts";
import { spireXSignOpenAsync } from "./utils/spireXSignOpenAsync.ts";

// One-use action tokens expire after ten minutes.
export const TOKEN_EXPIRY = 1000 * 60 * 10;
export const JWT_EXPIRY = "1h";
export const DEVICE_AUTH_JWT_EXPIRY = "1h";
/**
 * Passkey-scoped JWTs grant destructive admin powers (delete a
 * device, recover a device enrollment) without further user
 * verification, so they expire fast — the user re-does the
 * WebAuthn ceremony on each session.
 */
export const JWT_EXPIRY_PASSKEY = "5m";
const DEVICE_CHALLENGE_EXPIRY = 1000 * 60; // 60 seconds

// 3-19 chars long
const usernameRegex = /^(\w{3,19})$/;
const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── Zod schemas for trust-boundary validation ──────────────────────────
const wsAuthMsg = z.object({
    token: z.string().min(1),
    type: z.literal("auth"),
});

const jwtPayload = z.object({
    bearerToken: z.string().optional(),
    exp: z.number().optional(),
    scope: z.literal("user"),
    user: UserSchema,
});

const authPayload = z.object({
    password: z.string().min(1).max(ACCOUNT_PASSWORD_MAX_LENGTH),
    username: z.string().trim().min(3).max(19).regex(usernameRegex),
});

const boundedRegistrationPayload = z.object({
    deviceName: z.string().trim().min(1).max(100),
    intent: z.enum(["create-account", "enroll-device"]),
    password: z.string().max(ACCOUNT_PASSWORD_MAX_LENGTH).optional(),
    preKey: z
        .string()
        .min(2)
        .max(8192)
        .regex(/^(?:[0-9a-fA-F]{2})+$/),
    preKeyIndex: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    preKeySignature: z
        .string()
        .min(2)
        .max(16_384)
        .regex(/^(?:[0-9a-fA-F]{2})+$/),
    signed: z
        .string()
        .min(2)
        .max(8192)
        .regex(/^(?:[0-9a-fA-F]{2})+$/),
    signKey: z
        .string()
        .min(2)
        .max(8192)
        .regex(/^(?:[0-9a-fA-F]{2})+$/),
    username: z.string().trim().min(3).max(19).regex(usernameRegex).optional(),
});

const deviceAuthPayload = z.object({
    deviceID: z.string().regex(uuidRegex),
    signKey: z
        .string()
        .min(64)
        .max(8192)
        .regex(/^(?:[0-9a-fA-F]{2})+$/),
});

const deviceVerifyPayload = z.object({
    challengeID: z.string().regex(uuidRegex),
    signed: z
        .string()
        .min(2)
        .max(16_384)
        .regex(/^(?:[0-9a-fA-F]{2})+$/),
});

const mailPostPayload = z.object({
    header: z.custom<Uint8Array>(
        (val) => val instanceof Uint8Array && val.byteLength === 32,
    ),
    mail: MailWSSchema,
});
const MAIL_BATCH_MAX_ITEMS = 256;
const mailBatchPostPayload = z.object({
    mails: z.array(mailPostPayload).min(1).max(MAIL_BATCH_MAX_ITEMS),
});

interface MailBatchResult {
    error?: string;
    index: number;
    mailID?: string;
    ok: boolean;
    recipient?: string;
    status?: number;
}

interface ValidatedMailBatchEntry {
    header: Uint8Array;
    index: number;
    mail: MailWS;
    recipientDevice: Device;
}

const notificationSubscribePayload = z.object({
    channel: z.literal("expo"),
    events: z.array(z.string().min(1).max(64)).max(32).default(["mail"]),
    platform: z.enum(["android", "ios", "web"]).optional(),
    token: z.string().min(1).max(4096),
});

const getAppVersion = (): string => {
    try {
        const raw = fs.readFileSync(
            new URL("../package.json", import.meta.url),
            {
                encoding: "utf8",
            },
        );
        const pkg: unknown = JSON.parse(raw);
        if (
            typeof pkg === "object" &&
            pkg !== null &&
            "version" in pkg &&
            typeof pkg.version === "string"
        ) {
            return pkg.version;
        }
        return "unknown";
    } catch {
        return "unknown";
    }
};

const getCommitSha = (): string => {
    const sourceDir = path.dirname(fileURLToPath(import.meta.url));
    const repoRoot = path.resolve(sourceDir, "..");

    try {
        const sha = execSync("git rev-parse --verify --short=12 HEAD", {
            cwd: repoRoot,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
            timeout: 1500,
        }).trim();
        return sha || "unknown";
    } catch {
        return "unknown";
    }
};

export interface SpireOptions {
    /**
     * TCP port for the HTTP/WS server. If omitted, `run.ts` + `resolveSpireListenPort`
     * use the default (16777). Env: `API_PORT`.
     */
    apiPort?: number;
    dbType?: "mysql" | "sqlite3" | "sqlite3mem" | "sqlite";
}

export class Spire extends EventEmitter {
    private actionTokens = new Map<string, ActionToken>();
    private api = express();
    private calls: CallManager;
    private clients: ClientManager[] = [];
    private readonly commitSha = getCommitSha();
    private db: Database;
    private dbReady = false;
    private deviceChallenges = new Map<
        string,
        { deviceID: string; nonce: string; time: number }
    >();
    private mailPruneInterval: null | ReturnType<typeof setInterval> = null;
    private notifications: NotificationService;
    private queuedRequestIncrements = 0;

    private requestsTotal = 0;

    private requestsTotalLoaded = false;
    private server: null | Server = null;

    private signKeys: KeyPair;
    private readonly startedAt = new Date();
    private readonly version = getAppVersion();
    private wss: WebSocketServer = new WebSocketServer({
        maxPayload: MAX_CLIENT_MESSAGE_BYTES,
        noServer: true,
    });

    constructor(SK: string, options?: SpireOptions) {
        super();
        this.signKeys = xSignKeyPairFromSecret(XUtils.decodeHex(SK));

        // Proxy trust must match the deployment topology. Defaulting to zero
        // prevents direct deployments from accepting attacker-supplied
        // X-Forwarded-For values and bypassing IP rate limits.
        this.api.set(
            "trust proxy",
            resolveTrustProxyHops(process.env["SPIRE_TRUST_PROXY_HOPS"]),
        );
        this.api.disable("etag");

        this.db = new Database(options);
        this.calls = new CallManager(this.db, this.notify.bind(this));
        this.notifications = new NotificationService(
            this.db,
            this.clients,
            this.removeClient.bind(this),
        );
        this.db.on("ready", () => {
            this.dbReady = true;
            void this.db.pruneExpiredMail().catch(() => {
                /* best-effort — startup prune must not block bring-up */
            });
            if (this.mailPruneInterval) {
                clearInterval(this.mailPruneInterval);
            }
            this.mailPruneInterval = setInterval(
                () => {
                    void this.db.pruneExpiredMail().catch(() => {
                        /* periodic prune is best-effort */
                    });
                },
                24 * 60 * 60 * 1000,
            );
            this.bootstrapRequestCounter().catch((_err: unknown) => {
                // debugger: bootstrap request counter failed
            });
        });

        this.init(resolveSpireListenPort(options?.apiPort));
    }

    public async close(): Promise<void> {
        if (this.mailPruneInterval) {
            clearInterval(this.mailPruneInterval);
            this.mailPruneInterval = null;
        }
        this.wss.clients.forEach((ws) => {
            ws.terminate();
        });

        this.server?.close();
        this.wss.close();
        await this.db.close();
    }

    private async bootstrapRequestCounter(): Promise<void> {
        const persistedTotal = await this.db.getRequestsTotal();

        // Between the await above and this synchronous block, requests may
        // have incremented both `requestsTotal` and `queuedRequestIncrements`.
        // Capture the queue, mark loaded, then merge — never overwrite
        // `requestsTotal` (which already includes in-flight increments).
        const startupIncrements = this.queuedRequestIncrements;
        this.queuedRequestIncrements = 0;
        this.requestsTotalLoaded = true;

        // Add the persisted baseline on top of whatever the middleware
        // already counted in-memory, instead of overwriting it.
        this.requestsTotal += persistedTotal;

        if (startupIncrements > 0) {
            await this.db.incrementRequestsTotal(startupIncrements);
        }
    }

    private createActionToken(scope: TokenScopes): ActionToken {
        this.pruneActionTokens();
        const token: ActionToken = {
            key: crypto.randomUUID(),
            scope,
            time: new Date().toISOString(),
        };
        this.actionTokens.set(token.key, token);
        return token;
    }

    private deleteActionToken(key: ActionToken) {
        this.actionTokens.delete(key.key);
    }

    private disconnectDevices(deviceIDs: string[]): void {
        if (deviceIDs.length === 0) {
            return;
        }
        const ids = new Set(deviceIDs);
        for (const client of [...this.clients]) {
            const deviceID = client.getDeviceID();
            if (deviceID !== null && ids.has(deviceID)) {
                client.disconnect();
            }
        }
    }

    private init(apiPort: number): void {
        // Request traces (UUIDs and device public-key path segments redacted
        // in the `url` token). Enabled in all envs, including production.
        const accessFlag = process.env["SPIRE_HTTP_ACCESS_LOG"];
        const accessLogEnabled =
            accessFlag !== "0" &&
            accessFlag !== "false" &&
            accessFlag !== "off";
        if (accessLogEnabled) {
            morgan.token("url", (req: IncomingMessage) => {
                const r = req as IncomingMessage & { originalUrl?: string };
                return redactAccessLogUrl(r.originalUrl ?? r.url ?? "");
            });
            this.api.use(morgan("dev"));
        }

        this.api.use((_req, _res, next) => {
            this.requestsTotal += 1;

            if (!this.requestsTotalLoaded) {
                this.queuedRequestIncrements += 1;
            } else {
                this.db.incrementRequestsTotal(1).catch((_err: unknown) => {
                    // debugger: failed to persist request counter
                });
            }

            next();
        });

        // initialize the expression app configuration with loose routes/handlers
        initApp(
            this.api,
            this.db,
            this.validateToken.bind(this),
            this.signKeys,
            this.notify.bind(this),
            this.disconnectDevices.bind(this),
        );

        // WS auth: client sends { type: "auth", token } as first message
        this.wss.on("connection", (ws) => {
            const AUTH_TIMEOUT = 10_000;

            // Malformed and oversized frames emit `error`, including before
            // ClientManager exists. An unhandled socket error crashes Node.
            ws.on("error", () => {
                ws.close();
            });

            const timer = setTimeout(() => {
                ws.close();
            }, AUTH_TIMEOUT);

            const onFirstMessage = (data: ArrayBuffer | Buffer | Buffer[]) => {
                const str = Buffer.isBuffer(data)
                    ? data.toString()
                    : data instanceof ArrayBuffer
                      ? Buffer.from(data).toString()
                      : Buffer.concat(data).toString();
                clearTimeout(timer);
                ws.off("message", onFirstMessage);

                try {
                    const rawParsed: unknown = JSON.parse(str);
                    const authResult = wsAuthMsg.safeParse(rawParsed);
                    if (!authResult.success) {
                        throw new Error(
                            "Expected { type: 'auth', token }, got: " +
                                JSON.stringify(authResult.error.issues),
                        );
                    }
                    const result = verifyAuthJwt(authResult.data.token);
                    const jwtResult = jwtPayload.safeParse(result);
                    if (!jwtResult.success) {
                        throw new Error(
                            "Invalid JWT payload: " +
                                JSON.stringify(jwtResult.error.issues),
                        );
                    }
                    const userDetails: User = jwtResult.data.user;

                    const client = new ClientManager(
                        ws,
                        this.db,
                        this.calls,
                        this.notify.bind(this),
                        userDetails,
                    );

                    client.on("fail", () => {
                        this.removeClient(client);
                    });

                    client.once("authed", () => {
                        this.clients.push(client);
                    });
                } catch (_err: unknown) {
                    // debugger: WS auth failed
                    const errMsg: BaseMsg = {
                        transmissionID: crypto.randomUUID(),
                        type: "unauthorized",
                    };
                    ws.send(XUtils.packMessage(errMsg));
                    ws.close();
                }
            };

            ws.on("message", onFirstMessage);
            ws.on("close", () => {
                clearTimeout(timer);
            });
        });

        this.api.get(
            "/token/:tokenType",
            (req, res, next) => {
                if (getParam(req, "tokenType") !== "register") {
                    protect(req, res, next);
                } else {
                    next();
                }
            },
            (req, res) => {
                const allowedTokens = [
                    "file",
                    "register",
                    "avatar",
                    "device",
                    "invite",
                    "emoji",
                    "connect",
                ];

                const tokenType = getParam(req, "tokenType");

                if (!allowedTokens.includes(tokenType)) {
                    res.sendStatus(400);
                    return;
                }

                let scope;

                switch (tokenType) {
                    case "avatar":
                        scope = TokenScopes.Avatar;
                        break;
                    case "connect":
                        scope = TokenScopes.Connect;
                        break;
                    case "device":
                        scope = TokenScopes.Device;
                        break;
                    case "emoji":
                        scope = TokenScopes.Emoji;
                        break;
                    case "file":
                        scope = TokenScopes.File;
                        break;
                    case "invite":
                        scope = TokenScopes.Invite;
                        break;
                    case "register":
                        scope = TokenScopes.Register;
                        break;
                    default:
                        res.sendStatus(400);
                        return;
                }

                try {
                    const token = this.createActionToken(scope);

                    setTimeout(() => {
                        this.deleteActionToken(token);
                    }, TOKEN_EXPIRY);

                    const acceptHeader = req.get("accept")?.toLowerCase() || "";
                    const wantsJson =
                        acceptHeader.includes("application/json") &&
                        !acceptHeader.includes("application/msgpack") &&
                        !acceptHeader.includes("*/*");

                    if (wantsJson) {
                        return res.json(token);
                    }

                    res.set("Content-Type", "application/msgpack");
                    return res.send(msgpack.encode(token));
                } catch (_err: unknown) {
                    // debugger: token creation failed
                    return res.sendStatus(500);
                }
            },
        );

        this.api.post("/whoami", (req, res) => {
            if (!req.user) {
                res.sendStatus(401);
                return;
            }

            res.send(
                msgpack.encode({
                    exp: req.exp,
                    user: req.user,
                }),
            );
        });

        this.api.get("/healthz", (_req, res) => {
            if (!this.dbReady) {
                res.status(503).json({ dbReady: false, ok: false });
                return;
            }
            res.json({ dbReady: true, ok: true });
        });

        this.api.get("/status", async (req, res) => {
            const started = Date.now();
            const dbHealthy = this.dbReady ? await this.db.isHealthy() : false;
            const checkDurationMs = Date.now() - started;

            const ok = dbHealthy;
            if (!devApiKeySkipsRateLimits(req)) {
                res.json({ ok });
                return;
            }
            const canaryEnv = process.env["CANARY"]?.trim().toLowerCase();
            res.json({
                canary:
                    canaryEnv === "1" ||
                    canaryEnv === "true" ||
                    canaryEnv === "yes",
                checkDurationMs,
                now: new Date(),
                ok,
                version: this.version,
            });
        });

        /**
         * Dev-only process snapshot (same gate as rate-limit bypass: `DEV_API_KEY`
         * env + `x-dev-api-key` header). Returns 404 when not enabled or key wrong
         * so the route is not advertised to anonymous callers.
         * Lets local stress / `sample <pid>` workflows see RSS, WS count, etc.
         */
        this.api.get("/status/process", (req, res) => {
            if (!devApiKeySkipsRateLimits(req)) {
                res.sendStatus(404);
                return;
            }
            const mu = process.memoryUsage();
            const ru = process.resourceUsage();
            res.json({
                activeRequestsApprox: this.requestsTotal,
                dbReady: this.dbReady,
                hostOs: {
                    freemem: freemem(),
                    loadavg: loadavg(),
                    totalmem: totalmem(),
                },
                memory: {
                    arrayBuffers: mu.arrayBuffers,
                    external: mu.external,
                    heapTotal: mu.heapTotal,
                    heapUsed: mu.heapUsed,
                    rss: mu.rss,
                },
                pid: process.pid,
                resourceUsage: {
                    fsRead: ru.fsRead,
                    fsWrite: ru.fsWrite,
                    maxRSS: ru.maxRSS,
                    systemMicros: ru.systemCPUTime,
                    userMicros: ru.userCPUTime,
                },
                uptimeSeconds: Math.floor(process.uptime()),
                websocketClients: this.wss.clients.size,
            });
        });

        /**
         * Dev-only SQLite file + pragma snapshot (same gate as `/status/process`).
         */
        this.api.get("/status/sqlite", (req, res) => {
            if (!devApiKeySkipsRateLimits(req)) {
                res.sendStatus(404);
                return;
            }
            if (!this.dbReady) {
                res.status(503).json({ dbReady: false, ok: false });
                return;
            }
            try {
                const sqlite = this.db.getDevSqliteMonitor();
                res.json({ ok: true, sqlite });
            } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : String(err);
                res.status(500).json({ error: msg, ok: false });
            }
        });

        this.api.post("/goodbye", protect, (_req, res) => {
            // Access tokens are stateless. Clients clear them locally; this
            // endpoint exists only as a clean session boundary for callers.
            res.sendStatus(204);
        });

        // ── Device-key auth ──────────────────────────────────────────

        this.api.post("/auth/device", authLimiter, async (req, res) => {
            try {
                const parsed = deviceAuthPayload.safeParse(req.body);
                if (!parsed.success) {
                    return res
                        .status(400)
                        .send({ error: "deviceID and signKey required." });
                }
                const { deviceID, signKey } = parsed.data;

                const device = await this.db.retrieveDevice(deviceID);
                if (!device || device.signKey !== signKey) {
                    return res.status(404).send({ error: "Device not found." });
                }

                // Generate challenge nonce (32 bytes)
                const nonce = XUtils.encodeHex(xRandomBytes(32));
                const challengeID = crypto.randomUUID();
                this.deviceChallenges.set(challengeID, {
                    deviceID,
                    nonce,
                    time: Date.now(),
                });

                // Clean up expired challenges
                setTimeout(() => {
                    this.deviceChallenges.delete(challengeID);
                }, DEVICE_CHALLENGE_EXPIRY);

                return res.send(
                    msgpack.encode({ challenge: nonce, challengeID }),
                );
            } catch (_err: unknown) {
                // debugger: device challenge error
                return res.sendStatus(500);
            }
        });

        this.api.post("/auth/device/verify", authLimiter, async (req, res) => {
            try {
                const parsed = deviceVerifyPayload.safeParse(req.body);
                if (!parsed.success) {
                    return res.status(400).send({
                        error: "challengeID and signed required.",
                    });
                }
                const { challengeID, signed } = parsed.data;

                const challenge = this.deviceChallenges.get(challengeID);
                if (!challenge) {
                    return res.status(401).send({
                        error: "Challenge expired or not found.",
                    });
                }

                // Consume the challenge (single-use)
                this.deviceChallenges.delete(challengeID);

                // Check expiry
                if (Date.now() - challenge.time > DEVICE_CHALLENGE_EXPIRY) {
                    return res
                        .status(401)
                        .send({ error: "Challenge expired." });
                }

                // Look up the device to get its public signKey
                const device = await this.db.retrieveDevice(challenge.deviceID);
                if (!device) {
                    return res.status(404).send({ error: "Device not found." });
                }

                // Verify the Ed25519 signature
                const opened = await spireXSignOpenAsync(
                    XUtils.decodeHex(signed),
                    XUtils.decodeHex(device.signKey),
                );
                if (!opened) {
                    return res
                        .status(401)
                        .send({ error: "Signature verification failed." });
                }

                // Verify the signed content matches the challenge nonce
                const signedNonce = XUtils.encodeHex(opened);
                if (signedNonce !== challenge.nonce) {
                    return res
                        .status(401)
                        .send({ error: "Challenge mismatch." });
                }

                // Look up device owner
                const user = await this.db.retrieveUser(device.owner);
                if (!user) {
                    return res
                        .status(404)
                        .send({ error: "Device owner not found." });
                }

                // Device proof restores the same bounded account session as password login.
                const token = signAuthJwt(
                    { scope: "user", user: censorUser(user) },
                    DEVICE_AUTH_JWT_EXPIRY,
                );
                return res.send(
                    msgpack.encode({ token, user: censorUser(user) }),
                );
            } catch (_err: unknown) {
                // debugger: device verify error
                return res.sendStatus(500);
            }
        });

        this.api.post("/mail", protect, async (req, res) => {
            const senderDeviceDetails = req.device;
            if (!senderDeviceDetails) {
                res.sendStatus(401);
                return;
            }
            const authorUserDetails = getUser(req);

            const parsed = mailPostPayload.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid mail payload",
                    issues: parsed.error.issues,
                });
                return;
            }
            const { header, mail } = parsed.data;

            let recipientDeviceDetails;
            try {
                ({ recipientDevice: recipientDeviceDetails } =
                    await validateMailIngress(
                        this.db,
                        mail,
                        senderDeviceDetails.deviceID,
                        authorUserDetails.userID,
                    ));
            } catch (err: unknown) {
                if (err instanceof MailIngressValidationError) {
                    res.status(err.status).json({ error: err.message });
                    return;
                }
                throw err;
            }

            await this.db.saveMail(
                mail,
                header,
                senderDeviceDetails.deviceID,
                authorUserDetails.userID,
            );

            res.sendStatus(200);
            this.notify(
                recipientDeviceDetails.owner,
                "mail",
                crypto.randomUUID(),
                null,
                mail.recipient,
                mail.authorID,
                mail.nonce,
            );
        });

        this.api.post("/mail/batch", protect, async (req, res) => {
            const senderDeviceDetails = req.device;
            if (!senderDeviceDetails) {
                res.sendStatus(401);
                return;
            }
            const authorUserDetails = getUser(req);

            const parsed = mailBatchPostPayload.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid mail batch payload",
                    issues: parsed.error.issues,
                });
                return;
            }

            const results: MailBatchResult[] = [];
            const validEntries: ValidatedMailBatchEntry[] = [];
            for (const [index, item] of parsed.data.mails.entries()) {
                const { header, mail } = item;
                try {
                    const { recipientDevice } = await validateMailIngress(
                        this.db,
                        mail,
                        senderDeviceDetails.deviceID,
                        authorUserDetails.userID,
                    );
                    validEntries.push({
                        header,
                        index,
                        mail,
                        recipientDevice,
                    });
                } catch (err: unknown) {
                    const status =
                        err instanceof MailIngressValidationError
                            ? err.status
                            : 500;
                    const message =
                        err instanceof Error ? err.message : String(err);
                    results[index] = {
                        error: message,
                        index,
                        mailID: mail.mailID,
                        ok: false,
                        recipient: mail.recipient,
                        status,
                    };
                }
            }

            const deliveredEntries: ValidatedMailBatchEntry[] = [];
            if (validEntries.length > 0) {
                try {
                    await this.db.saveMailBatch(
                        validEntries.map((entry) => ({
                            header: entry.header,
                            mail: entry.mail,
                            senderDeviceID: senderDeviceDetails.deviceID,
                            userID: authorUserDetails.userID,
                        })),
                    );
                    for (const entry of validEntries) {
                        deliveredEntries.push(entry);
                        results[entry.index] = {
                            index: entry.index,
                            mailID: entry.mail.mailID,
                            ok: true,
                            recipient: entry.mail.recipient,
                        };
                    }
                } catch {
                    for (const entry of validEntries) {
                        try {
                            await this.db.saveMail(
                                entry.mail,
                                entry.header,
                                senderDeviceDetails.deviceID,
                                authorUserDetails.userID,
                            );
                            deliveredEntries.push(entry);
                            results[entry.index] = {
                                index: entry.index,
                                mailID: entry.mail.mailID,
                                ok: true,
                                recipient: entry.mail.recipient,
                            };
                        } catch (err: unknown) {
                            results[entry.index] = {
                                error:
                                    err instanceof Error
                                        ? err.message
                                        : String(err),
                                index: entry.index,
                                mailID: entry.mail.mailID,
                                ok: false,
                                recipient: entry.mail.recipient,
                                status: 500,
                            };
                        }
                    }
                }
            }

            res.send(msgpack.encode({ results }));
            for (const entry of deliveredEntries) {
                this.notify(
                    entry.recipientDevice.owner,
                    "mail",
                    crypto.randomUUID(),
                    null,
                    entry.mail.recipient,
                    entry.mail.authorID,
                    entry.mail.nonce,
                );
            }
        });

        this.api.get("/calls/active", protect, (req, res) => {
            const user = getUser(req);
            res.setHeader(
                "Cache-Control",
                "no-store, no-cache, must-revalidate, proxy-revalidate",
            );
            res.setHeader("Pragma", "no-cache");
            res.setHeader("Expires", "0");
            res.json({ calls: this.calls.activeCallsForUser(user.userID) });
        });

        this.api.get("/calls/ice-servers", protect, async (_req, res) => {
            res.json({ iceServers: await resolveIceServersFromEnv() });
        });

        this.api.post(
            "/device/:id/notifications/subscriptions",
            protect,
            async (req, res) => {
                const device = req.device;
                if (!device) {
                    res.sendStatus(401);
                    return;
                }
                if (device.deviceID !== getParam(req, "id")) {
                    res.sendStatus(403);
                    return;
                }

                const parsed = notificationSubscribePayload.safeParse(req.body);
                if (!parsed.success) {
                    res.status(400).json({
                        error: "Invalid notification subscription payload",
                        issues: parsed.error.issues,
                    });
                    return;
                }

                const subscription = await this.db.saveNotificationSubscription(
                    {
                        channel: parsed.data.channel,
                        deviceID: device.deviceID,
                        events: parsed.data.events,
                        platform: parsed.data.platform ?? null,
                        token: parsed.data.token,
                        userID: getUser(req).userID,
                    },
                );

                res.status(201).json(subscription);
            },
        );

        this.api.delete(
            "/device/:id/notifications/subscriptions/:subscriptionID",
            protect,
            async (req, res) => {
                const device = req.device;
                if (!device) {
                    res.sendStatus(401);
                    return;
                }
                if (device.deviceID !== getParam(req, "id")) {
                    res.sendStatus(403);
                    return;
                }

                const removed = await this.db.removeNotificationSubscription({
                    deviceID: device.deviceID,
                    subscriptionID: getParam(req, "subscriptionID"),
                    userID: getUser(req).userID,
                });
                res.sendStatus(removed ? 204 : 404);
            },
        );

        this.api.post(
            "/auth",
            authLimiter,
            accountAuthLimiter,
            async (req, res) => {
                const parsed = authPayload.safeParse(req.body);
                if (!parsed.success) {
                    res.status(400).json({
                        error: "Invalid credentials format",
                    });
                    return;
                }
                const { password } = parsed.data;
                const username = parsed.data.username.toLowerCase();

                try {
                    const userEntry = await this.db.retrieveUser(username);
                    if (!userEntry) {
                        await verifyPassword(password, null);
                        res.sendStatus(401);
                        return;
                    }

                    const { needsRehash, valid } = await verifyPassword(
                        password,
                        userEntry,
                    );

                    if (!valid) {
                        res.sendStatus(401);
                        return;
                    }

                    if (needsRehash) {
                        const newHash = await hashPasswordArgon2(password);
                        await this.db.rehashPassword(userEntry.userID, newHash);
                    }

                    const token = signAuthJwt(
                        { scope: "user", user: censorUser(userEntry) },
                        JWT_EXPIRY,
                    );

                    res.send(
                        msgpack.encode({ token, user: censorUser(userEntry) }),
                    );
                } catch (_err: unknown) {
                    // debugger: auth error
                    res.sendStatus(500);
                }
            },
        );

        this.api.post(
            "/register",
            authLimiter,
            accountAuthLimiter,
            async (req, res) => {
                try {
                    const regParsed = RegistrationPayloadSchema.safeParse(
                        req.body,
                    );
                    if (!regParsed.success) {
                        res.status(400).json({
                            error: "Invalid registration payload",
                            issues: regParsed.error.issues,
                        });
                        return;
                    }
                    const regPayload = regParsed.data;
                    const bounded =
                        boundedRegistrationPayload.safeParse(regPayload);
                    if (!bounded.success) {
                        res.status(400).json({
                            error: "Invalid registration payload",
                            issues: bounded.error.issues,
                        });
                        return;
                    }
                    if (!usernameRegex.test(regPayload.username)) {
                        res.status(400).send({
                            error: "Username must be between three and nineteen letters, digits, or underscores.",
                        });
                        return;
                    }
                    const normalizedPayload = {
                        ...regPayload,
                        username: normalizeRegistrationUsername(
                            regPayload.username,
                        ),
                    };

                    const regKey = await spireXSignOpenAsync(
                        XUtils.decodeHex(normalizedPayload.signed),
                        XUtils.decodeHex(normalizedPayload.signKey),
                    );

                    if (
                        regKey &&
                        regKey.length === 16 &&
                        this.validateToken(
                            uuidStringify(regKey),
                            TokenScopes.Register,
                        )
                    ) {
                        if (
                            !(await verifyDevicePayloadPreKeySignature(
                                normalizedPayload,
                            ))
                        ) {
                            res.status(400).send({
                                error: "Signed prekey signature is invalid.",
                            });
                            return;
                        }
                        const existingUser = await this.db.retrieveUser(
                            normalizedPayload.username,
                        );
                        if (
                            normalizedPayload.intent === "create-account" &&
                            existingUser
                        ) {
                            res.status(409).send({
                                error: "Username is already registered. Sign in instead.",
                            });
                            return;
                        }
                        if (
                            normalizedPayload.intent === "enroll-device" &&
                            !existingUser
                        ) {
                            await verifyPassword(
                                normalizedPayload.password ?? "",
                                null,
                            );
                            res.status(401).send({
                                error: "Invalid username or password.",
                            });
                            return;
                        }
                        if (existingUser) {
                            const existingBySignKey =
                                await this.db.retrieveDevice(
                                    normalizedPayload.signKey,
                                );
                            if (existingBySignKey) {
                                res.status(400).send({
                                    error: "Public key is already registered.",
                                });
                                return;
                            }
                            let requesterPasskeyID: string | undefined;
                            if (req.passkey?.passkeyID) {
                                const passkey =
                                    await this.db.retrievePasskeyInternal(
                                        req.passkey.passkeyID,
                                    );
                                if (
                                    !passkey ||
                                    passkey.userID !== existingUser.userID
                                ) {
                                    res.status(403).send({
                                        error: "Passkey verification does not match this account.",
                                    });
                                    return;
                                }
                                requesterPasskeyID = req.passkey.passkeyID;
                            } else {
                                if (
                                    typeof normalizedPayload.password !==
                                        "string" ||
                                    normalizedPayload.password.trim().length ===
                                        0
                                ) {
                                    res.status(401).send({
                                        error: "Password is required to add this device.",
                                    });
                                    return;
                                }
                                const { needsRehash, valid } =
                                    await verifyPassword(
                                        normalizedPayload.password,
                                        existingUser,
                                    );
                                if (!valid) {
                                    res.sendStatus(401);
                                    return;
                                }
                                if (needsRehash) {
                                    const newHash = await hashPasswordArgon2(
                                        normalizedPayload.password,
                                    );
                                    await this.db.rehashPassword(
                                        existingUser.userID,
                                        newHash,
                                    );
                                }
                            }
                            const activeDevices =
                                await this.db.retrieveUserDeviceList([
                                    existingUser.userID,
                                ]);
                            if (
                                activeDevices.length >=
                                MAX_ACTIVE_DEVICES_PER_USER
                            ) {
                                res.status(409).send({
                                    error: `Each account is limited to ${String(MAX_ACTIVE_DEVICES_PER_USER)} active devices. Remove an old device before adding another.`,
                                });
                                return;
                            }
                            const pendingResponse =
                                createPendingDeviceEnrollmentRequest(
                                    existingUser.userID,
                                    normalizedPayload,
                                    this.notify.bind(this),
                                    {
                                        deferOwnerNotification: true,
                                        ...(requesterPasskeyID
                                            ? { requesterPasskeyID }
                                            : {}),
                                    },
                                );
                            res.status(202).send(
                                msgpack.encode(pendingResponse),
                            );
                            return;
                        }
                        if (
                            typeof normalizedPayload.password !== "string" ||
                            normalizedPayload.password.trim().length === 0
                        ) {
                            res.status(400).send({
                                error: "Password is required to register a new account.",
                            });
                            return;
                        }
                        const passwordError = validateAccountPassword(
                            normalizedPayload.password,
                            normalizedPayload.username,
                        );
                        if (passwordError) {
                            res.status(400).send({
                                error: passwordError,
                            });
                            return;
                        }
                        const [user, err] = await this.db.createUser(
                            regKey,
                            normalizedPayload,
                        );
                        if (err !== null) {
                            const errCode =
                                "code" in err && typeof err.code === "string"
                                    ? err.code
                                    : undefined;
                            const errText = String(err);
                            const usernameConflict =
                                errText.includes("users_username_unique") ||
                                errText.includes("users.username");
                            const signKeyConflict =
                                errText.includes("devices_signKey_unique") ||
                                errText.includes("devices.signKey");
                            const isUniqueConstraint =
                                errCode === "ER_DUP_ENTRY" ||
                                errCode === "SQLITE_CONSTRAINT_UNIQUE" ||
                                errText.includes("UNIQUE constraint failed");
                            if (isUniqueConstraint && usernameConflict) {
                                res.status(400).send({
                                    error: "Username is already registered.",
                                });
                                return;
                            }
                            if (isUniqueConstraint && signKeyConflict) {
                                res.status(400).send({
                                    error: "Public key is already registered.",
                                });
                                return;
                            }
                            res.sendStatus(500);
                        } else {
                            if (!user) {
                                res.sendStatus(500);
                                return;
                            }
                            const device = await this.db.retrieveDevice(
                                normalizedPayload.signKey,
                            );
                            if (!device) {
                                res.sendStatus(500);
                                return;
                            }
                            const censored = censorUser(user);
                            const token = signAuthJwt(
                                { scope: "user", user: censored },
                                JWT_EXPIRY,
                            );
                            res.send(
                                msgpack.encode({
                                    device,
                                    token,
                                    user: censored,
                                }),
                            );
                        }
                    } else if (regKey && regKey.length !== 16) {
                        res.status(400).send({
                            error: "Invalid registration token payload.",
                        });
                    } else {
                        res.status(400).send({
                            error: "Invalid or no token supplied.",
                        });
                    }
                } catch (err: unknown) {
                    const requestId = crypto.randomUUID();
                    const message =
                        err instanceof Error ? err.message : String(err);
                    console.error(
                        `[spire] /register failed requestId=${requestId} message=${message}`,
                    );
                    if (err instanceof Error && err.stack) {
                        console.error(err.stack);
                    }
                    res.status(500).json({
                        error: `Registration failed. requestId=${requestId}`,
                    });
                }
            },
        );

        this.server = this.api.listen(apiPort);

        // Accept all WS upgrades — auth happens post-connection.
        this.server.on("upgrade", (req, socket, head) => {
            this.wss.handleUpgrade(req, socket, head, (ws) => {
                this.wss.emit("connection", ws);
            });
        });
    }

    private notify(
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
        headlessPushUserID?: string,
        mailNonce?: Uint8Array,
    ): void {
        this.notifications.notify({
            data,
            event,
            ...(headlessPushUserID ? { headlessPushUserID } : {}),
            ...(mailNonce ? { mailNonce } : {}),
            transmissionID,
            userID,
            ...(deviceID ? { deviceID } : {}),
        });
    }

    private pruneActionTokens(now = Date.now()): void {
        for (const [key, token] of this.actionTokens) {
            const createdAt = new Date(token.time).getTime();
            if (
                !Number.isFinite(createdAt) ||
                now - createdAt >= TOKEN_EXPIRY
            ) {
                this.actionTokens.delete(key);
            }
        }
    }

    private removeClient(client: ClientManager): void {
        const idx = this.clients.indexOf(client);
        if (idx !== -1) {
            this.clients.splice(idx, 1);
        }
    }

    private validateToken(key: string, scope: TokenScopes): boolean {
        this.pruneActionTokens();
        const token = this.actionTokens.get(key);
        if (!token || token.scope !== scope) {
            return false;
        }
        this.deleteActionToken(token);
        return true;
    }
}

export function resolveTrustProxyHops(value: string | undefined): number {
    if (value === undefined || value.trim() === "") {
        return 0;
    }
    const hops = Number(value);
    if (!Number.isInteger(hops) || hops < 0 || hops > 10) {
        throw new Error(
            "SPIRE_TRUST_PROXY_HOPS must be an integer from 0 to 10.",
        );
    }
    return hops;
}

// Usernames are case-insensitive at the protocol level — `User` and
// `user` must resolve to the same account. We canonicalize to
// lowercase at the registration boundary so the persisted row, the
// UNIQUE index, and every downstream lookup all agree on a single
// representation. `Database.retrieveUser` applies the same normalization.
function normalizeRegistrationUsername(username: string): string {
    return username.trim().toLowerCase();
}

/**
 * Masks identifying material in the access-log URL: hyphenated UUIDs, and
 * `/device/...` path segments that hold Ed25519 public-key material.
 */
function redactAccessLogUrl(url: string): string {
    let s = url.replace(
        /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
        "[uuid]",
    );
    // Device id is a hex public key, not a UUID: strip the segment after /device/
    s = s.replace(/(\/device\/)([0-9a-fA-F]{16,})(?=[/?#]|$)/g, "$1[device]");
    return s;
}

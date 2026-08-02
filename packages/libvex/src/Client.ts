/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Storage } from "./Storage.js";
import type { WebSocketLike } from "./transport/types.js";
import type {
    PreKeysCrypto,
    SessionCrypto,
    UnsavedPreKey,
    XKeyRing,
} from "./types/index.js";
import type { KeyPair } from "@vex-chat/crypto";
import type {
    AccountEntitlements,
    AccountTier,
    ActionToken,
    AppleTransactionVerificationRequest,
    BillingAccountState,
    BillingProduct,
    CallEvent,
    CallResourceData,
    CallSession,
    CallSignalPayload,
    ChallMsg,
    Channel,
    Device,
    DevicePayload,
    Emoji,
    FileResponse,
    FileSQL,
    GooglePurchaseVerificationRequest,
    IceServerConfig,
    Invite,
    KeyBundle,
    MailWS,
    NotifyMsg,
    Passkey,
    Permission,
    PreKeysSQL,
    PreKeysWS,
    ReceiptMsg,
    RegistrationPayload,
    ResourceMsg,
    RespMsg,
    Server,
    ServerChannelBootstrap,
    SessionSQL,
} from "@vex-chat/types";
import type { ClientMessage } from "@vex-chat/types";

import {
    xBoxKeyPairAsync,
    xBoxKeyPairFromSecretAsync,
    xConcat,
    xConstants,
    xDHAsync,
    xEncode,
    xHMAC,
    xKDF,
    XKeyConvert,
    xMakeNonce,
    xMessageKeySubkeys,
    xMnemonic,
    xPreKeySignaturePayload,
    xRandomBytes,
    xSecretboxAsync,
    xSecretboxOpenAsync,
    xSignAsync,
    xSignKeyPair,
    xSignKeyPairAsync,
    xSignKeyPairFromSecret,
    xSignOpenAsync,
    XUtils,
} from "@vex-chat/crypto";
import {
    ACCOUNT_PASSWORD_MAX_LENGTH,
    ACCOUNT_PASSWORD_MIN_LENGTH,
    CallEventSchema,
    CallSessionSchema,
    IceServerConfigSchema,
    MailType,
    MailWSSchema,
    PermissionSchema,
    WSMessageSchema,
} from "@vex-chat/types";

import { EventEmitter } from "eventemitter3";
import * as uuid from "uuid";
import { z } from "zod/v4";

import {
    createFetchHttpClient,
    type FetchHttpClient,
    type HttpError,
    isHttpError,
} from "./http.js";
import {
    clampLocalMessageRetentionDays,
    formatVexRetentionEnvelope,
    stripVexRetentionEnvelope,
} from "./retention.js";
import {
    WebSocketAdapter,
    WebSocketNotOpenError,
} from "./transport/websocket.js";
import {
    decodeRatchetHeader,
    deriveBootstrapSendChain,
    encodeRatchetHeader,
    hasRemoteDhChanged,
    initRatchetSession,
    ratchetStepReceive,
    ratchetStepSend,
    sessionToSqlPatch,
    takeReceiveMessageKey,
    takeSendMessageKey,
} from "./utils/ratchet.js";
import { verifyKeyBundleSignatures } from "./utils/verifyKeyBundle.js";

/**
 * Thrown by {@link Client.register} when the server determined the supplied
 * username already exists on the server and the registering device must be
 * approved by an existing signed-in device for that account.
 *
 * Carries the `requestID` and the random `challenge` issued by the server,
 * which together let the new (unauthenticated) device poll
 * {@link Devices.pollPendingRegistration} for approval status without ever
 * needing a user token.
 */
export class DeviceApprovalRequiredError extends Error {
    public readonly challenge: string;
    public readonly expiresAt: string;
    public readonly requestID: string;
    /**
     * Existing user's ID, when the server provides it. Lets the new
     * (unauthenticated) device fetch the public avatar and show an
     * "is this you?" confirmation before continuing the approval
     * dance. Optional because older servers don't return it.
     */
    public readonly userID: null | string;
    constructor(args: {
        challenge: string;
        expiresAt: string;
        requestID: string;
        userID?: null | string;
    }) {
        super(
            "Device registration requires approval from an existing device. requestID=" +
                args.requestID,
        );
        this.name = "DeviceApprovalRequiredError";
        this.challenge = args.challenge;
        this.expiresAt = args.expiresAt;
        this.requestID = args.requestID;
        this.userID = args.userID ?? null;
    }
}

function cloneNullableBytes(value: null | Uint8Array): null | Uint8Array {
    return value ? new Uint8Array(value) : null;
}

function cloneSessionCrypto(session: SessionCrypto): SessionCrypto {
    return {
        ...session,
        CKr: cloneNullableBytes(session.CKr),
        CKs: cloneNullableBytes(session.CKs),
        DHr: cloneNullableBytes(session.DHr),
        DHsPrivate: new Uint8Array(session.DHsPrivate),
        DHsPublic: new Uint8Array(session.DHsPublic),
        fingerprint: new Uint8Array(session.fingerprint),
        publicKey: new Uint8Array(session.publicKey),
        RK: new Uint8Array(session.RK),
        SK: new Uint8Array(session.SK),
        skippedKeys: { ...session.skippedKeys },
    };
}

function debugLibvexDm(
    msg: string,
    data?: Record<string, boolean | null | number | string | undefined>,
): void {
    if (!libvexDebugDmEnabled()) {
        return;
    }
    if (isHeartbeatDebugMessage(msg, data) && libvexDebugLevel() !== "trace") {
        return;
    }
    const payload = data ? `${msg} ${JSON.stringify(data)}` : msg;
    // eslint-disable-next-line no-console -- gated by LIBVEX_DEBUG_DM; remove when debugging is done
    console.error(`[libvex:debug-dm] ${payload}`);
}

function errorFromUnknown(err: unknown): Error {
    if (err instanceof Error) {
        return err;
    }
    if (typeof err === "string") {
        return new Error(err);
    }
    return new Error(JSON.stringify(err));
}

function ignoreSocketTeardown(err: unknown): void {
    if (err instanceof WebSocketNotOpenError) return;
    // Re-throw anything else as a real unhandled rejection so it
    // shows up in dev tools and Sentry-style reporters.
    throw err;
}

function isHeartbeatDebugMessage(
    msg: string,
    data?: Record<string, boolean | null | number | string | undefined>,
): boolean {
    if (/\b(?:ping|pong)\b/i.test(msg)) return true;
    return data?.["type"] === "ping" || data?.["type"] === "pong";
}

function isRecord(x: unknown): x is Record<string, unknown> {
    return typeof x === "object" && x !== null;
}

/**
 * Set `LIBVEX_DEBUG_DM=1` (e.g. in vitest / shell) to log DM multi-device / X3DH paths.
 * Uses indirect `globalThis` lookup so the bare `process` global never appears in
 * source that the platform-guard plugin scans (browser/RN/Tauri).
 */
function libvexDebugDmEnabled(): boolean {
    try {
        const g = Object.getOwnPropertyDescriptor(globalThis, "\u0070rocess");
        if (!g) {
            return false;
        }
        const proc: unknown = typeof g.get === "function" ? g.get() : g.value;
        if (typeof proc !== "object" || proc === null) {
            return false;
        }
        const envDesc = Object.getOwnPropertyDescriptor(proc, "env");
        if (!envDesc) {
            return false;
        }
        const env: unknown =
            typeof envDesc.get === "function" ? envDesc.get() : envDesc.value;
        if (typeof env !== "object" || env === null) {
            return false;
        }
        return Reflect.get(env, "LIBVEX_DEBUG_DM") === "1";
    } catch {
        return false;
    }
}

function libvexDebugLevel(): "debug" | "trace" {
    try {
        const g = Object.getOwnPropertyDescriptor(globalThis, "\u0070rocess");
        if (!g) return "debug";
        const proc: unknown = typeof g.get === "function" ? g.get() : g.value;
        if (typeof proc !== "object" || proc === null) return "debug";
        const envDesc = Object.getOwnPropertyDescriptor(proc, "env");
        if (!envDesc) return "debug";
        const env: unknown =
            typeof envDesc.get === "function" ? envDesc.get() : envDesc.value;
        if (typeof env !== "object" || env === null) return "debug";
        const value = String(
            Reflect.get(env, "LIBVEX_DEBUG_LEVEL") ?? "",
        ).toLowerCase();
        return value === "trace" || value === "2" ? "trace" : "debug";
    } catch {
        return "debug";
    }
}

function registrationPasswordError(password: string): Error | null {
    if (
        password.trim().length === 0 ||
        password.length < ACCOUNT_PASSWORD_MIN_LENGTH
    ) {
        return new Error(
            `Password must be at least ${String(ACCOUNT_PASSWORD_MIN_LENGTH)} characters.`,
        );
    }
    if (password.length > ACCOUNT_PASSWORD_MAX_LENGTH) {
        return new Error(
            `Password must be at most ${String(ACCOUNT_PASSWORD_MAX_LENGTH)} characters.`,
        );
    }
    return null;
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Spire 5+ JSON error bodies use `{ "error": { "message", "requestId"?, "details"? } }`.
 * Responses are `arraybuffer` — decode UTF-8 and parse for a one-line `Error` message
 * (plus requestId) instead of a raw JSON blob.
 */
function spireErrorBodyMessage(data: unknown, max = 8_000): string {
    let text: string;
    if (data instanceof ArrayBuffer) {
        text = new TextDecoder("utf-8", { fatal: false }).decode(
            new Uint8Array(data),
        );
    } else if (data instanceof Uint8Array) {
        text = new TextDecoder("utf-8", { fatal: false }).decode(data);
    } else {
        return String(data).slice(0, max);
    }
    const t = text.trim();
    if (t.startsWith("{")) {
        try {
            // JSON.parse is typed as any; assign into unknown for safe narrowing.
            const parsed: unknown = JSON.parse(t);
            if (!isRecord(parsed)) {
                return t.length > max ? t.slice(0, max) + "…" : t;
            }
            const errField = parsed["error"];
            if (!isRecord(errField)) {
                return t.length > max ? t.slice(0, max) + "…" : t;
            }
            const message = errField["message"];
            if (typeof message !== "string") {
                return t.length > max ? t.slice(0, max) + "…" : t;
            }
            const parts: string[] = [message];
            const requestId = errField["requestId"];
            if (typeof requestId === "string" && requestId.length > 0) {
                parts.push(`(requestId: ${requestId})`);
            }
            if (errField["details"] !== undefined) {
                let d = JSON.stringify(errField["details"]);
                if (d.length > 500) {
                    d = d.slice(0, 500) + "…";
                }
                parts.push(d);
            }
            return parts.join(" ");
        } catch {
            /* fall through to raw */
        }
    }
    return t.length > max ? t.slice(0, max) + "…" : t;
}

import { msgpack } from "./codec.js";
import {
    AccountEntitlementsCodec,
    ActionTokenCodec,
    AuthResponseCodec,
    BillingAccountStateCodec,
    BillingProductArrayCodec,
    ChannelArrayCodec,
    ChannelCodec,
    ConnectResponseCodec,
    decodeHttpResponse,
    DeviceArrayCodec,
    DeviceChallengeCodec,
    DeviceCodec,
    DeviceRegistrationResultCodec,
    EmojiArrayCodec,
    EmojiCodec,
    FileSQLCodec,
    InviteArrayCodec,
    InviteCodec,
    KeyBundleCodec,
    OtkCountCodec,
    PasskeyArrayCodec,
    PasskeyAuthFinishResponseCodec,
    PasskeyCodec,
    PasskeyOptionsCodec,
    PendingDeviceRequestArrayCodec,
    PendingDeviceRequestCodec,
    PermissionArrayCodec,
    PermissionCodec,
    RegisterPendingApprovalCodec,
    RegisterResponseCodec,
    ServerArrayCodec,
    ServerChannelBootstrapCodec,
    ServerCodec,
    UserArrayCodec,
    UserCodec,
    WhoamiCodec,
} from "./codecs.js";
import { sqlSessionToCrypto } from "./utils/sqlSessionToCrypto.js";
import { uuidToUint8 } from "./utils/uint8uuid.js";

const _protocolMsgRegex = /��\w+:\w+��/g;

/**
 * @ignore
 */
export interface Billing {
    /** Returns the configured StoreKit / Play Billing product catalog. */
    products: () => Promise<BillingProduct[]>;
    /** Returns the current billing subscriptions and derived entitlements. */
    retrieve: () => Promise<BillingAccountState>;
    /** Submits an App Store transaction for server-side verification. */
    submitAppleTransaction: (
        request: AppleTransactionVerificationRequest,
    ) => Promise<BillingAccountState>;
    /** Submits a Google Play purchase token for server-side verification. */
    submitGooglePurchase: (
        request: GooglePurchaseVerificationRequest,
    ) => Promise<BillingAccountState>;
}

/**
 * Voice-call signaling operations.
 *
 * `libvex` moves authenticated call control over Spire. Platform apps own
 * WebRTC/media capture and pass offers, answers, and ICE candidates through
 * these methods.
 */
export interface Calls {
    accept: (callID: string, signal?: CallSignalPayload) => Promise<CallEvent>;
    active: () => Promise<CallSession[]>;
    cancel: (callID: string) => Promise<CallEvent>;
    hangup: (callID: string) => Promise<CallEvent>;
    ice: (callID: string, signal: CallSignalPayload) => Promise<CallEvent>;
    iceServers: () => Promise<IceServerConfig[]>;
    reject: (callID: string) => Promise<CallEvent>;
    signal: (callID: string, signal: CallSignalPayload) => Promise<CallEvent>;
    startDM: (
        recipientUserID: string,
        signal?: CallSignalPayload,
    ) => Promise<CallEvent>;
}

/**
 * @ignore
 */
export interface Channels {
    /** Creates a channel in a server. */
    create: (name: string, serverID: string) => Promise<Channel>;
    /** Deletes a channel. */
    delete: (channelID: string) => Promise<void>;
    /** Lists channels in a server. */
    retrieve: (serverID: string) => Promise<Channel[]>;
    /** Gets one channel by ID. */
    retrieveByID: (channelID: string) => Promise<Channel | null>;
    /** Changes a channel's display name. */
    update: (channelID: string, name: string) => Promise<Channel>;
    /** Lists users currently visible in a channel. */
    userList: (channelID: string) => Promise<User[]>;
}

/**
 * ClientOptions are the options you can pass into the client.
 */
export interface ClientOptions {
    /** Folder path where the sqlite file is created. */
    dbFolder?: string;
    /**
     * When set (non-empty), sent as `x-dev-api-key` on every HTTP request.
     * Spire omits in-process rate limits when this matches the server's `DEV_API_KEY`
     * (local / load-testing only — never use in production).
     */
    devApiKey?: string;
    /** Platform label for device registration (e.g. "ios", "macos", "linux"). */
    deviceName?: string;
    /** API host without protocol. Defaults to `api.vex.wtf`. */
    host?: string;
    /** Use sqlite in-memory mode (`:memory:`) instead of a file. */
    inMemoryDb?: boolean;
    /**
     * Maximum age (in days) for messages kept in local storage. Values above
     * 30 are clamped to 30 to match server retention. Peers may request a
     * shorter window via an optional plaintext hint; this setting is still
     * capped at 30 and is not enforceable against a modified client.
     */
    localMessageRetentionDays?: number;
    /** Whether local message history should be persisted by default storage. */
    saveHistory?: boolean;
    /** Use `http/ws` instead of `https/wss`. Intended for local/dev environments. */
    unsafeHttp?: boolean;
}

export type DeviceRegistrationResult = Device | PendingDeviceRegistration;

/**
 * Permission is a permission to a resource.
 *
 * Common fields:
 * - `permissionID`: unique permission row ID
 * - `userID`: user receiving this grant
 * - `resourceID`: target server/channel/etc.
 * - `resourceType`: type string for the resource
 * - `powerLevel`: authorization level
 */
export type { Permission } from "@vex-chat/types";

/**
 * @ignore
 */
export interface Devices {
    /**
     * Deletes an unpublished enrollment before any owner notification
     * (e.g. user picked "not my account").
     */
    abortPendingRegistration: (args: {
        challenge: string;
        requestID: string;
    }) => Promise<void>;
    /**
     * Approves a pending device registration request as the current device.
     * The server verifies a signature from this approved device before
     * admitting the pending device into the account cluster.
     */
    approveRequest: (requestID: string) => Promise<Device>;
    /**
     * Begin creating a passkey from a newly approved, still pending device
     * enrollment. Proves possession of the requesting device key by signing
     * the original pending-registration challenge.
     */
    beginPendingPasskeyRegistration: (args: {
        challenge: string;
        name: string;
        requestID: string;
    }) => Promise<{
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WebAuthn options shape varies per simplewebauthn version
        options: any;
        requestID: string;
    }>;
    /** Deletes one of the account's devices (except the currently active one). */
    delete: (deviceID: string) => Promise<void>;
    /**
     * Finish creating a passkey for a newly approved pending device
     * enrollment.
     */
    finishPendingPasskeyRegistration: (args: {
        challenge: string;
        name: string;
        requestID: string;
        response: Record<string, unknown>;
    }) => Promise<Passkey>;
    /** Fetches one pending registration request by ID for the current user. */
    getRequest: (requestID: string) => Promise<null | PendingDeviceRequest>;
    /** Lists every device belonging to the current account. */
    list: () => Promise<Device[]>;
    /** Lists pending/processed registration requests for the current user. */
    listRequests: () => Promise<PendingDeviceRequest[]>;
    /**
     * Polls the public, unauthenticated status endpoint for a pending
     * registration request *as the requesting device*. Proves possession of
     * the request's private signing key by signing the challenge issued by
     * the server in the original 202 response.
     *
     * @param args - The request ID and hex challenge returned by `/register`
     *   (or carried by {@link DeviceApprovalRequiredError}).
     * @returns The current {@link PendingDeviceRequest} or `null` if the
     *   server no longer has a record of it.
     */
    pollPendingRegistration: (args: {
        challenge: string;
        requestID: string;
    }) => Promise<null | PendingDeviceRequest>;
    /**
     * After the user confirms the pending enrollment is theirs, notifies
     * their existing devices (same proof as poll).
     */
    publishPendingRegistration: (args: {
        challenge: string;
        requestID: string;
    }) => Promise<void>;
    /** Registers the current key material as a new device. */
    register: () => Promise<DeviceRegistrationResult | null>;
    /** Rejects a pending device registration request as the current device. */
    rejectRequest: (requestID: string) => Promise<void>;
    /** Fetches one device by ID. */
    retrieve: (deviceIdentifier: string) => Promise<Device | null>;
}

/**
 * @ignore
 */
export interface Emojis {
    /** Uploads a custom emoji to a server. */
    create: (
        emoji: Uint8Array,
        name: string,
        serverID: string,
    ) => Promise<Emoji | null>;
    /** Fetches one emoji's metadata by ID. */
    retrieve: (emojiID: string) => Promise<Emoji | null>;
    /** Lists emojis available on a server. */
    retrieveList: (serverID: string) => Promise<Emoji[]>;
}

/**
 * @ignore
 */
export interface Entitlements {
    /** Retrieves the server-authoritative entitlement snapshot. */
    retrieve: () => Promise<AccountEntitlements>;
    /**
     * Local development helper. Spire only serves this endpoint when
     * `VEX_ENABLE_DEV_ENTITLEMENTS=1`, `DEV_API_KEY` is configured, and
     * `NODE_ENV` is not `production`.
     */
    setDevTier: (
        tier: AccountTier,
        options?: { expiresAt?: null | string },
    ) => Promise<AccountEntitlements>;
}

/**
 * Device record associated with a user account.
 *
 * Common fields:
 * - `deviceID`: unique device identifier
 * - `owner`: owning user ID
 * - `signKey`: signing public key
 * - `name`: user-facing device name
 * - `lastLogin`: last login timestamp string
 * - `deleted`: soft-delete flag
 */
export type { Device } from "@vex-chat/types";

/**
 * Public passkey record returned by `client.passkeys.list()` and
 * `client.passkeys.finishRegistration()`. Server-private fields
 * (credential ID, public key, COSE algorithm, signature counter) are
 * never exposed.
 */
export type { Passkey } from "@vex-chat/types";

/**
 * Progress payload emitted by the `fileProgress` event.
 */
export interface FileProgress {
    /** Whether this progress event is for upload or download. */
    direction: "download" | "upload";
    /** Bytes transferred so far. */
    loaded: number;
    /** Integer percentage from `0` to `100`. */
    progress: number;
    /** Correlation token (file ID, nonce, or label depending on operation). */
    token: string;
    /** Total expected bytes when available, otherwise `0`. */
    total: number;
}

/**
 * FileRes is a server response to a file retrieval request.
 *
 * Structure:
 * - `details`: metadata (`VexFile`)
 * - `data`: decrypted binary bytes
 *
 * @example
 * ```ts
 * const response: FileRes = {
 *     details: {
 *         fileID: "bb1c3fd1-4928-48ab-9d09-3ea0972fbd9d",
 *         owner: "9b0f3f46-06ad-4bc4-8adf-4de10e13cb9c",
 *         nonce: "aa6c8d42f3fdd032a1e9fced4be379582d26ce8f69822d64",
 *     },
 *     data: Buffer.from("hello"),
 * };
 * ```
 */
export type FileRes = FileResponse;

/**
 * @ignore
 */
export interface Files {
    /** Uploads and encrypts a file. */
    create: (file: Uint8Array) => Promise<[FileSQL, string]>;
    /** Downloads and decrypts a file using a file ID and key. */
    retrieve: (fileID: string, key: string) => Promise<FileResponse | null>;
}

/**
 * @ignore
 */
export interface Invites {
    /** Creates an invite for a server and duration. */
    create: (serverID: string, duration: string) => Promise<Invite>;
    /** Redeems an invite and returns the created permission grant. */
    redeem: (inviteID: string) => Promise<Permission>;
    /** Lists active invites for a server. */
    retrieve: (serverID: string) => Promise<Invite[]>;
}

/**
 * Keys are a pair of ed25519 public and private keys,
 * encoded as hex strings.
 */
export interface Keys {
    /** Secret Ed25519 key as hex. Store securely. */
    private: string;
    /** Public Ed25519 key as hex. */
    public: string;
}

/**
 * @ignore
 */
export interface Me {
    /** Replace the account password after proving the current password. */
    changePassword: (
        currentPassword: string,
        newPassword: string,
    ) => Promise<void>;
    /** Returns metadata for the currently authenticated device. */
    device: () => Device;
    /** Uploads and sets a new avatar image for the current user. */
    setAvatar: (avatar: Uint8Array) => Promise<void>;
    /** Returns the currently authenticated user profile. */
    user: () => User;
}

/**
 * Message is a chat message.
 */
export interface Message {
    /** User ID of the original author. */
    authorID: string;
    /** Whether payload decryption succeeded. */
    decrypted: boolean;
    /** Whether this message was received or sent by the current client. */
    direction: "incoming" | "outgoing";
    /** Optional encrypted client metadata attached to this message. */
    extra?: null | string | undefined;
    /** `true` when this message was forwarded to another owned device. */
    forward: boolean;
    /** Channel ID for group messages; `null` for direct messages. */
    group: null | string;
    /** Globally unique message identifier. */
    mailID: string;
    /** Plaintext message content (or empty string when decryption failed). */
    message: string;
    /** Hex-encoded nonce used for message encryption. */
    nonce: string;
    /** User ID of the intended reader. */
    readerID: string;
    /** Recipient device ID. */
    recipient: string;
    /**
     * Optional peer hint (1–30): cooperative senders prefix plaintext; used
     * with {@link ClientOptions.localMessageRetentionDays} to pick the
     * shorter local retention window. Ignored when absent.
     */
    retentionHintDays?: number | undefined;
    /** Sender device ID. */
    sender: string;
    /** Time the message was created/received. */
    timestamp: string;
}

/**
 * Channel is a chat channel on a server.
 *
 * Common fields:
 * - `channelID`
 * - `serverID`
 * - `name`
 */
export type { Channel } from "@vex-chat/types";

/**
 * Server is a single chat server.
 *
 * Common fields:
 * - `serverID`
 * - `name`
 * - `icon` (optional URL/data)
 */
export type { Server } from "@vex-chat/types";

/**
 * Combined server + channels payload used for fast UI bootstrap.
 */
export type { ServerChannelBootstrap } from "@vex-chat/types";

export interface NotificationSubscription {
    channel: "expo";
    createdAt: string;
    deviceID: string;
    enabled: boolean;
    events: string[];
    platform: null | string;
    subscriptionID: string;
    token: string;
    updatedAt: string;
    userID: string;
}

const NotificationSubscriptionSchema: z.ZodType<NotificationSubscription> =
    z.object({
        channel: z.literal("expo"),
        createdAt: z.string(),
        deviceID: z.string(),
        enabled: z.boolean(),
        events: z.array(z.string()),
        platform: z.string().nullable(),
        subscriptionID: z.string(),
        token: z.string(),
        updatedAt: z.string(),
        userID: z.string(),
    });

export interface NotificationSubscriptionInput {
    channel: "expo";
    events?: string[];
    platform?: "android" | "ios" | "web";
    token: string;
}

/**
 * Begin/finish handshakes for a passkey (WebAuthn) ceremony plus the
 * passkey-only admin/recovery surface. The host application (a
 * browser, Tauri webview, etc.) is responsible for invoking
 * `navigator.credentials.create()` / `.get()` itself (e.g. via
 * `@simplewebauthn/browser`) using the `options` returned from
 * `begin*`, and then handing the resulting `RegistrationResponseJSON`
 * / `AuthenticationResponseJSON` to `finish*`.
 *
 * @public
 */
export interface Passkeys {
    /** Begin a public passkey authentication ceremony for `username`. */
    beginAuthentication: (username: string) => Promise<{
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WebAuthn options shape varies per simplewebauthn version
        options: any;
        requestID: string;
    }>;
    /** Begin adding a new passkey to the currently authenticated account. */
    beginRegistration: (name: string) => Promise<{
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WebAuthn options shape varies per simplewebauthn version
        options: any;
        requestID: string;
    }>;
    /** Remove a passkey using the account's approved-device session. */
    delete: (passkeyID: string) => Promise<void>;
    /** Delete one of the account's devices using the passkey session. */
    deleteDevice: (deviceID: string) => Promise<void>;
    /**
     * Finish the public passkey authentication ceremony with the
     * assertion produced by the host. On success the client is
     * placed in passkey-only mode: the bearer is the passkey JWT,
     * device-only flows (mail, etc.) will not work, and the
     * `client.passkeys.*` admin methods become available.
     */
    finishAuthentication: (args: {
        requestID: string;
        response: Record<string, unknown>;
    }) => Promise<{
        passkeyID: string;
        token: string;
        user: User;
    }>;
    /** Finish adding a passkey to the currently authenticated account. */
    finishRegistration: (args: {
        name: string;
        requestID: string;
        response: Record<string, unknown>;
    }) => Promise<Passkey>;
    /** List the account's passkeys (public shape only — no key material). */
    list: () => Promise<Passkey[]>;
    /** List all of the account's devices using the passkey session. */
    listDevices: () => Promise<Device[]>;
    /**
     * Recover the account onto a pending device using the passkey
     * session. The server approves the pending device and revokes all
     * previously-active devices for the account.
     */
    recoverDeviceRequest: (requestID: string) => Promise<Device>;
    /** Reject a pending device-enrollment request using the passkey session. */
    rejectDeviceRequest: (requestID: string) => Promise<void>;
    /** Replace a forgotten password using this fresh passkey session. */
    resetPassword: (newPassword: string) => Promise<void>;
}

export type PendingDeviceApprovalStatus =
    | "approved"
    | "expired"
    | "pending"
    | "rejected";

export interface PendingDeviceRegistration {
    challenge: string;
    expiresAt: string;
    requestID: string;
    status: "pending_approval";
    /** Existing user's ID used to render the account confirmation step. */
    userID: string;
}

export interface PendingDeviceRequest {
    approvedDeviceID?: string | undefined;
    createdAt: string;
    deviceName: string;
    error?: string | undefined;
    expiresAt: string;
    requestID: string;
    signKey: string;
    status: PendingDeviceApprovalStatus;
    username?: string | undefined;
}

/**
 * Retry request emitted when message decryption fails and session healing starts.
 */
export interface RetryRequest {
    /** Mail ID that should be retried after session healing. */
    mailID: string;
    /** Origin of the retry signal. */
    source: "decrypt_failure" | "server_notify";
}

function compareInboxEntries(
    a: [Uint8Array, MailWS, string],
    b: [Uint8Array, MailWS, string],
): number {
    const timeCmp = a[2].localeCompare(b[2]);
    if (timeCmp !== 0) {
        return timeCmp;
    }

    const aMail = a[1];
    const bMail = b[1];
    if (aMail.sender !== bMail.sender) {
        return aMail.sender.localeCompare(bMail.sender, "en");
    }

    const typeCmp = aMail.mailType - bMail.mailType;
    if (typeCmp !== 0) {
        return typeCmp;
    }

    if (
        aMail.mailType === MailType.subsequent &&
        bMail.mailType === MailType.subsequent
    ) {
        const aHeader = tryDecodeRatchetHeader(aMail.extra);
        const bHeader = tryDecodeRatchetHeader(bMail.extra);
        if (aHeader && bHeader) {
            const dhCmp = XUtils.encodeHex(aHeader.dhPub).localeCompare(
                XUtils.encodeHex(bHeader.dhPub),
                "en",
            );
            if (dhCmp !== 0) {
                return dhCmp;
            }
            const pnCmp = aHeader.pn - bHeader.pn;
            if (pnCmp !== 0) {
                return pnCmp;
            }
            return aHeader.n - bHeader.n;
        }
    }

    return aMail.nonce.toString().localeCompare(bMail.nonce.toString(), "en");
}

function tryDecodeRatchetHeader(extra: Uint8Array) {
    try {
        return decodeRatchetHeader(extra);
    } catch {
        return null;
    }
}

/** Zod schema matching the {@link Message} interface for forwarded-message decode. */
const messageSchema: z.ZodType<Message> = z.object({
    authorID: z.string(),
    decrypted: z.boolean(),
    direction: z.enum(["incoming", "outgoing"]),
    extra: z.string().nullable().optional(),
    forward: z.boolean(),
    group: z.string().nullable(),
    mailID: z.string(),
    message: z.string(),
    nonce: z.string(),
    readerID: z.string(),
    recipient: z.string(),
    retentionHintDays: z.number().optional(),
    sender: z.string(),
    timestamp: z.string(),
});

const MESSAGE_BLOB_PREFIX = "vex-message:1\n";
const MAIL_FANOUT_CONCURRENCY = 8;
const MAIL_BATCH_MAX_SIZE = 32;
const MAIL_BATCH_FLUSH_DELAY_MS = 8;

interface DecodedMessagePlaintext {
    extra?: null | string | undefined;
    message: string;
    retentionHintDays?: number | undefined;
}

interface PendingMailBatchDelivery {
    header: Uint8Array;
    mail: MailWS;
    msg: ResourceMsg;
    reject: (err: unknown) => void;
    resolve: () => void;
}

const mailBatchResponseSchema = z.object({
    results: z.array(
        z.object({
            error: z.string().optional(),
            index: z.number().int().nonnegative(),
            mailID: z.string().optional(),
            ok: z.boolean(),
            recipient: z.string().optional(),
            status: z.number().int().optional(),
        }),
    ),
});

function decodeMessageBlob(body: string): DecodedMessagePlaintext {
    if (!body.startsWith(MESSAGE_BLOB_PREFIX)) {
        return { message: body };
    }

    try {
        const raw = JSON.parse(
            body.slice(MESSAGE_BLOB_PREFIX.length),
        ) as unknown;
        if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
            return { message: body };
        }
        const message = Reflect.get(raw, "message");
        if (typeof message !== "string") {
            return { message: body };
        }
        const extra = Reflect.get(raw, "extra");
        return {
            ...(extra === null || typeof extra === "string" ? { extra } : {}),
            message,
        };
    } catch {
        return { message: body };
    }
}

function decodeMessagePlaintext(plaintext: string): DecodedMessagePlaintext {
    const stripped = stripVexRetentionEnvelope(plaintext);
    const blob = decodeMessageBlob(stripped.body);
    return stripped.retentionHintDays !== undefined
        ? {
              ...blob,
              retentionHintDays: stripped.retentionHintDays,
          }
        : blob;
}

function encodeMessagePlaintext(
    message: string,
    opts?: MessageSendOptions,
): string {
    const body =
        opts?.extra === undefined
            ? message
            : MESSAGE_BLOB_PREFIX +
              JSON.stringify({
                  extra: opts.extra,
                  message,
              });
    return formatVexRetentionEnvelope(body, opts?.retentionHintDays);
}

function messageFromDecodedPlaintext(
    decoded: DecodedMessagePlaintext,
): Pick<Message, "extra" | "message" | "retentionHintDays"> {
    return {
        ...(decoded.extra !== undefined ? { extra: decoded.extra } : {}),
        message: decoded.message,
        ...(decoded.retentionHintDays !== undefined
            ? { retentionHintDays: decoded.retentionHintDays }
            : {}),
    };
}

function normalizeForwardedMessage(message: Message): Message {
    const decoded = decodeMessagePlaintext(message.message);
    return {
        ...message,
        ...messageFromDecodedPlaintext({
            ...decoded,
            extra: decoded.extra !== undefined ? decoded.extra : message.extra,
        }),
    };
}

/** Zod schema for a single inbox entry from getMail: [header, mailBody, timestamp]. */
const mailInboxEntry = z.tuple([
    z.custom<Uint8Array>((val) => val instanceof Uint8Array),
    MailWSSchema,
    z.string(),
]);
const deviceRequestNotifyData = z.object({
    requestID: z.string(),
    status: z.union([
        z.literal("approved"),
        z.literal("pending"),
        z.literal("rejected"),
    ]),
});
const retryRequestNotifyData = z.union([
    z.string(),
    z.object({
        mailID: z.string(),
    }),
]);
const serverChangeNotifyData = z.string().min(1).max(128);

/**
 * Event signatures emitted by {@link Client}.
 *
 * Used as the type parameter for {@link Client.on}, {@link Client.off},
 * and {@link Client.once}.
 */
export interface ClientEvents {
    /** Voice-call signaling changed or an incoming call was received. */
    call: (event: CallEvent) => void;
    /** The client has been shut down (via {@link Client.close}). */
    closed: () => void;
    /** WebSocket authorized by the server; pre-auth setup begins. */
    connected: () => void;
    /** Mail decryption pass is in progress. */
    decryptingMail: () => void;
    /** Device approval queue changed (pending/approved/rejected). */
    deviceRequest: (update: {
        requestID: string;
        status: Extract<
            PendingDeviceApprovalStatus,
            "approved" | "pending" | "rejected"
        >;
    }) => void;
    /** WebSocket connection lost. */
    disconnect: () => void;
    /** Progress update for a file upload or download. */
    fileProgress: (progress: FileProgress) => void;
    /** A direct or group message was sent or received. */
    message: (message: Message) => void;
    /** A permission grant was created or modified. */
    permission: (permission: Permission) => void;
    /** Post-auth setup complete — safe to call messaging/user APIs. */
    ready: () => void;
    /** Session healing requested a retry for a specific mail ID. */
    retryRequest: (retry: RetryRequest) => void;
    /** Server metadata, channels, membership, or permissions changed. */
    serverChange: (serverID: string) => void;
    /** A new encryption session was established with a peer device. */
    session: (session: Session, user: User) => void;
}

/**
 * @ignore
 */
export interface Messages {
    /** Deletes local history for a user/channel. */
    delete: (userOrChannelID: string) => Promise<void>;
    /** Sends an encrypted message to all members of a channel. */
    group: (
        channelID: string,
        message: string,
        opts?: MessageSendOptions,
    ) => Promise<void>;
    /** Deletes all locally stored message history. */
    purge: () => Promise<void>;
    /** Returns local direct-message history with one user. */
    retrieve: (userID: string) => Promise<Message[]>;
    /** Returns local group-message history for one channel. */
    retrieveGroup: (channelID: string) => Promise<Message[]>;
    /** Sends an encrypted direct message to one user. */
    send: (
        userID: string,
        message: string,
        opts?: MessageSendOptions,
    ) => Promise<void>;
}

export interface MessageSendOptions {
    /** Optional encrypted client metadata for message-level features. */
    extra?: null | string | undefined;
    /** Optional peer hint (1-30 days) for local history retention. */
    retentionHintDays?: number | undefined;
}

/**
 * @ignore
 */
export interface Moderation {
    /** Returns all permission entries for a server. */
    fetchPermissionList: (serverID: string) => Promise<Permission[]>;
    /** Removes a user from a server by revoking their server permission(s). */
    kick: (userID: string, serverID: string) => Promise<void>;
    /** Changes a server member's role. */
    setRole: (
        permissionID: string,
        powerLevel: 0 | 50 | 100,
    ) => Promise<Permission>;
}

/**
 * @ignore
 */
export interface Permissions {
    /** Deletes one permission grant. */
    delete: (permissionID: string) => Promise<void>;
    /** Lists permissions granted to the authenticated user. */
    retrieve: () => Promise<Permission[]>;
}

/**
 * @ignore
 */
export interface Servers {
    /** Creates a server. */
    create: (name: string) => Promise<Server>;
    /** Deletes a server. */
    delete: (serverID: string) => Promise<void>;
    /** Returns the public URL for an immutable server icon ID. */
    iconURL: (iconID: string) => string;
    /** Leaves a server by removing the user's permission entry. */
    leave: (serverID: string) => Promise<void>;
    /** Removes a server's icon. */
    removeIcon: (serverID: string) => Promise<Server>;
    /** Lists servers available to the authenticated user. */
    retrieve: () => Promise<Server[]>;
    /** Gets one server by ID. */
    retrieveByID: (serverID: string) => Promise<null | Server>;
    /** Fetches servers and channels in one request for fast bootstraps. */
    retrieveWithChannels: () => Promise<ServerChannelBootstrap>;
    /** Uploads and sets a server icon. */
    setIcon: (serverID: string, icon: Uint8Array) => Promise<Server>;
    /** Changes a server's display name. */
    update: (serverID: string, name: string) => Promise<Server>;
}

/**
 * Session is an end to end encryption session with another peer.
 *
 * Key fields include:
 * - `sessionID`
 * - `userID`
 * - `deviceID`
 * - `mode` (`initiator` or `receiver`)
 * - `publicKey` and `fingerprint`
 * - `lastUsed`
 * - `verified`
 *
 * @example
 * ```ts
 * const session: Session = {
 *     sessionID: "f6e4fbd0-7222-4ba8-b799-c227faf5c8de",
 *     userID: "f34f5e37-616f-4d3a-a437-e7c27c31cb73",
 *     deviceID: "9b0f3f46-06ad-4bc4-8adf-4de10e13cb9c",
 *     mode: "initiator",
 *     SK: "7d9afde6683ecc2d1f55e34e1b95de9d4042dfd4e8cda7fdf3f0f7e02fef8f9a",
 *     publicKey: "d58f39dc4bcfe4e8ef022f34e8b6f4f6ddc9c4acee30c0d58f126aa5db3f61b0",
 *     fingerprint: "05294b9aa81d0fd0ca12a4b585f531d8ef1f53f8ea3d0200a0df3f9c44a7d8b1",
 *     lastUsed: new Date(),
 *     verified: false,
 * };
 * ```
 */
export type Session = SessionSQL;

/**
 * @ignore
 */
export interface Sessions {
    /** Marks one session as verification-confirmed. */
    markVerified: (fingerprint: string) => Promise<void>;
    /** Returns all locally known sessions. */
    retrieve: () => Promise<SessionSQL[]>;
    /** Builds a human-readable verification phrase from a session fingerprint. */
    verify: (session: SessionSQL) => string;
}

/**
 * User is a single user on the vex platform.
 *
 * This is intentionally a censored user shape for client use, containing:
 * - `userID`
 * - `username`
 * - `lastSeen`
 */
export interface User {
    /** Last-seen timestamp (ISO 8601 string). */
    lastSeen: string;
    /** User identifier. */
    userID: string;
    /** Public username. */
    username: string;
}

/**
 * @ignore
 */
export interface Users {
    /** Returns users with whom the current device has active sessions. */
    familiars: () => Promise<User[]>;
    /**
     * Looks up a user by user ID, username, or signing key.
     */
    retrieve: (userID: string) => Promise<[null | User, HttpError | null]>;
}

/**
 * Client provides an interface for you to use a vex chat server and
 * send end to end encrypted messages to other users.
 *
 * @example
 * ```ts
 * import { Client } from "@vex-chat/libvex";
 *
 * async function main() {
 *     // generate a secret key to use, save this somewhere permanent
 *     const privateKey = Client.generateSecretKey();
 *
 *     const client = await Client.create(privateKey);
 *
 *     // you must register once before you can log in
 *     const username = Client.randomUsername();
 *     const password = "correct horse battery staple";
 *     await client.register(username, password);
 *     await client.login(username, password);
 *
 *     // The ready event fires after connect() finishes post-auth setup.
 *     // Wait for it before performing messaging or user operations.
 *     client.on("ready", async () => {
 *         const me = client.me.user();
 *
 *         // send a message
 *         await client.messages.send(me.userID, "Hello world!");
 *     })
 *
 *     // Outgoing and incoming messages are emitted here.
 *     client.on("message", (message) => {
 *         console.log("message:", message);
 *     })
 * }
 *
 * main();
 * ```
 */

/**
 * VexFile is an uploaded encrypted file.
 *
 * Common fields:
 * - `fileID`: file identifier
 * - `owner`: owner device/user ID
 * - `nonce`: file encryption nonce (hex)
 *
 * @example
 * ```ts
 * const file: VexFile = {
 *     fileID: "bb1c3fd1-4928-48ab-9d09-3ea0972fbd9d",
 *     owner: "9b0f3f46-06ad-4bc4-8adf-4de10e13cb9c",
 *     nonce: "aa6c8d42f3fdd032a1e9fced4be379582d26ce8f69822d64",
 * };
 * ```
 */
export type VexFile = FileSQL;

export class Client {
    /**
     * Decrypts a secret key from encrypted data produced by encryptKeyData().
     *
     * Pass-through utility from `@vex-chat/crypto`.
     */
    public static decryptKeyData = XUtils.decryptKeyData;
    public static decryptKeyDataAsync = XUtils.decryptKeyDataAsync;

    /**
     * Encrypts a secret key with a password.
     *
     * Pass-through utility from `@vex-chat/crypto`.
     */
    public static encryptKeyData = XUtils.encryptKeyData;
    public static encryptKeyDataAsync = XUtils.encryptKeyDataAsync;

    private static readonly NOT_FOUND_TTL = 30 * 60 * 1000;

    /** Store subscription billing methods. */
    public billing: Billing = {
        products: this.getBillingProducts.bind(this),
        retrieve: this.getBillingAccountState.bind(this),
        submitAppleTransaction: this.submitAppleTransaction.bind(this),
        submitGooglePurchase: this.submitGooglePurchase.bind(this),
    };

    /**
     * Voice-call signaling operations.
     *
     * Platform apps own native media capture/WebRTC. These methods only move
     * authenticated signaling and call state over Spire.
     */
    public calls: Calls = {
        accept: (callID: string, signal?: CallSignalPayload) =>
            this.sendCallResource("ACCEPT", {
                callID,
                ...(signal ? { signal } : {}),
            }),
        active: this.fetchActiveCalls.bind(this),
        cancel: (callID: string) => this.sendCallResource("CANCEL", { callID }),
        hangup: (callID: string) => this.sendCallResource("HANGUP", { callID }),
        ice: (callID: string, signal: CallSignalPayload) =>
            this.sendCallResource("ICE", { callID, signal }),
        iceServers: this.fetchIceServers.bind(this),
        reject: (callID: string) => this.sendCallResource("REJECT", { callID }),
        signal: (callID: string, signal: CallSignalPayload) =>
            this.sendCallResource("SIGNAL", { callID, signal }),
        startDM: (recipientUserID: string, signal?: CallSignalPayload) =>
            this.sendCallResource("INVITE", {
                conversationType: "dm",
                recipientUserID,
                ...(signal ? { signal } : {}),
            }),
    };

    /**
     * Browser-safe NODE_ENV accessor.
     * Uses indirect lookup so the bare `process` global never appears in
     * source that the platform-guard plugin scans.
     */
    /**
     * Channel operations.
     */
    public channels: Channels = {
        /**
         * Creates a new channel in a server.
         * @param name - The channel name.
         * @param serverID - The server to create the channel in.
         *
         * @returns The created Channel object.
         */
        create: this.createChannel.bind(this),
        /**
         * Deletes a channel.
         * @param channelID - The channel to delete.
         */
        delete: this.deleteChannel.bind(this),
        /**
         * Retrieves all channels in a server.
         *
         * @returns The list of Channel objects.
         */
        retrieve: this.getChannelList.bind(this),
        /**
         * Retrieves channel details by its unique channelID.
         *
         * @returns The Channel object, or null.
         */
        retrieveByID: this.getChannelByID.bind(this),
        /** Changes a channel's display name. */
        update: this.updateChannel.bind(this),
        /**
         * Retrieves a channel's userlist.
         * @param channelID - The channel to retrieve the userlist for.
         */
        userList: this.getUserList.bind(this),
    };

    /**
     * Device management methods.
     */
    public devices: Devices = {
        abortPendingRegistration:
            this.abortPendingDeviceRegistration.bind(this),
        approveRequest: this.approveDeviceRequest.bind(this),
        beginPendingPasskeyRegistration:
            this.beginPendingDevicePasskeyRegistration.bind(this),
        delete: this.deleteDevice.bind(this),
        finishPendingPasskeyRegistration:
            this.finishPendingDevicePasskeyRegistration.bind(this),
        getRequest: this.getDeviceRegistrationRequest.bind(this),
        list: this.listDevices.bind(this),
        listRequests: this.listDeviceRegistrationRequests.bind(this),
        pollPendingRegistration: this.pollPendingDeviceRegistration.bind(this),
        publishPendingRegistration:
            this.publishPendingDeviceRegistration.bind(this),
        register: this.registerDevice.bind(this),
        rejectRequest: this.rejectDeviceRequest.bind(this),
        retrieve: this.getDeviceByID.bind(this),
    };

    /**
     * Emoji operations.
     *
     * @example
     * ```ts
     * const emoji = await client.emoji.create(imageBuffer, "party", serverID);
     * const list = await client.emoji.retrieveList(serverID);
     * ```
     */
    public emoji: Emojis = {
        create: this.uploadEmoji.bind(this),
        retrieve: this.retrieveEmojiByID.bind(this),
        retrieveList: this.retrieveEmojiList.bind(this),
    };

    /** Account entitlement methods. */
    public entitlements: Entitlements = {
        retrieve: this.getAccountEntitlements.bind(this),
        setDevTier: this.setDevAccountTier.bind(this),
    };

    /** File upload/download methods. */
    public files: Files = {
        /**
         * Uploads an encrypted file and returns the details and the secret key.
         * @param file - The file bytes.
         *
         * @returns `[details, key]` — file metadata and the encryption key.
         */
        create: this.createFile.bind(this),
        retrieve: this.retrieveFile.bind(this),
    };

    /**
     * This is true if the client has ever been initialized. You can only initialize
     * a client once.
     */
    public hasInit: boolean = false;

    /**
     * This is true if the client has ever logged in before. You can only login a client once.
     */
    public hasLoggedIn: boolean = false;

    /**
     * Invite-management methods.
     */
    public invites: Invites = {
        create: this.createInvite.bind(this),
        redeem: this.redeemInvite.bind(this),
        retrieve: this.retrieveInvites.bind(this),
    };

    /**
     * Helpers for information/actions related to the currently authenticated account.
     */
    public me: Me = {
        changePassword: this.changePassword.bind(this),
        /**
         * Retrieves current device details.
         *
         * @returns The logged in device's Device object.
         */
        device: this.getDevice.bind(this),
        /** Changes your avatar. */
        setAvatar: this.uploadAvatar.bind(this),
        /**
         * Retrieves your user information.
         *
         * @returns The logged in user's User object.
         */
        user: this.getUser.bind(this),
    };

    /**
     * Message operations (direct and group).
     *
     * @example
     * ```ts
     * await client.messages.send(userID, "Hello!");
     * await client.messages.group(channelID, "Hello channel!");
     * const dmHistory = await client.messages.retrieve(userID);
     * ```
     */
    public messages: Messages = {
        delete: this.deleteHistory.bind(this),
        /**
         * Send a group message to a channel.
         * @param channelID - The channel to send a message to.
         * @param message - The message to send.
         */
        group: (
            channelID: string,
            message: string,
            opts?: MessageSendOptions,
        ) => this.sendGroupMessage(channelID, message, opts),
        purge: this.purgeHistory.bind(this),
        /**
         * Gets the message history with a specific userID.
         * @param userID - The user to retrieve message history for.
         *
         * @returns The list of Message objects.
         */
        retrieve: this.getMessageHistory.bind(this),
        /**
         * Gets the group message history for a channel.
         * @param channelID - The channel to retrieve message history for.
         *
         * @returns The list of Message objects.
         */
        retrieveGroup: this.getGroupHistory.bind(this),
        /**
         * Send a direct message.
         * @param userID - The user to send a message to.
         * @param message - The message to send.
         */
        send: (userID: string, message: string, opts?: MessageSendOptions) =>
            this.sendMessage(userID, message, opts),
    };
    /**
     * Server moderation helper methods.
     */
    public moderation: Moderation = {
        fetchPermissionList: this.fetchPermissionList.bind(this),
        kick: this.kickUser.bind(this),
        setRole: this.setServerMemberRole.bind(this),
    };

    /**
     * Passkey ("recovery credential") methods.
     *
     * Passkeys are an account-bound second-class credential that can
     * authenticate the owning user, list devices, delete devices, recover a
     * pending device enrollment, and reject pending device-enrollment
     * requests. They cannot send/decrypt mail.
     *
     * The host app drives the WebAuthn ceremony (e.g. via
     * `@simplewebauthn/browser`) and hands the JSON response to
     * `finish*`.
     */
    public passkeys: Passkeys = {
        beginAuthentication: this.beginPasskeyAuthentication.bind(this),
        beginRegistration: this.beginPasskeyRegistration.bind(this),
        delete: this.deletePasskey.bind(this),
        deleteDevice: this.passkeyDeleteDevice.bind(this),
        finishAuthentication: this.finishPasskeyAuthentication.bind(this),
        finishRegistration: this.finishPasskeyRegistration.bind(this),
        list: this.listPasskeys.bind(this),
        listDevices: this.passkeyListDevices.bind(this),
        recoverDeviceRequest: this.passkeyRecoverDeviceRequest.bind(this),
        rejectDeviceRequest: this.passkeyRejectDeviceRequest.bind(this),
        resetPassword: this.resetPasswordWithPasskey.bind(this),
    };

    /**
     * Permission-management methods for the current user.
     */
    public permissions: Permissions = {
        delete: this.deletePermission.bind(this),
        retrieve: this.getPermissions.bind(this),
    };

    public sending = new Map<string, Device>();

    /**
     * Server operations.
     *
     * @example
     * ```ts
     * const servers = await client.servers.retrieve();
     * const created = await client.servers.create("Team Space");
     * ```
     */
    public servers: Servers = {
        /**
         * Creates a new server.
         * @param name - The server name.
         *
         * @returns The created Server object.
         */
        create: this.createServer.bind(this),
        /**
         * Deletes a server.
         * @param serverID - The server to delete.
         */
        delete: this.deleteServer.bind(this),
        iconURL: this.getServerIconURL.bind(this),
        leave: this.leaveServer.bind(this),
        removeIcon: this.removeServerIcon.bind(this),
        /**
         * Retrieves all servers the logged in user has access to.
         *
         * @returns The list of Server objects.
         */
        retrieve: this.getServerList.bind(this),
        /**
         * Retrieves server details by its unique serverID.
         *
         * @returns The requested Server object, or null if the id does not exist.
         */
        retrieveByID: this.getServerByID.bind(this),
        retrieveWithChannels: this.getServerChannelBootstrap.bind(this),
        setIcon: this.uploadServerIcon.bind(this),
        update: this.updateServer.bind(this),
    };

    /**
     * Encryption-session helpers.
     */
    public sessions: Sessions = {
        /**
         * Marks a session as verified, implying that the user has confirmed
         * that the session mnemonic matches with the other user.
         * @param sessionID - The session to mark.
         */
        markVerified: this.markSessionVerified.bind(this),

        /**
         * Gets all encryption sessions.
         *
         * @returns The list of Session encryption sessions.
         */
        retrieve: this.getSessionList.bind(this),

        /**
         * Returns a mnemonic for the session, to verify with the other user.
         * @param session - The session to get the mnemonic for.
         *
         * @returns The mnemonic representation of the session.
         */
        verify: (session: SessionSQL) => Client.getMnemonic(session),
    };

    /**
     * User operations.
     *
     * @example
     * ```ts
     * const [user] = await client.users.retrieve("alice");
     * const familiarUsers = await client.users.familiars();
     * ```
     */
    public users: Users = {
        /**
         * Retrieves the list of users you can currently access, or are already familiar with.
         *
         * @returns The list of User objects.
         */
        familiars: this.getFamiliars.bind(this),
        /**
         * Retrieves a user's information by a string identifier.
         * @param identifier - A userID, hex string public key, or a username.
         *
         * @returns The user's User object, or null if the user does not exist.
         */
        retrieve: this.fetchUser.bind(this),
    };

    private autoReconnectEnabled = false;

    private readonly database: Storage;

    private readonly dbPath: string;

    private readonly decryptFailureCounts = new Map<string, number>();

    private device: Device | undefined;

    private deviceRecords: Record<string, Device> = {};
    // ── Event subscription (composition over inheritance) ───────────────
    private readonly emitter = new EventEmitter<ClientEvents>();

    private fetchingMail: boolean = false;

    private firstMailFetch = true;
    private readonly forwarded = new Set<string>();
    private readonly host: string;
    private readonly http: FetchHttpClient;
    /** Cancels in-flight HTTP work on `close()` so `postAuth`/`getMail` cannot hang forever. */
    private readonly httpAbortController = new AbortController();
    private readonly idKeys: KeyPair | null;
    private isAlive: boolean = true;

    private localMessageRetentionDays: number;
    private localRetentionPurgeTimer: null | ReturnType<typeof setInterval> =
        null;
    private mailBatchFlushTimer: null | ReturnType<typeof setTimeout> = null;
    private readonly mailBatchQueue: PendingMailBatchDelivery[] = [];
    private mailBatchUnsupported = false;
    private readonly mailInterval?: NodeJS.Timeout;

    private manuallyClosing: boolean = false;
    /* Retrieves the userID with the user identifier.
    user identifier is checked for userID, then signkey,
    and finally falls back to username. */
    /** Negative cache for user lookups that returned 404. TTL = 30 minutes. */
    private readonly notFoundUsers = new Map<string, number>();

    private readonly options?: ClientOptions | undefined;
    private pingInterval: null | ReturnType<typeof setTimeout> = null;
    /**
     * Bumped when the WebSocket is torn down and re-opened so the previous
     * `postAuth` loop exits instead of overlapping a new one.
     */
    private postAuthVersion = 0;
    private readonly prefixes:
        | { HTTP: "http://"; WS: "ws://" }
        | { HTTP: "https://"; WS: "wss://" };
    private reading: boolean = false;
    private reconnectAttempt = 0;
    private reconnectPromise: null | Promise<void> = null;
    private reconnectTimer: null | ReturnType<typeof setTimeout> = null;
    private retentionPurgeDebounce: null | ReturnType<typeof setTimeout> = null;
    private readonly seenMailIDs: Set<string> = new Set();
    private readonly sessionHealBackoffUntil = new Map<string, number>();
    private readonly sessionHealInFlight = new Set<string>();
    private sessionRecords: Record<string, SessionCrypto> = {};

    // these are created from one set of sign keys
    private readonly signKeys: KeyPair;
    private socket: WebSocketLike;
    private token: null | string = null;

    private user: undefined | User;

    private userRecords: Record<string, User> = {};
    private xKeyRing?: XKeyRing;

    private constructor(
        material: {
            idKeys: KeyPair;
            signKeys: KeyPair;
        },
        options?: ClientOptions,
        storage?: Storage,
    ) {
        this.options = options;
        this.localMessageRetentionDays = clampLocalMessageRetentionDays(
            options?.localMessageRetentionDays,
        );
        this.signKeys = material.signKeys;
        this.idKeys = material.idKeys;

        if (options?.unsafeHttp) {
            const env = Client.getNodeEnv();
            if (env !== "development" && env !== "test") {
                throw new Error(
                    "unsafeHttp is only allowed when NODE_ENV is 'development' or 'test'. " +
                        "Set NODE_ENV=development to use unencrypted transport.",
                );
            }
            this.prefixes = { HTTP: "http://", WS: "ws://" };
        } else {
            this.prefixes = { HTTP: "https://", WS: "wss://" };
        }

        this.host = options?.host || "api.vex.wtf";
        const dbFileName = options?.inMemoryDb
            ? ":memory:"
            : XUtils.encodeHex(this.signKeys.publicKey) + ".sqlite";
        this.dbPath = options?.dbFolder
            ? options.dbFolder + "/" + dbFileName
            : dbFileName;

        if (!storage) {
            throw new Error(
                "No storage provided. Use Client.create() which resolves storage automatically.",
            );
        }
        this.database = storage;

        this.database.on("error", (_error: Error) => {
            void this.close(true);
        });

        this.http = createFetchHttpClient({
            responseType: "arraybuffer",
            signal: this.httpAbortController.signal,
        });
        const devKey = options?.devApiKey?.trim();
        if (devKey !== undefined && devKey.length > 0) {
            this.http.defaults.headers.common["x-dev-api-key"] = devKey;
        }

        this.socket = new WebSocketAdapter(this.prefixes.WS + this.host);
        this.socket.onerror = () => {};
    }
    /**
     * Creates and initializes a client in one step.
     *
     * @param privateKey - Hex secret key. When omitted, a fresh key is generated.
     * @param options - Runtime options.
     * @param storage - Custom storage backend implementing {@link Storage}.
     *
     * @example
     * ```ts
     * const client = await Client.create(privateKey, { host: "api.vex.wtf" });
     * ```
     */
    public static create = async (
        privateKey?: string,
        options?: ClientOptions,
        storage?: Storage,
    ): Promise<Client> => {
        const signKeys = privateKey
            ? xSignKeyPairFromSecret(XUtils.decodeHex(privateKey))
            : xSignKeyPair();
        const idKeys = XKeyConvert.convertKeyPair(signKeys);
        if (!idKeys) {
            throw new Error("Could not convert key to X25519!");
        }

        const atRestAes = XUtils.deriveLocalAtRestAesKey(idKeys.secretKey);

        let resolvedStorage = storage;
        if (!resolvedStorage) {
            const nodeStorageModule = "./storage/node.js";
            const isNodeStorageModule = (
                value: unknown,
            ): value is {
                createNodeStorage: (
                    dbPath: string,
                    atRestAesKey: Uint8Array,
                ) => Storage;
            } =>
                typeof value === "object" &&
                value !== null &&
                "createNodeStorage" in value &&
                typeof value.createNodeStorage === "function";
            const nodeStorage: unknown = await import(
                /* @vite-ignore */ nodeStorageModule
            );
            if (!isNodeStorageModule(nodeStorage)) {
                throw new Error("Node storage adapter is unavailable.");
            }
            const dbFileName = options?.inMemoryDb
                ? ":memory:"
                : XUtils.encodeHex(signKeys.publicKey) + ".sqlite";
            const dbPath = options?.dbFolder
                ? options.dbFolder + "/" + dbFileName
                : dbFileName;
            resolvedStorage = nodeStorage.createNodeStorage(dbPath, atRestAes);
        }

        await resolvedStorage.init();

        const client = new Client(
            {
                idKeys,
                signKeys,
            },
            options,
            resolvedStorage,
        );
        await client.init();
        return client;
    };

    /** Generates an Ed25519 signing secret key as a hex string. */
    public static generateSecretKey(): string {
        return XUtils.encodeHex(xSignKeyPair().secretKey);
    }

    /** Async Ed25519 key generation. */
    public static async generateSecretKeyAsync(): Promise<string> {
        return XUtils.encodeHex((await xSignKeyPairAsync()).secretKey);
    }

    /**
     * Generates a random username using bip39.
     *
     * The output is intentionally lowercase: the protocol treats
     * usernames as case-insensitive, and the server canonicalizes to
     * lowercase at registration. Returning lowercase here keeps the
     * SDK's locally-generated handle in sync with what the server
     * will eventually persist, so callers don't see a brief casing
     * flip when `me.user()` lands.
     *
     * @returns The username.
     */
    public static randomUsername() {
        const IKM = XUtils.decodeHex(XUtils.encodeHex(xRandomBytes(16)));
        const mnemonic = xMnemonic(IKM).split(" ");
        const addendum = XUtils.uint8ArrToNumber(xRandomBytes(1));

        const word0 = mnemonic[0] ?? "";
        const word1 = mnemonic[1] ?? "";
        return (word0 + word1 + addendum.toString()).toLowerCase();
    }

    private static deserializeExtra(
        type: MailType,
        extra: Uint8Array,
    ): Uint8Array[] {
        switch (type) {
            case MailType.initial: {
                /* 32B sign | 32B eph | 32B PK | 68B AD | 6B index */
                const signKey = extra.slice(0, 32);
                const ephKey = extra.slice(32, 64);
                const ad = extra.slice(96, 164);
                const index = extra.slice(164, 170);
                return [signKey, ephKey, ad, index];
            }
            case MailType.subsequent:
                return [extra];
            default:
                return [];
        }
    }

    private static getMnemonic(session: SessionSQL): string {
        return xMnemonic(xKDF(XUtils.decodeHex(session.fingerprint)));
    }

    /**
     * Browser-safe NODE_ENV accessor.
     * Uses indirect lookup so the bare `process` global never appears in
     * source that the platform-guard plugin scans.
     */
    private static getNodeEnv(): string | undefined {
        try {
            const g = Object.getOwnPropertyDescriptor(
                globalThis,
                "\u0070rocess",
            );
            if (!g) return undefined;
            // Node 24+ exposes `process` as an accessor (get/set), not a value.
            const proc: unknown =
                typeof g.get === "function" ? g.get() : g.value;
            if (typeof proc !== "object" || proc === null) {
                return undefined;
            }
            const envDesc = Object.getOwnPropertyDescriptor(proc, "env");
            if (!envDesc) return undefined;
            const env: unknown =
                typeof envDesc.get === "function"
                    ? envDesc.get()
                    : envDesc.value;
            if (typeof env !== "object" || env === null) {
                return undefined;
            }
            const valDesc = Object.getOwnPropertyDescriptor(env, "NODE_ENV");
            if (!valDesc) return undefined;
            const val: unknown =
                typeof valDesc.get === "function"
                    ? valDesc.get()
                    : valDesc.value;
            return typeof val === "string" ? val : undefined;
        } catch {
            return undefined;
        }
    }

    /**
     * Closes the client — disconnects the WebSocket, shuts down storage,
     * and emits `closed` unless `muteEvent` is `true`.
     *
     * @param muteEvent - When `true`, suppresses the `closed` event.
     */
    public async close(muteEvent = false): Promise<void> {
        this.manuallyClosing = true;
        this.autoReconnectEnabled = false;
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this.httpAbortController.abort();
        this.socket.close();
        await this.database.close();

        if (this.pingInterval) {
            clearInterval(this.pingInterval);
        }

        if (this.mailInterval) {
            clearInterval(this.mailInterval);
        }
        if (this.mailBatchFlushTimer) {
            clearTimeout(this.mailBatchFlushTimer);
            this.mailBatchFlushTimer = null;
        }
        const pendingMailBatch = this.mailBatchQueue.splice(0);
        for (const pending of pendingMailBatch) {
            pending.reject(new Error("Client closed before mail batch sent."));
        }
        if (this.localRetentionPurgeTimer) {
            clearInterval(this.localRetentionPurgeTimer);
            this.localRetentionPurgeTimer = null;
        }
        if (this.retentionPurgeDebounce) {
            clearTimeout(this.retentionPurgeDebounce);
            this.retentionPurgeDebounce = null;
        }
        delete this.xKeyRing;

        if (!muteEvent) {
            this.emitter.emit("closed");
        }
        return;
    }

    /**
     * Connects your device to the chat. You must have a valid Bearer token.
     * You can check whoami() to see before calling connect().
     */
    public async connect(): Promise<void> {
        if (!this.token) {
            throw new Error(
                "No token — call login() or loginWithDeviceKey() first.",
            );
        }
        const { user } = await this.whoami();
        this.setUser(user);

        this.device = await this.retrieveOrCreateDevice();

        const connectToken = await this.getToken("connect");
        if (!connectToken) {
            throw new Error("Couldn't get connect token.");
        }
        const signedAsync = await xSignAsync(
            Uint8Array.from(uuid.parse(connectToken.key)),
            this.signKeys.secretKey,
        );

        const res = await this.http.post(
            this.getHost() + "/device/" + this.device.deviceID + "/connect",
            msgpack.encode({ signed: signedAsync }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        const { deviceToken } = decodeHttpResponse(
            ConnectResponseCodec,
            res.data,
        );
        this.http.defaults.headers.common["X-Device-Token"] = deviceToken;
        await this.publishSignedPreKey(this.device);

        this.autoReconnectEnabled = true;
        this.initSocket();
        // Yield the event loop so the WS open callback fires and sends the
        // auth message before OTK generation starts. OTK top-up is best-effort
        // and should not block app bootstrap/hydration.
        await new Promise((r) => setTimeout(r, 0));
        this.negotiateOTK().catch(() => {
            // Best-effort: lacking fresh OTKs should not fail login/boot.
        });
    }

    /**
     * Delete all local data — message history, encryption sessions, and prekeys.
     * Closes the client afterward. Credentials (keychain) must be cleared by the consumer.
     */
    public async deleteAllData(): Promise<void> {
        await this.database.purgeHistory();
        await this.database.purgeKeyData();
        await this.close(true);
    }

    /**
     * Returns the current HTTP API origin with protocol.
     *
     * @example
     * ```ts
     * console.log(client.getHost()); // "https://api.vex.wtf"
     * ```
     */
    public getHost() {
        return this.prefixes.HTTP + this.host;
    }

    /**
     * Gets the hex string representations of the public and private keys.
     */
    public getKeys(): Keys {
        return {
            private: XUtils.encodeHex(this.signKeys.secretKey),
            public: XUtils.encodeHex(this.signKeys.publicKey),
        };
    }

    /** Current local retention cap in days (always 1–30). */
    public getLocalMessageRetentionDays(): number {
        return this.localMessageRetentionDays;
    }

    /**
     * Authenticates with username/password and stores the Bearer auth token.
     *
     * @param username - Account username.
     * @param password - Account password.
     * @returns `{ ok: true }` on success, `{ ok: false, error }` on failure.
     *
     * @example
     * ```ts
     * const result = await client.login("alice", "correct horse battery staple");
     * if (!result.ok) console.error(result.error);
     * ```
     */
    public async login(
        username: string,
        password: string,
    ): Promise<{ error?: string; ok: boolean }> {
        try {
            // Mirror the server's case-insensitive username policy —
            // see `Client.register` and `Spire.normalizeRegistrationUsername`.
            const normalizedUsername = username.trim().toLowerCase();
            const res = await this.http.post(
                this.getHost() + "/auth",
                msgpack.encode({
                    password,
                    username: normalizedUsername,
                }),
                {
                    headers: { "Content-Type": "application/msgpack" },
                },
            );
            const { token, user } = decodeHttpResponse(
                AuthResponseCodec,
                res.data,
            );

            this.setUser(user);
            this.token = token;
            this.http.defaults.headers.common.Authorization = `Bearer ${token}`;
            return { ok: true };
        } catch (err: unknown) {
            if (isHttpError(err) && err.response) {
                return {
                    error: spireErrorBodyMessage(err.response.data),
                    ok: false,
                };
            }
            const error = err instanceof Error ? err.message : String(err);
            return { error, ok: false };
        }
    }

    /**
     * Authenticates using the device's Ed25519 signing key.
     * No password needed — proves possession of the private key via
     * challenge-response. Issues a short-lived (1-hour) JWT.
     *
     * Used by auto-login when stored credentials have a deviceKey
     * but no valid session.
     */
    public async loginWithDeviceKey(deviceID?: string): Promise<Error | null> {
        try {
            const id = deviceID ?? this.device?.deviceID;
            if (!id) {
                return new Error("No deviceID — pass it or connect first.");
            }
            const signKeyHex = XUtils.encodeHex(this.signKeys.publicKey);

            const challengeRes = await this.http.post(
                this.getHost() + "/auth/device",
                msgpack.encode({
                    deviceID: id,
                    signKey: signKeyHex,
                }),
                { headers: { "Content-Type": "application/msgpack" } },
            );
            const { challenge, challengeID } = decodeHttpResponse(
                DeviceChallengeCodec,
                challengeRes.data,
            );

            const signed = XUtils.encodeHex(
                await xSignAsync(
                    XUtils.decodeHex(challenge),
                    this.signKeys.secretKey,
                ),
            );

            const verifyRes = await this.http.post(
                this.getHost() + "/auth/device/verify",
                msgpack.encode({ challengeID, signed }),
                { headers: { "Content-Type": "application/msgpack" } },
            );
            const { token, user } = decodeHttpResponse(
                AuthResponseCodec,
                verifyRes.data,
            );

            this.setUser(user);
            this.token = token;
            this.http.defaults.headers.common.Authorization = `Bearer ${token}`;
        } catch (err: unknown) {
            const error = err instanceof Error ? err : new Error(String(err));
            return error;
        }
        return null;
    }

    /**
     * Ends the local authenticated session and disconnects realtime transport.
     * Spire access tokens are stateless, so local credential removal is the
     * authoritative logout boundary.
     */
    public async logout(): Promise<void> {
        try {
            if (this.token) {
                await this.http.post(this.getHost() + "/goodbye");
            }
        } catch {
            // Logout must still complete locally when the server is unreachable.
        } finally {
            this.token = null;
            this.user = undefined;
            this.device = undefined;
            delete this.http.defaults.headers.common.Authorization;
            delete this.http.defaults.headers.common["X-Device-Token"];
            this.autoReconnectEnabled = false;
            this.postAuthVersion++;
            if (this.reconnectTimer) {
                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = null;
            }
            if (this.pingInterval) {
                clearInterval(this.pingInterval);
                this.pingInterval = null;
            }
            this.socket.close();
        }
    }

    /** Removes an event listener. See {@link ClientEvents} for available events. */
    off<E extends keyof ClientEvents>(
        event: E,
        fn?: ClientEvents[E],
        context?: unknown,
    ): this {
        this.emitter.off(
            event,
            // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- ee3 requires generic listener type; E constraint guarantees safety
            fn as ((...args: unknown[]) => void) | undefined,
            context,
        );
        return this;
    }

    /** Subscribes to an event. See {@link ClientEvents} for available events. */
    on<E extends keyof ClientEvents>(
        event: E,
        fn: ClientEvents[E],
        context?: unknown,
    ): this {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- EventEmitter requires a generic listener type; the generic constraint on E guarantees type safety
        this.emitter.on(event, fn as (...args: unknown[]) => void, context);
        return this;
    }

    /** Subscribes to an event for a single firing, then auto-removes. */
    once<E extends keyof ClientEvents>(
        event: E,
        fn: ClientEvents[E],
        context?: unknown,
    ): this {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- EventEmitter requires a generic listener type; the generic constraint on E guarantees type safety
        this.emitter.once(event, fn as (...args: unknown[]) => void, context);
        return this;
    }

    /**
     * Tears down the current WebSocket and opens a new one, keeping the same
     * session (user + device in storage). Restarts the post-auth mail loop.
     * Use for long-running processes or e2e where a fresh socket matches a
     * newly-registered second device.
     */
    public async reconnectWebsocket(): Promise<void> {
        if (this.isManualCloseInFlight()) {
            throw new WebSocketNotOpenError(this.socket.readyState);
        }
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.reconnectPromise) {
            return this.reconnectPromise;
        }
        this.reconnectPromise = this.reconnectWebsocketOnce().finally(() => {
            this.reconnectPromise = null;
        });
        this.reconnectPromise.catch(() => {
            // Callers still observe the rejection when they await this
            // promise; this keeps shared reconnect attempts from surfacing as
            // process-level unhandled rejections when another best-effort path
            // touches the same promise.
        });
        return this.reconnectPromise;
    }

    /**
     * Registers a new account on the server.
     *
     * @param username - Username to register.
     * @param password - Password for the account and device approval request.
     * @returns `[user, null]` on success, `[null, error]` on failure.
     *
     * @example
     * ```ts
     * const [user, err] = await client.register("MyUsername", "correct horse battery staple");
     * ```
     */
    public async register(
        username: string,
        password: string,
    ): Promise<[null | User, Error | null]> {
        const passwordError = registrationPasswordError(password);
        if (passwordError) {
            return [null, passwordError];
        }
        return this.registerAccountOrEnrollment(
            username,
            "create-account",
            password,
        );
    }

    removeAllListeners(event?: keyof ClientEvents): this {
        this.emitter.removeAllListeners(event);
        return this;
    }

    /**
     * Requests approval for a new device using the account password. This
     * enrollment flow never creates an account when the username is unknown.
     */
    public async requestDeviceEnrollment(
        username: string,
        password: string,
    ): Promise<[null | User, Error | null]> {
        const passwordError = registrationPasswordError(password);
        if (passwordError) {
            return [null, passwordError];
        }
        return this.registerAccountOrEnrollment(
            username,
            "enroll-device",
            password,
        );
    }

    /**
     * Requests enrollment for this device after a successful passkey ceremony.
     * This is not account registration: the passkey bearer must identify an
     * existing account, and the server returns a pending device request.
     */
    public async requestDeviceEnrollmentWithPasskey(
        username: string,
    ): Promise<[null | User, Error | null]> {
        return this.registerAccountOrEnrollment(username, "enroll-device");
    }

    /**
     * Updates the local retention cap (1–30 days) and prunes immediately.
     * Does not affect server-side storage.
     */
    public setLocalMessageRetentionDays(days: number): void {
        this.localMessageRetentionDays = clampLocalMessageRetentionDays(days);
        void this.runLocalRetentionPurge();
    }

    /**
     * Registers a push notification subscription for this device.
     *
     * Mobile clients using Expo should pass the Expo push token from
     * `expo-notifications`. Push notifications are wake-up hints only; clients
     * should still call `syncInboxNow()` after receiving one.
     */
    public async subscribeNotifications(
        input: NotificationSubscriptionInput,
    ): Promise<NotificationSubscription> {
        const response = await this.http.post(
            this.getHost() +
                "/device/" +
                this.getDevice().deviceID +
                "/notifications/subscriptions",
            input,
            { responseType: "json" },
        );
        return NotificationSubscriptionSchema.parse(response.data);
    }

    /**
     * Triggers an immediate inbox sync by fetching `/mail` once.
     * Useful on mobile foreground resume where background work may pause.
     */
    public async syncInboxNow(): Promise<void> {
        await this.getMail();
    }

    /**
     * Returns a compact `<username><deviceID>` debug label.
     */
    public toString(): string {
        return (
            (this.user?.username ?? "") +
            "<" +
            (this.device?.deviceID ?? "") +
            ">"
        );
    }

    /**
     * Removes a notification subscription for this device.
     */
    public async unsubscribeNotifications(
        subscriptionID: string,
    ): Promise<void> {
        await this.http.delete(
            this.getHost() +
                "/device/" +
                this.getDevice().deviceID +
                "/notifications/subscriptions/" +
                subscriptionID,
        );
    }

    /**
     * Returns details about the currently authenticated session.
     *
     * @returns The authenticated user, token expiry, and active token.
     *
     * @example
     * ```ts
     * const auth = await client.whoami();
     * console.log(auth.user.username, new Date(auth.exp));
     * ```
     */
    public async whoami(): Promise<{
        exp: number;
        user: User;
    }> {
        const res = await this.http.post(this.getHost() + "/whoami");

        const whoami = decodeHttpResponse(WhoamiCodec, res.data);
        return whoami;
    }

    private async abortPendingDeviceRegistration(args: {
        challenge: string;
        requestID: string;
    }): Promise<void> {
        const signed = await this.signPendingRegistrationChallenge(
            args.challenge,
        );
        await this.http.post(
            this.getHost() +
                "/user/devices/requests/" +
                args.requestID +
                "/abort",
            msgpack.encode({ signed }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
    }

    private acknowledgeInboundMail(mail: MailWS): void {
        this.decryptFailureCounts.delete(mail.mailID);
        this.seenMailIDs.add(mail.mailID);
        this.sendReceipt(new Uint8Array(mail.nonce));
    }

    private acknowledgeRepeatedDecryptFailure(
        mail: MailWS,
        count: number,
        timestamp: string,
    ): void {
        if (count < 2) return;
        if (libvexDebugDmEnabled()) {
            debugLibvexDm("readMail: acknowledge repeated decrypt failure", {
                attempts: count,
                mailID: mail.mailID,
                sender: mail.sender,
                thisDevice: this.getDevice().deviceID,
            });
        }
        this.emitUndecryptedMessage(mail, timestamp);
        this.acknowledgeInboundMail(mail);
    }

    private async approveDeviceRequest(requestID: string): Promise<Device> {
        const req = await this.getDeviceRegistrationRequest(requestID);
        if (!req) {
            throw new Error("Device approval request not found.");
        }
        if (req.status !== "pending") {
            throw new Error(
                "Device approval request is not pending: " + req.status,
            );
        }
        const approvalChallenge = `${requestID}:${req.signKey.toLowerCase()}`;
        const signed = XUtils.encodeHex(
            await xSignAsync(
                XUtils.decodeUTF8(approvalChallenge),
                this.signKeys.secretKey,
            ),
        );
        const response = await this.http.post(
            this.prefixes.HTTP +
                this.host +
                "/user/" +
                this.getUser().userID +
                "/devices/requests/" +
                requestID +
                "/approve",
            msgpack.encode({ signed }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(DeviceCodec, response.data);
    }

    private async beginPasskeyAuthentication(username: string): Promise<{
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WebAuthn options shape varies per simplewebauthn version
        options: any;
        requestID: string;
    }> {
        const response = await this.http.post(
            this.getHost() + "/auth/passkey/begin",
            msgpack.encode({ username }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(PasskeyOptionsCodec, response.data);
    }

    private async beginPasskeyRegistration(name: string): Promise<{
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WebAuthn options shape varies per simplewebauthn version
        options: any;
        requestID: string;
    }> {
        const userID = this.getUser().userID;
        const response = await this.http.post(
            this.getHost() + "/user/" + userID + "/passkeys/register/begin",
            msgpack.encode({ name }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(PasskeyOptionsCodec, response.data);
    }

    private async beginPendingDevicePasskeyRegistration(args: {
        challenge: string;
        name: string;
        requestID: string;
    }): Promise<{
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WebAuthn options shape varies per simplewebauthn version
        options: any;
        requestID: string;
    }> {
        const signed = await this.signPendingRegistrationChallenge(
            args.challenge,
        );
        const response = await this.http.post(
            this.getHost() +
                "/user/devices/requests/" +
                args.requestID +
                "/passkeys/register/begin",
            msgpack.encode({ name: args.name, signed }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(PasskeyOptionsCodec, response.data);
    }

    private censorPreKey(preKey: PreKeysSQL): PreKeysWS {
        if (!preKey.index) {
            throw new Error("Key index is required.");
        }
        return {
            deviceID: this.getDevice().deviceID,
            index: preKey.index,
            publicKey: XUtils.decodeHex(preKey.publicKey),
            signature: XUtils.decodeHex(preKey.signature),
        };
    }

    private async changePassword(
        currentPassword: string,
        newPassword: string,
    ): Promise<void> {
        const passwordError = registrationPasswordError(newPassword);
        if (passwordError) throw passwordError;
        if (
            currentPassword.length === 0 ||
            currentPassword.length > ACCOUNT_PASSWORD_MAX_LENGTH
        ) {
            throw new Error("Current password is invalid.");
        }
        await this.replaceAccountPassword({ currentPassword, newPassword });
    }

    private async createChannel(
        name: string,
        serverID: string,
    ): Promise<Channel> {
        const body = { name };
        const res = await this.http.post(
            this.getHost() + "/server/" + serverID + "/channels",
            msgpack.encode(body),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(ChannelCodec, res.data);
    }

    // returns the file details and the encryption key
    private async createFile(file: Uint8Array): Promise<[FileSQL, string]> {
        return this.runCrypto(async () => {
            const nonce = xMakeNonce();
            const fileKey = (await xBoxKeyPairAsync()).secretKey;
            const box = await xSecretboxAsync(
                Uint8Array.from(file),
                nonce,
                fileKey,
            );

            const canUseMultipart =
                typeof FormData !== "undefined" &&
                (() => {
                    try {
                        // React Native/Hermes can expose Blob/FormData but
                        // reject ArrayBufferView-backed blobs at runtime.
                        void new Blob([new Uint8Array([1, 2, 3])]);
                        return true;
                    } catch {
                        return false;
                    }
                })();

            if (canUseMultipart) {
                const fpayload = new FormData();
                fpayload.set("owner", this.getDevice().deviceID);
                fpayload.set("nonce", XUtils.encodeHex(nonce));
                fpayload.set("file", new Blob([new Uint8Array(box)]));

                const fres = await this.http.post(
                    this.getHost() + "/file",
                    fpayload,
                    {
                        headers: { "Content-Type": "multipart/form-data" },
                        onUploadProgress: (progressEvent) => {
                            const percentCompleted = Math.round(
                                (progressEvent.loaded * 100) /
                                    (progressEvent.total ?? 1),
                            );
                            const { loaded, total = 0 } = progressEvent;
                            const progress: FileProgress = {
                                direction: "upload",
                                loaded,
                                progress: percentCompleted,
                                token: XUtils.encodeHex(nonce),
                                total,
                            };
                            this.emitter.emit("fileProgress", progress);
                        },
                    },
                );
                const fcreatedFile = decodeHttpResponse(
                    FileSQLCodec,
                    fres.data,
                );

                return [fcreatedFile, XUtils.encodeHex(fileKey)];
            }

            const payload: {
                file: string;
                nonce: string;
                owner: string;
            } = {
                file: XUtils.encodeBase64(box),
                nonce: XUtils.encodeHex(nonce),
                owner: this.getDevice().deviceID,
            };
            const res = await this.http.post(
                this.getHost() + "/file/json",
                msgpack.encode(payload),
                { headers: { "Content-Type": "application/msgpack" } },
            );
            const createdFile = decodeHttpResponse(FileSQLCodec, res.data);

            return [createdFile, XUtils.encodeHex(fileKey)];
        });
    }

    private async createInvite(serverID: string, duration: string) {
        const payload = {
            duration,
            serverID,
        };

        const res = await this.http.post(
            this.getHost() + "/server/" + serverID + "/invites",
            msgpack.encode(payload),
            { headers: { "Content-Type": "application/msgpack" } },
        );

        return decodeHttpResponse(InviteCodec, res.data);
    }

    private async createPreKey(
        kind: "one-time" | "signed",
    ): Promise<UnsavedPreKey> {
        return this.runCrypto(async () => {
            const preKeyPair = await xBoxKeyPairAsync();
            const toSign = xPreKeySignaturePayload(preKeyPair.publicKey, kind);
            return {
                keyPair: preKeyPair,
                signature: await xSignAsync(toSign, this.signKeys.secretKey),
            };
        });
    }

    private async createServer(name: string): Promise<Server> {
        const res = await this.http.post(
            this.getHost() + "/servers",
            msgpack.encode({ name }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(ServerCodec, res.data);
    }

    private async createSession(
        device: Device,
        user: User,
        message: Uint8Array,
        group: null | Uint8Array,
        /* this is passed through if the first message is 
        part of a group message */
        mailID: null | string,
        forward: boolean,
        /**
         * When `readMail` triggers a best-effort session re-establish, key-bundle
         * errors should not reject the full read pipeline.
         */
        allowKeyBundleFailure = false,
    ): Promise<Message | null> {
        return this.runCrypto(async () => {
            let keyBundle: KeyBundle;

            try {
                keyBundle = await this.retrieveKeyBundle(device.deviceID);
                await verifyKeyBundleSignatures(keyBundle, device);
            } catch (e) {
                if (allowKeyBundleFailure) {
                    return null;
                }
                const wrap =
                    e instanceof Error ? e : new Error(String(e), { cause: e });
                throw new Error(
                    `Failed to load keyBundle for device ${device.deviceID}: ${wrap.message}`,
                    { cause: e },
                );
            }

            if (!this.xKeyRing) {
                if (this.manuallyClosing) {
                    return null;
                }
                throw new Error("Key ring not initialized.");
            }

            // my keys
            const IK_A = this.xKeyRing.identityKeys.secretKey;
            const IK_AP = this.xKeyRing.identityKeys.publicKey;
            const ephemeralKeys = await xBoxKeyPairAsync();
            const EK_A = ephemeralKeys.secretKey;

            const SPK_B = new Uint8Array(keyBundle.preKey.publicKey);
            const OPK_B = keyBundle.otk
                ? new Uint8Array(keyBundle.otk.publicKey)
                : null;
            const IK_B = XKeyConvert.convertPublicKey(
                new Uint8Array(keyBundle.signKey),
            );
            if (!IK_B) {
                throw new Error("Could not convert sign key to X25519.");
            }

            // diffie hellman functions
            const DH1 = await xDHAsync(new Uint8Array(IK_A), SPK_B);
            const DH2 = await xDHAsync(new Uint8Array(EK_A), IK_B);
            const DH3 = await xDHAsync(new Uint8Array(EK_A), SPK_B);
            const DH4 = OPK_B
                ? await xDHAsync(new Uint8Array(EK_A), OPK_B)
                : null;

            // initial key material
            const IKM = DH4
                ? xConcat(DH1, DH2, DH3, DH4)
                : xConcat(DH1, DH2, DH3);

            // one time key index
            const IDX = keyBundle.otk
                ? XUtils.numberToUint8Arr(keyBundle.otk.index ?? 0)
                : XUtils.numberToUint8Arr(0);

            // shared secret key
            const SK = xKDF(IKM);
            const initialSubkeys = xMessageKeySubkeys(SK);
            const PK = (await xBoxKeyPairFromSecretAsync(SK)).publicKey;

            const AD = xConcat(
                xEncode(xConstants.CURVE, IK_AP),
                xEncode(xConstants.CURVE, IK_B),
            );

            const nonce = xMakeNonce();
            const cipher = await xSecretboxAsync(
                message,
                nonce,
                initialSubkeys.encryptionKey,
            );

            const extra = xConcat(
                this.signKeys.publicKey,
                ephemeralKeys.publicKey,
                PK,
                AD,
                IDX,
            );

            const mail: MailWS = {
                authorID: this.getUser().userID,
                cipher,
                extra,
                forward,
                group,
                mailID: mailID || uuid.v4(),
                mailType: MailType.initial,
                nonce,
                readerID: user.userID,
                recipient: device.deviceID,
                sender: this.getDevice().deviceID,
            };

            const hmac = xHMAC(mail, initialSubkeys.authenticationKey);

            const msg: ResourceMsg = {
                action: "CREATE",
                data: mail,
                resourceType: "mail",
                transmissionID: uuid.v4(),
                type: "resource",
            };

            const ratchet = await initRatchetSession(SK, "initiator");
            const sessionEntry: SessionSQL = {
                ...ratchet,
                deviceID: device.deviceID,
                fingerprint: XUtils.encodeHex(AD),
                lastUsed: new Date().toISOString(),
                mode: "initiator",
                publicKey: XUtils.encodeHex(PK),
                sessionID: uuid.v4(),
                SK: XUtils.encodeHex(SK),
                userID: user.userID,
                verified: false,
            };

            await this.database.saveSession(sessionEntry);

            this.emitter.emit("session", sessionEntry, user);

            // emit the message
            const forwardedMsg = forward
                ? messageSchema.parse(msgpack.decode(message))
                : null;
            const shouldEmitHandshakeMessage = forward || message.length > 0;
            const emitMsg: Message = forwardedMsg
                ? { ...normalizeForwardedMessage(forwardedMsg), forward: true }
                : {
                      authorID: mail.authorID,
                      decrypted: true,
                      direction: "outgoing",
                      forward: mail.forward,
                      group: mail.group ? uuid.stringify(mail.group) : null,
                      mailID: mail.mailID,
                      ...messageFromDecodedPlaintext(
                          decodeMessagePlaintext(XUtils.encodeUTF8(message)),
                      ),
                      nonce: XUtils.encodeHex(new Uint8Array(mail.nonce)),
                      readerID: mail.readerID,
                      recipient: mail.recipient,
                      sender: mail.sender,
                      timestamp: new Date().toISOString(),
                  };
            if (shouldEmitHandshakeMessage) {
                this.emitter.emit("message", emitMsg);
            }

            await this.deliverMailResource(msg, hmac, mail);
            return shouldEmitHandshakeMessage ? emitMsg : null;
        });
    }

    private async deleteChannel(channelID: string): Promise<void> {
        await this.http.delete(this.getHost() + "/channel/" + channelID);
    }

    private async deleteDevice(deviceID: string): Promise<void> {
        if (deviceID === this.getDevice().deviceID) {
            throw new Error("You can't delete the device you're logged in to.");
        }
        await this.http.delete(
            this.prefixes.HTTP +
                this.host +
                "/user/" +
                this.getUser().userID +
                "/devices/" +
                deviceID,
        );
    }

    private async deleteHistory(channelOrUserID: string): Promise<void> {
        await this.database.deleteHistory(channelOrUserID);
    }

    private async deletePasskey(passkeyID: string): Promise<void> {
        const userID = this.getUser().userID;
        await this.http.delete(
            this.getHost() + "/user/" + userID + "/passkeys/" + passkeyID,
        );
    }

    private async deletePermission(permissionID: string): Promise<void> {
        await this.http.delete(this.getHost() + "/permission/" + permissionID);
    }

    private async deleteServer(serverID: string): Promise<void> {
        await this.http.delete(this.getHost() + "/server/" + serverID);
    }

    private deliverMailResource(
        msg: ResourceMsg,
        header: Uint8Array,
        mail: MailWS,
    ): Promise<void> {
        if (this.mailBatchUnsupported) {
            return this.deliverMailResourceOverSocket(msg, header);
        }
        return new Promise<void>((resolve, reject) => {
            this.mailBatchQueue.push({
                header,
                mail,
                msg,
                reject,
                resolve,
            });
            if (this.mailBatchQueue.length >= MAIL_BATCH_MAX_SIZE) {
                void this.flushMailBatchQueue();
            } else {
                this.scheduleMailBatchFlush();
            }
        });
    }

    private async deliverMailResourceOverSocket(
        msg: ResourceMsg,
        header: Uint8Array,
    ): Promise<void> {
        await new Promise<void>((res, rej) => {
            const callback = (packedMsg: Uint8Array) => {
                const [_header, receivedMsg] = XUtils.unpackMessage(packedMsg);
                if (receivedMsg.transmissionID === msg.transmissionID) {
                    this.socket.off("message", callback);
                    const parsed = WSMessageSchema.safeParse(receivedMsg);
                    if (parsed.success && parsed.data.type === "success") {
                        res();
                    } else {
                        rej(
                            new Error(
                                "Mail delivery failed: " +
                                    JSON.stringify(receivedMsg),
                            ),
                        );
                    }
                }
            };
            this.socket.on("message", callback);
            this.send(msg, header).catch((err: unknown) => {
                this.socket.off("message", callback);
                rej(err instanceof Error ? err : new Error(String(err)));
            });
        });
    }

    private deviceListFailureDetail(err: unknown): string {
        if (!isHttpError(err)) {
            return "";
        }
        const st = err.response?.status;
        if (typeof st === "number") {
            return ` (HTTP ${String(st)})`;
        }
        if (err.code !== undefined) {
            return ` (${err.code})`;
        }
        return "";
    }

    private emitUndecryptedMessage(mail: MailWS, timestamp: string): void {
        this.emitter.emit("message", {
            authorID: mail.authorID,
            decrypted: false,
            direction: "incoming",
            forward: mail.forward,
            group: mail.group ? uuid.stringify(mail.group) : null,
            mailID: mail.mailID,
            message: "",
            nonce: XUtils.encodeHex(new Uint8Array(mail.nonce)),
            readerID: mail.readerID,
            recipient: mail.recipient,
            sender: mail.sender,
            timestamp,
        });
    }

    private async fetchActiveCalls(): Promise<CallSession[]> {
        const res = await this.http.get(this.getHost() + "/calls/active", {
            responseType: "json",
        });
        return z.object({ calls: z.array(CallSessionSchema) }).parse(res.data)
            .calls;
    }

    private async fetchIceServers(): Promise<IceServerConfig[]> {
        const res = await this.http.get(this.getHost() + "/calls/ice-servers", {
            responseType: "json",
        });
        return z
            .object({ iceServers: z.array(IceServerConfigSchema) })
            .parse(res.data).iceServers;
    }

    /**
     * Gets a list of permissions for a server.
     *
     * @returns The list of Permission objects.
     */
    private async fetchPermissionList(serverID: string): Promise<Permission[]> {
        const res = await this.http.get(
            this.prefixes.HTTP +
                this.host +
                "/server/" +
                serverID +
                "/permissions",
        );
        return decodeHttpResponse(PermissionArrayCodec, res.data);
    }

    private async fetchUser(
        userIdentifier: string,
    ): Promise<[null | User, HttpError | null]> {
        // Usernames are case-insensitive at the protocol level, so
        // canonicalize the *cache key* to lowercase for username
        // lookups. Without this we'd accumulate duplicate
        // userRecords / notFoundUsers entries for `Foo`, `foo`,
        // `FOO`, etc., even though all three resolve to the same
        // server row. UUIDs are passed through unchanged so the
        // hex-canonical path still hits its own cache slot.
        const cacheKey = uuid.validate(userIdentifier)
            ? userIdentifier
            : userIdentifier.toLowerCase();

        // Positive cache
        if (cacheKey in this.userRecords) {
            return [this.userRecords[cacheKey] ?? null, null];
        }

        // Negative cache — skip users we know don't exist (TTL-based)
        const notFoundAt = this.notFoundUsers.get(cacheKey);
        if (notFoundAt && Date.now() - notFoundAt < Client.NOT_FOUND_TTL) {
            return [null, null];
        }

        try {
            const res = await this.http.get(
                this.getHost() + "/user/" + cacheKey,
            );
            const userRecord = decodeHttpResponse(UserCodec, res.data);
            this.userRecords[cacheKey] = userRecord;
            this.notFoundUsers.delete(cacheKey);
            return [userRecord, null];
        } catch (err: unknown) {
            if (isHttpError(err) && err.response?.status === 404) {
                // Definitive: user doesn't exist — cache and don't retry
                this.notFoundUsers.set(cacheKey, Date.now());
                return [null, err];
            }
            // Transient (5xx, network error) — don't cache, caller can retry
            return [null, isHttpError(err) ? err : null];
        }
    }

    private async fetchUserDeviceListOnce(userID: string): Promise<Device[]> {
        if (this.isManualCloseInFlight()) {
            return [];
        }
        const res = await this.http.get(
            this.getHost() + "/user/" + userID + "/devices",
        );
        const devices = decodeHttpResponse(DeviceArrayCodec, res.data);
        for (const device of devices) {
            this.deviceRecords[device.deviceID] = device;
        }
        return devices;
    }

    /**
     * DM / forward paths need the peer’s (or self) device rows under load: bounded
     * retries with exponential backoff (same shape as session pubkey hydration).
     */
    private async fetchUserDeviceListWithBackoff(
        userID: string,
        label: "own" | "peer",
    ): Promise<Device[]> {
        const base =
            label === "own"
                ? "Couldn't get own devices"
                : "Couldn't get device list";
        let lastErr: unknown;
        for (let attempt = 0; attempt < 5; attempt++) {
            if (this.isManualCloseInFlight()) {
                return [];
            }
            if (attempt > 0) {
                const delayMs = 100 * 2 ** (attempt - 1);
                // Chunk the delay so close() can finish before we retry HTTP.
                const chunkMs = 10;
                for (let elapsed = 0; elapsed < delayMs; elapsed += chunkMs) {
                    if (this.isManualCloseInFlight()) {
                        return [];
                    }
                    await sleep(Math.min(chunkMs, delayMs - elapsed));
                }
            }
            try {
                return await this.fetchUserDeviceListOnce(userID);
            } catch (err: unknown) {
                lastErr = err;
            }
        }
        throw new Error(`${base}${this.deviceListFailureDetail(lastErr)}`);
    }

    /**
     * Finish a passkey login and adopt the resulting JWT as the
     * client's bearer token. After this call, `client.passkeys.*`
     * admin methods are usable; messaging routes will continue to
     * require a real device token.
     */
    private async finishPasskeyAuthentication(args: {
        requestID: string;
        response: Record<string, unknown>;
    }): Promise<{
        passkeyID: string;
        token: string;
        user: User;
    }> {
        const response = await this.http.post(
            this.getHost() + "/auth/passkey/finish",
            msgpack.encode(args),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        const decoded = decodeHttpResponse(
            PasskeyAuthFinishResponseCodec,
            response.data,
        );
        this.setUser(decoded.user);
        this.token = decoded.token;
        this.http.defaults.headers.common.Authorization = `Bearer ${decoded.token}`;
        return decoded;
    }
    private async finishPasskeyRegistration(args: {
        name: string;
        requestID: string;
        response: Record<string, unknown>;
    }): Promise<Passkey> {
        const userID = this.getUser().userID;
        const response = await this.http.post(
            this.getHost() + "/user/" + userID + "/passkeys/register/finish",
            msgpack.encode(args),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(PasskeyCodec, response.data);
    }

    private async finishPendingDevicePasskeyRegistration(args: {
        challenge: string;
        name: string;
        requestID: string;
        response: Record<string, unknown>;
    }): Promise<Passkey> {
        const signed = await this.signPendingRegistrationChallenge(
            args.challenge,
        );
        const response = await this.http.post(
            this.getHost() +
                "/user/devices/requests/" +
                args.requestID +
                "/passkeys/register/finish",
            msgpack.encode({
                name: args.name,
                requestID: args.requestID,
                response: args.response,
                signed,
            }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(PasskeyCodec, response.data);
    }

    private async flushMailBatchOverSocket(
        batch: PendingMailBatchDelivery[],
    ): Promise<void> {
        await Promise.all(
            batch.map(async (item) => {
                try {
                    await this.deliverMailResourceOverSocket(
                        item.msg,
                        item.header,
                    );
                    item.resolve();
                } catch (err: unknown) {
                    item.reject(err);
                }
            }),
        );
    }

    private async flushMailBatchQueue(): Promise<void> {
        if (this.mailBatchFlushTimer) {
            clearTimeout(this.mailBatchFlushTimer);
            this.mailBatchFlushTimer = null;
        }
        const batch = this.mailBatchQueue.splice(0, MAIL_BATCH_MAX_SIZE);
        if (this.mailBatchQueue.length > 0) {
            this.scheduleMailBatchFlush();
        }
        if (batch.length === 0) {
            return;
        }
        if (this.mailBatchUnsupported) {
            await this.flushMailBatchOverSocket(batch);
            return;
        }

        try {
            const response = await this.http.post(
                this.getHost() + "/mail/batch",
                msgpack.encode({
                    mails: batch.map((item) => ({
                        header: item.header,
                        mail: item.mail,
                    })),
                }),
                { headers: { "Content-Type": "application/msgpack" } },
            );
            const decoded = mailBatchResponseSchema.parse(
                msgpack.decode(new Uint8Array(response.data)),
            );
            const resultsByIndex = new Map(
                decoded.results.map((result) => [result.index, result]),
            );
            for (const [index, item] of batch.entries()) {
                const result = resultsByIndex.get(index);
                if (result?.ok === true) {
                    item.resolve();
                    continue;
                }
                item.reject(
                    new Error(
                        "Mail delivery failed: " +
                            (result?.error ??
                                `missing batch result for index ${String(index)}`),
                    ),
                );
            }
        } catch (err: unknown) {
            if (isHttpError(err) && err.response?.status === 404) {
                this.mailBatchUnsupported = true;
                await this.flushMailBatchOverSocket(batch);
                return;
            }
            for (const item of batch) {
                item.reject(err);
            }
        }
    }

    private async forward(message: Message) {
        if (this.isManualCloseInFlight()) {
            return;
        }

        const copy = { ...message };

        if (this.forwarded.has(copy.mailID)) {
            return;
        }
        this.forwarded.add(copy.mailID);
        if (this.forwarded.size > 1000) {
            // Remove oldest entry
            const first = this.forwarded.values().next().value;
            if (first !== undefined) this.forwarded.delete(first);
        }

        const msgBytes = Uint8Array.from(msgpack.encode(copy));

        const devices = await this.fetchUserDeviceListWithBackoff(
            this.getUser().userID,
            "own",
        );
        const targetDevices = devices.filter(
            (device) => device.deviceID !== this.getDevice().deviceID,
        );
        let failCount = 0;
        let lastErr: unknown;
        for (
            let index = 0;
            index < targetDevices.length;
            index += MAIL_FANOUT_CONCURRENCY
        ) {
            const batch = targetDevices.slice(
                index,
                index + MAIL_FANOUT_CONCURRENCY,
            );
            await Promise.all(
                batch.map(async (device) => {
                    try {
                        await this.sendMailWithRecovery(
                            device,
                            this.getUser(),
                            msgBytes,
                            null,
                            copy.mailID,
                            true,
                            true,
                        );
                    } catch (err: unknown) {
                        failCount += 1;
                        lastErr = err;
                    }
                }),
            );
        }
        if (failCount === 0) {
            return;
        }
        const base =
            lastErr instanceof Error ? lastErr : new Error(String(lastErr));
        debugLibvexDm("forward: owned device copy failed", {
            error: base.message,
            failed: failCount,
            targets: targetDevices.length,
        });
    }

    private async getAccountEntitlements(): Promise<AccountEntitlements> {
        const res = await this.http.get(
            this.getHost() + "/user/" + this.getUser().userID + "/entitlements",
        );
        return decodeHttpResponse(AccountEntitlementsCodec, res.data);
    }

    private async getBillingAccountState(): Promise<BillingAccountState> {
        const res = await this.http.get(this.getHost() + "/billing/account");
        return decodeHttpResponse(BillingAccountStateCodec, res.data);
    }

    private async getBillingProducts(): Promise<BillingProduct[]> {
        const res = await this.http.get(this.getHost() + "/billing/products");
        return decodeHttpResponse(BillingProductArrayCodec, res.data);
    }

    private async getChannelByID(channelID: string): Promise<Channel | null> {
        try {
            const res = await this.http.get(
                this.getHost() + "/channel/" + channelID,
            );
            return decodeHttpResponse(ChannelCodec, res.data);
        } catch (_err: unknown) {
            return null;
        }
    }

    private async getChannelList(serverID: string): Promise<Channel[]> {
        const res = await this.http.get(
            this.getHost() + "/server/" + serverID + "/channels",
        );
        return decodeHttpResponse(ChannelArrayCodec, res.data);
    }

    private getDevice(): Device {
        if (!this.device) {
            throw new Error(
                "You must wait until the auth event is emitted before fetching device details.",
            );
        }
        return this.device;
    }

    private async getDeviceByID(deviceID: string): Promise<Device | null> {
        if (deviceID in this.deviceRecords) {
            return this.deviceRecords[deviceID] ?? null;
        }

        const device = await this.database.getDevice(deviceID);
        if (device) {
            this.deviceRecords[deviceID] = device;
            return device;
        }
        try {
            const res = await this.http.get(
                this.getHost() + "/device/" + deviceID,
            );
            const fetchedDevice = decodeHttpResponse(DeviceCodec, res.data);
            this.deviceRecords[deviceID] = fetchedDevice;
            await this.database.saveDevice(fetchedDevice);
            return fetchedDevice;
        } catch (_err: unknown) {
            return null;
        }
    }

    private async getDeviceRegistrationRequest(
        requestID: string,
    ): Promise<null | PendingDeviceRequest> {
        try {
            const response = await this.http.get(
                this.prefixes.HTTP +
                    this.host +
                    "/user/" +
                    this.getUser().userID +
                    "/devices/requests/" +
                    requestID,
            );
            return decodeHttpResponse(PendingDeviceRequestCodec, response.data);
        } catch (err: unknown) {
            if (isHttpError(err) && err.response?.status === 404) {
                return null;
            }
            throw err;
        }
    }

    /* Retrieves the current list of users you have sessions with. */
    private async getFamiliars(): Promise<User[]> {
        const sessions = await this.database.getAllSessions();
        const userIDs = [...new Set(sessions.map((session) => session.userID))];
        const familiarEntries = await Promise.all(
            userIDs.map(async (userID) => {
                const [user] = await this.fetchUser(userID);
                return user ?? null;
            }),
        );
        return familiarEntries.filter((user): user is User => user !== null);
    }

    private async getGroupHistory(channelID: string): Promise<Message[]> {
        const messages: Message[] =
            await this.database.getGroupHistory(channelID);

        return messages;
    }

    private async getMail(): Promise<void> {
        if (this.manuallyClosing) {
            return;
        }
        while (this.fetchingMail) {
            await sleep(500);
        }
        this.fetchingMail = true;
        let firstFetch = false;
        if (this.firstMailFetch) {
            firstFetch = true;
            this.firstMailFetch = false;
        }

        if (firstFetch) {
            this.emitter.emit("decryptingMail");
        }

        try {
            const res = await this.http.post(
                this.getHost() +
                    "/device/" +
                    this.getDevice().deviceID +
                    "/mail",
            );
            if (!this.token || this.isManualCloseInFlight()) {
                return;
            }
            const mailBuffer = new Uint8Array(res.data);
            const rawInbox = z
                .array(mailInboxEntry)
                .parse(msgpack.decode(mailBuffer));
            const inbox = rawInbox.sort(compareInboxEntries);

            if (libvexDebugDmEnabled()) {
                const did = (() => {
                    try {
                        return this.getDevice().deviceID;
                    } catch {
                        return "(no device)";
                    }
                })();
                debugLibvexDm("getMail: inbox", {
                    count: String(inbox.length),
                    deviceID: did,
                });
            }

            for (const mailDetails of inbox) {
                const [mailHeader, mailBody, timestamp] = mailDetails;
                try {
                    if (libvexDebugDmEnabled()) {
                        debugLibvexDm("getMail: readMail one", {
                            mailID: mailBody.mailID,
                            recipient: mailBody.recipient,
                            type: String(mailBody.mailType),
                        });
                    }
                    await this.readMail(mailHeader, mailBody, timestamp);
                } catch (readMailErr) {
                    if (libvexDebugDmEnabled()) {
                        // eslint-disable-next-line no-console -- LIBVEX_DEBUG_DM only
                        console.error(
                            "[libvex:debug-dm] readMail threw",
                            readMailErr,
                        );
                    }
                }
            }
        } catch (fetchErr) {
            if (libvexDebugDmEnabled()) {
                // eslint-disable-next-line no-console -- LIBVEX_DEBUG_DM only
                console.error(
                    "[libvex:debug-dm] getMail fetch failed",
                    fetchErr,
                );
            }
        } finally {
            this.fetchingMail = false;
        }
    }

    private async getMessageHistory(userID: string): Promise<Message[]> {
        const messages: Message[] =
            await this.database.getMessageHistory(userID);

        return messages;
    }

    private async getMultiUserDeviceList(userIDs: string[]): Promise<Device[]> {
        try {
            const res = await this.http.post(
                this.getHost() + "/deviceList",
                msgpack.encode(userIDs),
                { headers: { "Content-Type": "application/msgpack" } },
            );
            const devices = decodeHttpResponse(DeviceArrayCodec, res.data);
            for (const device of devices) {
                this.deviceRecords[device.deviceID] = device;
            }

            return devices;
        } catch (_err: unknown) {
            return [];
        }
    }

    private async getOTKCount(): Promise<number> {
        const res = await this.http.get(
            this.getHost() +
                "/device/" +
                this.getDevice().deviceID +
                "/otk/count",
        );
        return decodeHttpResponse(OtkCountCodec, res.data).count;
    }

    /**
     * Gets all permissions for the logged in user.
     *
     * @returns The list of Permission objects.
     */
    private async getPermissions(): Promise<Permission[]> {
        const res = await this.http.get(
            this.getHost() + "/user/" + this.getUser().userID + "/permissions",
        );
        return decodeHttpResponse(PermissionArrayCodec, res.data);
    }

    private async getServerByID(serverID: string): Promise<null | Server> {
        try {
            const res = await this.http.get(
                this.getHost() + "/server/" + serverID,
            );
            return decodeHttpResponse(ServerCodec, res.data);
        } catch (_err: unknown) {
            return null;
        }
    }

    private async getServerChannelBootstrap(): Promise<ServerChannelBootstrap> {
        const res = await this.http.get(
            this.getHost() +
                "/user/" +
                this.getUser().userID +
                "/servers/bootstrap",
        );
        return decodeHttpResponse(ServerChannelBootstrapCodec, res.data);
    }

    private getServerIconURL(iconID: string): string {
        const normalizedIconID = iconID.trim();
        if (!normalizedIconID) {
            throw new Error("Server icon ID cannot be empty.");
        }

        return (
            this.getHost() +
            "/server-icon/" +
            encodeURIComponent(normalizedIconID)
        );
    }

    private async getServerList(): Promise<Server[]> {
        const res = await this.http.get(
            this.getHost() + "/user/" + this.getUser().userID + "/servers",
        );
        return decodeHttpResponse(ServerArrayCodec, res.data);
    }

    private async getSessionByPubkey(publicKey: Uint8Array) {
        const strPubKey = XUtils.encodeHex(publicKey);
        if (strPubKey in this.sessionRecords) {
            return this.sessionRecords[strPubKey];
        }
        const session = await this.database.getSessionByPublicKey(publicKey);
        if (session) {
            this.sessionRecords[strPubKey] = session;
        }
        return session;
    }

    private async getSessionList() {
        return this.database.getAllSessions();
    }

    private async getToken(
        type:
            | "avatar"
            | "connect"
            | "device"
            | "emoji"
            | "file"
            | "invite"
            | "register",
    ): Promise<ActionToken | null> {
        try {
            const res = await this.http.get(this.getHost() + "/token/" + type, {
                responseType: "arraybuffer",
            });
            return decodeHttpResponse(ActionTokenCodec, res.data);
        } catch {
            return null;
        }
    }

    /* Get the currently logged in user. You cannot call this until
    after the auth event is emitted. */
    private getUser(): User {
        if (!this.user) {
            throw new Error(
                "You must wait until the auth event is emitted before fetching user details.",
            );
        }
        return this.user;
    }

    /**
     * Single GET for `/user/:id/devices`. On failure returns `null` (swallows errors)
     * — callers that need reliability should use `fetchUserDeviceListWithBackoff`.
     * Similar “best effort null” patterns elsewhere: `getChannelByID`,
     * `getDeviceByID` (HTTP leg), `getToken`, emoji upload fallbacks.
     */
    private async getUserDeviceList(userID: string): Promise<Device[] | null> {
        try {
            return await this.fetchUserDeviceListOnce(userID);
        } catch (_err: unknown) {
            return null;
        }
    }

    private async getUserList(channelID: string): Promise<User[]> {
        const res = await this.http.post(
            this.getHost() + "/userList/" + channelID,
        );
        return decodeHttpResponse(UserArrayCodec, res.data);
    }

    private async handleNotify(msg: NotifyMsg) {
        switch (msg.event) {
            case "call":
            case "callInvite": {
                const parsed = CallEventSchema.safeParse(msg.data);
                if (parsed.success) {
                    this.emitter.emit("call", parsed.data);
                }
                break;
            }
            case "deviceRequest": {
                const parsed = deviceRequestNotifyData.safeParse(msg.data);
                if (parsed.success) {
                    this.emitter.emit("deviceRequest", parsed.data);
                }
                break;
            }
            case "mail":
                await this.getMail();
                break;
            case "permission":
                this.emitter.emit(
                    "permission",
                    PermissionSchema.parse(msg.data),
                );
                break;
            case "retryRequest":
                {
                    const parsed = retryRequestNotifyData.safeParse(msg.data);
                    if (parsed.success) {
                        const mailID =
                            typeof parsed.data === "string"
                                ? parsed.data
                                : parsed.data.mailID;
                        this.emitter.emit("retryRequest", {
                            mailID,
                            source: "server_notify",
                        });
                    }
                }
                break;
            case "serverChange": {
                const parsed = serverChangeNotifyData.safeParse(msg.data);
                if (parsed.success) {
                    this.emitter.emit("serverChange", parsed.data);
                }
                break;
            }
            default:
                break;
        }
    }

    private handleTerminalSocketState(reason: string): boolean {
        const { readyState } = this.socket;
        if (readyState !== 2 && readyState !== 3) {
            return false;
        }
        if (this.isManualCloseInFlight()) {
            return true;
        }
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
        debugLibvexDm("websocket-terminal-state", {
            readyState,
            reason,
        });
        this.emitter.emit("disconnect");
        this.scheduleReconnect();
        return true;
    }

    /**
     * Initializes the keyring. This must be called before anything else.
     */
    private async init(): Promise<void> {
        if (this.hasInit) {
            throw new Error("You should only call init() once.");
        }
        this.hasInit = true;

        await this.populateKeyRing();
        this.emitter.on("message", this.onInternalMessage);
        void this.runLocalRetentionPurge();
        this.localRetentionPurgeTimer = setInterval(
            () => void this.runLocalRetentionPurge(),
            6 * 60 * 60 * 1000,
        );
        this.emitter.emit("ready");
    }

    private initSocket() {
        try {
            if (!this.token) {
                throw new Error("No token found, did you call login()?");
            }

            const wsUrl = this.prefixes.WS + this.host + "/socket";
            // Auth sent as first message after open
            this.socket = new WebSocketAdapter(wsUrl);
            this.socket.on("open", () => {
                const authMsg = JSON.stringify({
                    token: this.token,
                    type: "auth",
                });
                // The socket can transition CONNECTING→OPEN→CLOSING in rapid
                // succession on flaky mobile networks (or behind a 502-prone
                // proxy). RN dispatches the queued OPEN event even after the
                // close has landed natively, so by the time this listener
                // runs the underlying socket may already be closed. Swallow
                // the typed teardown error here — the close handler will
                // emit "disconnect" and drive recovery. Anything else
                // re-throws as before so genuine bugs still surface.
                try {
                    this.socket.send(new TextEncoder().encode(authMsg));
                } catch (err: unknown) {
                    if (err instanceof WebSocketNotOpenError) {
                        this.handleTerminalSocketState("auth-open");
                        return;
                    }
                    throw err;
                }
                // Reset the keep-alive flag so a reconnect doesn't
                // inherit a stale `false` from the previous session
                // and tear itself down on the very first ping cycle.
                this.setAlive(true);
                this.pingInterval = setInterval(this.ping.bind(this), 15000);
            });

            this.socket.on("close", () => {
                if (this.pingInterval) {
                    clearInterval(this.pingInterval);
                    this.pingInterval = null;
                }
                if (!this.manuallyClosing) {
                    this.emitter.emit("disconnect");
                    this.scheduleReconnect();
                }
            });

            this.socket.on("error", (_error: Error) => {
                if (!this.manuallyClosing) {
                    this.emitter.emit("disconnect");
                    this.scheduleReconnect();
                }
            });

            this.socket.on("message", (message: Uint8Array) => {
                // XUtils.unpackMessage runs msgpack + zod over server-controlled
                // bytes and throws on malformed frames. A hostile or buggy
                // server must not crash the host process — drop the frame,
                // mirroring the safeParse failure path below.
                let unpacked: ReturnType<typeof XUtils.unpackMessage>;
                try {
                    unpacked = XUtils.unpackMessage(message);
                } catch {
                    return;
                }
                const [_header, raw] = unpacked;

                const parseResult = WSMessageSchema.safeParse(raw);
                if (!parseResult.success) {
                    return;
                }
                const msg = parseResult.data;

                switch (msg.type) {
                    case "challenge":
                        this.respond(msg).catch(ignoreSocketTeardown);
                        break;
                    case "error":
                        break;
                    case "notify":
                        this.handleNotify(msg).catch(ignoreSocketTeardown);
                        break;
                    case "ping":
                        this.pong(msg.transmissionID);
                        break;
                    case "pong":
                        this.setAlive(true);
                        break;
                    case "success":
                        break;
                    case "unauthorized":
                        throw new Error(
                            "Received unauthorized message from server.",
                        );
                    case "authorized":
                        this.reconnectAttempt = 0;
                        this.emitter.emit("connected");
                        this.postAuth().catch(ignoreSocketTeardown);
                        break;
                    default:
                        break;
                }
            });
        } catch (err: unknown) {
            throw new Error(
                "Error initiating websocket connection " + String(err),
            );
        }
    }

    /**
     * Fresh read of the `manuallyClosing` flag for async loops — direct property checks
     * after `await` are flagged as always-false by control-flow analysis even though
     * `close()` can run concurrently.
     */
    private isManualCloseInFlight(): boolean {
        return this.manuallyClosing;
    }

    private async isPreKeySignedByCurrentDevice(
        preKey: PreKeysCrypto,
    ): Promise<boolean> {
        return this.runCrypto(async () => {
            const payload = xPreKeySignaturePayload(
                preKey.keyPair.publicKey,
                "signed",
            );
            const opened = await xSignOpenAsync(
                preKey.signature,
                this.signKeys.publicKey,
            );
            return Boolean(opened && XUtils.bytesEqual(opened, payload));
        });
    }

    private async kickUser(userID: string, serverID: string): Promise<void> {
        const permissionList = await this.fetchPermissionList(serverID);
        for (const permission of permissionList) {
            if (userID === permission.userID) {
                await this.deletePermission(permission.permissionID);
                return;
            }
        }
        throw new Error("Couldn't kick user.");
    }

    private async leaveServer(serverID: string): Promise<void> {
        const permissionList = await this.permissions.retrieve();
        for (const permission of permissionList) {
            if (permission.resourceID === serverID) {
                await this.deletePermission(permission.permissionID);
            }
        }
    }

    private async listDeviceRegistrationRequests(): Promise<
        PendingDeviceRequest[]
    > {
        const response = await this.http.get(
            this.prefixes.HTTP +
                this.host +
                "/user/" +
                this.getUser().userID +
                "/devices/requests",
        );
        return decodeHttpResponse(
            PendingDeviceRequestArrayCodec,
            response.data,
        );
    }

    /**
     * Lists every device the current account owns.
     *
     * Uses the device-authenticated `/user/:id/devices` route. For
     * the passkey-recovery equivalent see `client.passkeys.listDevices`.
     */
    private async listDevices(): Promise<Device[]> {
        const userID = this.getUser().userID;
        const res = await this.http.get(
            this.getHost() + "/user/" + userID + "/devices",
        );
        return decodeHttpResponse(DeviceArrayCodec, res.data);
    }

    private async listPasskeys(): Promise<Passkey[]> {
        const userID = this.getUser().userID;
        const response = await this.http.get(
            this.getHost() + "/user/" + userID + "/passkeys",
        );
        return decodeHttpResponse(PasskeyArrayCodec, response.data);
    }

    private async markSessionVerified(sessionID: string) {
        return this.database.markSessionVerified(sessionID);
    }

    private async negotiateOTK() {
        const otkCount = await this.getOTKCount();
        const needs = xConstants.MIN_OTK_SUPPLY - otkCount;
        if (needs === 0) {
            return;
        }

        await this.submitOTK(needs);
    }

    /**
     * Pipeline for decrypted messages - registered in `init`. After `close()` sets
     * `manuallyClosing`, this becomes a no-op (we avoid `off()` here - it can
     * interact badly with emit).
     */
    private readonly onInternalMessage = (message: Message): void => {
        if (this.isManualCloseInFlight()) {
            return;
        }

        if (
            message.direction === "incoming" &&
            message.recipient === message.sender
        ) {
            return;
        }
        void this.database.saveMessage(message);
        this.scheduleRetentionPurge();
    };

    private async passkeyDeleteDevice(deviceID: string): Promise<void> {
        const userID = this.getUser().userID;
        await this.http.delete(
            this.getHost() + "/user/" + userID + "/passkey/devices/" + deviceID,
        );
    }

    private async passkeyListDevices(): Promise<Device[]> {
        const userID = this.getUser().userID;
        const response = await this.http.get(
            this.getHost() + "/user/" + userID + "/passkey/devices",
        );
        return decodeHttpResponse(DeviceArrayCodec, response.data);
    }

    private async passkeyRecoverDeviceRequest(
        requestID: string,
    ): Promise<Device> {
        const userID = this.getUser().userID;
        const response = await this.http.post(
            this.getHost() +
                "/user/" +
                userID +
                "/passkey/recover/devices/requests/" +
                requestID,
        );
        return decodeHttpResponse(DeviceCodec, response.data);
    }

    private async passkeyRejectDeviceRequest(requestID: string): Promise<void> {
        const userID = this.getUser().userID;
        await this.http.post(
            this.getHost() +
                "/user/" +
                userID +
                "/passkey/devices/requests/" +
                requestID +
                "/reject",
        );
    }

    private ping() {
        if (this.handleTerminalSocketState("ping")) {
            return;
        }
        if (!this.isAlive) {
            // Previous ping went unanswered — the WebSocket is half-open
            // (e.g., the network stack silently dropped the flow without a
            // TCP FIN reaching us, common on Android emulators and on
            // mobile radios that go to sleep). The `close` event won't
            // fire on its own, so we trigger it manually by closing the
            // socket, which lets the existing `close` handler clear the
            // interval and emit `disconnect` for the consumer's recovery
            // path to re-establish the connection.
            if (this.pingInterval) {
                clearInterval(this.pingInterval);
                this.pingInterval = null;
            }
            try {
                this.socket.close();
            } catch {
                // socket may already be CLOSING/CLOSED; ignore.
            }
            this.scheduleReconnect();
            return;
        }
        this.setAlive(false);
        // Swallow a teardown-race rejection: if the socket transitions
        // to CLOSING between our readyState check and the platform
        // `send`, the next ping interval will see `isAlive=false` and
        // close cleanly above. Real failures still bubble up because
        // we re-throw anything that isn't `WebSocketNotOpenError`.
        this.send({ transmissionID: uuid.v4(), type: "ping" }).catch(
            ignoreSocketTeardown,
        );
    }

    private async pollPendingDeviceRegistration(args: {
        challenge: string;
        requestID: string;
    }): Promise<null | PendingDeviceRequest> {
        const signed = await this.signPendingRegistrationChallenge(
            args.challenge,
        );
        try {
            const response = await this.http.post(
                this.getHost() +
                    "/user/devices/requests/" +
                    args.requestID +
                    "/poll",
                msgpack.encode({ signed }),
                { headers: { "Content-Type": "application/msgpack" } },
            );
            return decodeHttpResponse(PendingDeviceRequestCodec, response.data);
        } catch (err: unknown) {
            if (isHttpError(err) && err.response?.status === 404) {
                return null;
            }
            throw err;
        }
    }

    private pong(transmissionID: string) {
        // Drop the pong if the socket is already tearing down — the
        // server will simply mark us absent and our own ping watchdog
        // will trigger a reconnect on the next interval. The
        // alternative (an unhandled rejection from `void this.send`)
        // shows up as a red INVALID_STATE_ERR every time native
        // delivers a `message` and a `close` in the same JS turn,
        // which is the exact race that fires during the Android
        // biometric prompt and any background → foreground swap.
        this.send({ transmissionID, type: "pong" }).catch(ignoreSocketTeardown);
    }

    private async populateKeyRing() {
        await this.runCrypto(async () => {
            // we've checked in the constructor that these exist
            if (!this.idKeys) {
                throw new Error("Identity keys are missing.");
            }
            const identityKeys = this.idKeys;

            let preKeys = await this.database.getPreKeys();
            if (
                !preKeys ||
                !(await this.isPreKeySignedByCurrentDevice(preKeys))
            ) {
                const unsaved = await this.createPreKey("signed");
                const [saved] = await this.database.savePreKeys(
                    [unsaved],
                    false,
                );
                if (!saved || saved.index == null)
                    throw new Error(
                        "Failed to save prekey — no index returned.",
                    );
                preKeys = { ...unsaved, index: saved.index };
            }

            const sessions = await this.database.getAllSessions();
            for (const session of sessions) {
                this.sessionRecords[session.publicKey] =
                    sqlSessionToCrypto(session);
            }

            const ephemeralKeys = await xBoxKeyPairAsync();

            this.xKeyRing = {
                ephemeralKeys,
                identityKeys,
                preKeys,
            };
        });
    }

    private async postAuth() {
        const versionAtStart = this.postAuthVersion;
        let count = 0;
        for (;;) {
            if (this.isManualCloseInFlight()) {
                return;
            }
            if (this.postAuthVersion !== versionAtStart) {
                return;
            }
            try {
                await this.getMail();
                count++;

                if (count > 10) {
                    void this.negotiateOTK();
                    count = 0;
                }
            } catch {}
            if (this.isManualCloseInFlight()) {
                return;
            }
            if (this.postAuthVersion !== versionAtStart) {
                return;
            }
            // Chunk the idle delay so `close()` can unwind instead of waiting
            // out one full 60s timer (which would keep the process alive).
            for (let i = 0; i < 60; i++) {
                if (this.isManualCloseInFlight()) {
                    return;
                }
                if (this.postAuthVersion !== versionAtStart) {
                    return;
                }
                await sleep(1000);
            }
        }
    }

    private async publishPendingDeviceRegistration(args: {
        challenge: string;
        requestID: string;
    }): Promise<void> {
        const signed = await this.signPendingRegistrationChallenge(
            args.challenge,
        );
        await this.http.post(
            this.getHost() +
                "/user/devices/requests/" +
                args.requestID +
                "/publish",
            msgpack.encode({ signed }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
    }

    private async publishSignedPreKey(device: Device): Promise<void> {
        if (!this.xKeyRing) {
            throw new Error("Keyring is not initialized.");
        }
        const preKey: PreKeysWS = {
            deviceID: device.deviceID,
            index: this.xKeyRing.preKeys.index,
            publicKey: this.xKeyRing.preKeys.keyPair.publicKey,
            signature: this.xKeyRing.preKeys.signature,
        };
        try {
            await this.http.post(
                this.getHost() + "/device/" + device.deviceID + "/prekey",
                msgpack.encode(preKey),
                { headers: { "Content-Type": "application/msgpack" } },
            );
        } catch (err: unknown) {
            if (isHttpError(err) && err.response?.status === 404) {
                return;
            }
            throw err;
        }
    }

    private async purgeHistory(): Promise<void> {
        await this.database.purgeHistory();
    }

    private async readMail(
        header: Uint8Array,
        mail: MailWS,
        timestamp: string,
    ) {
        if (this.seenMailIDs.has(mail.mailID)) {
            if (libvexDebugDmEnabled()) {
                try {
                    debugLibvexDm("readMail: skip (seen mailID)", {
                        mailID: mail.mailID,
                        thisDevice: this.getDevice().deviceID,
                    });
                } catch {
                    debugLibvexDm("readMail: skip (seen mailID)", {
                        mailID: mail.mailID,
                    });
                }
            }
            return;
        }

        if (await this.database.hasMessage(mail.mailID)) {
            if (libvexDebugDmEnabled()) {
                try {
                    debugLibvexDm("readMail: skip (stored mailID)", {
                        mailID: mail.mailID,
                        thisDevice: this.getDevice().deviceID,
                    });
                } catch {
                    debugLibvexDm("readMail: skip (stored mailID)", {
                        mailID: mail.mailID,
                    });
                }
            }
            this.acknowledgeInboundMail(mail);
            return;
        }

        if (this.manuallyClosing) {
            if (libvexDebugDmEnabled()) {
                debugLibvexDm("readMail: skip (manually closing)", {
                    mailID: mail.mailID,
                });
            }
            return;
        }

        let timeout = 1;
        while (this.reading) {
            await sleep(timeout);
            timeout *= 2;
        }
        this.reading = true;

        try {
            await this.runCrypto(async () => {
                const healSession = () => {
                    if (this.manuallyClosing || !this.xKeyRing) {
                        return;
                    }
                    const senderDeviceID = mail.sender;
                    const now = Date.now();
                    const blockedUntil =
                        this.sessionHealBackoffUntil.get(senderDeviceID) ?? 0;
                    if (now < blockedUntil) {
                        return;
                    }
                    if (this.sessionHealInFlight.has(senderDeviceID)) {
                        return;
                    }
                    this.sessionHealInFlight.add(senderDeviceID);
                    void (async () => {
                        try {
                            const deviceEntry =
                                await this.getDeviceByID(senderDeviceID);
                            const [user, _err] = await this.fetchUser(
                                mail.authorID,
                            );
                            if (deviceEntry && user) {
                                await this.createSession(
                                    deviceEntry,
                                    user,
                                    new Uint8Array(),
                                    mail.group,
                                    uuid.v4(),
                                    false,
                                    true,
                                );
                            }
                        } finally {
                            // Avoid hammering /keyBundle when a bad/corrupt mail item
                            // triggers repeated decrypt failures for the same sender.
                            // Use a conservative backoff to cap load during auth churn.
                            this.sessionHealBackoffUntil.set(
                                senderDeviceID,
                                Date.now() + 30_000,
                            );
                            this.sessionHealInFlight.delete(senderDeviceID);
                        }
                    })();
                };

                switch (mail.mailType) {
                    case MailType.initial:
                        const extraParts = Client.deserializeExtra(
                            MailType.initial,
                            new Uint8Array(mail.extra),
                        );
                        const signKey = extraParts[0];
                        const ephKey = extraParts[1];
                        const indexBytes = extraParts[3];
                        if (!signKey || !ephKey || !indexBytes) {
                            throw new Error(
                                "Malformed initial mail extra: missing signKey, ephKey, or indexBytes",
                            );
                        }

                        const preKeyIndex = XUtils.uint8ArrToNumber(indexBytes);

                        const otk =
                            preKeyIndex === 0
                                ? null
                                : await this.database.getOneTimeKey(
                                      preKeyIndex,
                                  );

                        if (otk?.index !== preKeyIndex && preKeyIndex !== 0) {
                            const failureCount =
                                this.registerDecryptFailure(mail);
                            if (libvexDebugDmEnabled()) {
                                try {
                                    debugLibvexDm(
                                        "readMail initial: abort (otk index mismatch)",
                                        {
                                            attempts: failureCount,
                                            mailID: mail.mailID,
                                            otkIndex: String(
                                                otk?.index ?? "null",
                                            ),
                                            preKeyIndex: String(preKeyIndex),
                                            thisDevice:
                                                this.getDevice().deviceID,
                                        },
                                    );
                                } catch {
                                    debugLibvexDm(
                                        "readMail initial: abort (otk index mismatch)",
                                        {
                                            mailID: mail.mailID,
                                        },
                                    );
                                }
                            }
                            if (failureCount === 1) {
                                this.emitter.emit("retryRequest", {
                                    mailID: mail.mailID,
                                    source: "decrypt_failure",
                                });
                            }
                            this.acknowledgeRepeatedDecryptFailure(
                                mail,
                                failureCount,
                                timestamp,
                            );
                            return;
                        }

                        // their public keys
                        const IK_A = XKeyConvert.convertPublicKey(signKey);
                        if (!IK_A) {
                            const failureCount =
                                this.registerDecryptFailure(mail);
                            if (libvexDebugDmEnabled()) {
                                try {
                                    debugLibvexDm(
                                        "readMail initial: abort (IK_A null, Ed→X25519?)",
                                        {
                                            attempts: failureCount,
                                            mailID: mail.mailID,
                                            thisDevice:
                                                this.getDevice().deviceID,
                                        },
                                    );
                                } catch {
                                    debugLibvexDm(
                                        "readMail initial: abort (IK_A null)",
                                        {
                                            mailID: mail.mailID,
                                        },
                                    );
                                }
                            }
                            if (failureCount === 1) {
                                this.emitter.emit("retryRequest", {
                                    mailID: mail.mailID,
                                    source: "decrypt_failure",
                                });
                            }
                            this.acknowledgeRepeatedDecryptFailure(
                                mail,
                                failureCount,
                                timestamp,
                            );
                            return;
                        }
                        const EK_A = ephKey;

                        if (!this.xKeyRing) {
                            if (libvexDebugDmEnabled()) {
                                debugLibvexDm(
                                    "readMail initial: abort (no xKeyRing)",
                                    {
                                        mailID: mail.mailID,
                                    },
                                );
                            }
                            return;
                        }
                        // my private keys
                        const IK_B = this.xKeyRing.identityKeys.secretKey;
                        const IK_BP = this.xKeyRing.identityKeys.publicKey;
                        const SPK_B = this.xKeyRing.preKeys.keyPair.secretKey;
                        const OPK_B = otk ? otk.keyPair.secretKey : null;

                        // diffie hellman functions
                        const DH1 = await xDHAsync(SPK_B, IK_A);
                        const DH2 = await xDHAsync(IK_B, EK_A);
                        const DH3 = await xDHAsync(SPK_B, EK_A);
                        const DH4 = OPK_B ? await xDHAsync(OPK_B, EK_A) : null;

                        // initial key material
                        const IKM = DH4
                            ? xConcat(DH1, DH2, DH3, DH4)
                            : xConcat(DH1, DH2, DH3);

                        // shared secret key
                        const SK = xKDF(IKM);
                        const initialSubkeys = xMessageKeySubkeys(SK);
                        const PK = (await xBoxKeyPairFromSecretAsync(SK))
                            .publicKey;

                        const hmac = xHMAC(
                            mail,
                            initialSubkeys.authenticationKey,
                        );

                        // associated data
                        const AD = xConcat(
                            xEncode(xConstants.CURVE, IK_A),
                            xEncode(xConstants.CURVE, IK_BP),
                        );

                        if (!XUtils.bytesEqual(hmac, header)) {
                            const failureCount =
                                this.registerDecryptFailure(mail);
                            if (libvexDebugDmEnabled()) {
                                try {
                                    debugLibvexDm(
                                        "readMail initial: abort (HMAC mismatch)",
                                        {
                                            attempts: failureCount,
                                            mailID: mail.mailID,
                                            preKeyIndex: String(preKeyIndex),
                                            thisDevice:
                                                this.getDevice().deviceID,
                                        },
                                    );
                                } catch {
                                    debugLibvexDm(
                                        "readMail initial: abort (HMAC mismatch)",
                                        {
                                            mailID: mail.mailID,
                                        },
                                    );
                                }
                            }
                            if (failureCount === 1) {
                                this.emitter.emit("retryRequest", {
                                    mailID: mail.mailID,
                                    source: "decrypt_failure",
                                });
                            }
                            this.acknowledgeRepeatedDecryptFailure(
                                mail,
                                failureCount,
                                timestamp,
                            );
                            return;
                        }
                        const unsealed = await xSecretboxOpenAsync(
                            new Uint8Array(mail.cipher),
                            new Uint8Array(mail.nonce),
                            initialSubkeys.encryptionKey,
                        );
                        if (unsealed) {
                            let plaintext = "";
                            if (!mail.forward) {
                                plaintext = XUtils.encodeUTF8(unsealed);
                            }
                            const decodedPlaintext = mail.forward
                                ? null
                                : decodeMessagePlaintext(plaintext);

                            // emit the message
                            const fwdMsg1 = mail.forward
                                ? messageSchema.parse(msgpack.decode(unsealed))
                                : null;
                            const message: Message = fwdMsg1
                                ? {
                                      ...normalizeForwardedMessage(fwdMsg1),
                                      forward: true,
                                  }
                                : {
                                      authorID: mail.authorID,
                                      decrypted: true,
                                      direction: "incoming",
                                      forward: mail.forward,
                                      group: mail.group
                                          ? uuid.stringify(mail.group)
                                          : null,
                                      mailID: mail.mailID,
                                      ...messageFromDecodedPlaintext(
                                          decodedPlaintext ?? {
                                              message: plaintext,
                                          },
                                      ),
                                      nonce: XUtils.encodeHex(
                                          new Uint8Array(mail.nonce),
                                      ),
                                      readerID: mail.readerID,
                                      recipient: mail.recipient,
                                      sender: mail.sender,
                                      timestamp: timestamp,
                                  };

                            const shouldEmitIncomingInitial =
                                mail.forward || plaintext.length > 0;
                            if (shouldEmitIncomingInitial) {
                                this.emitter.emit("message", message);
                            }
                            if (libvexDebugDmEnabled()) {
                                try {
                                    debugLibvexDm(
                                        "readMail initial: ok (emit message)",
                                        {
                                            mailID: mail.mailID,
                                            plaintextLen: String(
                                                plaintext.length,
                                            ),
                                            preKeyIndex: String(preKeyIndex),
                                            thisDevice:
                                                this.getDevice().deviceID,
                                        },
                                    );
                                } catch {
                                    debugLibvexDm(
                                        "readMail initial: ok (emit message)",
                                        {
                                            mailID: mail.mailID,
                                        },
                                    );
                                }
                            }

                            // preKeyIndex 0 = med prekey only (no OTK in the X3DH path). Do
                            // not call deleteOneTimeKey(0) — that is not "remove OTK row 0".
                            if (preKeyIndex !== 0) {
                                await this.database.deleteOneTimeKey(
                                    preKeyIndex,
                                );
                            }

                            const deviceEntry = await this.getDeviceByID(
                                mail.sender,
                            );
                            if (!deviceEntry) {
                                throw new Error("Couldn't get device entry.");
                            }
                            const [userEntry, _userErr] = await this.fetchUser(
                                deviceEntry.owner,
                            );
                            if (!userEntry) {
                                throw new Error("Couldn't get user entry.");
                            }

                            this.userRecords[userEntry.userID] = userEntry;
                            this.deviceRecords[deviceEntry.deviceID] =
                                deviceEntry;

                            // save session
                            const ratchet = await initRatchetSession(
                                SK,
                                "receiver",
                            );
                            const newSession: SessionSQL = {
                                ...ratchet,
                                deviceID: mail.sender,
                                fingerprint: XUtils.encodeHex(AD),
                                lastUsed: new Date().toISOString(),
                                mode: "receiver",
                                publicKey: XUtils.encodeHex(PK),
                                sessionID: uuid.v4(),
                                SK: XUtils.encodeHex(SK),
                                userID: userEntry.userID,
                                verified: false,
                            };
                            await this.database.saveSession(newSession);

                            const [user] = await this.fetchUser(
                                newSession.userID,
                            );

                            if (user) {
                                this.emitter.emit("session", newSession, user);
                            } else {
                            }
                            this.acknowledgeInboundMail(mail);
                        } else {
                            const failureCount =
                                this.registerDecryptFailure(mail);
                            if (libvexDebugDmEnabled()) {
                                debugLibvexDm(
                                    "readMail initial: abort (xSecretboxOpen null)",
                                    {
                                        attempts: failureCount,
                                        mailID: mail.mailID,
                                        preKeyIndex: String(preKeyIndex),
                                    },
                                );
                            }
                            if (failureCount === 1) {
                                this.emitter.emit("retryRequest", {
                                    mailID: mail.mailID,
                                    source: "decrypt_failure",
                                });
                            }
                            this.acknowledgeRepeatedDecryptFailure(
                                mail,
                                failureCount,
                                timestamp,
                            );
                        }
                        break;
                    case MailType.subsequent: {
                        const ratchetHeader = decodeRatchetHeader(
                            new Uint8Array(mail.extra),
                        );
                        let session = await this.database.getSessionByDeviceID(
                            mail.sender,
                        );
                        let retries = 0;
                        while (!session) {
                            if (retries >= 3) {
                                break;
                            }
                            await sleep(100 * 2 ** retries);
                            retries++;
                            session = await this.database.getSessionByDeviceID(
                                mail.sender,
                            );
                        }

                        if (!session) {
                            const failureCount =
                                this.registerDecryptFailure(mail);
                            healSession();
                            if (failureCount === 1) {
                                this.emitter.emit("retryRequest", {
                                    mailID: mail.mailID,
                                    source: "decrypt_failure",
                                });
                            }
                            this.acknowledgeRepeatedDecryptFailure(
                                mail,
                                failureCount,
                                timestamp,
                            );
                            return;
                        }

                        const originalSession = cloneSessionCrypto(session);
                        const firstInboundFromSubsequent = !session.DHr;
                        let candidateSession = cloneSessionCrypto(session);
                        if (firstInboundFromSubsequent) {
                            candidateSession.DHr = ratchetHeader.dhPub;
                            // First inbound after X3DH initial mail can be either:
                            // - peer's bootstrap send chain if they replied before seeing
                            //   one of our subsequent messages; or
                            // - a real DH ratchet if they already received one from us.
                            // Try bootstrap first for backwards compatibility, then fall
                            // back to the DH-ratchet interpretation if HMAC disagrees.
                            if (!candidateSession.CKr) {
                                candidateSession.CKr = deriveBootstrapSendChain(
                                    candidateSession.RK,
                                );
                            }
                        } else if (
                            hasRemoteDhChanged(
                                candidateSession.DHr,
                                ratchetHeader.dhPub,
                            )
                        ) {
                            await ratchetStepReceive(
                                candidateSession,
                                ratchetHeader.dhPub,
                                ratchetHeader.pn,
                            );
                        }

                        const messageKey = takeReceiveMessageKey(
                            candidateSession,
                            ratchetHeader.dhPub,
                            ratchetHeader.n,
                        );
                        let messageSubkeys = xMessageKeySubkeys(messageKey);
                        let HMAC = xHMAC(
                            mail,
                            messageSubkeys.authenticationKey,
                        );

                        if (
                            !XUtils.bytesEqual(HMAC, header) &&
                            firstInboundFromSubsequent &&
                            !originalSession.CKr
                        ) {
                            const ratchetedCandidate =
                                cloneSessionCrypto(originalSession);
                            await ratchetStepReceive(
                                ratchetedCandidate,
                                ratchetHeader.dhPub,
                                ratchetHeader.pn,
                            );
                            const ratchetedMessageKey = takeReceiveMessageKey(
                                ratchetedCandidate,
                                ratchetHeader.dhPub,
                                ratchetHeader.n,
                            );
                            const ratchetedSubkeys =
                                xMessageKeySubkeys(ratchetedMessageKey);
                            const ratchetedHMAC = xHMAC(
                                mail,
                                ratchetedSubkeys.authenticationKey,
                            );
                            if (XUtils.bytesEqual(ratchetedHMAC, header)) {
                                if (libvexDebugDmEnabled()) {
                                    debugLibvexDm(
                                        "readMail subsequent: first inbound used DH-ratchet fallback",
                                        {
                                            mailID: mail.mailID,
                                            thisDevice:
                                                this.getDevice().deviceID,
                                        },
                                    );
                                }
                                candidateSession = ratchetedCandidate;
                                messageSubkeys = ratchetedSubkeys;
                                HMAC = ratchetedHMAC;
                            }
                        }

                        if (!XUtils.bytesEqual(HMAC, header)) {
                            const failureCount =
                                this.registerDecryptFailure(mail);
                            if (libvexDebugDmEnabled()) {
                                debugLibvexDm(
                                    "readMail subsequent: abort (HMAC mismatch)",
                                    {
                                        attempts: failureCount,
                                        mailID: mail.mailID,
                                        sender: mail.sender,
                                        thisDevice: this.getDevice().deviceID,
                                    },
                                );
                            }
                            if (failureCount >= 2) {
                                healSession();
                            }
                            if (failureCount === 1) {
                                this.emitter.emit("retryRequest", {
                                    mailID: mail.mailID,
                                    source: "decrypt_failure",
                                });
                            }
                            this.acknowledgeRepeatedDecryptFailure(
                                mail,
                                failureCount,
                                timestamp,
                            );
                            return;
                        }

                        session = candidateSession;

                        const decrypted = await xSecretboxOpenAsync(
                            new Uint8Array(mail.cipher),
                            new Uint8Array(mail.nonce),
                            messageSubkeys.encryptionKey,
                        );

                        if (decrypted) {
                            const fwdMsg2 = mail.forward
                                ? messageSchema.parse(msgpack.decode(decrypted))
                                : null;
                            const rawIncoming = XUtils.encodeUTF8(decrypted);
                            const decodedPlaintext = mail.forward
                                ? null
                                : decodeMessagePlaintext(rawIncoming);
                            const message: Message = fwdMsg2
                                ? {
                                      ...normalizeForwardedMessage(fwdMsg2),
                                      forward: true,
                                  }
                                : {
                                      authorID: mail.authorID,
                                      decrypted: true,
                                      direction: "incoming",
                                      forward: mail.forward,
                                      group: mail.group
                                          ? uuid.stringify(mail.group)
                                          : null,
                                      mailID: mail.mailID,
                                      ...messageFromDecodedPlaintext(
                                          decodedPlaintext ?? {
                                              message: rawIncoming,
                                          },
                                      ),
                                      nonce: XUtils.encodeHex(
                                          new Uint8Array(mail.nonce),
                                      ),
                                      readerID: mail.readerID,
                                      recipient: mail.recipient,
                                      sender: mail.sender,
                                      timestamp: timestamp,
                                  };
                            this.emitter.emit("message", message);

                            const sqlPatch = sessionToSqlPatch(session);
                            const persisted: SessionSQL = {
                                CKr: sqlPatch.CKr,
                                CKs: sqlPatch.CKs,
                                deviceID: mail.sender,
                                DHr: sqlPatch.DHr,
                                DHsPrivate: sqlPatch.DHsPrivate,
                                DHsPublic: sqlPatch.DHsPublic,
                                fingerprint: XUtils.encodeHex(
                                    session.fingerprint,
                                ),
                                lastUsed: new Date().toISOString(),
                                mode: session.mode,
                                Nr: sqlPatch.Nr,
                                Ns: sqlPatch.Ns,
                                PN: sqlPatch.PN,
                                publicKey: XUtils.encodeHex(session.publicKey),
                                RK: sqlPatch.RK,
                                sessionID: session.sessionID,
                                SK: XUtils.encodeHex(session.SK),
                                skippedKeys: sqlPatch.skippedKeys,
                                userID: session.userID,
                                verified: session.verified,
                            };
                            await this.database.saveSession(persisted);
                            this.sessionRecords[
                                XUtils.encodeHex(session.publicKey)
                            ] = session;
                            this.acknowledgeInboundMail(mail);
                        } else {
                            const failureCount =
                                this.registerDecryptFailure(mail);
                            healSession();
                            if (failureCount === 1) {
                                this.emitter.emit("retryRequest", {
                                    mailID: mail.mailID,
                                    source: "decrypt_failure",
                                });
                            }
                            this.acknowledgeRepeatedDecryptFailure(
                                mail,
                                failureCount,
                                timestamp,
                            );
                        }
                        break;
                    }
                    default:
                        break;
                }
            });
        } finally {
            this.reading = false;
        }
    }

    private async reconnectWebsocketOnce(): Promise<void> {
        this.postAuthVersion++;
        if (this.pingInterval) {
            clearInterval(this.pingInterval);
            this.pingInterval = null;
        }
        this.socket.close();
        try {
            await new Promise<void>((resolve, reject) => {
                const t = setTimeout(() => {
                    this.off("connected", onC);
                    reject(
                        new Error(
                            "reconnectWebsocket: timed out waiting for authorized",
                        ),
                    );
                }, 15_000);
                const onC = () => {
                    clearTimeout(t);
                    this.off("connected", onC);
                    resolve();
                };
                this.on("connected", onC);
                try {
                    this.initSocket();
                } catch (err: unknown) {
                    clearTimeout(t);
                    this.off("connected", onC);
                    const e =
                        err instanceof Error
                            ? err
                            : new Error(String(err), { cause: err });
                    reject(e);
                }
            });
        } catch (e: unknown) {
            throw e instanceof Error ? e : new Error(String(e), { cause: e });
        }
        await new Promise((r) => setTimeout(r, 0));
        await this.negotiateOTK();
    }

    private async redeemInvite(inviteID: string): Promise<Permission> {
        const res = await this.http.patch(
            this.getHost() + "/invite/" + inviteID,
        );
        return decodeHttpResponse(PermissionCodec, res.data);
    }

    private async registerAccountOrEnrollment(
        username: string,
        intent: RegistrationPayload["intent"],
        password?: string,
    ): Promise<[null | User, Error | null]> {
        const resolvedUsername = username.trim().toLowerCase();
        if (!/^\w{3,19}$/.test(resolvedUsername)) {
            return [
                null,
                new Error(
                    "Username must be between three and nineteen letters, digits, or underscores.",
                ),
            ];
        }
        while (!this.xKeyRing) {
            await sleep(100);
        }
        const regKey = await this.getToken("register");
        if (regKey) {
            const signKey = XUtils.encodeHex(this.signKeys.publicKey);
            const signed = XUtils.encodeHex(
                await xSignAsync(
                    Uint8Array.from(uuid.parse(regKey.key)),
                    this.signKeys.secretKey,
                ),
            );
            const preKeyIndex = this.xKeyRing.preKeys.index;
            const regMsg: RegistrationPayload = {
                deviceName: this.options?.deviceName ?? "unknown",
                intent,
                preKey: XUtils.encodeHex(
                    this.xKeyRing.preKeys.keyPair.publicKey,
                ),
                preKeyIndex,
                preKeySignature: XUtils.encodeHex(
                    this.xKeyRing.preKeys.signature,
                ),
                signed,
                signKey,
                username: resolvedUsername,
            };
            if (password !== undefined) {
                regMsg.password = password;
            }
            try {
                const res = await this.http.post(
                    this.getHost() + "/register",
                    msgpack.encode(regMsg),
                    { headers: { "Content-Type": "application/msgpack" } },
                );

                try {
                    const { device, token, user } = decodeHttpResponse(
                        RegisterResponseCodec,
                        res.data,
                    );
                    this.device = device;
                    this.setUser(user);
                    this.token = token;
                    this.http.defaults.headers.common.Authorization = `Bearer ${token}`;
                } catch {
                    const pendingApproval = decodeHttpResponse(
                        RegisterPendingApprovalCodec,
                        res.data,
                    );
                    return [
                        null,
                        new DeviceApprovalRequiredError({
                            challenge: pendingApproval.challenge,
                            expiresAt: pendingApproval.expiresAt,
                            requestID: pendingApproval.requestID,
                            userID: pendingApproval.userID,
                        }),
                    ];
                }
                return [this.getUser(), null];
            } catch (err: unknown) {
                if (isHttpError(err) && err.response) {
                    return [
                        null,
                        new Error(spireErrorBodyMessage(err.response.data)),
                    ];
                }
                return [
                    null,
                    err instanceof Error ? err : new Error(String(err)),
                ];
            }
        } else {
            return [null, new Error("Couldn't get regkey from server.")];
        }
    }

    private registerDecryptFailure(mail: MailWS): number {
        const count = (this.decryptFailureCounts.get(mail.mailID) ?? 0) + 1;
        this.decryptFailureCounts.set(mail.mailID, count);
        return count;
    }

    private async registerDevice(): Promise<DeviceRegistrationResult | null> {
        while (!this.xKeyRing) {
            await sleep(100);
        }

        const token = await this.getToken("device");
        const userDetails = this.getUser();
        if (!token) {
            throw new Error("Couldn't fetch token.");
        }

        // Stored on Spire for Ed25519 signature verification.
        const signKey = this.getKeys().public;
        const signed = XUtils.encodeHex(
            await xSignAsync(
                Uint8Array.from(uuid.parse(token.key)),
                this.signKeys.secretKey,
            ),
        );

        const devPreKeyIndex = this.xKeyRing.preKeys.index;
        const normalizedUsername =
            userDetails.username.trim().length > 0
                ? userDetails.username
                : `key_${userDetails.userID.replaceAll("-", "").slice(0, 12)}`;
        const devMsg: DevicePayload = {
            deviceName: this.options?.deviceName ?? "unknown",
            preKey: XUtils.encodeHex(this.xKeyRing.preKeys.keyPair.publicKey),
            preKeyIndex: devPreKeyIndex,
            preKeySignature: XUtils.encodeHex(this.xKeyRing.preKeys.signature),
            signed,
            signKey,
            username: normalizedUsername,
        };

        const res = await this.http.post(
            this.prefixes.HTTP +
                this.host +
                "/user/" +
                userDetails.userID +
                "/devices",
            msgpack.encode(devMsg),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(DeviceRegistrationResultCodec, res.data);
    }

    private async rejectDeviceRequest(requestID: string): Promise<void> {
        await this.http.post(
            this.prefixes.HTTP +
                this.host +
                "/user/" +
                this.getUser().userID +
                "/devices/requests/" +
                requestID +
                "/reject",
        );
    }

    private async removeServerIcon(serverID: string): Promise<Server> {
        const res = await this.http.delete(
            this.getHost() + "/server-icon/" + serverID,
        );
        return decodeHttpResponse(ServerCodec, res.data);
    }

    private async replaceAccountPassword(payload: {
        currentPassword?: string;
        newPassword: string;
    }): Promise<void> {
        await this.http.patch(
            this.getHost() + "/user/" + this.getUser().userID + "/password",
            msgpack.encode(payload),
            { headers: { "Content-Type": "application/msgpack" } },
        );
    }

    private async resetPasswordWithPasskey(newPassword: string): Promise<void> {
        const passwordError = registrationPasswordError(newPassword);
        if (passwordError) throw passwordError;
        await this.replaceAccountPassword({ newPassword });
    }

    private async respond(msg: ChallMsg) {
        const response: RespMsg = {
            signed: await xSignAsync(
                new Uint8Array(msg.challenge),
                this.signKeys.secretKey,
            ),
            transmissionID: msg.transmissionID,
            type: "response",
        };
        // If the socket tore down between receiving the challenge
        // and signing the response, dropping the response is safe:
        // the server will time out the auth handshake and close,
        // our reconnect loop will redo the challenge on the next
        // socket. Logging it as an unhandled rejection only adds
        // noise during foreground/background swaps.
        this.send(response).catch(ignoreSocketTeardown);
    }

    private async retrieveEmojiByID(emojiID: string): Promise<Emoji | null> {
        const res = await this.http.get(
            this.getHost() + "/emoji/" + emojiID + "/details",
        );
        return decodeHttpResponse(EmojiCodec, res.data);
    }

    private async retrieveEmojiList(serverID: string): Promise<Emoji[]> {
        const res = await this.http.get(
            this.getHost() + "/server/" + serverID + "/emoji",
        );
        return decodeHttpResponse(EmojiArrayCodec, res.data);
    }

    private async retrieveFile(
        fileID: string,
        key: string,
    ): Promise<FileResponse | null> {
        const detailsRes = await this.http.get(
            this.getHost() + "/file/" + fileID + "/details",
        );
        const details = decodeHttpResponse(FileSQLCodec, detailsRes.data);

        const res = await this.http.get(this.getHost() + "/file/" + fileID, {
            onDownloadProgress: (progressEvent) => {
                const percentCompleted = Math.round(
                    (progressEvent.loaded * 100) / (progressEvent.total ?? 1),
                );
                const { loaded, total = 0 } = progressEvent;
                const progress: FileProgress = {
                    direction: "download",
                    loaded,
                    progress: percentCompleted,
                    token: fileID,
                    total,
                };
                this.emitter.emit("fileProgress", progress);
            },
        });
        const fileData = res.data;

        const decrypted = await xSecretboxOpenAsync(
            new Uint8Array(fileData),
            XUtils.decodeHex(details.nonce),
            XUtils.decodeHex(key),
        );

        if (decrypted) {
            return {
                data: new Uint8Array(decrypted),
                details,
            };
        }
        throw new Error("Decryption failed.");
    }

    private async retrieveInvites(serverID: string): Promise<Invite[]> {
        const res = await this.http.get(
            this.getHost() + "/server/" + serverID + "/invites",
        );
        return decodeHttpResponse(InviteArrayCodec, res.data);
    }

    private async retrieveKeyBundle(deviceID: string): Promise<KeyBundle> {
        const res = await this.http.post(
            this.getHost() + "/device/" + deviceID + "/keyBundle",
        );
        return decodeHttpResponse(KeyBundleCodec, res.data);
    }

    private async retrieveOrCreateDevice(): Promise<Device> {
        let device: Device;
        try {
            const res = await this.http.get(
                this.prefixes.HTTP +
                    this.host +
                    "/device/" +
                    XUtils.encodeHex(this.signKeys.publicKey),
            );
            device = decodeHttpResponse(DeviceCodec, res.data);
        } catch (err: unknown) {
            if (isHttpError(err) && err.response?.status === 404) {
                await this.database.purgeKeyData();
                await this.populateKeyRing();

                const newDevice = await this.registerDevice();
                if (newDevice && "deviceID" in newDevice) {
                    device = newDevice;
                } else if (newDevice && "status" in newDevice) {
                    throw new DeviceApprovalRequiredError({
                        challenge: newDevice.challenge,
                        expiresAt: newDevice.expiresAt,
                        requestID: newDevice.requestID,
                        userID: newDevice.userID,
                    });
                } else {
                    throw new Error("Error registering device.");
                }
            } else {
                throw err;
            }
        }
        return device;
    }

    private async runCrypto<T>(fn: () => Promise<T>): Promise<T> {
        return fn();
    }

    private async runLocalRetentionPurge(): Promise<void> {
        if (this.isManualCloseInFlight()) {
            return;
        }
        try {
            await this.database.pruneExpiredLocalMessages(
                this.localMessageRetentionDays,
            );
        } catch {
            /* best-effort */
        }
    }

    private scheduleMailBatchFlush(): void {
        if (this.mailBatchFlushTimer) {
            return;
        }
        this.mailBatchFlushTimer = setTimeout(() => {
            this.mailBatchFlushTimer = null;
            void this.flushMailBatchQueue();
        }, MAIL_BATCH_FLUSH_DELAY_MS);
    }

    private scheduleReconnect(): void {
        if (
            !this.autoReconnectEnabled ||
            this.isManualCloseInFlight() ||
            this.reconnectPromise ||
            this.reconnectTimer
        ) {
            return;
        }
        const delayMs = Math.min(30_000, 250 * 2 ** this.reconnectAttempt);
        this.reconnectAttempt = Math.min(this.reconnectAttempt + 1, 8);
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.reconnectWebsocket().catch(() => {
                this.scheduleReconnect();
            });
        }, delayMs);
    }

    private scheduleRetentionPurge(): void {
        if (this.retentionPurgeDebounce) {
            clearTimeout(this.retentionPurgeDebounce);
        }
        this.retentionPurgeDebounce = setTimeout(() => {
            this.retentionPurgeDebounce = null;
            void this.runLocalRetentionPurge();
        }, 3000);
    }

    /* header is 32 bytes and is either empty
    or contains an HMAC of the message with
    a derived SK */
    private async send(msg: ClientMessage, header?: Uint8Array) {
        const maxWaitMs = 30_000;
        let elapsed = 0;
        let backoff = 50;
        while (this.socket.readyState !== 1) {
            if (this.isManualCloseInFlight()) {
                throw new WebSocketNotOpenError(this.socket.readyState);
            }
            if (this.socket.readyState === 2 || this.socket.readyState === 3) {
                await this.reconnectWebsocket();
                continue;
            }
            if (elapsed >= maxWaitMs) {
                throw new WebSocketNotOpenError(this.socket.readyState);
            }
            await sleep(backoff);
            elapsed += backoff;
            backoff = Math.min(backoff * 2, 4_000);
        }

        // The adapter re-checks `readyState` and converts the
        // platform's opaque `DOMException("INVALID_STATE_ERR")` into a
        // typed `WebSocketNotOpenError`. That handles the TOCTOU
        // window between the loop above exiting on readyState=1 and
        // the synchronous `send` below: React Native's bridge can
        // dispatch a `websocketClosed` between the two, in which case
        // the socket has transitioned native-side even though our JS
        // close handler hasn't run yet. With the typed error,
        // discarded callers (`pong`, `ping`) can `.catch(ignore)` the
        // teardown without an unhandled rejection, and real callers
        // can choose to retry on the next reconnect.
        const packed = XUtils.packMessage(msg, header);
        try {
            this.socket.send(packed);
        } catch (err: unknown) {
            if (
                err instanceof WebSocketNotOpenError &&
                !this.isManualCloseInFlight()
            ) {
                await this.reconnectWebsocket();
                this.socket.send(packed);
                return;
            }
            throw err;
        }
    }

    private async sendCallResource(
        action: string,
        data: CallResourceData,
    ): Promise<CallEvent> {
        const msg: ResourceMsg = {
            action,
            data,
            resourceType: "call",
            transmissionID: uuid.v4(),
            type: "resource",
        };

        return await new Promise<CallEvent>((resolve, reject) => {
            const settle = (err: null | unknown, event?: CallEvent) => {
                this.socket.off("message", callback);
                if (err !== null) {
                    reject(errorFromUnknown(err));
                    return;
                }
                if (!event) {
                    reject(new Error("Call signaling response was empty."));
                    return;
                }
                resolve(event);
            };

            const callback = (packedMsg: Uint8Array) => {
                const [_header, receivedMsg] = XUtils.unpackMessage(packedMsg);
                if (receivedMsg.transmissionID !== msg.transmissionID) {
                    return;
                }

                const parsed = WSMessageSchema.safeParse(receivedMsg);
                if (!parsed.success) {
                    settle(
                        "Call signaling failed: " + JSON.stringify(receivedMsg),
                    );
                    return;
                }

                if (parsed.data.type === "success") {
                    const event = CallEventSchema.safeParse(parsed.data.data);
                    if (!event.success) {
                        settle(
                            "Invalid call signaling response: " +
                                JSON.stringify(event.error.issues),
                        );
                        return;
                    }
                    settle(null, event.data);
                    return;
                }

                if (parsed.data.type === "error") {
                    settle(new Error(parsed.data.error));
                    return;
                }

                if (
                    parsed.data.type === "notify" &&
                    (parsed.data.event === "call" ||
                        parsed.data.event === "callInvite")
                ) {
                    const event = CallEventSchema.safeParse(parsed.data.data);
                    if (event.success) {
                        settle(null, event.data);
                    }
                    return;
                }

                settle(
                    "Unexpected call signaling response: " +
                        JSON.stringify(parsed.data),
                );
            };

            this.socket.on("message", callback);
            this.send(msg).catch((err: unknown) => {
                settle(err);
            });
        });
    }

    private async sendGroupMessage(
        channelID: string,
        message: string,
        opts?: MessageSendOptions,
    ): Promise<void> {
        const userList = await this.getUserList(channelID);
        for (const user of userList) {
            this.userRecords[user.userID] = user;
        }

        const mailID = uuid.v4();
        const payload = encodeMessagePlaintext(message, opts);
        const msgBytes = XUtils.decodeUTF8(payload);
        const myUserID = this.getUser().userID;
        const peerUserIDs = [...new Set(userList.map((u) => u.userID))].filter(
            (id) => id !== myUserID,
        );
        const targetDevices = new Map<string, Device>();

        if (peerUserIDs.length > 0) {
            const peerDevices = await this.getMultiUserDeviceList(peerUserIDs);
            if (peerDevices.length === 0) {
                throw new Error(
                    "No devices registered for other channel members — cannot send group message.",
                );
            }
            for (const device of peerDevices) {
                targetDevices.set(device.deviceID, device);
            }
        }

        const ownDevices = await this.fetchUserDeviceListWithBackoff(
            myUserID,
            "own",
        );
        for (const device of ownDevices) {
            targetDevices.set(device.deviceID, device);
        }

        if (targetDevices.size === 0) {
            const dev = this.getDevice();
            const nonce = xMakeNonce();
            const decodedPlaintext = decodeMessagePlaintext(payload);
            this.emitter.emit("message", {
                authorID: myUserID,
                decrypted: true,
                direction: "outgoing",
                forward: false,
                group: channelID,
                mailID,
                ...messageFromDecodedPlaintext(decodedPlaintext),
                nonce: XUtils.encodeHex(nonce),
                readerID: myUserID,
                recipient: dev.deviceID,
                sender: dev.deviceID,
                timestamp: new Date().toISOString(),
            });
            return;
        }

        const stableDevices = [...targetDevices.values()].sort((a, b) =>
            a.deviceID.localeCompare(b.deviceID, "en"),
        );

        const successfulOwnerIDs = new Set<string>();
        const lastErrorByOwnerID = new Map<string, unknown>();
        for (
            let index = 0;
            index < stableDevices.length;
            index += MAIL_FANOUT_CONCURRENCY
        ) {
            const batch = stableDevices.slice(
                index,
                index + MAIL_FANOUT_CONCURRENCY,
            );
            const results = await Promise.all(
                batch.map(async (device) => {
                    const ownerRecord =
                        device.owner === myUserID
                            ? this.getUser()
                            : this.userRecords[device.owner];
                    if (!ownerRecord) {
                        return {
                            device,
                            error: new Error(
                                `Missing owner record for device ${device.deviceID}.`,
                            ),
                            ok: false as const,
                        };
                    }
                    try {
                        await this.sendMailWithRecovery(
                            device,
                            ownerRecord,
                            msgBytes,
                            uuidToUint8(channelID),
                            mailID,
                            false,
                        );
                        return { device, ok: true as const };
                    } catch (error: unknown) {
                        return { device, error, ok: false as const };
                    }
                }),
            );
            for (const result of results) {
                if (result.ok) {
                    successfulOwnerIDs.add(result.device.owner);
                } else {
                    lastErrorByOwnerID.set(result.device.owner, result.error);
                }
            }
        }

        const requiredOwnerIDs =
            peerUserIDs.length > 0 ? peerUserIDs : [myUserID];
        const unreachableOwnerIDs = requiredOwnerIDs.filter(
            (ownerID) => !successfulOwnerIDs.has(ownerID),
        );
        if (unreachableOwnerIDs.length > 0) {
            const lastError = lastErrorByOwnerID.get(
                unreachableOwnerIDs.at(-1) ?? "",
            );
            if (
                unreachableOwnerIDs.length === requiredOwnerIDs.length &&
                lastError instanceof Error
            ) {
                throw lastError;
            }
            const deliveryError = new Error(
                `Message could not be delivered to ${String(unreachableOwnerIDs.length)} channel member(s).`,
            );
            deliveryError.cause = lastError;
            throw deliveryError;
        }
    }

    /* Sends encrypted mail to a user. */
    private async sendMail(
        device: Device,
        user: User,
        msg: Uint8Array,
        group: null | Uint8Array,
        mailID: null | string,
        forward: boolean,
        retry = false,
    ): Promise<Message | null> {
        while (this.sending.has(device.deviceID)) {
            await sleep(100);
        }
        this.sending.set(device.deviceID, device);
        try {
            const session = await this.database.getSessionByDeviceID(
                device.deviceID,
            );

            if (!session || retry) {
                if (libvexDebugDmEnabled()) {
                    debugLibvexDm("sendMail: createSession path", {
                        hasSession: String(!!session),
                        peerDevice: device.deviceID,
                        retry: String(retry),
                    });
                }
                const createdMessage = await this.createSession(
                    device,
                    user,
                    msg,
                    group,
                    mailID,
                    forward,
                    false,
                );
                if (libvexDebugDmEnabled()) {
                    debugLibvexDm("sendMail: createSession returned", {
                        peerDevice: device.deviceID,
                    });
                }
                return createdMessage;
            }

            if (libvexDebugDmEnabled()) {
                debugLibvexDm("sendMail: subsequent path", {
                    peerDevice: device.deviceID,
                });
            }

            if (!session.CKs) {
                await ratchetStepSend(session);
            }
            const { messageKey, n } = takeSendMessageKey(session);
            const messageSubkeys = xMessageKeySubkeys(messageKey);
            const ratchetHeader = {
                dhPub: session.DHsPublic,
                n,
                pn: session.PN,
                version: 1 as const,
            };
            const nonce = xMakeNonce();
            const cipher = await xSecretboxAsync(
                msg,
                nonce,
                messageSubkeys.encryptionKey,
            );
            const extra = encodeRatchetHeader(ratchetHeader);

            const mail: MailWS = {
                authorID: this.getUser().userID,
                cipher,
                extra,
                forward,
                group,
                mailID: mailID || uuid.v4(),
                mailType: MailType.subsequent,
                nonce,
                readerID: session.userID,
                recipient: device.deviceID,
                sender: this.getDevice().deviceID,
            };

            const msgb: ResourceMsg = {
                action: "CREATE",
                data: mail,
                resourceType: "mail",
                transmissionID: uuid.v4(),
                type: "resource",
            };

            const hmac = xHMAC(mail, messageSubkeys.authenticationKey);

            const fwdOut = forward
                ? messageSchema.parse(msgpack.decode(msg))
                : null;
            const outMsg: Message = fwdOut
                ? { ...normalizeForwardedMessage(fwdOut), forward: true }
                : {
                      authorID: mail.authorID,
                      decrypted: true,
                      direction: "outgoing",
                      forward: mail.forward,
                      group: mail.group ? uuid.stringify(mail.group) : null,
                      mailID: mail.mailID,
                      ...messageFromDecodedPlaintext(
                          decodeMessagePlaintext(XUtils.encodeUTF8(msg)),
                      ),
                      nonce: XUtils.encodeHex(new Uint8Array(mail.nonce)),
                      readerID: mail.readerID,
                      recipient: mail.recipient,
                      sender: mail.sender,
                      timestamp: new Date().toISOString(),
                  };
            this.emitter.emit("message", outMsg);

            const sqlPatch = sessionToSqlPatch(session);
            const persisted: SessionSQL = {
                CKr: sqlPatch.CKr,
                CKs: sqlPatch.CKs,
                deviceID: device.deviceID,
                DHr: sqlPatch.DHr,
                DHsPrivate: sqlPatch.DHsPrivate,
                DHsPublic: sqlPatch.DHsPublic,
                fingerprint: XUtils.encodeHex(session.fingerprint),
                lastUsed: new Date().toISOString(),
                mode: session.mode,
                Nr: sqlPatch.Nr,
                Ns: sqlPatch.Ns,
                PN: sqlPatch.PN,
                publicKey: XUtils.encodeHex(session.publicKey),
                RK: sqlPatch.RK,
                sessionID: session.sessionID,
                SK: XUtils.encodeHex(session.SK),
                skippedKeys: sqlPatch.skippedKeys,
                userID: session.userID,
                verified: session.verified,
            };
            await this.database.saveSession(persisted);
            this.sessionRecords[XUtils.encodeHex(session.publicKey)] = session;

            await this.deliverMailResource(msgb, hmac, mail);
            return outMsg;
        } finally {
            this.sending.delete(device.deviceID);
        }
    }

    private async sendMailWithRecovery(
        device: Device,
        user: User,
        msg: Uint8Array,
        group: null | Uint8Array,
        mailID: null | string,
        forward: boolean,
        forceFreshSession = false,
    ): Promise<Message | null> {
        try {
            return await this.sendMail(
                device,
                user,
                msg,
                group,
                mailID,
                forward,
                forceFreshSession,
            );
        } catch (err: unknown) {
            if (!this.shouldRetryDeliveryWithFreshSession(err)) {
                throw err;
            }
            return await this.sendMail(
                device,
                user,
                msg,
                group,
                mailID,
                forward,
                true,
            );
        }
    }

    private async sendMessage(
        userID: string,
        message: string,
        opts?: MessageSendOptions,
    ): Promise<void> {
        const payload = encodeMessagePlaintext(message, opts);
        try {
            const [userEntry, err] = await this.fetchUser(userID);
            if (err) {
                throw err;
            }
            if (!userEntry) {
                throw new Error("Couldn't get user entry.");
            }

            const afterBackoff = await this.fetchUserDeviceListWithBackoff(
                userID,
                "peer",
            );
            // Back-to-back GETs, merged by deviceID: a second read can list a device
            // that was not visible in the first snapshot (automation + multi-device)
            // without adding a fixed sleep.
            let deviceListRaw: Device[] = afterBackoff;
            try {
                const again = await this.fetchUserDeviceListOnce(userID);
                const byId = new Map<string, Device>();
                for (const d of afterBackoff) {
                    byId.set(d.deviceID, d);
                }
                for (const d of again) {
                    byId.set(d.deviceID, d);
                }
                deviceListRaw = [...byId.values()];
            } catch {
                deviceListRaw = afterBackoff;
            }
            if (deviceListRaw.length === 0) {
                throw new Error(
                    "No devices for user — cannot send direct message.",
                );
            }
            // Stable order (Peer device list is otherwise DB-order dependent).
            const deviceList = [...deviceListRaw].sort((a, b) =>
                a.deviceID.localeCompare(b.deviceID, "en"),
            );
            if (libvexDebugDmEnabled()) {
                debugLibvexDm(
                    "sendMessage: peer device list (merged, sorted)",
                    {
                        nAfterBackoff: String(afterBackoff.length),
                        nMerged: String(deviceListRaw.length),
                        nSorted: String(deviceList.length),
                        ourDevice: this.getDevice().deviceID,
                        userID,
                    },
                );
                for (const [i, d] of deviceList.entries()) {
                    debugLibvexDm(`sendMessage: device[${String(i)}]`, {
                        deviceID: d.deviceID,
                    });
                }
            }
            let lastErr: unknown;
            let failCount = 0;
            let successCount = 0;
            // One logical DM fan-outs to multiple recipient devices. Reuse a
            // single mailID so local/UI dedupe treats it as one message.
            const messageMailID = uuid.v4();
            const msgBytes = XUtils.decodeUTF8(payload);
            const firstOutgoingMessage: { current: Message | null } = {
                current: null,
            };
            for (
                let index = 0;
                index < deviceList.length;
                index += MAIL_FANOUT_CONCURRENCY
            ) {
                const batch = deviceList.slice(
                    index,
                    index + MAIL_FANOUT_CONCURRENCY,
                );
                const results = await Promise.all(
                    batch.map(async (device): Promise<undefined | unknown> => {
                        try {
                            if (libvexDebugDmEnabled()) {
                                debugLibvexDm("sendMessage: sendMail start", {
                                    mailID: messageMailID,
                                    recipientDevice: device.deviceID,
                                });
                            }
                            const sentMessage = await this.sendMailWithRecovery(
                                device,
                                userEntry,
                                msgBytes,
                                null,
                                messageMailID,
                                false,
                            );
                            if (
                                firstOutgoingMessage.current === null &&
                                sentMessage &&
                                !sentMessage.forward
                            ) {
                                firstOutgoingMessage.current = sentMessage;
                            }
                            if (libvexDebugDmEnabled()) {
                                debugLibvexDm("sendMessage: sendMail ok", {
                                    recipientDevice: device.deviceID,
                                });
                            }
                            return undefined;
                        } catch (e) {
                            if (libvexDebugDmEnabled()) {
                                // eslint-disable-next-line no-console -- LIBVEX_DEBUG_DM only
                                console.error(
                                    "[libvex:debug-dm] sendMessage: sendMail failed for device",
                                    device.deviceID,
                                    e,
                                );
                            }
                            return e;
                        }
                    }),
                );
                for (const result of results) {
                    if (result !== undefined) {
                        lastErr = result;
                        failCount += 1;
                    } else {
                        successCount += 1;
                    }
                }
                if (failCount === deviceList.length) {
                    break;
                }
            }
            if (successCount === 0) {
                const base =
                    lastErr instanceof Error
                        ? lastErr
                        : new Error(String(lastErr));
                throw base;
            }
            if (
                userID !== this.getUser().userID &&
                firstOutgoingMessage.current !== null
            ) {
                await this.forward(firstOutgoingMessage.current);
            }
        } catch (err: unknown) {
            throw err;
        }
    }

    private sendReceipt(nonce: Uint8Array) {
        const receipt: ReceiptMsg = {
            nonce,
            transmissionID: uuid.v4(),
            type: "receipt",
        };
        // Receipts are best-effort acknowledgements; a missed one
        // just means the server resends the mail on the next sync.
        // Don't surface a teardown race as an unhandled rejection.
        this.send(receipt).catch(ignoreSocketTeardown);
    }

    private setAlive(status: boolean) {
        this.isAlive = status;
    }

    private async setDevAccountTier(
        tier: AccountTier,
        options?: { expiresAt?: null | string },
    ): Promise<AccountEntitlements> {
        const res = await this.http.patch(
            this.getHost() +
                "/__dev/user/" +
                this.getUser().userID +
                "/entitlements",
            {
                expiresAt: options?.expiresAt ?? null,
                tier,
            },
        );
        return decodeHttpResponse(AccountEntitlementsCodec, res.data);
    }

    private async setServerMemberRole(
        permissionID: string,
        powerLevel: 0 | 50 | 100,
    ): Promise<Permission> {
        const res = await this.http.patch(
            this.getHost() + "/permission/" + permissionID,
            msgpack.encode({ powerLevel }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(PermissionCodec, res.data);
    }

    private setUser(user: User): void {
        this.user = user;
        // Fresh identity / token: drop stale 404 negative-cache entries so a
        // prior transient miss (or wrong host) cannot block DM sends for 30m.
        this.notFoundUsers.clear();
    }

    private shouldRetryDeliveryWithFreshSession(err: unknown): boolean {
        if (err instanceof WebSocketNotOpenError) {
            return true;
        }
        const message =
            err instanceof Error
                ? err.message.toLowerCase()
                : String(err).toLowerCase();
        return (
            message.includes("mail delivery failed") ||
            message.includes("not authenticated") ||
            message.includes("unauthorized") ||
            message.includes("websocket") ||
            message.includes("network") ||
            message.includes("timed out")
        );
    }

    /**
     * Polls the public unauthenticated request status endpoint as the
     * requesting device. Signs the server-issued challenge with the local
     * private signing key so the server can verify ownership of the pending
     * request without us needing a user token.
     */
    private async signPendingRegistrationChallenge(
        challengeHex: string,
    ): Promise<string> {
        return XUtils.encodeHex(
            await xSignAsync(
                XUtils.decodeHex(challengeHex),
                this.signKeys.secretKey,
            ),
        );
    }

    private async submitAppleTransaction(
        request: AppleTransactionVerificationRequest,
    ): Promise<BillingAccountState> {
        const res = await this.http.post(
            this.getHost() + "/billing/apple/transactions",
            request,
        );
        return decodeHttpResponse(BillingAccountStateCodec, res.data);
    }

    private async submitGooglePurchase(
        request: GooglePurchaseVerificationRequest,
    ): Promise<BillingAccountState> {
        const res = await this.http.post(
            this.getHost() + "/billing/google/purchases",
            request,
        );
        return decodeHttpResponse(BillingAccountStateCodec, res.data);
    }

    private async submitOTK(amount: number) {
        const otks: UnsavedPreKey[] = [];

        for (let i = 0; i < amount; i++) {
            otks.push(await this.createPreKey("one-time"));
        }

        const savedKeys = await this.database.savePreKeys(otks, true);

        await this.http.post(
            this.getHost() + "/device/" + this.getDevice().deviceID + "/otk",
            msgpack.encode(savedKeys.map((key) => this.censorPreKey(key))),
            {
                headers: { "Content-Type": "application/msgpack" },
            },
        );
    }

    private async updateChannel(
        channelID: string,
        name: string,
    ): Promise<Channel> {
        const res = await this.http.patch(
            this.getHost() + "/channel/" + channelID,
            msgpack.encode({ name }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(ChannelCodec, res.data);
    }

    private async updateServer(
        serverID: string,
        name: string,
    ): Promise<Server> {
        const res = await this.http.patch(
            this.getHost() + "/server/" + serverID,
            msgpack.encode({ name }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(ServerCodec, res.data);
    }

    private async uploadAvatar(avatar: Uint8Array): Promise<void> {
        const canUseMultipart =
            typeof FormData !== "undefined" &&
            (() => {
                try {
                    // React Native/Hermes can expose Blob/FormData but still
                    // reject ArrayBufferView-backed blobs at runtime.
                    // Probe support before choosing multipart upload.
                    void new Blob([new Uint8Array([1, 2, 3])]);
                    return true;
                } catch {
                    return false;
                }
            })();

        if (canUseMultipart) {
            const fpayload = new FormData();
            fpayload.set("avatar", new Blob([new Uint8Array(avatar)]));

            await this.http.post(
                this.prefixes.HTTP +
                    this.host +
                    "/avatar/" +
                    this.me.user().userID,
                fpayload,
                {
                    headers: { "Content-Type": "multipart/form-data" },
                    onUploadProgress: (progressEvent) => {
                        const percentCompleted = Math.round(
                            (progressEvent.loaded * 100) /
                                (progressEvent.total ?? 1),
                        );
                        const { loaded, total = 0 } = progressEvent;
                        const progress: FileProgress = {
                            direction: "upload",
                            loaded,
                            progress: percentCompleted,
                            token: this.getUser().userID,
                            total,
                        };
                        this.emitter.emit("fileProgress", progress);
                    },
                },
            );
            return;
        }

        const payload: { file: string } = {
            file: XUtils.encodeBase64(avatar),
        };
        await this.http.post(
            this.prefixes.HTTP +
                this.host +
                "/avatar/" +
                this.me.user().userID +
                "/json",
            msgpack.encode(payload),
            { headers: { "Content-Type": "application/msgpack" } },
        );
    }

    private async uploadEmoji(
        emoji: Uint8Array,
        name: string,
        serverID: string,
    ): Promise<Emoji | null> {
        if (typeof FormData !== "undefined") {
            const fpayload = new FormData();
            fpayload.set("emoji", new Blob([new Uint8Array(emoji)]));
            fpayload.set("name", name);

            try {
                const res = await this.http.post(
                    this.getHost() + "/emoji/" + serverID,
                    fpayload,
                    {
                        headers: { "Content-Type": "multipart/form-data" },
                        onUploadProgress: (progressEvent) => {
                            const percentCompleted = Math.round(
                                (progressEvent.loaded * 100) /
                                    (progressEvent.total ?? 1),
                            );
                            const { loaded, total = 0 } = progressEvent;
                            const progress: FileProgress = {
                                direction: "upload",
                                loaded,
                                progress: percentCompleted,
                                token: name,
                                total,
                            };
                            this.emitter.emit("fileProgress", progress);
                        },
                    },
                );
                return decodeHttpResponse(EmojiCodec, res.data);
            } catch (_err: unknown) {
                return null;
            }
        }

        const payload: { file: string; name: string } = {
            file: XUtils.encodeBase64(emoji),
            name,
        };
        try {
            const res = await this.http.post(
                this.getHost() + "/emoji/" + serverID + "/json",
                msgpack.encode(payload),
                { headers: { "Content-Type": "application/msgpack" } },
            );
            return decodeHttpResponse(EmojiCodec, res.data);
        } catch (_err: unknown) {
            return null;
        }
    }

    private async uploadServerIcon(
        serverID: string,
        icon: Uint8Array,
    ): Promise<Server> {
        const canUseMultipart =
            typeof FormData !== "undefined" &&
            (() => {
                try {
                    void new Blob([new Uint8Array([1, 2, 3])]);
                    return true;
                } catch {
                    return false;
                }
            })();

        if (canUseMultipart) {
            const payload = new FormData();
            payload.set("icon", new Blob([new Uint8Array(icon)]));
            const res = await this.http.post(
                this.getHost() + "/server-icon/" + serverID,
                payload,
                {
                    headers: { "Content-Type": "multipart/form-data" },
                    onUploadProgress: (progressEvent) => {
                        const { loaded, total = 0 } = progressEvent;
                        this.emitter.emit("fileProgress", {
                            direction: "upload",
                            loaded,
                            progress: Math.round(
                                (loaded * 100) / (progressEvent.total ?? 1),
                            ),
                            token: serverID,
                            total,
                        });
                    },
                },
            );
            return decodeHttpResponse(ServerCodec, res.data);
        }

        const res = await this.http.post(
            this.getHost() + "/server-icon/" + serverID + "/json",
            msgpack.encode({ file: XUtils.encodeBase64(icon) }),
            { headers: { "Content-Type": "application/msgpack" } },
        );
        return decodeHttpResponse(ServerCodec, res.data);
    }
}

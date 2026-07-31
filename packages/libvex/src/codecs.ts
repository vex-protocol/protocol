/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Pre-built codec instances for every HTTP response type.
 *
 * Usage: import { UserCodec } from "./codecs.js";
 *        const data = decodeHttpResponse(UserCodec, res.data);
 *
 * decode() returns typed data without runtime validation (SDK trusts server).
 * For trust boundary validation, use codec.decodeSafe() directly.
 */
import {
    AccountEntitlementsSchema,
    ActionTokenSchema,
    BillingAccountStateSchema,
    BillingProductSchema,
    ChannelSchema,
    DeviceSchema,
    EmojiSchema,
    FederationMigrationChallengeSchema,
    FederationMigrationImportResultSchema,
    FederationMigrationPrepareResultSchema,
    FileSQLSchema,
    InviteSchema,
    KeyBundleSchema,
    PasskeySchema,
    PermissionSchema,
    ServerChannelBootstrapSchema,
    ServerSchema,
    UserSchema,
} from "@vex-chat/types";

import { z } from "zod/v4";

import { createCodec } from "./codec.js";

// ── Named schema codecs ─────────────────────────────────────────────────────

export const UserCodec = createCodec(UserSchema);
export const DeviceCodec = createCodec(DeviceSchema);
export const ServerCodec = createCodec(ServerSchema);
export const ChannelCodec = createCodec(ChannelSchema);
export const PermissionCodec = createCodec(PermissionSchema);
export const InviteCodec = createCodec(InviteSchema);
export const EmojiCodec = createCodec(EmojiSchema);
export const FileSQLCodec = createCodec(FileSQLSchema);
export const FederationMigrationChallengeCodec = createCodec(
    FederationMigrationChallengeSchema,
);
export const FederationMigrationImportResultCodec = createCodec(
    FederationMigrationImportResultSchema,
);
export const FederationMigrationPrepareResultCodec = createCodec(
    FederationMigrationPrepareResultSchema,
);
export const ActionTokenCodec = createCodec(ActionTokenSchema);
export const AccountEntitlementsCodec = createCodec(AccountEntitlementsSchema);
export const BillingAccountStateCodec = createCodec(BillingAccountStateSchema);
export const KeyBundleCodec = createCodec(KeyBundleSchema);

// ── Array codecs ────────────────────────────────────────────────────────────

export const UserArrayCodec = createCodec(z.array(UserSchema));
export const DeviceArrayCodec = createCodec(z.array(DeviceSchema));
export const ServerArrayCodec = createCodec(z.array(ServerSchema));
export const ChannelArrayCodec = createCodec(z.array(ChannelSchema));
export const PermissionArrayCodec = createCodec(z.array(PermissionSchema));
export const InviteArrayCodec = createCodec(z.array(InviteSchema));
export const EmojiArrayCodec = createCodec(z.array(EmojiSchema));
export const ServerChannelBootstrapCodec = createCodec(
    ServerChannelBootstrapSchema,
);
export const BillingProductArrayCodec = createCodec(
    z.array(BillingProductSchema),
);

// ── Inline ad-hoc response codecs ───────────────────────────────────────────

export const ConnectResponseCodec = createCodec(
    z.object({ deviceToken: z.string() }),
);

export const AuthResponseCodec = createCodec(
    z.object({
        token: z.string(),
        user: UserSchema,
    }),
);

export const RegisterResponseCodec = createCodec(
    z.object({
        device: DeviceSchema,
        token: z.string(),
        user: UserSchema,
    }),
);

export const RegisterPendingApprovalCodec = createCodec(
    z.object({
        challenge: z.string(),
        expiresAt: z.string(),
        requestID: z.string(),
        status: z.literal("pending_approval"),
        userID: z.string(),
    }),
);

export const DeviceChallengeCodec = createCodec(
    z.object({
        challenge: z.string(),
        challengeID: z.string(),
    }),
);

export const DeviceRegistrationResultCodec = createCodec(
    z.union([
        DeviceSchema,
        z.object({
            challenge: z.string(),
            expiresAt: z.string(),
            requestID: z.string(),
            status: z.literal("pending_approval"),
            userID: z.string(),
        }),
    ]),
);

export const PendingDeviceRequestCodec = createCodec(
    z.object({
        approvedDeviceID: z.string().optional(),
        createdAt: z.string(),
        deviceName: z.string(),
        error: z.string().optional(),
        expiresAt: z.string(),
        requestID: z.string(),
        signKey: z.string(),
        status: z.union([
            z.literal("approved"),
            z.literal("expired"),
            z.literal("pending"),
            z.literal("rejected"),
        ]),
        username: z.string().optional(),
    }),
);

export const PendingDeviceRequestArrayCodec = createCodec(
    z.array(
        z.object({
            approvedDeviceID: z.string().optional(),
            createdAt: z.string(),
            deviceName: z.string(),
            error: z.string().optional(),
            expiresAt: z.string(),
            requestID: z.string(),
            signKey: z.string(),
            status: z.union([
                z.literal("approved"),
                z.literal("expired"),
                z.literal("pending"),
                z.literal("rejected"),
            ]),
            username: z.string().optional(),
        }),
    ),
);

export const WhoamiCodec = createCodec(
    z.object({
        exp: z.number(),
        user: UserSchema,
    }),
);

export const OtkCountCodec = createCodec(z.object({ count: z.number() }));

// ── Passkey response codecs ────────────────────────────────────────────────

export const PasskeyCodec = createCodec(PasskeySchema);
export const PasskeyArrayCodec = createCodec(z.array(PasskeySchema));

/**
 * The shape of `/user/:id/passkeys/register/begin` and
 * `/auth/passkey/begin` responses. `options` is the WebAuthn JSON
 * the host hands straight to `navigator.credentials.create()` /
 * `.get()` (via `@simplewebauthn/browser`); we don't validate its
 * inner shape because both ends of the wire (`@simplewebauthn/server`
 * on spire, `@simplewebauthn/browser` on the host) already do.
 */
export const PasskeyOptionsCodec = createCodec(
    z.object({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- WebAuthn options shape varies by simplewebauthn version
        options: z.unknown() as z.ZodType<any>,
        requestID: z.string(),
    }),
);

export const PasskeyAuthFinishResponseCodec = createCodec(
    z.object({
        passkeyID: z.string(),
        token: z.string(),
        user: UserSchema,
    }),
);

// ── Helper: decode binary HTTP response buffer ──────────────────────────────

/**
 * Decode a binary HTTP response with a typed codec.
 * Uses decodeSafe (Zod-validated) so schema mismatches surface immediately.
 */
export function decodeHttpResponse<T>(
    codec: { decodeSafe: (data: Uint8Array) => T },
    /** Accepts `unknown` so callers can pass transport response data directly. */
    data: unknown,
): T {
    if (data instanceof Uint8Array) {
        return codec.decodeSafe(data);
    }
    if (data instanceof ArrayBuffer) {
        return codec.decodeSafe(new Uint8Array(data));
    }
    throw new Error("Expected Uint8Array or ArrayBuffer from HTTP response");
}

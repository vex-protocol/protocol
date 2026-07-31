/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { KeyBundle, MailWS } from "./keys.js";
import type { RegistryPosition } from "./registry.js";
import type { Channel, Invite, Permission, Server } from "./servers.js";
import type { User } from "./users.js";

import { z } from "zod/v4";

import { uint8 } from "./common.js";
import { KeyBundleSchema, MailWSSchema } from "./keys.js";
import { RegistryBytes32Schema, RegistryPositionSchema } from "./registry.js";

const LEGACY_INVITE_ID_PATTERN =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FEDERATED_INVITE_ID_PATTERN =
    /^v1\.([0-9a-f]{64})\.([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const RoomRevisionSchema = z
    .string()
    .max(16)
    .regex(/^(?:0|[1-9][0-9]*)$/)
    .refine(
        (value) => BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER),
        "Room revision exceeds the supported range",
    );
const FederationUuidSchema = z.uuid();
const FederationChannelSchema: z.ZodType<Channel> = z
    .object({
        channelID: FederationUuidSchema,
        name: z.string().trim().min(1).max(100),
        serverID: FederationUuidSchema,
    })
    .strict();
export interface FederationDevice {
    deviceID: string;
    owner: string;
    signKey: string;
}

export const FederationDeviceSchema: z.ZodType<FederationDevice> = z
    .object({
        deviceID: FederationUuidSchema,
        owner: RegistryBytes32Schema,
        signKey: z.string().regex(/^[0-9a-f]{64}$/),
    })
    .strict();
const FederationInviteSchema: z.ZodType<Invite> = z
    .object({
        expiration: z.iso.datetime(),
        inviteID: FederationUuidSchema,
        owner: RegistryBytes32Schema,
        serverID: FederationUuidSchema,
    })
    .strict();
const FederationPermissionSchema: z.ZodType<Permission> = z
    .object({
        permissionID: FederationUuidSchema,
        powerLevel: z.union([z.literal(0), z.literal(50), z.literal(100)]),
        resourceID: FederationUuidSchema,
        resourceType: z.literal("server"),
        userID: RegistryBytes32Schema,
    })
    .strict();
const FederationUserSchema: z.ZodType<User> = z
    .object({
        lastSeen: z.iso.datetime(),
        userID: RegistryBytes32Schema,
        username: z.string().regex(/^[a-z0-9_]{3,19}$/),
    })
    .strict();

/** Signed federation request for a remote account's public devices. */
export interface FederationAccountQuery {
    accountId: string;
}

/** Public account and devices returned by its authoritative homeserver. */
export interface FederationAccountResult {
    devices: FederationDevice[];
    position: RegistryPosition;
    user: User;
}

export interface FederationInvitePreview {
    channels: Channel[];
    invite: Invite;
    server: Server;
}

export interface FederationInviteQuery {
    inviteId: string;
}

export interface FederationInviteRedeemQuery extends FederationInviteQuery {
    accountId: string;
}

export interface FederationInviteRedeemResult {
    permission: Permission;
    snapshot: FederationRoomSnapshot;
}

export interface FederationInviteReference {
    homeserverId: null | string;
    inviteId: string;
}

/** Signed request that atomically consumes a remote device one-time key. */
export interface FederationKeyBundleQuery {
    accountId: string;
    deviceId: string;
    requesterAccountId: string;
}

/** Device-bound key bundle returned by an authoritative homeserver. */
export interface FederationKeyBundleResult {
    device: FederationDevice;
    keyBundle: KeyBundle;
    position: RegistryPosition;
}

/** E2EE mail relayed between authoritative homeservers. */
export interface FederationMailEnvelope {
    header: Uint8Array;
    mail: MailWS;
    registrySequence: string;
    roomAuthorization: FederationRoomMailAuthorization | null;
    senderDeviceKey: string;
}

/** Idempotent remote mail delivery result. */
export interface FederationMailResult {
    duplicate: boolean;
}

export interface FederationMigrationAuthorization extends FederationMigrationAuthorizationInput {
    signature: string;
}

export interface FederationMigrationAuthorizationInput {
    accountId: string;
    destinationHomeserverId: string;
    deviceKey: string;
    expiresAt: number;
    nonce: string;
    sourceHomeserverId: string;
}

export interface FederationMigrationAvatarReference {
    contentType: string;
    sha256: string;
    size: number;
}

export interface FederationMigrationBlobResult {
    contentType: string;
    data: Uint8Array;
}

export type FederationMigrationChallenge =
    FederationMigrationAuthorizationInput;

export interface FederationMigrationCompleteResult {
    completed: boolean;
}

export interface FederationMigrationFileQuery extends FederationMigrationQuery {
    fileId: string;
}

export interface FederationMigrationFileReference {
    fileId: string;
    nonce: string;
    ownerDeviceKey: string;
    sha256: string;
    size: number;
}

export interface FederationMigrationImportRequest {
    migrationId: string;
    sourceHomeserverId: string;
}

export interface FederationMigrationImportResult {
    avatarImported: boolean;
    filesImported: number;
    mailDeferred: number;
    mailImported: number;
    roomsImported: number;
}

export interface FederationMigrationMailEntry {
    header: Uint8Array;
    mail: MailWS;
    recipientDeviceKey: string;
    time: string;
}

export interface FederationMigrationMailPage {
    entries: FederationMigrationMailEntry[];
    nextCursor: null | number;
}

export interface FederationMigrationMailQuery extends FederationMigrationQuery {
    cursor: number;
}

export interface FederationMigrationManifest {
    accountId: string;
    authorization: FederationMigrationAuthorization;
    avatar: FederationMigrationAvatarReference | null;
    files: FederationMigrationFileReference[];
    migrationId: string;
    rooms: FederationMigrationRoomReference[];
    transferExpiresAt: number;
}

export interface FederationMigrationPrepareResult {
    expiresAt: number;
    migrationId: string;
}

export interface FederationMigrationQuery {
    migrationId: string;
}

export interface FederationMigrationRoomReference {
    homeserverId: string;
    serverId: string;
}

export interface FederationRoomDeletion {
    originHomeserverId: string;
    revision: string;
    serverId: string;
}

export interface FederationRoomInvitesQuery {
    accountId: string;
    serverId: string;
}

/** Portable room membership authorization signed by the room homeserver. */
export interface FederationRoomMailAuthorization {
    channelId: string;
    expiresAt: number;
    originHomeserverId: string;
    recipientAccountId: string;
    revision: string;
    senderAccountId: string;
    serverId: string;
    signature: string;
}

/** Request for a room authority to authorize one sender/recipient account pair. */
export type FederationRoomMailAuthorizationQuery = Omit<
    FederationRoomMailAuthorization,
    "expiresAt" | "originHomeserverId" | "revision" | "signature"
>;

/** Public member entry in an authoritative room snapshot. */
export interface FederationRoomMember {
    permissionId: string;
    powerLevel: number;
    userId: string;
}

export type FederationRoomMutation =
    | { channelId: string; name: string; type: "rename-channel" }
    | { channelId: string; type: "delete-channel" }
    | { durationMs: number; type: "create-invite" }
    | { file: Uint8Array; type: "set-icon" }
    | { name: string; type: "create-channel" }
    | { name: string; type: "rename-server" }
    | { permissionId: string; powerLevel: 0 | 50 | 100; type: "update-member" }
    | { permissionId: string; type: "remove-member" }
    | { type: "delete-server" }
    | { type: "remove-icon" };

export interface FederationRoomMutationQuery {
    accountId: string;
    mutation: FederationRoomMutation;
    serverId: string;
}

export type FederationRoomMutationResult =
    | {
          channel: Channel;
          resultType: "channel";
          snapshot: FederationRoomSnapshot;
      }
    | {
          invite: Invite;
          resultType: "invite";
          snapshot: FederationRoomSnapshot;
      }
    | {
          permission: Permission;
          resultType: "permission";
          snapshot: FederationRoomSnapshot;
      }
    | {
          resultType: "deleted";
          snapshot: FederationRoomSnapshot | null;
      }
    | {
          resultType: "left";
          snapshot: FederationRoomSnapshot;
      }
    | {
          resultType: "server";
          server: Server;
          snapshot: FederationRoomSnapshot;
      };

export interface FederationRoomPushResult {
    accepted: boolean;
}

/** Authoritative room state used to create or refresh a local mirror. */
export interface FederationRoomSnapshot {
    channels: Channel[];
    members: FederationRoomMember[];
    revision: string;
    server: Server;
}

export interface FederationRoomSnapshotQuery {
    accountId: string;
    serverId: string;
}

/** Format a portable invite reference without exposing a homeserver URL. */
export function formatFederationInviteReference(
    homeserverId: string,
    inviteId: string,
): string {
    if (!/^0x[0-9a-f]{64}$/i.test(homeserverId)) {
        throw new Error("Homeserver ID must be a bytes32 value.");
    }
    if (!LEGACY_INVITE_ID_PATTERN.test(inviteId)) {
        throw new Error("Invite ID must be a UUID.");
    }
    return `v1.${homeserverId.slice(2).toLowerCase()}.${inviteId.toLowerCase()}`;
}

/** Parse a portable invite reference or a legacy local UUID. */
export function parseFederationInviteReference(
    value: string,
): FederationInviteReference | null {
    const normalized = value.trim();
    if (LEGACY_INVITE_ID_PATTERN.test(normalized)) {
        return { homeserverId: null, inviteId: normalized.toLowerCase() };
    }
    const match = FEDERATED_INVITE_ID_PATTERN.exec(normalized);
    if (match === null || match[1] === undefined || match[2] === undefined) {
        return null;
    }
    return {
        homeserverId: `0x${match[1].toLowerCase()}`,
        inviteId: match[2].toLowerCase(),
    };
}

export const FederationAccountQuerySchema: z.ZodType<FederationAccountQuery> = z
    .object({ accountId: RegistryBytes32Schema })
    .strict()
    .describe("Federation account query");

export const FederationAccountResultSchema: z.ZodType<FederationAccountResult> =
    z
        .object({
            devices: z.array(FederationDeviceSchema).min(1).max(20),
            position: RegistryPositionSchema,
            user: FederationUserSchema,
        })
        .strict()
        .describe("Authoritative federation account result");

export const FederationKeyBundleQuerySchema: z.ZodType<FederationKeyBundleQuery> =
    z
        .object({
            accountId: RegistryBytes32Schema,
            deviceId: FederationUuidSchema,
            requesterAccountId: RegistryBytes32Schema,
        })
        .strict()
        .describe("Federation key-bundle query");

export const FederationKeyBundleResultSchema: z.ZodType<FederationKeyBundleResult> =
    z
        .object({
            device: FederationDeviceSchema,
            keyBundle: KeyBundleSchema,
            position: RegistryPositionSchema,
        })
        .strict()
        .describe("Authoritative federation key bundle");

export const FederationMailEnvelopeSchema: z.ZodType<FederationMailEnvelope> = z
    .object({
        header: uint8.refine(
            (value) => value.byteLength === 32,
            "Mail authentication header must contain 32 bytes",
        ),
        mail: MailWSSchema,
        registrySequence: z
            .string()
            .max(78)
            .regex(/^(?:0|[1-9][0-9]*)$/),
        roomAuthorization: z.lazy(() =>
            FederationRoomMailAuthorizationSchema.nullable(),
        ),
        senderDeviceKey: RegistryBytes32Schema,
    })
    .strict()
    .describe("Federated E2EE mail envelope");

export const FederationMailResultSchema: z.ZodType<FederationMailResult> = z
    .object({ duplicate: z.boolean() })
    .strict()
    .describe("Federated mail delivery result");

const roomServerSchema: z.ZodType<Server> = z
    .object({
        homeserverId: RegistryBytes32Schema,
        icon: z
            .string()
            .regex(/^[a-zA-Z0-9._-]{1,255}$/)
            .optional(),
        name: z.string().trim().min(1).max(100),
        revision: RoomRevisionSchema,
        serverID: FederationUuidSchema,
    })
    .strict();

export const FederationRoomMailAuthorizationSchema: z.ZodType<FederationRoomMailAuthorization> =
    z
        .object({
            channelId: FederationUuidSchema,
            expiresAt: z
                .number()
                .int()
                .nonnegative()
                .max(Number.MAX_SAFE_INTEGER),
            originHomeserverId: RegistryBytes32Schema,
            recipientAccountId: RegistryBytes32Schema,
            revision: RoomRevisionSchema,
            senderAccountId: RegistryBytes32Schema,
            serverId: FederationUuidSchema,
            signature: z.string().regex(/^[0-9a-f]{128}$/),
        })
        .strict()
        .describe("Portable signed room mail authorization");

export const FederationRoomMailAuthorizationQuerySchema: z.ZodType<FederationRoomMailAuthorizationQuery> =
    z
        .object({
            channelId: FederationUuidSchema,
            recipientAccountId: RegistryBytes32Schema,
            senderAccountId: RegistryBytes32Schema,
            serverId: FederationUuidSchema,
        })
        .strict();

export const FederationRoomMemberSchema: z.ZodType<FederationRoomMember> = z
    .object({
        permissionId: FederationUuidSchema,
        powerLevel: z.union([z.literal(0), z.literal(50), z.literal(100)]),
        userId: RegistryBytes32Schema,
    })
    .strict();

export const FederationRoomSnapshotSchema: z.ZodType<FederationRoomSnapshot> = z
    .object({
        channels: z.array(FederationChannelSchema).min(1).max(1_000),
        members: z.array(FederationRoomMemberSchema).min(1).max(10_000),
        revision: RoomRevisionSchema,
        server: roomServerSchema,
    })
    .strict()
    .refine(
        (snapshot) => snapshot.server.revision === snapshot.revision,
        "Room snapshot revision does not match the server",
    )
    .refine(
        (snapshot) =>
            snapshot.channels.every(
                (channel) => channel.serverID === snapshot.server.serverID,
            ),
        "Room snapshot contains a channel from another server",
    )
    .refine(
        (snapshot) =>
            new Set(snapshot.channels.map((channel) => channel.channelID))
                .size === snapshot.channels.length,
        "Room snapshot contains duplicate channels",
    )
    .refine(
        (snapshot) =>
            new Set(snapshot.members.map((member) => member.userId)).size ===
            snapshot.members.length,
        "Room snapshot contains duplicate members",
    )
    .refine(
        (snapshot) =>
            new Set(snapshot.members.map((member) => member.permissionId))
                .size === snapshot.members.length,
        "Room snapshot contains duplicate permissions",
    );

export const FederationRoomSnapshotQuerySchema: z.ZodType<FederationRoomSnapshotQuery> =
    z
        .object({
            accountId: RegistryBytes32Schema,
            serverId: FederationUuidSchema,
        })
        .strict();

const roomMutationSchema: z.ZodType<FederationRoomMutation> =
    z.discriminatedUnion("type", [
        z
            .object({
                name: z.string().trim().min(1).max(100),
                type: z.literal("create-channel"),
            })
            .strict(),
        z
            .object({
                channelId: FederationUuidSchema,
                name: z.string().trim().min(1).max(100),
                type: z.literal("rename-channel"),
            })
            .strict(),
        z
            .object({
                channelId: FederationUuidSchema,
                type: z.literal("delete-channel"),
            })
            .strict(),
        z
            .object({
                name: z.string().trim().min(1).max(100),
                type: z.literal("rename-server"),
            })
            .strict(),
        z
            .object({
                durationMs: z.number().int().min(60_000).max(31_536_000_000),
                type: z.literal("create-invite"),
            })
            .strict(),
        z
            .object({
                file: uint8.refine(
                    (value) =>
                        value.byteLength > 0 && value.byteLength <= 5_242_880,
                    "Room icon must contain at most 5 MiB",
                ),
                type: z.literal("set-icon"),
            })
            .strict(),
        z.object({ type: z.literal("remove-icon") }).strict(),
        z
            .object({
                permissionId: FederationUuidSchema,
                powerLevel: z.union([
                    z.literal(0),
                    z.literal(50),
                    z.literal(100),
                ]),
                type: z.literal("update-member"),
            })
            .strict(),
        z
            .object({
                permissionId: FederationUuidSchema,
                type: z.literal("remove-member"),
            })
            .strict(),
        z.object({ type: z.literal("delete-server") }).strict(),
    ]);

export const FederationRoomMutationQuerySchema: z.ZodType<FederationRoomMutationQuery> =
    z
        .object({
            accountId: RegistryBytes32Schema,
            mutation: roomMutationSchema,
            serverId: FederationUuidSchema,
        })
        .strict();

export const FederationRoomMutationResultSchema: z.ZodType<FederationRoomMutationResult> =
    z.discriminatedUnion("resultType", [
        z
            .object({
                channel: FederationChannelSchema,
                resultType: z.literal("channel"),
                snapshot: FederationRoomSnapshotSchema,
            })
            .strict(),
        z
            .object({
                invite: FederationInviteSchema,
                resultType: z.literal("invite"),
                snapshot: FederationRoomSnapshotSchema,
            })
            .strict(),
        z
            .object({
                permission: FederationPermissionSchema,
                resultType: z.literal("permission"),
                snapshot: FederationRoomSnapshotSchema,
            })
            .strict(),
        z
            .object({
                resultType: z.literal("server"),
                server: roomServerSchema,
                snapshot: FederationRoomSnapshotSchema,
            })
            .strict(),
        z
            .object({
                resultType: z.literal("deleted"),
                snapshot: FederationRoomSnapshotSchema.nullable(),
            })
            .strict(),
        z
            .object({
                resultType: z.literal("left"),
                snapshot: FederationRoomSnapshotSchema,
            })
            .strict(),
    ]);

export const FederationRoomInvitesQuerySchema: z.ZodType<FederationRoomInvitesQuery> =
    z
        .object({
            accountId: RegistryBytes32Schema,
            serverId: FederationUuidSchema,
        })
        .strict();

export const FederationRoomInvitesResultSchema: z.ZodType<Invite[]> = z
    .array(FederationInviteSchema)
    .max(1_000);

export const FederationRoomDeletionSchema: z.ZodType<FederationRoomDeletion> = z
    .object({
        originHomeserverId: RegistryBytes32Schema,
        revision: RoomRevisionSchema,
        serverId: FederationUuidSchema,
    })
    .strict();

export const FederationRoomPushResultSchema: z.ZodType<FederationRoomPushResult> =
    z.object({ accepted: z.boolean() }).strict();

const migrationIdSchema = z.uuid();
const migrationAuthorizationShape = {
    accountId: RegistryBytes32Schema,
    destinationHomeserverId: RegistryBytes32Schema,
    deviceKey: RegistryBytes32Schema,
    expiresAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    nonce: RegistryBytes32Schema,
    sourceHomeserverId: RegistryBytes32Schema,
} as const;

export const FederationMigrationAuthorizationInputSchema: z.ZodType<FederationMigrationAuthorizationInput> =
    z.object(migrationAuthorizationShape).strict();

export const FederationMigrationAuthorizationSchema: z.ZodType<FederationMigrationAuthorization> =
    z
        .object({
            ...migrationAuthorizationShape,
            signature: z.string().regex(/^[0-9a-f]{128}$/),
        })
        .strict();

export const FederationMigrationChallengeSchema: z.ZodType<FederationMigrationChallenge> =
    FederationMigrationAuthorizationInputSchema;

export const FederationMigrationCompleteResultSchema: z.ZodType<FederationMigrationCompleteResult> =
    z.object({ completed: z.boolean() }).strict();

export const FederationMigrationPrepareResultSchema: z.ZodType<FederationMigrationPrepareResult> =
    z
        .object({
            expiresAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
            migrationId: migrationIdSchema,
        })
        .strict();

export const FederationMigrationAvatarReferenceSchema: z.ZodType<FederationMigrationAvatarReference> =
    z
        .object({
            contentType: z.string().min(1).max(255),
            sha256: RegistryBytes32Schema,
            size: z
                .number()
                .int()
                .nonnegative()
                .max(5 * 1024 * 1024),
        })
        .strict();

export const FederationMigrationRoomReferenceSchema: z.ZodType<FederationMigrationRoomReference> =
    z
        .object({
            homeserverId: RegistryBytes32Schema,
            serverId: FederationUuidSchema,
        })
        .strict();

export const FederationMigrationFileReferenceSchema: z.ZodType<FederationMigrationFileReference> =
    z
        .object({
            fileId: z.string().min(1).max(255),
            nonce: z.string().regex(/^[0-9a-f]{48}$/),
            ownerDeviceKey: RegistryBytes32Schema,
            sha256: RegistryBytes32Schema,
            size: z
                .number()
                .int()
                .nonnegative()
                .max(25 * 1024 * 1024),
        })
        .strict();

export const FederationMigrationManifestSchema: z.ZodType<FederationMigrationManifest> =
    z
        .object({
            accountId: RegistryBytes32Schema,
            authorization: FederationMigrationAuthorizationSchema,
            avatar: FederationMigrationAvatarReferenceSchema.nullable(),
            files: z.array(FederationMigrationFileReferenceSchema).max(10_000),
            migrationId: migrationIdSchema,
            rooms: z.array(FederationMigrationRoomReferenceSchema).max(10_000),
            transferExpiresAt: z
                .number()
                .int()
                .positive()
                .max(Number.MAX_SAFE_INTEGER),
        })
        .strict();

export const FederationMigrationQuerySchema: z.ZodType<FederationMigrationQuery> =
    z.object({ migrationId: migrationIdSchema }).strict();

export const FederationMigrationMailQuerySchema: z.ZodType<FederationMigrationMailQuery> =
    z
        .object({
            cursor: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
            migrationId: migrationIdSchema,
        })
        .strict();

export const FederationMigrationMailEntrySchema: z.ZodType<FederationMigrationMailEntry> =
    z
        .object({
            header: uint8.refine(
                (value) => value.byteLength === 32,
                "Mail authentication header must contain 32 bytes",
            ),
            mail: MailWSSchema,
            recipientDeviceKey: RegistryBytes32Schema,
            time: z.iso.datetime(),
        })
        .strict();

export const FederationMigrationMailPageSchema: z.ZodType<FederationMigrationMailPage> =
    z
        .object({
            entries: z.array(FederationMigrationMailEntrySchema).max(100),
            nextCursor: z.number().int().nonnegative().nullable(),
        })
        .strict();

export const FederationMigrationFileQuerySchema: z.ZodType<FederationMigrationFileQuery> =
    z
        .object({
            fileId: z.string().min(1).max(255),
            migrationId: migrationIdSchema,
        })
        .strict();

export const FederationMigrationBlobResultSchema: z.ZodType<FederationMigrationBlobResult> =
    z
        .object({
            contentType: z.string().min(1).max(255),
            data: uint8.refine(
                (value) => value.byteLength <= 25 * 1024 * 1024,
                "Migration blob exceeds 25 MiB",
            ),
        })
        .strict();

export const FederationMigrationImportRequestSchema: z.ZodType<FederationMigrationImportRequest> =
    z
        .object({
            migrationId: migrationIdSchema,
            sourceHomeserverId: RegistryBytes32Schema,
        })
        .strict();

export const FederationMigrationImportResultSchema: z.ZodType<FederationMigrationImportResult> =
    z
        .object({
            avatarImported: z.boolean(),
            filesImported: z.number().int().nonnegative(),
            mailDeferred: z.number().int().nonnegative(),
            mailImported: z.number().int().nonnegative(),
            roomsImported: z.number().int().nonnegative(),
        })
        .strict();

export const FederationInviteQuerySchema: z.ZodType<FederationInviteQuery> = z
    .object({ inviteId: FederationUuidSchema })
    .strict();

export const FederationInvitePreviewSchema: z.ZodType<FederationInvitePreview> =
    z
        .object({
            channels: z.array(FederationChannelSchema).min(1).max(1_000),
            invite: FederationInviteSchema,
            server: roomServerSchema,
        })
        .strict();

export const FederationInviteRedeemQuerySchema: z.ZodType<FederationInviteRedeemQuery> =
    z
        .object({
            accountId: RegistryBytes32Schema,
            inviteId: FederationUuidSchema,
        })
        .strict();

export const FederationInviteRedeemResultSchema: z.ZodType<FederationInviteRedeemResult> =
    z
        .object({
            permission: FederationPermissionSchema,
            snapshot: FederationRoomSnapshotSchema,
        })
        .strict();

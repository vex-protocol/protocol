/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database } from "../Database.ts";
import type { HomeserverMigrationService } from "../federation/HomeserverMigrationService.ts";
import type { KeyPair } from "@vex-chat/crypto";
import type {
    Device,
    FederationDevice,
    FederationMailEnvelope,
    FederationRoomDeletion,
    FederationRoomMutationQuery,
    FederationRoomMutationResult,
    FederationRoomSnapshot,
    IdentityResolver,
    Permission,
    RegistryIdentityResolution,
    Server,
} from "@vex-chat/types";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import {
    FederationAccountQuerySchema,
    FederationInviteQuerySchema,
    FederationInviteRedeemQuerySchema,
    FederationKeyBundleQuerySchema,
    FederationMailEnvelopeSchema,
    FederationMigrationFileQuerySchema,
    FederationMigrationMailQuerySchema,
    FederationMigrationQuerySchema,
    FederationRoomDeletionSchema,
    FederationRoomInvitesQuerySchema,
    FederationRoomMailAuthorizationQuerySchema,
    FederationRoomMutationQuerySchema,
    FederationRoomSnapshotQuerySchema,
    FederationRoomSnapshotSchema,
    MailType,
} from "@vex-chat/types";

import { stringify as uuidStringify } from "uuid";

import { POWER_LEVELS } from "../ClientManager.ts";
import { FederationServiceError } from "../federation/FederationService.ts";
import {
    createFederationResponseHeaders,
    createFederationRoomMailAuthorization,
    FEDERATION_REQUEST_MAX_SKEW_MS,
    FEDERATION_REQUEST_NONCE_TTL_MS,
    FEDERATION_VERSION,
    FederationHeaders,
    verifyFederationRequestSignature,
    verifyFederationRoomMailAuthorization,
} from "../federation/signatures.ts";
import { msgpack } from "../utils/msgpack.ts";

import {
    deleteServerIconFile,
    removeServerIcon,
    saveServerIcon,
    ServerIconError,
} from "./serverIcon.ts";

const FEDERATION_BODY_LIMIT = 6 * 1024 * 1024;
const KEY_BUNDLE_LIMIT = 30;
const KEY_BUNDLE_MAX_BUCKETS = 10_000;
const KEY_BUNDLE_WINDOW_MS = 15 * 60 * 1000;
const ROOM_AUTHORIZATION_TTL_MS = 60_000;

export interface FederationRouterOptions {
    db: Pick<
        Database,
        | "consumeFederationNonce"
        | "createChannel"
        | "createInvite"
        | "createPermission"
        | "deleteChannelIfNotLast"
        | "deletePermission"
        | "deleteServer"
        | "getKeyBundle"
        | "retrieveChannel"
        | "retrieveChannels"
        | "retrieveDevice"
        | "retrieveInvite"
        | "retrievePermission"
        | "retrievePermissions"
        | "retrievePermissionsByResourceID"
        | "retrieveRoomSnapshot"
        | "retrieveServer"
        | "retrieveServerInvites"
        | "retrieveUser"
        | "retrieveUserDeviceList"
        | "saveFederatedMail"
        | "updateChannel"
        | "updatePermissionPowerLevel"
        | "updateServer"
    >;
    homeserverId: string;
    migration?:
        | Pick<
              HomeserverMigrationService,
              | "completeSourceMigration"
              | "readMigrationAvatar"
              | "readMigrationFile"
              | "readMigrationMail"
              | "readMigrationManifest"
          >
        | undefined;
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
        headlessPushUserID?: string,
        mailNonce?: Uint8Array,
    ) => void;
    resolver: IdentityResolver;
    roomChanged?:
        | ((
              snapshot: FederationRoomSnapshot,
              previousSnapshot?: FederationRoomSnapshot,
          ) => Promise<void>)
        | undefined;
    roomDeleted?:
        | ((snapshot: FederationRoomSnapshot) => Promise<void>)
        | undefined;
    roomDeletionReceived?:
        | ((
              deletion: FederationRoomDeletion,
              originHomeserverId: string,
          ) => Promise<void>)
        | undefined;
    roomSnapshotReceived?:
        | ((
              snapshot: FederationRoomSnapshot,
              originHomeserverId: string,
          ) => Promise<void>)
        | undefined;
    signKeys: KeyPair;
}

interface FederationContext {
    nonce: string;
    origin: string;
}

interface KeyBundleRateBucket {
    count: number;
    resetAt: number;
}

class FederationRouteError extends Error {
    public readonly status: number;

    constructor(status: number, message: string) {
        super(message);
        this.name = "FederationRouteError";
        this.status = status;
    }
}

export function getFederationRouter(
    options: FederationRouterOptions,
): express.Router {
    const router = express.Router();
    const contexts = new WeakMap<express.Request, FederationContext>();
    const keyBundleRateBuckets = new Map<string, KeyBundleRateBucket>();

    router.use(
        express.raw({
            limit: FEDERATION_BODY_LIMIT,
            type: "application/msgpack",
        }),
    );
    router.use(async (request, response, next) => {
        try {
            if (!(request.body instanceof Uint8Array)) {
                response
                    .status(415)
                    .json({ error: "MessagePack body required." });
                return;
            }
            const version = requestHeader(request, FederationHeaders.version);
            const origin = requestHeader(request, FederationHeaders.origin);
            const destination = requestHeader(
                request,
                FederationHeaders.destination,
            );
            const nonce = requestHeader(request, FederationHeaders.nonce);
            const signature = requestHeader(
                request,
                FederationHeaders.signature,
            );
            const timestampRaw = requestHeader(
                request,
                FederationHeaders.timestamp,
            );
            if (
                version !== FEDERATION_VERSION ||
                !isBytes32(origin) ||
                destination !== options.homeserverId ||
                !isBytes32(nonce) ||
                signature === undefined ||
                !/^[0-9a-f]{128}$/.test(signature) ||
                timestampRaw === undefined ||
                !/^(?:0|[1-9][0-9]*)$/.test(timestampRaw)
            ) {
                response
                    .status(401)
                    .json({ error: "Invalid federation proof." });
                return;
            }
            const localHomeserver = await options.resolver.resolveHomeserver(
                options.homeserverId,
            );
            if (
                !localHomeserver?.record.active ||
                localHomeserver.record.signingKey !==
                    `0x${XUtils.encodeHex(options.signKeys.publicKey)}`
            ) {
                response.status(503).json({
                    error: "Federation signing key does not match the finalized registry.",
                });
                return;
            }
            const timestamp = Number(timestampRaw);
            const now = Date.now();
            if (
                !Number.isSafeInteger(timestamp) ||
                Math.abs(now - timestamp) > FEDERATION_REQUEST_MAX_SKEW_MS
            ) {
                response
                    .status(401)
                    .json({ error: "Federation proof expired." });
                return;
            }
            const originIdentity =
                await options.resolver.resolveHomeserver(origin);
            if (!originIdentity?.record.active) {
                response
                    .status(401)
                    .json({ error: "Unknown federation origin." });
                return;
            }
            if (request.originalUrl.includes("?")) {
                response
                    .status(401)
                    .json({ error: "Federation queries are not supported." });
                return;
            }
            const path = request.originalUrl;
            if (
                !verifyFederationRequestSignature(
                    {
                        body: request.body,
                        destination,
                        method: request.method,
                        nonce,
                        origin,
                        path,
                        timestamp,
                    },
                    signature,
                    originIdentity.record.signingKey,
                )
            ) {
                response
                    .status(401)
                    .json({ error: "Invalid federation proof." });
                return;
            }
            const consumed = await options.db.consumeFederationNonce(
                origin,
                nonce,
                now + FEDERATION_REQUEST_NONCE_TTL_MS,
                now,
            );
            if (!consumed) {
                response
                    .status(409)
                    .json({ error: "Federation replay rejected." });
                return;
            }
            contexts.set(request, {
                nonce,
                origin,
            });
            next();
        } catch {
            response.status(401).json({ error: "Invalid federation proof." });
        }
    });

    router.post("/account", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(request, FederationAccountQuerySchema);
            const identity = await authoritativeIdentity(
                options,
                query.accountId,
            );
            const user = await options.db.retrieveUser(query.accountId);
            if (!user) {
                sendSigned(options, context, response, 404, {
                    error: "Account not found.",
                });
                return;
            }
            const activeKeys = new Set(
                identity.devices.map((device) =>
                    withoutHexPrefix(device.deviceKey),
                ),
            );
            const devices = (
                await options.db.retrieveUserDeviceList([query.accountId])
            ).filter((device) =>
                activeKeys.has(withoutHexPrefix(device.signKey)),
            );
            if (devices.length === 0) {
                sendSigned(options, context, response, 404, {
                    error: "Account has no active local devices.",
                });
                return;
            }
            sendSigned(options, context, response, 200, {
                devices: devices.map(publicFederationDevice),
                position: identity.position,
                user: {
                    lastSeen: user.lastSeen,
                    userID: user.userID,
                    username: identity.username?.username ?? user.username,
                },
            });
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/key-bundle", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(request, FederationKeyBundleQuerySchema);
            const identity = await authoritativeIdentity(
                options,
                query.accountId,
            );
            await authoritativeOriginAccount(
                options,
                context,
                query.requesterAccountId,
            );
            const device = await options.db.retrieveDevice(query.deviceId);
            const activeKeys = new Set(
                identity.devices.map((entry) =>
                    withoutHexPrefix(entry.deviceKey),
                ),
            );
            if (
                !device ||
                device.owner !== query.accountId ||
                !activeKeys.has(withoutHexPrefix(device.signKey))
            ) {
                sendSigned(options, context, response, 404, {
                    error: "Active device not found.",
                });
                return;
            }
            if (
                !consumeKeyBundleQuota(
                    keyBundleRateBuckets,
                    `${query.requesterAccountId}:${query.accountId}:${query.deviceId}`,
                    Date.now(),
                )
            ) {
                throw new FederationRouteError(
                    429,
                    "Key-bundle request limit exceeded.",
                );
            }
            const keyBundle = await options.db.getKeyBundle(device.deviceID);
            if (!keyBundle) {
                sendSigned(options, context, response, 404, {
                    error: "Key bundle not found.",
                });
                return;
            }
            sendSigned(options, context, response, 200, {
                device: publicFederationDevice(device),
                keyBundle,
                position: identity.position,
            });
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/invite/preview", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(request, FederationInviteQuerySchema);
            const invite = await options.db.retrieveInvite(query.inviteId);
            if (!invite || Date.parse(invite.expiration) <= Date.now()) {
                throw new FederationRouteError(404, "Invite not found.");
            }
            const server = await authoritativeRoom(options, invite.serverID);
            const channels = await options.db.retrieveChannels(server.serverID);
            sendSigned(options, context, response, 200, {
                channels,
                invite,
                server,
            });
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/invite/redeem", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(request, FederationInviteRedeemQuerySchema);
            await authoritativeOriginAccount(options, context, query.accountId);
            const invite = await options.db.retrieveInvite(query.inviteId);
            if (!invite || Date.parse(invite.expiration) <= Date.now()) {
                throw new FederationRouteError(404, "Invite not found.");
            }
            await authoritativeRoom(options, invite.serverID);
            const previousSnapshot = await roomSnapshot(
                options,
                invite.serverID,
            );
            const permission = await options.db.createPermission(
                query.accountId,
                "server",
                invite.serverID,
                0,
            );
            const snapshot = await options.db.retrieveRoomSnapshot(
                invite.serverID,
            );
            if (!snapshot) {
                throw new FederationRouteError(
                    500,
                    "Room state is unavailable.",
                );
            }
            notifyRoomMembers(options, snapshot);
            await options.roomChanged?.(snapshot, previousSnapshot);
            sendSigned(options, context, response, 200, {
                permission,
                snapshot,
            });
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/room", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(request, FederationRoomSnapshotQuerySchema);
            await authoritativeOriginAccount(options, context, query.accountId);
            await requireRoomMember(options, query.serverId, query.accountId);
            const snapshot = await options.db.retrieveRoomSnapshot(
                query.serverId,
            );
            if (!snapshot) {
                throw new FederationRouteError(404, "Room not found.");
            }
            sendSigned(options, context, response, 200, snapshot);
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/room/invites", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(request, FederationRoomInvitesQuerySchema);
            await authoritativeOriginAccount(options, context, query.accountId);
            const permission = await requireRoomMember(
                options,
                query.serverId,
                query.accountId,
            );
            requirePower(permission, POWER_LEVELS.INVITE);
            const invites = await options.db.retrieveServerInvites(
                query.serverId,
            );
            sendSigned(options, context, response, 200, invites);
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/room/mutate", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(request, FederationRoomMutationQuerySchema);
            await authoritativeOriginAccount(options, context, query.accountId);
            const actor = await requireRoomMember(
                options,
                query.serverId,
                query.accountId,
            );
            const previousSnapshot = await roomSnapshot(
                options,
                query.serverId,
            );
            const result = await mutateRoom(options, actor, query);
            if (result.snapshot) {
                notifyRoomMembers(options, result.snapshot);
                if (result.resultType !== "invite") {
                    await options.roomChanged?.(
                        result.snapshot,
                        previousSnapshot,
                    );
                }
            }
            sendSigned(options, context, response, 200, result);
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/room/update", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const snapshot = parseBody(request, FederationRoomSnapshotSchema);
            if (
                snapshot.server.homeserverId !== context.origin ||
                !options.roomSnapshotReceived
            ) {
                throw new FederationRouteError(
                    403,
                    "Room update is not accepted.",
                );
            }
            await options.roomSnapshotReceived(snapshot, context.origin);
            sendSigned(options, context, response, 200, { accepted: true });
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/room/deleted", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const deletion = parseBody(request, FederationRoomDeletionSchema);
            if (
                deletion.originHomeserverId !== context.origin ||
                !options.roomDeletionReceived
            ) {
                throw new FederationRouteError(
                    403,
                    "Room deletion is not accepted.",
                );
            }
            await options.roomDeletionReceived(deletion, context.origin);
            sendSigned(options, context, response, 200, { accepted: true });
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/room/authorize-mail", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const query = parseBody(
                request,
                FederationRoomMailAuthorizationQuerySchema,
            );
            await authoritativeOriginAccount(
                options,
                context,
                query.senderAccountId,
            );
            const server = await authoritativeRoom(options, query.serverId);
            const channel = await options.db.retrieveChannel(query.channelId);
            if (!channel || channel.serverID !== server.serverID) {
                throw new FederationRouteError(404, "Channel not found.");
            }
            await Promise.all([
                requireRoomMember(
                    options,
                    query.serverId,
                    query.senderAccountId,
                ),
                requireRoomMember(
                    options,
                    query.serverId,
                    query.recipientAccountId,
                ),
            ]);
            sendSigned(
                options,
                context,
                response,
                200,
                createFederationRoomMailAuthorization(
                    {
                        ...query,
                        expiresAt: Date.now() + ROOM_AUTHORIZATION_TTL_MS,
                        originHomeserverId: options.homeserverId,
                        revision: server.revision ?? "0",
                    },
                    options.signKeys.secretKey,
                ),
            );
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    router.post("/mail", async (request, response) => {
        const context = requireContext(contexts, request);
        try {
            const envelope = parseBody(request, FederationMailEnvelopeSchema);
            const sender = await options.resolver.resolveIdentity(
                envelope.mail.authorID,
                { minimumSequence: envelope.registrySequence },
            );
            if (
                !sender ||
                sender.homeserver.homeserverId !== context.origin ||
                !sender.devices.some(
                    (device) => device.deviceKey === envelope.senderDeviceKey,
                )
            ) {
                sendSigned(options, context, response, 403, {
                    error: "Sender is not authoritative or active.",
                });
                return;
            }
            if (envelope.mail.group === null) {
                if (envelope.roomAuthorization !== null) {
                    throw new FederationRouteError(
                        400,
                        "Direct mail cannot contain a room authorization.",
                    );
                }
            } else {
                await verifyRoomEnvelope(options, envelope);
            }
            if (
                envelope.mail.mailType === MailType.initial &&
                initialSenderKey(envelope.mail.extra) !==
                    envelope.senderDeviceKey
            ) {
                sendSigned(options, context, response, 403, {
                    error: "Initial message identity key does not match the sender device.",
                });
                return;
            }

            const recipient = await authoritativeIdentity(
                options,
                envelope.mail.readerID,
            );
            const recipientDevice = await options.db.retrieveDevice(
                envelope.mail.recipient,
            );
            const recipientKeys = new Set(
                recipient.devices.map((device) =>
                    withoutHexPrefix(device.deviceKey),
                ),
            );
            if (
                !recipientDevice ||
                recipientDevice.owner !== envelope.mail.readerID ||
                !recipientKeys.has(withoutHexPrefix(recipientDevice.signKey))
            ) {
                sendSigned(options, context, response, 404, {
                    error: "Recipient device is not active on this homeserver.",
                });
                return;
            }

            const inserted = await options.db.saveFederatedMail(
                envelope.mail,
                envelope.header,
            );
            sendSigned(options, context, response, 200, {
                duplicate: !inserted,
            });
            if (inserted) {
                options.notify(
                    recipientDevice.owner,
                    "mail",
                    crypto.randomUUID(),
                    null,
                    envelope.mail.recipient,
                    envelope.mail.authorID,
                    envelope.mail.nonce,
                );
            }
        } catch (error: unknown) {
            sendRouteError(options, context, response, error);
        }
    });

    if (options.migration) {
        router.post("/migration/avatar", async (request, response) => {
            const context = requireContext(contexts, request);
            try {
                const query = parseBody(
                    request,
                    FederationMigrationQuerySchema,
                );
                const result = await options.migration?.readMigrationAvatar(
                    context.origin,
                    query,
                );
                sendSigned(options, context, response, 200, result);
            } catch (error: unknown) {
                sendRouteError(options, context, response, error);
            }
        });

        router.post("/migration/complete", async (request, response) => {
            const context = requireContext(contexts, request);
            try {
                const query = parseBody(
                    request,
                    FederationMigrationQuerySchema,
                );
                const result = await options.migration?.completeSourceMigration(
                    context.origin,
                    query,
                );
                sendSigned(options, context, response, 200, result);
            } catch (error: unknown) {
                sendRouteError(options, context, response, error);
            }
        });

        router.post("/migration/file", async (request, response) => {
            const context = requireContext(contexts, request);
            try {
                const query = parseBody(
                    request,
                    FederationMigrationFileQuerySchema,
                );
                const result = await options.migration?.readMigrationFile(
                    context.origin,
                    query,
                );
                sendSigned(options, context, response, 200, result);
            } catch (error: unknown) {
                sendRouteError(options, context, response, error);
            }
        });

        router.post("/migration/mail", async (request, response) => {
            const context = requireContext(contexts, request);
            try {
                const query = parseBody(
                    request,
                    FederationMigrationMailQuerySchema,
                );
                const result = await options.migration?.readMigrationMail(
                    context.origin,
                    query,
                );
                sendSigned(options, context, response, 200, result);
            } catch (error: unknown) {
                sendRouteError(options, context, response, error);
            }
        });

        router.post("/migration/manifest", async (request, response) => {
            const context = requireContext(contexts, request);
            try {
                const query = parseBody(
                    request,
                    FederationMigrationQuerySchema,
                );
                const result = await options.migration?.readMigrationManifest(
                    context.origin,
                    query,
                );
                sendSigned(options, context, response, 200, result);
            } catch (error: unknown) {
                sendRouteError(options, context, response, error);
            }
        });
    }

    return router;
}

async function authoritativeIdentity(
    options: FederationRouterOptions,
    accountId: string,
): Promise<RegistryIdentityResolution> {
    const identity = await options.resolver.resolveIdentity(accountId);
    if (
        !identity ||
        !identity.homeserver.active ||
        identity.homeserver.homeserverId !== options.homeserverId
    ) {
        throw new FederationRouteError(404, "Account is not hosted here.");
    }
    return identity;
}

async function authoritativeOriginAccount(
    options: FederationRouterOptions,
    context: FederationContext,
    accountId: string,
): Promise<RegistryIdentityResolution> {
    const identity = await options.resolver.resolveIdentity(accountId);
    if (
        !identity ||
        !identity.homeserver.active ||
        identity.homeserver.homeserverId !== context.origin
    ) {
        throw new FederationRouteError(
            403,
            "The origin homeserver is not authoritative for this account.",
        );
    }
    return identity;
}

async function authoritativeRoom(
    options: FederationRouterOptions,
    serverId: string,
): Promise<Server> {
    const server = await options.db.retrieveServer(serverId);
    if (
        !server ||
        server.homeserverId !== options.homeserverId ||
        server.revision === undefined
    ) {
        throw new FederationRouteError(404, "Room not found.");
    }
    return server;
}

function consumeKeyBundleQuota(
    buckets: Map<string, KeyBundleRateBucket>,
    key: string,
    now: number,
): boolean {
    const current = buckets.get(key);
    if (current && current.resetAt > now) {
        if (current.count >= KEY_BUNDLE_LIMIT) return false;
        current.count += 1;
        return true;
    }

    if (current) buckets.delete(key);
    if (buckets.size >= KEY_BUNDLE_MAX_BUCKETS) {
        for (const [bucketKey, bucket] of buckets) {
            if (bucket.resetAt <= now) buckets.delete(bucketKey);
        }
        if (buckets.size >= KEY_BUNDLE_MAX_BUCKETS) return false;
    }
    buckets.set(key, { count: 1, resetAt: now + KEY_BUNDLE_WINDOW_MS });
    return true;
}

async function iconMutation(operation: () => Promise<Server>): Promise<Server> {
    try {
        return await operation();
    } catch (error: unknown) {
        if (error instanceof ServerIconError) {
            throw new FederationRouteError(error.status, error.message);
        }
        throw error;
    }
}

function initialSenderKey(value: Uint8Array): null | string {
    return value.byteLength >= 32
        ? `0x${XUtils.encodeHex(value.slice(0, 32))}`
        : null;
}

function isBytes32(value: string | undefined): value is string {
    return value !== undefined && /^0x[0-9a-f]{64}$/.test(value);
}

async function mutateRoom(
    options: FederationRouterOptions,
    actor: Permission,
    query: FederationRoomMutationQuery,
): Promise<FederationRoomMutationResult> {
    switch (query.mutation.type) {
        case "create-channel": {
            requirePower(actor, POWER_LEVELS.CREATE);
            const channel = await options.db.createChannel(
                query.mutation.name,
                query.serverId,
            );
            return {
                channel,
                resultType: "channel",
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
        case "create-invite": {
            requirePower(actor, POWER_LEVELS.INVITE);
            const invite = await options.db.createInvite(
                crypto.randomUUID(),
                query.serverId,
                actor.userID,
                new Date(Date.now() + query.mutation.durationMs).toISOString(),
            );
            return {
                invite,
                resultType: "invite",
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
        case "delete-channel": {
            requirePower(actor, POWER_LEVELS.DELETE);
            const channel = await options.db.retrieveChannel(
                query.mutation.channelId,
            );
            if (!channel || channel.serverID !== query.serverId) {
                throw new FederationRouteError(404, "Channel not found.");
            }
            if (!(await options.db.deleteChannelIfNotLast(channel.channelID))) {
                throw new FederationRouteError(
                    409,
                    "A room must have at least one channel.",
                );
            }
            return {
                channel,
                resultType: "channel",
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
        case "delete-server": {
            requirePower(actor, 100);
            const snapshot = await roomSnapshot(options, query.serverId);
            await options.db.deleteServer(query.serverId);
            if (snapshot.server.icon) {
                await deleteServerIconFile(snapshot.server.icon);
            }
            notifyRoomMembers(options, snapshot);
            await options.roomDeleted?.(snapshot);
            return { resultType: "deleted", snapshot: null };
        }
        case "remove-icon": {
            requirePower(actor, POWER_LEVELS.CREATE);
            const server = await iconMutation(() =>
                removeServerIcon(options.db, query.serverId),
            );
            return {
                resultType: "server",
                server,
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
        case "remove-member": {
            const target = await roomPermission(
                options,
                query.serverId,
                query.mutation.permissionId,
            );
            await requireCanRemoveMember(
                options,
                actor,
                target,
                query.serverId,
            );
            await options.db.deletePermission(target.permissionID);
            const snapshot = await roomSnapshot(options, query.serverId);
            return target.userID === actor.userID
                ? { resultType: "left", snapshot }
                : { permission: target, resultType: "permission", snapshot };
        }
        case "rename-channel": {
            requirePower(actor, POWER_LEVELS.CREATE);
            const channel = await options.db.retrieveChannel(
                query.mutation.channelId,
            );
            if (!channel || channel.serverID !== query.serverId) {
                throw new FederationRouteError(404, "Channel not found.");
            }
            const updated = await options.db.updateChannel(
                channel.channelID,
                query.mutation.name,
            );
            if (!updated) {
                throw new FederationRouteError(404, "Channel not found.");
            }
            return {
                channel: updated,
                resultType: "channel",
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
        case "rename-server": {
            requirePower(actor, POWER_LEVELS.CREATE);
            const server = await options.db.updateServer(query.serverId, {
                name: query.mutation.name,
            });
            if (!server) {
                throw new FederationRouteError(404, "Room not found.");
            }
            return {
                resultType: "server",
                server,
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
        case "set-icon": {
            requirePower(actor, POWER_LEVELS.CREATE);
            const file = query.mutation.file;
            const server = await iconMutation(() =>
                saveServerIcon(options.db, query.serverId, file),
            );
            return {
                resultType: "server",
                server,
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
        case "update-member": {
            requirePower(actor, 100);
            const target = await roomPermission(
                options,
                query.serverId,
                query.mutation.permissionId,
            );
            if (target.userID === actor.userID) {
                throw new FederationRouteError(
                    400,
                    "An owner cannot change their own role.",
                );
            }
            const permission = await options.db.updatePermissionPowerLevel(
                target.permissionID,
                query.mutation.powerLevel,
            );
            if (!permission) {
                throw new FederationRouteError(404, "Member not found.");
            }
            return {
                permission,
                resultType: "permission",
                snapshot: await roomSnapshot(options, query.serverId),
            };
        }
    }
}

function notifyRoomMembers(
    options: FederationRouterOptions,
    snapshot: FederationRoomSnapshot,
): void {
    for (const member of snapshot.members) {
        options.notify(
            member.userId,
            "serverChange",
            crypto.randomUUID(),
            snapshot.server.serverID,
        );
    }
}

function parseBody<T>(
    request: express.Request,
    schema: { parse(value: unknown): T },
): T {
    if (!Buffer.isBuffer(request.body)) {
        throw new FederationRouteError(
            400,
            "Expected a MessagePack request body.",
        );
    }
    return schema.parse(msgpack.decode(new Uint8Array(request.body)));
}

function publicFederationDevice(device: Device): FederationDevice {
    return {
        deviceID: device.deviceID,
        owner: device.owner,
        signKey: device.signKey.toLowerCase(),
    };
}

function requestHeader(
    request: express.Request,
    name: string,
): string | undefined {
    const value = request.headers[name];
    return typeof value === "string" ? value : undefined;
}

async function requireCanRemoveMember(
    options: FederationRouterOptions,
    actor: Permission,
    target: Permission,
    serverId: string,
): Promise<void> {
    if (
        target.userID !== actor.userID &&
        (actor.powerLevel < POWER_LEVELS.DELETE ||
            actor.powerLevel <= target.powerLevel)
    ) {
        throw new FederationRouteError(403, "Member cannot be removed.");
    }
    if (target.powerLevel >= 100) {
        const permissions =
            await options.db.retrievePermissionsByResourceID(serverId);
        if (
            !permissions.some(
                (permission) =>
                    permission.permissionID !== target.permissionID &&
                    permission.powerLevel >= 100,
            )
        ) {
            throw new FederationRouteError(
                409,
                "A room must retain at least one owner.",
            );
        }
    }
}

function requireContext(
    contexts: WeakMap<express.Request, FederationContext>,
    request: express.Request,
): FederationContext {
    const context = contexts.get(request);
    if (!context) throw new Error("Federation request was not authenticated.");
    return context;
}

function requirePower(permission: Permission, powerLevel: number): void {
    if (permission.powerLevel < powerLevel) {
        throw new FederationRouteError(403, "Room permission is insufficient.");
    }
}

async function requireRoomMember(
    options: FederationRouterOptions,
    serverId: string,
    accountId: string,
): Promise<Permission> {
    await authoritativeRoom(options, serverId);
    const permissions =
        await options.db.retrievePermissionsByResourceID(serverId);
    const permission = permissions.find((entry) => entry.userID === accountId);
    if (!permission) {
        throw new FederationRouteError(403, "Account is not a room member.");
    }
    return permission;
}

async function roomPermission(
    options: FederationRouterOptions,
    serverId: string,
    permissionId: string,
): Promise<Permission> {
    const permission = await options.db.retrievePermission(permissionId);
    if (
        !permission ||
        permission.resourceType !== "server" ||
        permission.resourceID !== serverId
    ) {
        throw new FederationRouteError(404, "Member not found.");
    }
    return permission;
}

async function roomSnapshot(
    options: FederationRouterOptions,
    serverId: string,
): Promise<FederationRoomSnapshot> {
    const snapshot = await options.db.retrieveRoomSnapshot(serverId);
    if (!snapshot) {
        throw new FederationRouteError(404, "Room not found.");
    }
    return snapshot;
}

function sendRouteError(
    options: FederationRouterOptions,
    context: FederationContext,
    response: express.Response,
    error: unknown,
): void {
    const status =
        error instanceof FederationRouteError ||
        error instanceof FederationServiceError
            ? error.status
            : 500;
    const message =
        error instanceof FederationRouteError ||
        error instanceof FederationServiceError
            ? error.message
            : "Federation request failed.";
    sendSigned(options, context, response, status, { error: message });
}

function sendSigned(
    options: FederationRouterOptions,
    context: FederationContext,
    response: express.Response,
    status: number,
    value: unknown,
): void {
    const body = msgpack.encode(value);
    response.set(
        createFederationResponseHeaders(
            {
                body,
                destination: context.origin,
                origin: options.homeserverId,
                requestNonce: context.nonce,
                status,
            },
            options.signKeys.secretKey,
        ),
    );
    response.status(status).type("application/msgpack").send(body);
}

async function verifyRoomEnvelope(
    options: FederationRouterOptions,
    envelope: FederationMailEnvelope,
): Promise<void> {
    const authorization = envelope.roomAuthorization;
    if (!authorization) {
        throw new FederationRouteError(
            403,
            "Federated room mail requires room authorization.",
        );
    }
    let channelId: string;
    try {
        channelId = uuidStringify(envelope.mail.group ?? new Uint8Array());
    } catch {
        throw new FederationRouteError(400, "Room channel ID is invalid.");
    }
    if (
        authorization.expiresAt < Date.now() ||
        authorization.channelId !== channelId ||
        authorization.senderAccountId !== envelope.mail.authorID ||
        authorization.recipientAccountId !== envelope.mail.readerID
    ) {
        throw new FederationRouteError(403, "Room authorization is invalid.");
    }
    const [channel, server, permissions, origin] = await Promise.all([
        options.db.retrieveChannel(authorization.channelId),
        options.db.retrieveServer(authorization.serverId),
        options.db.retrievePermissions(envelope.mail.readerID, "server"),
        options.resolver.resolveHomeserver(authorization.originHomeserverId),
    ]);
    if (
        !channel ||
        channel.serverID !== authorization.serverId ||
        !server ||
        server.homeserverId !== authorization.originHomeserverId ||
        server.revision === undefined ||
        BigInt(authorization.revision) < BigInt(server.revision) ||
        !permissions.some(
            (permission) => permission.resourceID === authorization.serverId,
        ) ||
        !origin?.record.active ||
        !verifyFederationRoomMailAuthorization(
            authorization,
            origin.record.signingKey,
        )
    ) {
        throw new FederationRouteError(403, "Room authorization is invalid.");
    }
}

function withoutHexPrefix(value: string): string {
    return value.startsWith("0x")
        ? value.slice(2).toLowerCase()
        : value.toLowerCase();
}

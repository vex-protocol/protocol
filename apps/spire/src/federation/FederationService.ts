/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database, FederationRoomOutboxEntry } from "../Database.ts";
import type { FederationClient } from "./FederationClient.ts";
import type { KeyPair } from "@vex-chat/crypto";
import type {
    Device,
    FederationAccountResult,
    FederationDevice,
    FederationInvitePreview,
    FederationInviteRedeemResult,
    FederationKeyBundleResult,
    FederationRoomDeletion,
    FederationRoomMailAuthorization,
    FederationRoomMutation,
    FederationRoomMutationResult,
    FederationRoomSnapshot,
    IdentityResolver,
    Invite,
    KeyBundle,
    MailWS,
    Permission,
    RegistryIdentityResolution,
    Server,
    User,
} from "@vex-chat/types";

import { createHash } from "node:crypto";

import { XUtils } from "@vex-chat/crypto";
import {
    FederationRoomDeletionSchema,
    FederationRoomSnapshotSchema,
} from "@vex-chat/types";

import { stringify as uuidStringify } from "uuid";

import {
    createFederationRoomMailAuthorization,
    verifyFederationRoomMailAuthorization,
} from "./signatures.ts";

const ROOM_AUTHORIZATION_CACHE_MAX = 10_000;

export interface FederationServiceOptions {
    client: FederationTransport;
    db: FederationDatabase;
    homeserverId: string;
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
    signKeys: KeyPair;
}

type FederationDatabase = Pick<
    Database,
    | "applyFederatedRoomDeletion"
    | "completeFederationRoomOutbox"
    | "deleteServer"
    | "enqueueFederationRoomOutbox"
    | "failFederationRoomOutbox"
    | "getKeyBundle"
    | "removeFederatedRoomMirror"
    | "retrieveChannel"
    | "retrieveDevice"
    | "retrieveFederationRoomOutbox"
    | "retrieveFederationRoomTombstone"
    | "retrievePermissions"
    | "retrievePermissionsByResourceID"
    | "retrieveRoomSnapshot"
    | "retrieveServer"
    | "retrieveServerByIcon"
    | "retrieveUser"
    | "retrieveUserDeviceList"
    | "saveFederatedRoom"
    | "saveMail"
>;
type FederationTransport = Pick<
    FederationClient,
    | "authorizeRoomMail"
    | "deliverMail"
    | "getAvatar"
    | "getKeyBundle"
    | "getServerIcon"
    | "mutateRoom"
    | "previewInvite"
    | "pushRoomDeletion"
    | "pushRoomSnapshot"
    | "queryAccount"
    | "queryRoom"
    | "queryRoomInvites"
    | "redeemInvite"
>;

/** Chain-neutral local/remote identity and mail routing for a Spire instance. */
export class FederationService {
    private readonly client: FederationTransport;
    private readonly db: FederationDatabase;
    private readonly homeserverId: string;
    private readonly notify: FederationServiceOptions["notify"];
    private outboxFlush: null | Promise<void> = null;
    private outboxStarted = false;
    private outboxTimer: null | ReturnType<typeof setTimeout> = null;
    private readonly resolver: IdentityResolver;
    private readonly roomAuthorizationCache = new Map<
        string,
        FederationRoomMailAuthorization
    >();
    private readonly signKeys: KeyPair;

    constructor(options: FederationServiceOptions) {
        this.client = options.client;
        this.db = options.db;
        this.homeserverId = options.homeserverId;
        this.notify = options.notify;
        this.resolver = options.resolver;
        this.signKeys = options.signKeys;
    }

    public async authorizeLocalSession(
        accountId: string,
        device?: Device,
    ): Promise<boolean> {
        const identity = await this.resolver.resolveIdentity(accountId);
        if (
            !identity ||
            !identity.homeserver.active ||
            identity.account.accountId !== accountId ||
            identity.account.homeserverId !== this.homeserverId
        ) {
            return false;
        }
        if (device === undefined) return true;
        return isActiveDevice(identity, device);
    }

    public async deliverMail(
        header: Uint8Array,
        mail: MailWS,
        authenticatedDevice: Device,
        authenticatedUserId: string,
    ): Promise<void> {
        this.validateSender(mail, authenticatedDevice, authenticatedUserId);
        const sender = await this.requireIdentity(authenticatedUserId);
        if (sender.homeserver.homeserverId !== this.homeserverId) {
            throw new FederationServiceError(
                409,
                "The sender account is no longer hosted by this server.",
            );
        }
        this.requireActiveDevice(sender, authenticatedDevice);

        const recipient = await this.requireIdentity(mail.readerID);
        const roomAuthorization =
            mail.group === null
                ? null
                : await this.authorizeRoomMail(mail, authenticatedUserId);
        if (recipient.homeserver.homeserverId === this.homeserverId) {
            await this.deliverLocal(
                header,
                mail,
                authenticatedDevice,
                authenticatedUserId,
                recipient,
            );
            return;
        }

        await this.client.deliverMail({
            header,
            mail,
            registrySequence: sender.position.sequence,
            roomAuthorization,
            senderDeviceKey: registryDeviceKey(authenticatedDevice.signKey),
        });
    }

    public async mutateRoom(
        serverId: string,
        accountId: string,
        mutation: FederationRoomMutation,
    ): Promise<FederationRoomMutationResult> {
        const server = await this.requireRemoteRoom(serverId, accountId);
        const result = await this.client.mutateRoom(
            server.homeserverId,
            accountId,
            serverId,
            mutation,
        );
        if (result.resultType === "left") {
            this.validateRoomAuthority(
                result.snapshot.server,
                server.homeserverId,
            );
            if (
                mutation.type !== "remove-member" ||
                result.snapshot.server.serverID !== serverId ||
                result.snapshot.members.some(
                    (member) => member.userId === accountId,
                )
            ) {
                throw new FederationServiceError(
                    502,
                    "The room homeserver returned an invalid leave result.",
                );
            }
            await this.db.deleteServer(serverId);
            return result;
        }
        if (result.resultType === "deleted") {
            if (mutation.type !== "delete-server" || result.snapshot !== null) {
                throw new FederationServiceError(
                    502,
                    "The room homeserver returned an invalid deletion result.",
                );
            }
            if (!server.revision) {
                throw new FederationServiceError(
                    409,
                    "Federated room revision is unavailable.",
                );
            }
            await this.db.applyFederatedRoomDeletion({
                originHomeserverId: server.homeserverId,
                revision: String(BigInt(server.revision) + 1n),
                serverId,
            });
            return result;
        }
        await this.validateRoomSnapshot(
            result.snapshot,
            server.homeserverId,
            accountId,
        );
        this.validateMutationResult(result, serverId);
        const permission = permissionFromSnapshot(result.snapshot, accountId);
        await this.db.saveFederatedRoom(result.snapshot, permission);
        return result;
    }

    public async previewInvite(
        originHomeserverId: string,
        inviteId: string,
    ): Promise<FederationInvitePreview> {
        if (originHomeserverId === this.homeserverId) {
            throw new FederationServiceError(400, "Invite is local.");
        }
        const preview = await this.client.previewInvite(
            originHomeserverId,
            inviteId,
        );
        this.validateRoomAuthority(preview.server, originHomeserverId);
        if (
            preview.invite.inviteID !== inviteId ||
            preview.invite.serverID !== preview.server.serverID ||
            preview.channels.some(
                (channel) => channel.serverID !== preview.server.serverID,
            )
        ) {
            throw new FederationServiceError(
                502,
                "The room homeserver returned an invalid invite preview.",
            );
        }
        return preview;
    }

    public async publishRoomDeletion(
        snapshot: FederationRoomSnapshot,
    ): Promise<void> {
        const nextRevision = String(BigInt(snapshot.revision) + 1n);
        const deletion: FederationRoomDeletion = {
            originHomeserverId: this.homeserverId,
            revision: nextRevision,
            serverId: snapshot.server.serverID,
        };
        await this.publishRoomState(snapshot, "deletion", deletion);
    }

    public async publishRoomSnapshot(
        snapshot: FederationRoomSnapshot,
        previousSnapshot?: FederationRoomSnapshot,
    ): Promise<void> {
        await this.publishRoomState(
            snapshot,
            "snapshot",
            snapshot,
            previousSnapshot,
        );
    }

    public async queryRoomInvites(
        serverId: string,
        accountId: string,
    ): Promise<Invite[]> {
        const server = await this.requireRemoteRoom(serverId, accountId);
        const invites = await this.client.queryRoomInvites(
            server.homeserverId,
            {
                accountId,
                serverId,
            },
        );
        if (invites.some((invite) => invite.serverID !== serverId)) {
            throw new FederationServiceError(
                502,
                "The room homeserver returned invalid invites.",
            );
        }
        return invites;
    }

    public async receiveRoomDeletion(
        deletion: FederationRoomDeletion,
        originHomeserverId: string,
    ): Promise<void> {
        if (deletion.originHomeserverId !== originHomeserverId) {
            throw new FederationServiceError(
                403,
                "Room deletion authority is invalid.",
            );
        }
        const localMembers = await this.localSnapshotMembers(deletion.serverId);
        const deleted = await this.db.applyFederatedRoomDeletion(deletion);
        if (!deleted) return;
        for (const accountId of localMembers) {
            this.notify(
                accountId,
                "serverChange",
                crypto.randomUUID(),
                deletion.serverId,
            );
        }
    }

    public async receiveRoomSnapshot(
        snapshot: FederationRoomSnapshot,
        originHomeserverId: string,
    ): Promise<void> {
        this.validateRoomAuthority(snapshot.server, originHomeserverId);
        const [existing, tombstone] = await Promise.all([
            this.db.retrieveServer(snapshot.server.serverID),
            this.db.retrieveFederationRoomTombstone(snapshot.server.serverID),
        ]);
        if (tombstone) {
            if (tombstone.homeserverId !== originHomeserverId) {
                throw new FederationServiceError(
                    409,
                    "Room tombstone authority does not match.",
                );
            }
            if (
                tombstone.permanent ||
                BigInt(snapshot.revision) <= BigInt(tombstone.revision)
            ) {
                return;
            }
        }
        if (existing) {
            if (
                existing.homeserverId !== originHomeserverId ||
                existing.revision === undefined
            ) {
                throw new FederationServiceError(
                    409,
                    "Room authority cannot change off-chain.",
                );
            }
            if (BigInt(snapshot.revision) <= BigInt(existing.revision)) {
                return;
            }
        }
        const previousLocalMembers = await this.localSnapshotMembers(
            snapshot.server.serverID,
        );
        const localMembers = await this.localMembersInSnapshot(snapshot);
        if (localMembers.length === 0) {
            if (previousLocalMembers.length === 0 && !tombstone) {
                throw new FederationServiceError(
                    403,
                    "Room snapshot has no local members.",
                );
            }
            await this.db.removeFederatedRoomMirror({
                homeserverId: originHomeserverId,
                revision: snapshot.revision,
                serverId: snapshot.server.serverID,
            });
            for (const accountId of previousLocalMembers) {
                this.notify(
                    accountId,
                    "serverChange",
                    crypto.randomUUID(),
                    snapshot.server.serverID,
                );
            }
            return;
        }
        await this.db.saveFederatedRoom(
            snapshot,
            permissionFromSnapshot(snapshot, localMembers[0]),
        );
        for (const accountId of localMembers) {
            this.notify(
                accountId,
                "serverChange",
                crypto.randomUUID(),
                snapshot.server.serverID,
            );
        }
    }

    public async redeemInvite(
        originHomeserverId: string,
        inviteId: string,
        accountId: string,
    ): Promise<FederationInviteRedeemResult> {
        const account = await this.requireIdentity(accountId);
        if (account.homeserver.homeserverId !== this.homeserverId) {
            throw new FederationServiceError(403, "Account is not local.");
        }
        const result = await this.client.redeemInvite(
            originHomeserverId,
            accountId,
            inviteId,
        );
        await this.validateRoomSnapshot(
            result.snapshot,
            originHomeserverId,
            accountId,
        );
        const member = result.snapshot.members.find(
            (entry) => entry.userId === accountId,
        );
        if (
            !member ||
            result.permission.userID !== accountId ||
            result.permission.resourceID !== result.snapshot.server.serverID ||
            result.permission.resourceType !== "server" ||
            result.permission.permissionID !== member.permissionId ||
            result.permission.powerLevel !== member.powerLevel
        ) {
            throw new FederationServiceError(
                502,
                "The room homeserver returned an invalid membership.",
            );
        }
        await this.db.saveFederatedRoom(result.snapshot, result.permission);
        return result;
    }

    public async refreshRoom(
        serverId: string,
        accountId: string,
    ): Promise<FederationRoomSnapshot> {
        const server = await this.requireRemoteRoom(serverId, accountId);
        const snapshot = await this.client.queryRoom(
            server.homeserverId,
            accountId,
            serverId,
        );
        await this.validateRoomSnapshot(
            snapshot,
            server.homeserverId,
            accountId,
        );
        await this.db.saveFederatedRoom(
            snapshot,
            permissionFromSnapshot(snapshot, accountId),
        );
        return snapshot;
    }

    public async resolveAccount(
        identifier: string,
    ): Promise<FederationAccountResult | null> {
        const identity = await this.resolveIdentity(identifier);
        if (!identity) return null;

        const result =
            identity.homeserver.homeserverId === this.homeserverId
                ? await this.localAccount(identity)
                : await this.client.queryAccount(identity.account.accountId);
        if (!result) return null;
        this.validateAccountResult(identity, result);
        return result;
    }

    public async resolveDevices(
        identifier: string,
    ): Promise<FederationDevice[] | null> {
        const account = await this.resolveAccount(identifier);
        return account?.devices ?? null;
    }

    public async resolveRoomUsers(
        channelId: string,
        accountId: string,
    ): Promise<User[]> {
        const channel = await this.db.retrieveChannel(channelId);
        if (!channel) {
            throw new FederationServiceError(404, "Channel not found.");
        }
        const server = await this.db.retrieveServer(channel.serverID);
        if (!server?.homeserverId) {
            throw new FederationServiceError(
                409,
                "Room does not have a federation authority.",
            );
        }
        const snapshot =
            server.homeserverId === this.homeserverId
                ? await this.db.retrieveRoomSnapshot(server.serverID)
                : await this.client.queryRoom(
                      server.homeserverId,
                      accountId,
                      server.serverID,
                  );
        if (!snapshot) {
            throw new FederationServiceError(404, "Room not found.");
        }
        await this.validateRoomSnapshot(
            snapshot,
            server.homeserverId,
            accountId,
        );
        if (server.homeserverId !== this.homeserverId) {
            const permission = await this.localRoomPermission(
                accountId,
                server.serverID,
            );
            await this.db.saveFederatedRoom(snapshot, permission);
        }
        const users = await Promise.all(
            snapshot.members.map(async (member) => {
                const result = await this.resolveAccount(member.userId);
                return result?.user ?? null;
            }),
        );
        const resolvedUsers = users.filter(
            (user): user is User => user !== null,
        );
        if (resolvedUsers.length !== users.length) {
            throw new FederationServiceError(
                502,
                "A room member is unavailable from its authoritative homeserver.",
            );
        }
        return resolvedUsers;
    }

    public async retrieveAvatar(
        accountId: string,
    ): Promise<null | { contentType: string; data: Uint8Array }> {
        const identity = await this.resolveIdentity(accountId);
        if (
            !identity ||
            identity.homeserver.homeserverId === this.homeserverId
        ) {
            return null;
        }
        return this.client.getAvatar(
            identity.homeserver.homeserverId,
            identity.account.accountId,
        );
    }

    public async retrieveKeyBundle(
        requesterAccountId: string,
        accountId: string,
        deviceId: string,
    ): Promise<KeyBundle | null> {
        const requester = await this.resolveIdentity(requesterAccountId);
        if (
            !requester ||
            requester.homeserver.homeserverId !== this.homeserverId
        ) {
            throw new FederationServiceError(
                403,
                "The requesting account is not hosted here.",
            );
        }
        const identity = await this.resolveIdentity(accountId);
        if (!identity) return null;
        const result =
            identity.homeserver.homeserverId === this.homeserverId
                ? await this.localKeyBundle(identity, deviceId)
                : await this.client.getKeyBundle(
                      requester.account.accountId,
                      identity.account.accountId,
                      deviceId,
                  );
        if (!result) return null;
        this.validateKeyBundleResult(identity, result, deviceId);
        return result.keyBundle;
    }

    public async retrieveServerIcon(
        iconId: string,
    ): Promise<null | { contentType: string; data: Uint8Array }> {
        const server = await this.db.retrieveServerByIcon(iconId);
        if (
            !server?.homeserverId ||
            server.homeserverId === this.homeserverId
        ) {
            return null;
        }
        return this.client.getServerIcon(server.homeserverId, iconId);
    }

    public start(): void {
        if (this.outboxStarted) return;
        this.outboxStarted = true;
        this.scheduleOutbox(0);
    }

    public async stop(): Promise<void> {
        this.outboxStarted = false;
        if (this.outboxTimer) {
            clearTimeout(this.outboxTimer);
            this.outboxTimer = null;
        }
        await this.outboxFlush;
    }

    private async authorizeRoomMail(
        mail: MailWS,
        senderAccountId: string,
    ): Promise<FederationRoomMailAuthorization> {
        let channelId: string;
        try {
            channelId = uuidStringify(mail.group ?? new Uint8Array());
        } catch {
            throw new FederationServiceError(
                400,
                "Room channel ID is invalid.",
            );
        }
        const channel = await this.db.retrieveChannel(channelId);
        const server = channel
            ? await this.db.retrieveServer(channel.serverID)
            : null;
        if (!channel || !server?.homeserverId || !server.revision) {
            throw new FederationServiceError(404, "Federated room not found.");
        }
        await this.localRoomPermission(senderAccountId, server.serverID);

        const query = {
            channelId,
            recipientAccountId: mail.readerID,
            senderAccountId,
            serverId: server.serverID,
        };
        const cacheKey = `${Object.values(query).join(":")}:${server.revision}`;
        const cacheReadAt = Date.now();
        const cached = this.roomAuthorizationCache.get(cacheKey);
        if (cached && cached.expiresAt > cacheReadAt + 5_000) return cached;
        if (cached) this.roomAuthorizationCache.delete(cacheKey);

        let authorization: FederationRoomMailAuthorization;
        if (server.homeserverId === this.homeserverId) {
            const snapshot = await this.db.retrieveRoomSnapshot(
                server.serverID,
            );
            if (
                !snapshot ||
                !snapshot.members.some(
                    (member) => member.userId === senderAccountId,
                ) ||
                !snapshot.members.some(
                    (member) => member.userId === mail.readerID,
                )
            ) {
                throw new FederationServiceError(
                    403,
                    "Sender or recipient is not a room member.",
                );
            }
            authorization = createFederationRoomMailAuthorization(
                {
                    ...query,
                    expiresAt: Date.now() + 60_000,
                    originHomeserverId: this.homeserverId,
                    revision: snapshot.revision,
                },
                this.signKeys.secretKey,
            );
        } else {
            authorization = await this.client.authorizeRoomMail(
                server.homeserverId,
                query,
            );
        }
        const origin = await this.resolver.resolveHomeserver(
            server.homeserverId,
        );
        const validationTime = Date.now();
        if (
            authorization.channelId !== query.channelId ||
            authorization.serverId !== query.serverId ||
            authorization.senderAccountId !== query.senderAccountId ||
            authorization.recipientAccountId !== query.recipientAccountId ||
            authorization.originHomeserverId !== server.homeserverId ||
            authorization.expiresAt <= validationTime ||
            authorization.expiresAt > validationTime + 2 * 60_000 ||
            !origin?.record.active ||
            !verifyFederationRoomMailAuthorization(
                authorization,
                origin.record.signingKey,
            )
        ) {
            throw new FederationServiceError(
                502,
                "Room homeserver returned an invalid mail authorization.",
            );
        }
        this.cacheRoomAuthorization(cacheKey, authorization, validationTime);
        return authorization;
    }

    private cacheRoomAuthorization(
        cacheKey: string,
        authorization: FederationRoomMailAuthorization,
        now: number,
    ): void {
        if (this.roomAuthorizationCache.size >= ROOM_AUTHORIZATION_CACHE_MAX) {
            for (const [key, cached] of this.roomAuthorizationCache) {
                if (cached.expiresAt <= now + 5_000) {
                    this.roomAuthorizationCache.delete(key);
                }
            }
        }
        while (
            this.roomAuthorizationCache.size >= ROOM_AUTHORIZATION_CACHE_MAX
        ) {
            const oldest = this.roomAuthorizationCache.keys().next();
            if (oldest.done) break;
            this.roomAuthorizationCache.delete(oldest.value);
        }
        this.roomAuthorizationCache.set(cacheKey, authorization);
    }

    private async deliverLocal(
        header: Uint8Array,
        mail: MailWS,
        authenticatedDevice: Device,
        authenticatedUserId: string,
        recipient: RegistryIdentityResolution,
    ): Promise<void> {
        const recipientDevice = await this.db.retrieveDevice(mail.recipient);
        if (
            !recipientDevice ||
            recipientDevice.owner !== mail.readerID ||
            !isActiveDevice(recipient, recipientDevice)
        ) {
            throw new FederationServiceError(
                400,
                "The recipient device is not active for this account.",
            );
        }
        await this.db.saveMail(
            mail,
            header,
            authenticatedDevice.deviceID,
            authenticatedUserId,
        );
        this.notify(
            recipientDevice.owner,
            "mail",
            crypto.randomUUID(),
            null,
            mail.recipient,
            mail.authorID,
            mail.nonce,
        );
    }

    private async deliverRoomOutbox(
        entry: FederationRoomOutboxEntry,
    ): Promise<void> {
        const payload: unknown = JSON.parse(entry.payload);
        if (entry.kind === "snapshot") {
            await this.client.pushRoomSnapshot(
                entry.destinationHomeserverId,
                FederationRoomSnapshotSchema.parse(payload),
            );
        } else {
            await this.client.pushRoomDeletion(
                entry.destinationHomeserverId,
                FederationRoomDeletionSchema.parse(payload),
            );
        }
        await this.db.completeFederationRoomOutbox(entry.eventId);
    }

    private flushRoomOutbox(): Promise<void> {
        if (this.outboxFlush) return this.outboxFlush;
        const operation = this.performRoomOutboxFlush();
        this.outboxFlush = operation;
        const clear = () => {
            if (this.outboxFlush === operation) this.outboxFlush = null;
        };
        void operation.then(clear, clear);
        return operation;
    }

    private async localAccount(
        identity: RegistryIdentityResolution,
    ): Promise<FederationAccountResult | null> {
        const user = await this.db.retrieveUser(identity.account.accountId);
        if (!user) return null;
        const devices = (
            await this.db.retrieveUserDeviceList([identity.account.accountId])
        ).filter((device) => isActiveDevice(identity, device));
        if (devices.length === 0) {
            throw new FederationServiceError(
                409,
                "The local account has no registry-authorized devices.",
            );
        }
        return {
            devices: devices.map(publicFederationDevice),
            position: identity.position,
            user: publicRegistryUser(identity, user),
        };
    }

    private async localKeyBundle(
        identity: RegistryIdentityResolution,
        deviceId: string,
    ): Promise<FederationKeyBundleResult | null> {
        const device = await this.db.retrieveDevice(deviceId);
        if (!device || !isActiveDevice(identity, device)) return null;
        const keyBundle = await this.db.getKeyBundle(deviceId);
        return keyBundle
            ? {
                  device: publicFederationDevice(device),
                  keyBundle,
                  position: identity.position,
              }
            : null;
    }

    private async localMembersInSnapshot(
        snapshot: FederationRoomSnapshot,
    ): Promise<string[]> {
        const candidates = await Promise.all(
            snapshot.members.map(async (member) => {
                const identity = await this.resolveIdentity(member.userId);
                if (!identity) {
                    throw new FederationServiceError(
                        502,
                        "Room snapshot contains an unregistered member.",
                    );
                }
                if (
                    identity.homeserver.homeserverId !== this.homeserverId ||
                    !(await this.db.retrieveUser(member.userId))
                ) {
                    return null;
                }
                return member.userId;
            }),
        );
        return candidates.filter((value): value is string => value !== null);
    }

    private async localRoomPermission(
        accountId: string,
        serverId: string,
    ): Promise<Permission> {
        const permissions = await this.db.retrievePermissions(
            accountId,
            "server",
        );
        const permission = permissions.find(
            (entry) => entry.resourceID === serverId,
        );
        if (!permission) {
            throw new FederationServiceError(
                403,
                "Account is not a room member.",
            );
        }
        return permission;
    }

    private async localSnapshotMembers(serverId: string): Promise<string[]> {
        const permissions =
            await this.db.retrievePermissionsByResourceID(serverId);
        const members = await Promise.all(
            permissions.map(async (permission) => {
                const identity = await this.resolveIdentity(permission.userID);
                return identity?.homeserver.homeserverId ===
                    this.homeserverId &&
                    (await this.db.retrieveUser(permission.userID))
                    ? permission.userID
                    : null;
            }),
        );
        return members.filter((value): value is string => value !== null);
    }

    private async performRoomOutboxFlush(): Promise<void> {
        const entries = await this.db.retrieveFederationRoomOutbox(Date.now());
        await Promise.all(
            entries.map(async (entry) => {
                try {
                    await this.deliverRoomOutbox(entry);
                } catch (error: unknown) {
                    const attempts = entry.attempts + 1;
                    await this.db.failFederationRoomOutbox(
                        entry.eventId,
                        attempts,
                        Date.now() + federationRetryDelay(attempts),
                    );
                    console.error(
                        "Room federation delivery failed:",
                        error instanceof Error ? error.message : String(error),
                    );
                }
            }),
        );
    }

    private async publishRoomState(
        snapshot: FederationRoomSnapshot,
        kind: FederationRoomOutboxEntry["kind"],
        payload: FederationRoomDeletion | FederationRoomSnapshot,
        previousSnapshot?: FederationRoomSnapshot,
    ): Promise<void> {
        this.validateRoomAuthority(snapshot.server, this.homeserverId);
        const memberIds = new Set([
            ...snapshot.members.map((member) => member.userId),
            ...(previousSnapshot?.members.map((member) => member.userId) ?? []),
        ]);
        const identities = await Promise.all(
            [...memberIds].map((accountId) => this.resolveIdentity(accountId)),
        );
        const resolvedIdentities = identities.filter(
            (identity): identity is RegistryIdentityResolution =>
                identity !== null,
        );
        if (resolvedIdentities.length !== identities.length) {
            throw new FederationServiceError(
                503,
                "A room member is unavailable in the finalized identity registry.",
            );
        }
        const destinations = new Set(
            resolvedIdentities
                .map((identity) => identity.homeserver.homeserverId)
                .filter((homeserverId) => homeserverId !== this.homeserverId),
        );
        const now = Date.now();
        for (const destinationHomeserverId of destinations) {
            const eventId = roomOutboxEventId(
                kind,
                destinationHomeserverId,
                snapshot.server.serverID,
                payload.revision,
            );
            await this.db.enqueueFederationRoomOutbox({
                createdAt: now,
                destinationHomeserverId,
                eventId,
                kind,
                nextAttemptAt: now,
                payload: JSON.stringify(payload),
            });
        }
        this.scheduleOutbox(0);
    }

    private requireActiveDevice(
        identity: RegistryIdentityResolution,
        device: Device,
    ): void {
        if (!isActiveDevice(identity, device)) {
            throw new FederationServiceError(
                403,
                "The authenticated device is not active in the identity registry.",
            );
        }
    }

    private async requireIdentity(
        identifier: string,
    ): Promise<RegistryIdentityResolution> {
        const identity = await this.resolveIdentity(identifier);
        if (!identity) {
            throw new FederationServiceError(
                404,
                "The account is not registered.",
            );
        }
        return identity;
    }

    private async requireRemoteRoom(
        serverId: string,
        accountId: string,
    ): Promise<Server & { homeserverId: string }> {
        const account = await this.requireIdentity(accountId);
        if (account.homeserver.homeserverId !== this.homeserverId) {
            throw new FederationServiceError(403, "Account is not local.");
        }
        const server = await this.db.retrieveServer(serverId);
        if (!server?.homeserverId) {
            throw new FederationServiceError(404, "Federated room not found.");
        }
        if (server.homeserverId === this.homeserverId) {
            throw new FederationServiceError(400, "Room is local.");
        }
        await this.localRoomPermission(accountId, serverId);
        return { ...server, homeserverId: server.homeserverId };
    }

    private async resolveIdentity(
        identifier: string,
    ): Promise<null | RegistryIdentityResolution> {
        let accountId: string;
        if (isBytes32(identifier)) {
            accountId = identifier.toLowerCase();
        } else {
            const username = identifier.trim().toLowerCase();
            if (!/^[a-z0-9_]{3,19}$/.test(username)) return null;
            const resolved = await this.resolver.resolveUsername(username);
            if (!resolved) return null;
            accountId = resolved.record.accountId;
        }
        const identity = await this.resolver.resolveIdentity(accountId);
        return identity?.homeserver.active ? identity : null;
    }

    private scheduleOutbox(delayMs: number): void {
        if (!this.outboxStarted) return;
        if (this.outboxTimer) clearTimeout(this.outboxTimer);
        this.outboxTimer = setTimeout(() => {
            this.outboxTimer = null;
            void this.flushRoomOutbox()
                .catch((error: unknown) => {
                    console.error(
                        "Room federation outbox failed:",
                        error instanceof Error ? error.message : String(error),
                    );
                })
                .finally(() => {
                    this.scheduleOutbox(5_000);
                });
        }, delayMs);
    }

    private validateAccountResult(
        identity: RegistryIdentityResolution,
        result: FederationAccountResult,
    ): void {
        if (
            result.user.userID !== identity.account.accountId ||
            result.position.source !== identity.position.source ||
            (identity.username &&
                result.user.username !== identity.username.username) ||
            result.devices.some(
                (device) =>
                    device.owner !== identity.account.accountId ||
                    !isActiveDevice(identity, device),
            )
        ) {
            throw new FederationServiceError(
                502,
                "The authoritative homeserver returned registry-inconsistent account data.",
            );
        }
    }

    private validateKeyBundleResult(
        identity: RegistryIdentityResolution,
        result: FederationKeyBundleResult,
        deviceId: string,
    ): void {
        if (
            result.position.source !== identity.position.source ||
            result.device.deviceID !== deviceId ||
            result.device.owner !== identity.account.accountId ||
            !isActiveDevice(identity, result.device) ||
            XUtils.encodeHex(result.keyBundle.signKey) !==
                result.device.signKey.toLowerCase() ||
            result.keyBundle.preKey.deviceID !== deviceId ||
            (result.keyBundle.otk?.deviceID !== undefined &&
                result.keyBundle.otk.deviceID !== deviceId)
        ) {
            throw new FederationServiceError(
                502,
                "The authoritative homeserver returned a registry-inconsistent key bundle.",
            );
        }
    }

    private validateMutationResult(
        result: Exclude<
            FederationRoomMutationResult,
            { resultType: "deleted" } | { resultType: "left" }
        >,
        serverId: string,
    ): void {
        const valid = (() => {
            switch (result.resultType) {
                case "channel":
                    return result.channel.serverID === serverId;
                case "invite":
                    return result.invite.serverID === serverId;
                case "permission":
                    return (
                        result.permission.resourceType === "server" &&
                        result.permission.resourceID === serverId
                    );
                case "server":
                    return result.server.serverID === serverId;
            }
        })();
        if (
            !valid ||
            result.snapshot.server.serverID !== serverId ||
            (result.resultType === "server" &&
                result.server.revision !== result.snapshot.revision)
        ) {
            throw new FederationServiceError(
                502,
                "The room homeserver returned an invalid mutation result.",
            );
        }
    }

    private validateRoomAuthority(
        server: FederationRoomSnapshot["server"],
        originHomeserverId: string,
    ): void {
        if (
            server.homeserverId !== originHomeserverId ||
            server.revision === undefined
        ) {
            throw new FederationServiceError(
                502,
                "The room homeserver returned inconsistent authority data.",
            );
        }
    }

    private async validateRoomSnapshot(
        snapshot: FederationRoomSnapshot,
        originHomeserverId: string,
        accountId: string,
    ): Promise<void> {
        this.validateRoomAuthority(snapshot.server, originHomeserverId);
        if (
            snapshot.revision !== snapshot.server.revision ||
            !snapshot.members.some((member) => member.userId === accountId) ||
            snapshot.channels.some(
                (channel) => channel.serverID !== snapshot.server.serverID,
            )
        ) {
            throw new FederationServiceError(
                502,
                "The room homeserver returned an invalid room snapshot.",
            );
        }
        const identities = await Promise.all(
            snapshot.members.map((member) =>
                this.resolveIdentity(member.userId),
            ),
        );
        if (identities.some((identity) => identity === null)) {
            throw new FederationServiceError(
                502,
                "The room homeserver returned an unregistered member.",
            );
        }
    }

    private validateSender(
        mail: MailWS,
        device: Device,
        authenticatedUserId: string,
    ): void {
        if (mail.sender !== device.deviceID) {
            throw new FederationServiceError(
                403,
                "Mail sender does not match the authenticated device.",
            );
        }
        if (mail.authorID !== authenticatedUserId) {
            throw new FederationServiceError(
                403,
                "Mail author does not match the authenticated user.",
            );
        }
    }
}

export class FederationServiceError extends Error {
    public readonly status: number;

    constructor(status: number, message: string) {
        super(message);
        this.name = "FederationServiceError";
        this.status = status;
    }
}

function federationRetryDelay(attempts: number): number {
    return Math.min(60 * 60_000, 1_000 * 2 ** Math.min(attempts, 12));
}

function isActiveDevice(
    identity: RegistryIdentityResolution,
    device: Pick<Device, "owner" | "signKey">,
): boolean {
    const key = registryDeviceKey(device.signKey);
    return (
        device.owner === identity.account.accountId &&
        identity.devices.some((entry) => entry.deviceKey === key)
    );
}

function isBytes32(value: string): boolean {
    return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function permissionFromSnapshot(
    snapshot: FederationRoomSnapshot,
    accountId: string | undefined,
): Permission {
    const member = snapshot.members.find((entry) => entry.userId === accountId);
    if (!member) {
        throw new FederationServiceError(
            502,
            "Room snapshot does not contain the expected member.",
        );
    }
    return {
        permissionID: member.permissionId,
        powerLevel: member.powerLevel,
        resourceID: snapshot.server.serverID,
        resourceType: "server",
        userID: member.userId,
    };
}

function publicFederationDevice(device: Device): FederationDevice {
    return {
        deviceID: device.deviceID,
        owner: device.owner,
        signKey: device.signKey.toLowerCase(),
    };
}

function publicRegistryUser(
    identity: RegistryIdentityResolution,
    user: User,
): User {
    return {
        lastSeen: user.lastSeen,
        userID: user.userID,
        username: identity.username?.username ?? user.username,
    };
}

function registryDeviceKey(value: string): string {
    const normalized = value.toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
        throw new FederationServiceError(400, "Device signing key is invalid.");
    }
    return `0x${normalized}`;
}

function roomOutboxEventId(
    kind: FederationRoomOutboxEntry["kind"],
    destinationHomeserverId: string,
    serverId: string,
    revision: string,
): string {
    return createHash("sha256")
        .update(
            [kind, destinationHomeserverId, serverId, revision].join("\n"),
            "utf8",
        )
        .digest("hex");
}

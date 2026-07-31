/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database, StoredHomeserverMigration } from "../Database.ts";
import type { FederationClient } from "./FederationClient.ts";
import type {
    Device,
    FederationMigrationAuthorization,
    FederationMigrationAvatarReference,
    FederationMigrationBlobResult,
    FederationMigrationChallenge,
    FederationMigrationFileQuery,
    FederationMigrationFileReference,
    FederationMigrationImportResult,
    FederationMigrationMailPage,
    FederationMigrationMailQuery,
    FederationMigrationManifest,
    FederationMigrationPrepareResult,
    FederationMigrationQuery,
    FederationRoomSnapshot,
    IdentityResolver,
    Permission,
    RegistryIdentityResolution,
} from "@vex-chat/types";

import { createHash, randomUUID } from "node:crypto";
import * as fsp from "node:fs/promises";
import path from "node:path";

import {
    xFederationMigrationAuthorizationDigest,
    xRandomBytes,
    xSignVerifyDetached,
    XUtils,
} from "@vex-chat/crypto";
import {
    FederationMigrationAuthorizationSchema,
    FederationMigrationManifestSchema,
    MAX_FILE_UPLOAD_BYTES,
} from "@vex-chat/types";

import { fileTypeFromBuffer } from "file-type";

import { ALLOWED_IMAGE_TYPES } from "../server/imageTypes.ts";

import { FederationServiceError } from "./FederationService.ts";

const MIGRATION_CHALLENGE_TTL_MS = 10 * 60 * 1_000;
const MIGRATION_TRANSFER_TTL_MS = 7 * 24 * 60 * 60 * 1_000;
const MAX_AVATAR_BYTES = 5 * 1024 * 1024;
const MAIL_PAGE_SIZE = 100;
const MAX_MAIL_PAGES = 10_000;

export interface HomeserverMigrationServiceOptions {
    avatarsDirectory?: string | undefined;
    client: MigrationTransport;
    db: MigrationDatabase;
    filesDirectory?: string | undefined;
    homeserverId: string;
    now?: (() => number) | undefined;
    resolver: IdentityResolver;
    uuid?: (() => string) | undefined;
}

type MigrationDatabase = Pick<
    Database,
    | "createHomeserverMigration"
    | "initializeHomeserverMigrationManifest"
    | "retrieveFile"
    | "retrieveFilesByOwners"
    | "retrieveHomeserverMigration"
    | "retrieveMigrationDevices"
    | "retrieveMigrationMail"
    | "retrieveRoomSnapshot"
    | "retrieveServers"
    | "retrieveUserDeviceList"
    | "saveFederatedRoom"
    | "saveMigratedMail"
    | "updateHomeserverMigrationCompleted"
    | "upsertMigratedFile"
>;

type MigrationTransport = Pick<
    FederationClient,
    | "completeMigration"
    | "getMigrationAvatar"
    | "getMigrationFile"
    | "getMigrationMail"
    | "getMigrationManifest"
    | "queryRoom"
>;

/** Coordinates a device-authorized, server-to-server homeserver migration. */
export class HomeserverMigrationService {
    private readonly avatarsDirectory: string;
    private readonly client: MigrationTransport;
    private readonly db: MigrationDatabase;
    private readonly filesDirectory: string;
    private readonly homeserverId: string;
    private readonly now: () => number;
    private readonly resolver: IdentityResolver;
    private readonly uuid: () => string;

    constructor(options: HomeserverMigrationServiceOptions) {
        this.avatarsDirectory = path.resolve(
            options.avatarsDirectory ?? "avatars",
        );
        this.client = options.client;
        this.db = options.db;
        this.filesDirectory = path.resolve(options.filesDirectory ?? "files");
        this.homeserverId = options.homeserverId;
        this.now = options.now ?? Date.now;
        this.resolver = options.resolver;
        this.uuid = options.uuid ?? randomUUID;
    }

    public async completeSourceMigration(
        originHomeserverId: string,
        query: FederationMigrationQuery,
    ): Promise<{ completed: boolean }> {
        const { row } = await this.requireTransfer(
            query.migrationId,
            originHomeserverId,
        );
        if (row.completedAt === null) {
            await this.db.updateHomeserverMigrationCompleted(
                row.migrationId,
                this.now(),
            );
        }
        return { completed: true };
    }

    public async createChallenge(
        accountId: string,
        device: Device,
        destinationHomeserverId: string,
    ): Promise<FederationMigrationChallenge> {
        const identity = await this.requireLocalIdentity(accountId, device);
        if (destinationHomeserverId === this.homeserverId) {
            throw new FederationServiceError(
                400,
                "The destination homeserver must be different from the current homeserver.",
            );
        }
        const destination = await this.resolver.resolveHomeserver(
            destinationHomeserverId,
        );
        if (!destination?.record.active) {
            throw new FederationServiceError(
                404,
                "The destination homeserver is not registered.",
            );
        }
        return {
            accountId: identity.account.accountId,
            destinationHomeserverId,
            deviceKey: registryDeviceKey(device.signKey),
            expiresAt: this.now() + MIGRATION_CHALLENGE_TTL_MS,
            nonce: `0x${XUtils.encodeHex(xRandomBytes(32))}`,
            sourceHomeserverId: this.homeserverId,
        };
    }

    public async importMigration(
        accountId: string,
        device: Device,
        sourceHomeserverId: string,
        migrationId: string,
    ): Promise<FederationMigrationImportResult> {
        const identity = await this.requireLocalIdentity(accountId, device);
        if (sourceHomeserverId === this.homeserverId) {
            throw new FederationServiceError(
                400,
                "The migration source must be remote.",
            );
        }
        const manifest = await this.client.getMigrationManifest(
            sourceHomeserverId,
            { migrationId },
        );
        this.validateImportManifest(
            manifest,
            identity,
            sourceHomeserverId,
            migrationId,
        );

        const roomsImported = await this.importRooms(manifest);
        const filesImported = await this.importFiles(
            manifest,
            accountId,
            device,
        );
        const avatarImported = await this.importAvatar(
            manifest,
            sourceHomeserverId,
        );
        const mail = await this.importMail(manifest, accountId);

        if (mail.deferred === 0) {
            await this.client.completeMigration(sourceHomeserverId, {
                migrationId,
            });
        }
        return {
            avatarImported,
            filesImported,
            mailDeferred: mail.deferred,
            mailImported: mail.imported,
            roomsImported,
        };
    }

    public async prepareMigration(
        authorization: FederationMigrationAuthorization,
        accountId: string,
        device: Device,
    ): Promise<FederationMigrationPrepareResult> {
        const now = this.now();
        if (
            authorization.accountId !== accountId ||
            authorization.sourceHomeserverId !== this.homeserverId ||
            authorization.deviceKey !== registryDeviceKey(device.signKey) ||
            authorization.expiresAt <= now ||
            authorization.expiresAt > now + MIGRATION_CHALLENGE_TTL_MS
        ) {
            throw new FederationServiceError(
                403,
                "The migration authorization does not match this session.",
            );
        }
        await this.requireLocalIdentity(accountId, device);
        const destination = await this.resolver.resolveHomeserver(
            authorization.destinationHomeserverId,
        );
        if (
            authorization.destinationHomeserverId === this.homeserverId ||
            !destination?.record.active
        ) {
            throw new FederationServiceError(
                404,
                "The destination homeserver is not registered.",
            );
        }
        if (!verifyMigrationAuthorization(authorization)) {
            throw new FederationServiceError(
                403,
                "The device migration signature is invalid.",
            );
        }

        const migrationId = this.uuid();
        const transferExpiresAt = now + MIGRATION_TRANSFER_TTL_MS;
        const row = await this.db.createHomeserverMigration({
            accountId,
            authorization: JSON.stringify(authorization),
            createdAt: now,
            destinationHomeserverId: authorization.destinationHomeserverId,
            deviceKey: authorization.deviceKey,
            manifest: null,
            migrationId,
            nonce: authorization.nonce,
            sourceHomeserverId: this.homeserverId,
            transferExpiresAt,
        });
        const storedAuthorization = parseAuthorization(row);
        if (!sameAuthorization(storedAuthorization, authorization)) {
            throw new FederationServiceError(
                409,
                "The migration nonce was already used by another authorization.",
            );
        }
        return {
            expiresAt: row.transferExpiresAt,
            migrationId: row.migrationId,
        };
    }

    public async readMigrationAvatar(
        originHomeserverId: string,
        query: FederationMigrationQuery,
    ): Promise<FederationMigrationBlobResult> {
        const { manifest } = await this.requireTransfer(
            query.migrationId,
            originHomeserverId,
        );
        if (!manifest.avatar) {
            throw new FederationServiceError(
                404,
                "Migration avatar not found.",
            );
        }
        const blob = await this.readAvatar(manifest.accountId);
        if (!blob || !matchesCommitment(blob.data, manifest.avatar)) {
            throw new FederationServiceError(
                409,
                "The migration avatar no longer matches its manifest.",
            );
        }
        return blob;
    }

    public async readMigrationFile(
        originHomeserverId: string,
        query: FederationMigrationFileQuery,
    ): Promise<FederationMigrationBlobResult> {
        const { manifest } = await this.requireTransfer(
            query.migrationId,
            originHomeserverId,
        );
        const reference = manifest.files.find(
            (file) => file.fileId === query.fileId,
        );
        if (!reference) {
            throw new FederationServiceError(404, "Migration file not found.");
        }
        const data = await readStorageFile(
            storagePath(this.filesDirectory, reference.fileId),
            MAX_FILE_UPLOAD_BYTES,
        );
        if (!matchesCommitment(data, reference)) {
            throw new FederationServiceError(
                409,
                "The migration file no longer matches its manifest.",
            );
        }
        return { contentType: "application/octet-stream", data };
    }

    public async readMigrationMail(
        originHomeserverId: string,
        query: FederationMigrationMailQuery,
    ): Promise<FederationMigrationMailPage> {
        const { identity, manifest, row } = await this.requireTransfer(
            query.migrationId,
            originHomeserverId,
        );
        const activeRegistryKeys = new Set(
            identity.devices
                .filter((device) => device.active)
                .map((device) => device.deviceKey),
        );
        const devices = await this.db.retrieveMigrationDevices(
            manifest.accountId,
        );
        const keyByDeviceId = new Map(
            devices
                .filter(
                    (device) =>
                        !device.deleted &&
                        activeRegistryKeys.has(
                            registryDeviceKey(device.signKey),
                        ),
                )
                .map((device) => [
                    device.deviceID,
                    registryDeviceKey(device.signKey),
                ]),
        );
        const rows = await this.db.retrieveMigrationMail(
            manifest.accountId,
            [...keyByDeviceId.keys()],
            new Date(requireMailCutoff(row)).toISOString(),
            query.cursor,
            MAIL_PAGE_SIZE,
        );
        const entries = rows.map((entry) => {
            const recipientDeviceKey = keyByDeviceId.get(
                entry.deliveryDeviceId,
            );
            if (!recipientDeviceKey) {
                throw new FederationServiceError(
                    409,
                    "Migration mail references an unknown local device.",
                );
            }
            return {
                header: entry.header,
                mail: entry.mail,
                recipientDeviceKey,
                time: entry.time,
            };
        });
        return {
            entries,
            nextCursor:
                rows.length === MAIL_PAGE_SIZE
                    ? query.cursor + rows.length
                    : null,
        };
    }

    public async readMigrationManifest(
        originHomeserverId: string,
        query: FederationMigrationQuery,
    ): Promise<FederationMigrationManifest> {
        const { manifest } = await this.requireTransfer(
            query.migrationId,
            originHomeserverId,
        );
        return manifest;
    }

    private async createAvatarReference(
        accountId: string,
    ): Promise<FederationMigrationAvatarReference | null> {
        const avatar = await this.readAvatar(accountId);
        return avatar ? commitment(avatar.data, avatar.contentType) : null;
    }

    private async createFileReferences(
        accountId: string,
    ): Promise<FederationMigrationFileReference[]> {
        const devices = await this.db.retrieveMigrationDevices(accountId);
        const keyByDeviceId = new Map(
            devices.map((device) => [
                device.deviceID,
                registryDeviceKey(device.signKey),
            ]),
        );
        const files = await this.db.retrieveFilesByOwners([
            ...keyByDeviceId.keys(),
        ]);
        const references: FederationMigrationFileReference[] = [];
        for (const file of files) {
            const ownerDeviceKey = keyByDeviceId.get(file.owner);
            if (!ownerDeviceKey) continue;
            const data = await readStorageFile(
                storagePath(this.filesDirectory, file.fileID),
                MAX_FILE_UPLOAD_BYTES,
            );
            references.push({
                fileId: file.fileID,
                nonce: file.nonce.toLowerCase(),
                ownerDeviceKey,
                sha256: sha256(data),
                size: data.byteLength,
            });
        }
        return references;
    }

    private async createRoomReferences(
        accountId: string,
    ): Promise<FederationMigrationManifest["rooms"]> {
        const servers = await this.db.retrieveServers(accountId);
        return servers.map((server) => ({
            homeserverId: server.homeserverId ?? this.homeserverId,
            serverId: server.serverID,
        }));
    }

    private async importAvatar(
        manifest: FederationMigrationManifest,
        sourceHomeserverId: string,
    ): Promise<boolean> {
        if (!manifest.avatar) return false;
        const blob = await this.client.getMigrationAvatar(sourceHomeserverId, {
            migrationId: manifest.migrationId,
        });
        const detected = await fileTypeFromBuffer(blob.data);
        if (
            !detected ||
            !ALLOWED_IMAGE_TYPES.includes(detected.mime) ||
            detected.mime !== manifest.avatar.contentType ||
            blob.contentType !== manifest.avatar.contentType ||
            !matchesCommitment(blob.data, manifest.avatar)
        ) {
            throw new FederationServiceError(
                502,
                "The source homeserver returned an invalid migration avatar.",
            );
        }
        await writeStorageFile(
            storagePath(this.avatarsDirectory, manifest.accountId),
            blob.data,
            false,
        );
        return true;
    }

    private async importFiles(
        manifest: FederationMigrationManifest,
        accountId: string,
        importingDevice: Device,
    ): Promise<number> {
        const localDevices = await this.db.retrieveUserDeviceList([accountId]);
        const deviceByKey = new Map(
            localDevices.map((device) => [
                registryDeviceKey(device.signKey),
                device,
            ]),
        );
        const localDeviceIds = new Set(
            localDevices.map((device) => device.deviceID),
        );
        let imported = 0;
        for (const reference of manifest.files) {
            const existing = await this.db.retrieveFile(reference.fileId);
            if (existing) {
                if (
                    existing.nonce.toLowerCase() !== reference.nonce ||
                    !localDeviceIds.has(existing.owner)
                ) {
                    throw new FederationServiceError(
                        409,
                        "A migration file conflicts with local data.",
                    );
                }
                const existingData = await readStorageFile(
                    storagePath(this.filesDirectory, reference.fileId),
                    MAX_FILE_UPLOAD_BYTES,
                );
                if (!matchesCommitment(existingData, reference)) {
                    throw new FederationServiceError(
                        409,
                        "A local migration file does not match its manifest.",
                    );
                }
                continue;
            }
            const blob = await this.client.getMigrationFile(
                manifest.authorization.sourceHomeserverId,
                {
                    fileId: reference.fileId,
                    migrationId: manifest.migrationId,
                },
            );
            if (
                blob.contentType !== "application/octet-stream" ||
                !matchesCommitment(blob.data, reference)
            ) {
                throw new FederationServiceError(
                    502,
                    "The source homeserver returned an invalid migration file.",
                );
            }
            const filePath = storagePath(this.filesDirectory, reference.fileId);
            await writeStorageFile(filePath, blob.data, true);
            const owner =
                deviceByKey.get(reference.ownerDeviceKey)?.deviceID ??
                importingDevice.deviceID;
            const inserted = await this.db.upsertMigratedFile({
                fileID: reference.fileId,
                nonce: reference.nonce,
                owner,
            });
            if (inserted) {
                imported += 1;
            } else {
                const concurrent = await this.db.retrieveFile(reference.fileId);
                if (
                    !concurrent ||
                    concurrent.nonce.toLowerCase() !== reference.nonce ||
                    !localDeviceIds.has(concurrent.owner)
                ) {
                    throw new FederationServiceError(
                        409,
                        "A migration file conflicted with a concurrent local write.",
                    );
                }
            }
        }
        return imported;
    }

    private async importMail(
        manifest: FederationMigrationManifest,
        accountId: string,
    ): Promise<{ deferred: number; imported: number }> {
        const identity = await this.resolver.resolveIdentity(accountId);
        const activeRegistryKeys = new Set(
            identity?.devices
                .filter((device) => device.active)
                .map((device) => device.deviceKey) ?? [],
        );
        const localDevices = await this.db.retrieveUserDeviceList([accountId]);
        const deviceByKey = new Map(
            localDevices
                .filter((device) =>
                    activeRegistryKeys.has(registryDeviceKey(device.signKey)),
                )
                .map((device) => [registryDeviceKey(device.signKey), device]),
        );
        let cursor = 0;
        let deferred = 0;
        let imported = 0;
        for (let pageIndex = 0; pageIndex < MAX_MAIL_PAGES; pageIndex += 1) {
            const page = await this.client.getMigrationMail(
                manifest.authorization.sourceHomeserverId,
                { cursor, migrationId: manifest.migrationId },
            );
            for (const entry of page.entries) {
                if (entry.mail.readerID !== accountId) {
                    throw new FederationServiceError(
                        502,
                        "The source homeserver returned migration mail for another account.",
                    );
                }
                const recipient = deviceByKey.get(entry.recipientDeviceKey);
                if (!recipient) {
                    deferred += 1;
                    continue;
                }
                if (
                    await this.db.saveMigratedMail(
                        entry.mail,
                        entry.header,
                        entry.time,
                        recipient.deviceID,
                    )
                ) {
                    imported += 1;
                }
            }
            if (page.nextCursor === null) {
                return { deferred, imported };
            }
            if (
                page.nextCursor <= cursor ||
                page.nextCursor !== cursor + page.entries.length
            ) {
                throw new FederationServiceError(
                    502,
                    "The source homeserver returned an invalid migration cursor.",
                );
            }
            cursor = page.nextCursor;
        }
        throw new FederationServiceError(
            502,
            "The source homeserver returned too many migration mail pages.",
        );
    }

    private async importRooms(
        manifest: FederationMigrationManifest,
    ): Promise<number> {
        let imported = 0;
        for (const reference of manifest.rooms) {
            const snapshot =
                reference.homeserverId === this.homeserverId
                    ? await this.db.retrieveRoomSnapshot(reference.serverId)
                    : await this.client.queryRoom(
                          reference.homeserverId,
                          manifest.accountId,
                          reference.serverId,
                      );
            if (!snapshot) {
                throw new FederationServiceError(
                    404,
                    "A room referenced by the migration no longer exists.",
                );
            }
            await this.requireRegisteredRoomMembers(snapshot);
            const permission = validateMigrationRoom(
                snapshot,
                reference.homeserverId,
                reference.serverId,
                manifest.accountId,
            );
            if (reference.homeserverId !== this.homeserverId) {
                await this.db.saveFederatedRoom(snapshot, permission);
            }
            imported += 1;
        }
        return imported;
    }

    private async readAvatar(
        accountId: string,
    ): Promise<FederationMigrationBlobResult | null> {
        let data: Uint8Array;
        try {
            data = await readStorageFile(
                storagePath(this.avatarsDirectory, accountId),
                MAX_AVATAR_BYTES,
            );
        } catch (error: unknown) {
            if (isNodeError(error, "ENOENT")) return null;
            throw error;
        }
        const detected = await fileTypeFromBuffer(data);
        if (!detected || !ALLOWED_IMAGE_TYPES.includes(detected.mime)) {
            throw new FederationServiceError(
                409,
                "The stored avatar has an unsupported media type.",
            );
        }
        return { contentType: detected.mime, data };
    }

    private async requireLocalIdentity(
        accountId: string,
        device: Device,
    ): Promise<RegistryIdentityResolution> {
        const identity = await this.resolver.resolveIdentity(accountId);
        const deviceKey = registryDeviceKey(device.signKey);
        if (
            !identity ||
            !identity.homeserver.active ||
            identity.homeserver.homeserverId !== this.homeserverId ||
            device.owner !== accountId ||
            device.deleted ||
            !identity.devices.some(
                (registryDevice) =>
                    registryDevice.active &&
                    registryDevice.deviceKey === deviceKey,
            )
        ) {
            throw new FederationServiceError(
                403,
                "The authenticated account and device are not active on this homeserver.",
            );
        }
        return identity;
    }

    private async requireRegisteredRoomMembers(
        snapshot: FederationRoomSnapshot,
    ): Promise<void> {
        const identities = await Promise.all(
            snapshot.members.map((member) =>
                this.resolver.resolveIdentity(member.userId),
            ),
        );
        if (identities.some((identity) => identity === null)) {
            throw new FederationServiceError(
                502,
                "A room authority returned an unregistered migration member.",
            );
        }
    }

    private async requireTransfer(
        migrationId: string,
        originHomeserverId: string,
    ): Promise<{
        identity: RegistryIdentityResolution;
        manifest: FederationMigrationManifest;
        row: StoredHomeserverMigration;
    }> {
        let row = await this.db.retrieveHomeserverMigration(migrationId);
        if (!row) {
            throw new FederationServiceError(404, "Migration not found.");
        }
        const authorization = parseAuthorization(row);
        if (
            row.sourceHomeserverId !== this.homeserverId ||
            row.destinationHomeserverId !== originHomeserverId ||
            authorization.destinationHomeserverId !== originHomeserverId
        ) {
            throw new FederationServiceError(
                403,
                "This homeserver cannot access the migration.",
            );
        }
        if (row.transferExpiresAt < this.now()) {
            throw new FederationServiceError(
                410,
                "Migration transfer expired.",
            );
        }
        const identity = await this.resolver.resolveIdentity(row.accountId);
        if (
            !identity ||
            !identity.homeserver.active ||
            identity.homeserver.homeserverId !== originHomeserverId
        ) {
            throw new FederationServiceError(
                409,
                "The finalized account route has not moved to the destination homeserver.",
            );
        }
        if (!verifyMigrationAuthorization(authorization)) {
            throw new FederationServiceError(
                409,
                "The stored migration authorization is invalid.",
            );
        }
        if (row.manifest === null) {
            const [rooms, files, avatar] = await Promise.all([
                this.createRoomReferences(row.accountId),
                this.createFileReferences(row.accountId),
                this.createAvatarReference(row.accountId),
            ]);
            const manifest = FederationMigrationManifestSchema.parse({
                accountId: row.accountId,
                authorization,
                avatar,
                files,
                migrationId: row.migrationId,
                rooms,
                transferExpiresAt: row.transferExpiresAt,
            });
            row = await this.db.initializeHomeserverMigrationManifest(
                row.migrationId,
                JSON.stringify(manifest),
                this.now(),
            );
        }
        return { identity, manifest: parseManifest(row), row };
    }

    private validateImportManifest(
        manifest: FederationMigrationManifest,
        identity: RegistryIdentityResolution,
        sourceHomeserverId: string,
        migrationId: string,
    ): void {
        const authorization = manifest.authorization;
        if (
            manifest.migrationId !== migrationId ||
            manifest.accountId !== identity.account.accountId ||
            authorization.accountId !== identity.account.accountId ||
            authorization.sourceHomeserverId !== sourceHomeserverId ||
            authorization.destinationHomeserverId !== this.homeserverId ||
            manifest.transferExpiresAt < this.now() ||
            !identity.devices.some(
                (device) =>
                    device.active &&
                    device.deviceKey === authorization.deviceKey,
            ) ||
            !verifyMigrationAuthorization(authorization)
        ) {
            throw new FederationServiceError(
                502,
                "The source homeserver returned an invalid migration manifest.",
            );
        }
    }
}

function commitment(
    data: Uint8Array,
    contentType: string,
): FederationMigrationAvatarReference {
    return { contentType, sha256: sha256(data), size: data.byteLength };
}

function isNodeError(error: unknown, code: string): boolean {
    return error instanceof Error && "code" in error && error.code === code;
}

function matchesCommitment(
    data: Uint8Array,
    reference: { sha256: string; size: number },
): boolean {
    return (
        data.byteLength === reference.size && sha256(data) === reference.sha256
    );
}

function parseAuthorization(
    row: StoredHomeserverMigration,
): FederationMigrationAuthorization {
    try {
        const authorization = FederationMigrationAuthorizationSchema.parse(
            JSON.parse(row.authorization),
        );
        if (
            authorization.accountId !== row.accountId ||
            authorization.destinationHomeserverId !==
                row.destinationHomeserverId ||
            authorization.deviceKey !== row.deviceKey ||
            authorization.nonce !== row.nonce ||
            authorization.sourceHomeserverId !== row.sourceHomeserverId
        ) {
            throw new Error("Stored migration authorization does not match.");
        }
        return authorization;
    } catch {
        throw new FederationServiceError(
            500,
            "The stored migration authorization is invalid.",
        );
    }
}

function parseManifest(
    row: StoredHomeserverMigration,
): FederationMigrationManifest {
    try {
        if (row.manifest === null) {
            throw new Error("Stored migration has not been frozen.");
        }
        const manifest = FederationMigrationManifestSchema.parse(
            JSON.parse(row.manifest),
        );
        const authorization = parseAuthorization(row);
        if (
            manifest.migrationId !== row.migrationId ||
            manifest.accountId !== row.accountId ||
            manifest.transferExpiresAt !== row.transferExpiresAt ||
            manifest.authorization.nonce !== row.nonce ||
            manifest.authorization.deviceKey !== row.deviceKey ||
            manifest.authorization.sourceHomeserverId !==
                row.sourceHomeserverId ||
            manifest.authorization.destinationHomeserverId !==
                row.destinationHomeserverId ||
            !sameAuthorization(manifest.authorization, authorization)
        ) {
            throw new Error("Stored migration fields do not match.");
        }
        return manifest;
    } catch {
        throw new FederationServiceError(
            500,
            "The stored migration manifest is invalid.",
        );
    }
}

async function readStorageFile(
    filePath: string,
    maximumBytes: number,
): Promise<Uint8Array> {
    const handle = await fsp.open(filePath, "r");
    try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.size > maximumBytes) {
            throw new FederationServiceError(
                413,
                "Migration file exceeds its size limit.",
            );
        }
        return new Uint8Array(await handle.readFile());
    } finally {
        await handle.close();
    }
}

function registryDeviceKey(value: string): string {
    const normalized = value.startsWith("0x") ? value.slice(2) : value;
    if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
        throw new FederationServiceError(409, "Device key is invalid.");
    }
    return `0x${normalized.toLowerCase()}`;
}

function requireMailCutoff(row: StoredHomeserverMigration): number {
    if (row.mailCutoffAt === null) {
        throw new FederationServiceError(
            500,
            "The migration mail snapshot is unavailable.",
        );
    }
    return row.mailCutoffAt;
}

function sameAuthorization(
    left: FederationMigrationAuthorization,
    right: FederationMigrationAuthorization,
): boolean {
    return (
        left.accountId === right.accountId &&
        left.destinationHomeserverId === right.destinationHomeserverId &&
        left.deviceKey === right.deviceKey &&
        left.expiresAt === right.expiresAt &&
        left.nonce === right.nonce &&
        left.signature === right.signature &&
        left.sourceHomeserverId === right.sourceHomeserverId
    );
}

function sha256(data: Uint8Array): string {
    return `0x${createHash("sha256").update(data).digest("hex")}`;
}

function storagePath(root: string, identifier: string): string {
    if (
        identifier.length < 1 ||
        identifier.length > 255 ||
        identifier === "." ||
        identifier === ".." ||
        identifier.includes("/") ||
        identifier.includes("\\") ||
        /[\u0000-\u001f\u007f]/.test(identifier)
    ) {
        throw new FederationServiceError(400, "Storage identifier is invalid.");
    }
    const resolved = path.resolve(root, identifier);
    if (path.dirname(resolved) !== root) {
        throw new FederationServiceError(400, "Storage identifier is invalid.");
    }
    return resolved;
}

function validateMigrationRoom(
    snapshot: FederationRoomSnapshot,
    homeserverId: string,
    serverId: string,
    accountId: string,
): Permission {
    const member = snapshot.members.find((entry) => entry.userId === accountId);
    if (
        snapshot.server.serverID !== serverId ||
        snapshot.server.homeserverId !== homeserverId ||
        snapshot.server.revision === undefined ||
        snapshot.revision !== snapshot.server.revision ||
        snapshot.channels.some((channel) => channel.serverID !== serverId) ||
        !member
    ) {
        throw new FederationServiceError(
            502,
            "A room authority returned an invalid migration snapshot.",
        );
    }
    return {
        permissionID: member.permissionId,
        powerLevel: member.powerLevel,
        resourceID: serverId,
        resourceType: "server",
        userID: accountId,
    };
}

function verifyMigrationAuthorization(
    authorization: FederationMigrationAuthorization,
): boolean {
    try {
        return xSignVerifyDetached(
            xFederationMigrationAuthorizationDigest(authorization),
            XUtils.decodeHex(authorization.signature),
            XUtils.decodeHex(authorization.deviceKey.slice(2)),
        );
    } catch {
        return false;
    }
}

async function writeStorageFile(
    filePath: string,
    data: Uint8Array,
    exclusive: boolean,
): Promise<void> {
    await fsp.mkdir(path.dirname(filePath), { recursive: true });
    if (!exclusive) {
        const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
        try {
            await fsp.writeFile(temporaryPath, data, {
                flag: "wx",
                mode: 0o600,
            });
            await fsp.rename(temporaryPath, filePath);
        } finally {
            await fsp.rm(temporaryPath, { force: true });
        }
        return;
    }
    try {
        await fsp.writeFile(filePath, data, {
            flag: "wx",
            mode: 0o600,
        });
    } catch (error: unknown) {
        if (!isNodeError(error, "EEXIST")) throw error;
        const existing = await readStorageFile(filePath, data.byteLength);
        if (sha256(existing) !== sha256(data)) {
            throw new FederationServiceError(
                409,
                "A migration file conflicts with local storage.",
            );
        }
    }
}

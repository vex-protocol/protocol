/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { RegistrationPayload } from "@vex-chat/types";

import * as fsp from "node:fs/promises";
import * as os from "node:os";
import path from "node:path";

import {
    xFederationMigrationAuthorizationDigest,
    xSignDetached,
    xSignKeyPair,
    XUtils,
} from "@vex-chat/crypto";
import { MailType } from "@vex-chat/types";

import { afterEach, describe, expect, it } from "vitest";

import { Database } from "../Database.ts";
import {
    HomeserverMigrationService,
    type HomeserverMigrationServiceOptions,
} from "../federation/HomeserverMigrationService.ts";

const ACCOUNT = hex32("a");
const SOURCE_HOMESERVER = hex32("b");
const DESTINATION_HOMESERVER = hex32("c");
const REGISTRY_SOURCE = "test:homeserver-migration";

describe("HomeserverMigrationService", () => {
    const databases: Database[] = [];
    const directories: string[] = [];

    afterEach(async () => {
        for (const database of databases.splice(0)) await database.close();
        for (const directory of directories.splice(0)) {
            await fsp.rm(directory, { force: true, recursive: true });
        }
    });

    it("moves portable state after the finalized homeserver route changes", async () => {
        const sourceDb = new Database({ dbType: "sqlite3mem" });
        const destinationDb = new Database({ dbType: "sqlite3mem" });
        databases.push(sourceDb, destinationDb);
        await Promise.all([ready(sourceDb), ready(destinationDb)]);

        const sourceDirectory = await fsp.mkdtemp(
            path.join(os.tmpdir(), "vex-source-migration-"),
        );
        const destinationDirectory = await fsp.mkdtemp(
            path.join(os.tmpdir(), "vex-destination-migration-"),
        );
        directories.push(sourceDirectory, destinationDirectory);
        const sourceFiles = path.join(sourceDirectory, "files");
        const sourceAvatars = path.join(sourceDirectory, "avatars");
        const destinationFiles = path.join(destinationDirectory, "files");
        const destinationAvatars = path.join(destinationDirectory, "avatars");
        await Promise.all([
            fsp.mkdir(sourceFiles),
            fsp.mkdir(sourceAvatars),
            fsp.mkdir(destinationFiles),
            fsp.mkdir(destinationAvatars),
        ]);

        const deviceKeys = xSignKeyPair();
        const sourceHomeserverKeys = xSignKeyPair();
        const destinationHomeserverKeys = xSignKeyPair();
        const sourceResolver = sourceDb.createRegistryStore(REGISTRY_SOURCE);
        const destinationResolver =
            destinationDb.createRegistryStore(REGISTRY_SOURCE);
        const initialEvents = [
            {
                endpoint: "https://source.example",
                epoch: "1",
                homeserverId: SOURCE_HOMESERVER,
                signingKey: registryKey(sourceHomeserverKeys.publicKey),
                type: "homeserver-registered" as const,
            },
            {
                endpoint: "https://destination.example",
                epoch: "1",
                homeserverId: DESTINATION_HOMESERVER,
                signingKey: registryKey(destinationHomeserverKeys.publicKey),
                type: "homeserver-registered" as const,
            },
            {
                accountId: ACCOUNT,
                epoch: "1",
                genesisDeviceKey: registryKey(deviceKeys.publicKey),
                homeserverId: SOURCE_HOMESERVER,
                recoveryCommitment: hex32("0"),
                type: "account-registered" as const,
            },
            {
                accountId: ACCOUNT,
                nameHash: hex32("d"),
                type: "username-registered" as const,
                username: "alice",
            },
        ];
        await Promise.all([
            sourceResolver.applyBatch(initialEvents, {
                checkpoint: "block-1",
                sequence: "1",
                source: REGISTRY_SOURCE,
            }),
            destinationResolver.applyBatch(initialEvents, {
                checkpoint: "block-1",
                sequence: "1",
                source: REGISTRY_SOURCE,
            }),
        ]);

        const payload = registrationPayload(deviceKeys.publicKey);
        const [sourceUser, sourceUserError] = await sourceDb.createUser(
            new Uint8Array(16),
            payload,
            ACCOUNT,
        );
        expect(sourceUserError).toBeNull();
        expect(sourceUser?.userID).toBe(ACCOUNT);
        const [sourceDevice] = await sourceDb.retrieveUserDeviceList([ACCOUNT]);
        expect(sourceDevice).toBeDefined();
        if (!sourceDevice) throw new Error("Source device was not created.");

        const room = await sourceDb.createServer(
            "Portable room",
            ACCOUNT,
            SOURCE_HOMESERVER,
        );
        const fileId = crypto.randomUUID();
        const fileData = Uint8Array.from([7, 11, 13, 17, 19]);
        await fsp.writeFile(path.join(sourceFiles, fileId), fileData);
        await sourceDb.createFile({
            fileID: fileId,
            nonce: "11".repeat(24),
            owner: sourceDevice.deviceID,
        });
        const avatarData = Uint8Array.from(
            Buffer.from(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl2nWQAAAAASUVORK5CYII=",
                "base64",
            ),
        );
        await fsp.writeFile(path.join(sourceAvatars, ACCOUNT), avatarData);

        const originalRecipient = sourceDevice.deviceID;
        const mail = {
            authorID: ACCOUNT,
            cipher: Uint8Array.from([1, 2, 3]),
            extra: Uint8Array.from([4, 5]),
            forward: false,
            group: null,
            mailID: crypto.randomUUID(),
            mailType: MailType.initial,
            nonce: Uint8Array.from({ length: 24 }, (_, index) => index + 1),
            readerID: ACCOUNT,
            recipient: originalRecipient,
            sender: sourceDevice.deviceID,
        };
        await sourceDb.saveFederatedMail(mail, new Uint8Array(32));
        const revokedKeys = xSignKeyPair();
        const revokedDevice = await sourceDb.createDevice(
            ACCOUNT,
            registrationPayload(revokedKeys.publicKey),
        );
        await sourceDb.saveFederatedMail(
            {
                ...mail,
                mailID: crypto.randomUUID(),
                nonce: Uint8Array.from(
                    { length: 24 },
                    (_, index) => index + 61,
                ),
                recipient: revokedDevice.deviceID,
            },
            new Uint8Array(32),
        );
        await sourceDb.deleteDevice(revokedDevice.deviceID);

        const sourceService = new HomeserverMigrationService({
            avatarsDirectory: sourceAvatars,
            client: unavailableTransport(),
            db: sourceDb,
            filesDirectory: sourceFiles,
            homeserverId: SOURCE_HOMESERVER,
            resolver: sourceResolver,
        });
        const challenge = await sourceService.createChallenge(
            ACCOUNT,
            sourceDevice,
            DESTINATION_HOMESERVER,
        );
        const authorization = {
            ...challenge,
            signature: XUtils.encodeHex(
                xSignDetached(
                    xFederationMigrationAuthorizationDigest(challenge),
                    deviceKeys.secretKey,
                ),
            ),
        };
        const [prepared, concurrentRetry] = await Promise.all([
            sourceService.prepareMigration(
                authorization,
                ACCOUNT,
                sourceDevice,
            ),
            sourceService.prepareMigration(
                authorization,
                ACCOUNT,
                sourceDevice,
            ),
        ]);
        expect(concurrentRetry).toEqual(prepared);

        await expect(
            sourceService.readMigrationManifest(DESTINATION_HOMESERVER, {
                migrationId: prepared.migrationId,
            }),
        ).rejects.toMatchObject({ status: 409 });

        // State remains live while the chain update is pending. The source
        // freezes only after it observes the finalized route change.
        const lateRoom = await sourceDb.createServer(
            "Joined while finalizing",
            ACCOUNT,
            SOURCE_HOMESERVER,
        );
        const lateFileId = crypto.randomUUID();
        await fsp.writeFile(
            path.join(sourceFiles, lateFileId),
            Uint8Array.from([23, 29, 31]),
        );
        await sourceDb.createFile({
            fileID: lateFileId,
            nonce: "44".repeat(24),
            owner: sourceDevice.deviceID,
        });
        const lateMail = {
            ...mail,
            mailID: crypto.randomUUID(),
            nonce: Uint8Array.from({ length: 24 }, (_, index) => index + 31),
        };
        await sourceDb.saveFederatedMail(lateMail, new Uint8Array(32));

        const routeChange = {
            accountId: ACCOUNT,
            epoch: "2",
            homeserverId: DESTINATION_HOMESERVER,
            type: "homeserver-changed" as const,
        };
        await Promise.all([
            sourceResolver.applyBatch([routeChange], {
                checkpoint: "block-2",
                sequence: "2",
                source: REGISTRY_SOURCE,
            }),
            destinationResolver.applyBatch([routeChange], {
                checkpoint: "block-2",
                sequence: "2",
                source: REGISTRY_SOURCE,
            }),
        ]);

        const [destinationUser, destinationUserError] =
            await destinationDb.createUser(
                new Uint8Array(16),
                payload,
                ACCOUNT,
            );
        expect(destinationUserError).toBeNull();
        expect(destinationUser?.userID).toBe(ACCOUNT);
        const [destinationDevice] = await destinationDb.retrieveUserDeviceList([
            ACCOUNT,
        ]);
        expect(destinationDevice).toBeDefined();
        if (!destinationDevice) {
            throw new Error("Destination device was not created.");
        }

        const destinationTransport = {
            completeMigration: (
                _source: string,
                query: { migrationId: string },
            ) =>
                sourceService.completeSourceMigration(
                    DESTINATION_HOMESERVER,
                    query,
                ),
            getMigrationAvatar: (
                _source: string,
                query: { migrationId: string },
            ) =>
                sourceService.readMigrationAvatar(
                    DESTINATION_HOMESERVER,
                    query,
                ),
            getMigrationFile: (
                _source: string,
                query: { fileId: string; migrationId: string },
            ) => sourceService.readMigrationFile(DESTINATION_HOMESERVER, query),
            getMigrationMail: (
                _source: string,
                query: { cursor: number; migrationId: string },
            ) => sourceService.readMigrationMail(DESTINATION_HOMESERVER, query),
            getMigrationManifest: (
                _source: string,
                query: { migrationId: string },
            ) =>
                sourceService.readMigrationManifest(
                    DESTINATION_HOMESERVER,
                    query,
                ),
            queryRoom: async (
                homeserverId: string,
                accountId: string,
                serverId: string,
            ) => {
                expect(homeserverId).toBe(SOURCE_HOMESERVER);
                expect(accountId).toBe(ACCOUNT);
                const snapshot = await sourceDb.retrieveRoomSnapshot(serverId);
                if (!snapshot) throw new Error("Room not found.");
                return snapshot;
            },
        } satisfies HomeserverMigrationServiceOptions["client"];
        const destinationService = new HomeserverMigrationService({
            avatarsDirectory: destinationAvatars,
            client: destinationTransport,
            db: destinationDb,
            filesDirectory: destinationFiles,
            homeserverId: DESTINATION_HOMESERVER,
            resolver: destinationResolver,
        });

        const result = await destinationService.importMigration(
            ACCOUNT,
            destinationDevice,
            SOURCE_HOMESERVER,
            prepared.migrationId,
        );
        expect(result).toEqual({
            avatarImported: true,
            filesImported: 2,
            mailDeferred: 0,
            mailImported: 2,
            roomsImported: 2,
        });

        const importedFile = await destinationDb.retrieveFile(fileId);
        expect(importedFile).toEqual({
            fileID: fileId,
            nonce: "11".repeat(24),
            owner: destinationDevice.deviceID,
        });
        await expect(
            fsp.readFile(path.join(destinationFiles, fileId)),
        ).resolves.toEqual(Buffer.from(fileData));
        await expect(
            fsp.readFile(path.join(destinationAvatars, ACCOUNT)),
        ).resolves.toEqual(Buffer.from(avatarData));

        const importedRoom = await destinationDb.retrieveServer(room.serverID);
        expect(importedRoom).toMatchObject({
            homeserverId: SOURCE_HOMESERVER,
            name: "Portable room",
        });
        await expect(
            destinationDb.retrieveServer(lateRoom.serverID),
        ).resolves.toMatchObject({ name: "Joined while finalizing" });
        const importedMail = await destinationDb.retrieveMail(
            destinationDevice.deviceID,
        );
        expect(importedMail).toHaveLength(2);
        expect(importedMail[0]?.[1]).toMatchObject({
            mailID: mail.mailID,
            recipient: originalRecipient,
        });
        const migration = await sourceDb.retrieveHomeserverMigration(
            prepared.migrationId,
        );
        expect(migration?.completedAt).not.toBeNull();
    });
});

function hex32(character: string): string {
    return `0x${character.repeat(64)}`;
}

function ready(database: Database): Promise<void> {
    return new Promise((resolve) => database.once("ready", resolve));
}

function registrationPayload(publicKey: Uint8Array): RegistrationPayload {
    return {
        deviceName: "Migration device",
        intent: "create-account",
        password: "a sufficiently long password",
        preKey: "11".repeat(32),
        preKeyIndex: 1,
        preKeySignature: "22".repeat(64),
        signed: "33".repeat(64),
        signKey: XUtils.encodeHex(publicKey),
        username: "alice",
    };
}

function registryKey(publicKey: Uint8Array): string {
    return `0x${XUtils.encodeHex(publicKey)}`;
}

function unavailableTransport(): HomeserverMigrationServiceOptions["client"] {
    const unavailable = () =>
        Promise.reject(new Error("Transport unavailable."));
    return {
        completeMigration: unavailable,
        getMigrationAvatar: unavailable,
        getMigrationFile: unavailable,
        getMigrationMail: unavailable,
        getMigrationManifest: unavailable,
        queryRoom: unavailable,
    };
}

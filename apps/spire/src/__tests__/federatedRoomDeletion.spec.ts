/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { FederationRoomSnapshot, Permission } from "@vex-chat/types";

import { MailType } from "@vex-chat/types";

import { parse as uuidParse } from "uuid";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Database } from "../Database.ts";

const ACCOUNT = `0x${"a".repeat(64)}`;
const HOMESERVER = `0x${"b".repeat(64)}`;

describe("federated room deletion tombstones", () => {
    let database: Database;

    beforeEach(async () => {
        database = new Database({ dbType: "sqlite3mem" });
        await ready(database);
    });

    afterEach(async () => {
        await database.close();
    });

    it("atomically removes room state and prevents replay resurrection", async () => {
        const serverId = crypto.randomUUID();
        const channelId = crypto.randomUUID();
        const permission = roomPermission(serverId);
        const snapshot = roomSnapshot(serverId, channelId, permission, "2");
        await database.saveFederatedRoom(snapshot, permission);
        const invite = await database.createInvite(
            crypto.randomUUID(),
            serverId,
            ACCOUNT,
            new Date(Date.now() + 60_000).toISOString(),
        );
        const emojiId = crypto.randomUUID();
        await database.createEmoji({
            emojiID: emojiId,
            name: "wave",
            owner: serverId,
        });
        const nonce = Uint8Array.from({ length: 24 }, (_, index) => index + 1);
        await database.saveFederatedMail(
            {
                authorID: ACCOUNT,
                cipher: Uint8Array.from([1]),
                extra: Uint8Array.from([2]),
                forward: false,
                group: uuidParse(channelId),
                mailID: crypto.randomUUID(),
                mailType: MailType.subsequent,
                nonce,
                readerID: ACCOUNT,
                recipient: "recipient-device",
                sender: "sender-device",
            },
            new Uint8Array(32),
        );

        await expect(
            database.applyFederatedRoomDeletion({
                originHomeserverId: HOMESERVER,
                revision: "3",
                serverId,
            }),
        ).resolves.toBe(true);

        await expect(database.retrieveServer(serverId)).resolves.toBeNull();
        await expect(database.retrieveChannel(channelId)).resolves.toBeNull();
        await expect(
            database.retrieveInvite(invite.inviteID),
        ).resolves.toBeNull();
        await expect(database.retrieveEmoji(emojiId)).resolves.toBeNull();
        await expect(database.hasMail(nonce, "recipient-device")).resolves.toBe(
            false,
        );
        await expect(
            database.retrieveFederationRoomTombstone(serverId),
        ).resolves.toMatchObject({
            homeserverId: HOMESERVER,
            permanent: true,
            revision: "3",
            serverId,
        });

        await expect(
            database.applyFederatedRoomDeletion({
                originHomeserverId: HOMESERVER,
                revision: "3",
                serverId,
            }),
        ).resolves.toBe(false);
        await expect(
            database.saveFederatedRoom(snapshot, permission),
        ).rejects.toThrow("permanently deleted");
    });

    it("does not let a stale deletion remove newer room state", async () => {
        const serverId = crypto.randomUUID();
        const permission = roomPermission(serverId);
        await database.saveFederatedRoom(
            roomSnapshot(serverId, crypto.randomUUID(), permission, "5"),
            permission,
        );

        await expect(
            database.applyFederatedRoomDeletion({
                originHomeserverId: HOMESERVER,
                revision: "5",
                serverId,
            }),
        ).resolves.toBe(false);
        await expect(database.retrieveServer(serverId)).resolves.toMatchObject({
            revision: "5",
        });
        await expect(
            database.retrieveFederationRoomTombstone(serverId),
        ).resolves.toBeNull();
    });

    it("suppresses stale mirrors but allows a newer re-invite", async () => {
        const serverId = crypto.randomUUID();
        const permission = roomPermission(serverId);
        const stale = roomSnapshot(
            serverId,
            crypto.randomUUID(),
            permission,
            "2",
        );
        await database.saveFederatedRoom(stale, permission);

        await expect(
            database.removeFederatedRoomMirror({
                homeserverId: HOMESERVER,
                revision: "3",
                serverId,
            }),
        ).resolves.toBe(true);
        await expect(
            database.retrieveFederationRoomTombstone(serverId),
        ).resolves.toMatchObject({
            homeserverId: HOMESERVER,
            permanent: false,
            revision: "3",
            serverId,
        });

        await expect(
            database.saveFederatedRoom(stale, permission),
        ).resolves.toBeUndefined();
        await expect(database.retrieveServer(serverId)).resolves.toBeNull();

        const rejoined = roomSnapshot(
            serverId,
            crypto.randomUUID(),
            permission,
            "4",
        );
        await database.saveFederatedRoom(rejoined, permission);
        await expect(database.retrieveServer(serverId)).resolves.toMatchObject({
            revision: "4",
        });
        await expect(
            database.retrieveFederationRoomTombstone(serverId),
        ).resolves.toBeNull();
    });
});

function ready(database: Database): Promise<void> {
    return new Promise((resolve, reject) => {
        database.once("ready", resolve);
        database.once("error", reject);
    });
}

function roomPermission(serverId: string): Permission {
    return {
        permissionID: crypto.randomUUID(),
        powerLevel: 100,
        resourceID: serverId,
        resourceType: "server",
        userID: ACCOUNT,
    };
}

function roomSnapshot(
    serverId: string,
    channelId: string,
    permission: Permission,
    revision: string,
): FederationRoomSnapshot {
    return {
        channels: [
            { channelID: channelId, name: "general", serverID: serverId },
        ],
        members: [
            {
                permissionId: permission.permissionID,
                powerLevel: permission.powerLevel,
                userId: permission.userID,
            },
        ],
        revision,
        server: {
            homeserverId: HOMESERVER,
            name: "Remote room",
            revision,
            serverID: serverId,
        },
    };
}

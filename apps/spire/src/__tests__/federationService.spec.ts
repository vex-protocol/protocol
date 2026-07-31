/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type {
    Channel,
    Device,
    FederationAccountResult,
    FederationInviteRedeemResult,
    FederationKeyBundleResult,
    FederationRoomSnapshot,
    IdentityResolver,
    MailWS,
    Permission,
    RegistryAccount,
    RegistryDevice,
    RegistryHomeserver,
    RegistryIdentityResolution,
    RegistryResolution,
    RegistryResolveOptions,
    RegistryUsername,
    User,
} from "@vex-chat/types";

import { xSignKeyPair, XUtils } from "@vex-chat/crypto";

import { parse as uuidParse } from "uuid";
import { describe, expect, it, vi } from "vitest";

import {
    FederationService,
    FederationServiceError,
    type FederationServiceOptions,
} from "../federation/FederationService.ts";
import { createFederationRoomMailAuthorization } from "../federation/signatures.ts";

const ACCOUNT = hex32("a");
const REMOTE_ACCOUNT = hex32("b");
const LOCAL_SERVER = hex32("c");
const REMOTE_SERVER = hex32("d");
const DEVICE_KEY = "1".repeat(64);
const REMOTE_DEVICE_KEY = "2".repeat(64);
const SOURCE = "eip155:84532/0x1111111111111111111111111111111111111111";
const POSITION = { checkpoint: "0xbeef", sequence: "42", source: SOURCE };

describe("FederationService", () => {
    it("resolves and validates a remote account by global username", async () => {
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const result: FederationAccountResult = {
            devices: [
                device("remote-device", REMOTE_ACCOUNT, REMOTE_DEVICE_KEY),
            ],
            position: POSITION,
            user: user(REMOTE_ACCOUNT, "remote"),
        };
        const fixture = serviceFixture([remote], {
            queryAccount: vi.fn(() => Promise.resolve(result)),
        });

        await expect(fixture.service.resolveAccount("REMOTE")).resolves.toEqual(
            result,
        );
        expect(fixture.client.queryAccount).toHaveBeenCalledWith(
            REMOTE_ACCOUNT,
        );
    });

    it("rejects device rows not authorized by the registry", async () => {
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const fixture = serviceFixture([remote], {
            queryAccount: vi.fn(() =>
                Promise.resolve({
                    devices: [
                        device("remote-device", REMOTE_ACCOUNT, "3".repeat(64)),
                    ],
                    position: POSITION,
                    user: user(REMOTE_ACCOUNT, "remote"),
                }),
            ),
        });

        await expect(
            fixture.service.resolveAccount("remote"),
        ).rejects.toMatchObject({
            status: 502,
        });
    });

    it("relays remote mail with the finalized sender position", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const fixture = serviceFixture([local, remote]);
        const sender = device("local-device", ACCOUNT, DEVICE_KEY);
        const outbound = mail(sender.deviceID, ACCOUNT, REMOTE_ACCOUNT);

        await fixture.service.deliverMail(
            new Uint8Array(32),
            outbound,
            sender,
            ACCOUNT,
        );

        expect(fixture.client.deliverMail).toHaveBeenCalledWith({
            header: new Uint8Array(32),
            mail: outbound,
            registrySequence: "42",
            roomAuthorization: null,
            senderDeviceKey: `0x${DEVICE_KEY}`,
        });
        expect(fixture.db.saveMail).not.toHaveBeenCalled();
    });

    it("stores local mail only for a registry-authorized recipient device", async () => {
        const senderIdentity = identity(
            ACCOUNT,
            LOCAL_SERVER,
            DEVICE_KEY,
            "local",
        );
        const recipientIdentity = identity(
            REMOTE_ACCOUNT,
            LOCAL_SERVER,
            REMOTE_DEVICE_KEY,
            "recipient",
        );
        const recipient = device(
            "recipient-device",
            REMOTE_ACCOUNT,
            REMOTE_DEVICE_KEY,
        );
        const fixture = serviceFixture(
            [senderIdentity, recipientIdentity],
            {},
            {
                retrieveDevice: vi.fn(() => Promise.resolve(recipient)),
            },
        );
        const sender = device("local-device", ACCOUNT, DEVICE_KEY);
        const inbound = mail(
            sender.deviceID,
            ACCOUNT,
            REMOTE_ACCOUNT,
            recipient.deviceID,
        );

        await fixture.service.deliverMail(
            new Uint8Array(32),
            inbound,
            sender,
            ACCOUNT,
        );

        expect(fixture.db.saveMail).toHaveBeenCalledOnce();
        expect(fixture.notify).toHaveBeenCalledWith(
            REMOTE_ACCOUNT,
            "mail",
            expect.any(String),
            null,
            recipient.deviceID,
            ACCOUNT,
            inbound.nonce,
        );
    });

    it("validates the device owner and identity key on remote key bundles", async () => {
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const remoteDevice = device(
            "remote-device",
            REMOTE_ACCOUNT,
            REMOTE_DEVICE_KEY,
        );
        const result: FederationKeyBundleResult = {
            device: remoteDevice,
            keyBundle: {
                preKey: {
                    deviceID: remoteDevice.deviceID,
                    index: 1,
                    publicKey: new Uint8Array(32),
                    signature: new Uint8Array(64),
                },
                signKey: Uint8Array.from(Buffer.from(REMOTE_DEVICE_KEY, "hex")),
            },
            position: POSITION,
        };
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const getKeyBundle = vi.fn(() => Promise.resolve(result));
        const fixture = serviceFixture([local, remote], {
            getKeyBundle,
        });

        await expect(
            fixture.service.retrieveKeyBundle(
                ACCOUNT,
                REMOTE_ACCOUNT,
                remoteDevice.deviceID,
            ),
        ).resolves.toEqual(result.keyBundle);
        expect(getKeyBundle).toHaveBeenCalledWith(
            ACCOUNT,
            REMOTE_ACCOUNT,
            remoteDevice.deviceID,
        );
    });

    it("rejects mail from a revoked sender device", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const fixture = serviceFixture([local, remote]);
        const sender = device("local-device", ACCOUNT, "4".repeat(64));

        await expect(
            fixture.service.deliverMail(
                new Uint8Array(32),
                mail(sender.deviceID, ACCOUNT, REMOTE_ACCOUNT),
                sender,
                ACCOUNT,
            ),
        ).rejects.toBeInstanceOf(FederationServiceError);
        expect(fixture.client.deliverMail).not.toHaveBeenCalled();
    });

    it("obtains and relays signed room authorization for remote group mail", async () => {
        const channelId = crypto.randomUUID();
        const serverId = crypto.randomUUID();
        const roomKeys = xSignKeyPair();
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        remote.homeserver.signingKey = `0x${XUtils.encodeHex(roomKeys.publicKey)}`;
        const authorization = createFederationRoomMailAuthorization(
            {
                channelId,
                expiresAt: Date.now() + 60_000,
                originHomeserverId: REMOTE_SERVER,
                recipientAccountId: REMOTE_ACCOUNT,
                revision: "7",
                senderAccountId: ACCOUNT,
                serverId,
            },
            roomKeys.secretKey,
        );
        const fixture = serviceFixture(
            [local, remote],
            {
                authorizeRoomMail: vi.fn(() => Promise.resolve(authorization)),
            },
            {
                retrieveChannel: vi.fn(() =>
                    Promise.resolve(channel(channelId, serverId)),
                ),
                retrievePermissions: vi.fn(() =>
                    Promise.resolve([permission(ACCOUNT, serverId, 0)]),
                ),
                retrieveServer: vi.fn(() =>
                    Promise.resolve({
                        homeserverId: REMOTE_SERVER,
                        name: "Remote room",
                        revision: "7",
                        serverID: serverId,
                    }),
                ),
            },
        );
        const sender = device("local-device", ACCOUNT, DEVICE_KEY);
        const outbound = {
            ...mail(sender.deviceID, ACCOUNT, REMOTE_ACCOUNT),
            group: uuidParse(channelId),
        };

        await fixture.service.deliverMail(
            new Uint8Array(32),
            outbound,
            sender,
            ACCOUNT,
        );

        expect(fixture.client.authorizeRoomMail).toHaveBeenCalledWith(
            REMOTE_SERVER,
            {
                channelId,
                recipientAccountId: REMOTE_ACCOUNT,
                senderAccountId: ACCOUNT,
                serverId,
            },
        );
        expect(fixture.client.deliverMail).toHaveBeenCalledWith(
            expect.objectContaining({ roomAuthorization: authorization }),
        );
    });

    it("persists a validated remote invite snapshot and membership", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const serverId = crypto.randomUUID();
        const roomPermission = permission(ACCOUNT, serverId, 0);
        const snapshot = roomSnapshot(serverId, REMOTE_SERVER, roomPermission);
        const result: FederationInviteRedeemResult = {
            permission: roomPermission,
            snapshot,
        };
        const fixture = serviceFixture([local], {
            redeemInvite: vi.fn(() => Promise.resolve(result)),
        });

        await expect(
            fixture.service.redeemInvite(
                REMOTE_SERVER,
                crypto.randomUUID(),
                ACCOUNT,
            ),
        ).resolves.toEqual(result);
        expect(fixture.db.saveFederatedRoom).toHaveBeenCalledWith(
            snapshot,
            roomPermission,
        );
    });

    it("queues room state for every participating remote homeserver", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const serverId = crypto.randomUUID();
        const localPermission = permission(ACCOUNT, serverId, 100);
        const remotePermission = permission(REMOTE_ACCOUNT, serverId, 0);
        const snapshot = roomSnapshot(serverId, LOCAL_SERVER, localPermission);
        snapshot.members.push({
            permissionId: remotePermission.permissionID,
            powerLevel: remotePermission.powerLevel,
            userId: remotePermission.userID,
        });
        const fixture = serviceFixture([local, remote]);

        await fixture.service.publishRoomSnapshot(snapshot);

        expect(
            fixture.db.enqueueFederationRoomOutbox,
        ).toHaveBeenCalledExactlyOnceWith(
            expect.objectContaining({
                destinationHomeserverId: REMOTE_SERVER,
                kind: "snapshot",
                payload: JSON.stringify(snapshot),
            }),
        );
    });

    it("refuses to publish a partial room membership graph", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const serverId = crypto.randomUUID();
        const localPermission = permission(ACCOUNT, serverId, 100);
        const snapshot = roomSnapshot(serverId, LOCAL_SERVER, localPermission);
        snapshot.members.push({
            permissionId: crypto.randomUUID(),
            powerLevel: 0,
            userId: REMOTE_ACCOUNT,
        });
        const fixture = serviceFixture([local]);

        await expect(
            fixture.service.publishRoomSnapshot(snapshot),
        ).rejects.toMatchObject({ status: 503 });
        expect(fixture.db.enqueueFederationRoomOutbox).not.toHaveBeenCalled();
    });

    it("rejects an incoming room snapshot with an unregistered member", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const serverId = crypto.randomUUID();
        const snapshot = roomSnapshot(
            serverId,
            REMOTE_SERVER,
            permission(ACCOUNT, serverId, 0),
        );
        snapshot.members.push({
            permissionId: crypto.randomUUID(),
            powerLevel: 0,
            userId: REMOTE_ACCOUNT,
        });
        const fixture = serviceFixture([local]);

        await expect(
            fixture.service.receiveRoomSnapshot(snapshot, REMOTE_SERVER),
        ).rejects.toMatchObject({ status: 502 });
        expect(fixture.db.saveFederatedRoom).not.toHaveBeenCalled();
    });

    it("ignores an out-of-order room snapshot before it can remove local state", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const serverId = crypto.randomUUID();
        const stale = roomSnapshot(
            serverId,
            REMOTE_SERVER,
            permission(REMOTE_ACCOUNT, serverId, 100),
        );
        stale.revision = "6";
        stale.server.revision = "6";
        const fixture = serviceFixture(
            [local, remote],
            {},
            {
                retrieveServer: vi.fn(() =>
                    Promise.resolve({
                        homeserverId: REMOTE_SERVER,
                        name: "Newer room state",
                        revision: "7",
                        serverID: serverId,
                    }),
                ),
            },
        );

        await fixture.service.receiveRoomSnapshot(stale, REMOTE_SERVER);

        expect(fixture.db.deleteServer).not.toHaveBeenCalled();
        expect(fixture.db.saveFederatedRoom).not.toHaveBeenCalled();
        expect(fixture.notify).not.toHaveBeenCalled();
    });

    it("records the revision when a snapshot removes the last local member", async () => {
        const local = identity(ACCOUNT, LOCAL_SERVER, DEVICE_KEY, "local");
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const serverId = crypto.randomUUID();
        const localPermission = permission(ACCOUNT, serverId, 0);
        const removed = roomSnapshot(
            serverId,
            REMOTE_SERVER,
            permission(REMOTE_ACCOUNT, serverId, 100),
        );
        removed.revision = "3";
        removed.server.revision = "3";
        const fixture = serviceFixture(
            [local, remote],
            {},
            {
                retrievePermissionsByResourceID: vi.fn(() =>
                    Promise.resolve([localPermission]),
                ),
                retrieveServer: vi.fn(() =>
                    Promise.resolve({
                        homeserverId: REMOTE_SERVER,
                        name: "Remote room",
                        revision: "2",
                        serverID: serverId,
                    }),
                ),
                retrieveUser: vi.fn((accountId) =>
                    Promise.resolve(
                        accountId === ACCOUNT
                            ? {
                                  ...user(ACCOUNT, "local"),
                                  passwordHash: "not-used-by-this-test",
                              }
                            : null,
                    ),
                ),
            },
        );

        await fixture.service.receiveRoomSnapshot(removed, REMOTE_SERVER);

        expect(fixture.db.removeFederatedRoomMirror).toHaveBeenCalledWith({
            homeserverId: REMOTE_SERVER,
            revision: "3",
            serverId,
        });
        expect(fixture.db.saveFederatedRoom).not.toHaveBeenCalled();
        expect(fixture.notify).toHaveBeenCalledWith(
            ACCOUNT,
            "serverChange",
            expect.any(String),
            serverId,
        );
    });

    it("acknowledges a delayed snapshot for a permanently deleted room", async () => {
        const remote = identity(
            REMOTE_ACCOUNT,
            REMOTE_SERVER,
            REMOTE_DEVICE_KEY,
            "remote",
        );
        const serverId = crypto.randomUUID();
        const snapshot = roomSnapshot(
            serverId,
            REMOTE_SERVER,
            permission(REMOTE_ACCOUNT, serverId, 100),
        );
        const fixture = serviceFixture(
            [remote],
            {},
            {
                retrieveFederationRoomTombstone: vi.fn(() =>
                    Promise.resolve({
                        deletedAt: 1,
                        homeserverId: REMOTE_SERVER,
                        permanent: true,
                        revision: "3",
                        serverId,
                    }),
                ),
            },
        );

        await fixture.service.receiveRoomSnapshot(snapshot, REMOTE_SERVER);

        expect(fixture.db.saveFederatedRoom).not.toHaveBeenCalled();
        expect(fixture.db.deleteServer).not.toHaveBeenCalled();
    });
});

class TestResolver implements IdentityResolver {
    public readonly source = SOURCE;

    private readonly identities: RegistryIdentityResolution[];

    constructor(identities: RegistryIdentityResolution[]) {
        this.identities = identities;
    }

    public async resolveAccount(
        accountId: string,
        _options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryAccount>> {
        const identity = await this.resolveIdentity(accountId);
        return identity
            ? { position: identity.position, record: identity.account }
            : null;
    }

    public async resolveDevice(
        accountId: string,
        deviceKey: string,
        _options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryDevice>> {
        const identity = await this.resolveIdentity(accountId);
        const record = identity?.devices.find(
            (device) => device.deviceKey === deviceKey,
        );
        return identity && record
            ? { position: identity.position, record }
            : null;
    }

    public resolveHomeserver(
        homeserverId: string,
        _options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryHomeserver>> {
        const identity = this.identities.find(
            (entry) => entry.homeserver.homeserverId === homeserverId,
        );
        return Promise.resolve(
            identity
                ? { position: identity.position, record: identity.homeserver }
                : null,
        );
    }

    public resolveIdentity(
        accountId: string,
        _options?: RegistryResolveOptions,
    ): Promise<null | RegistryIdentityResolution> {
        return Promise.resolve(
            this.identities.find(
                (identity) => identity.account.accountId === accountId,
            ) ?? null,
        );
    }

    public resolveUsername(
        username: string,
        _options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryUsername>> {
        const identity = this.identities.find(
            (entry) => entry.username?.username === username,
        );
        return Promise.resolve(
            identity?.username
                ? { position: identity.position, record: identity.username }
                : null,
        );
    }
}

function channel(channelID: string, serverID: string): Channel {
    return { channelID, name: "general", serverID };
}

function device(deviceID: string, owner: string, signKey: string): Device {
    return {
        deleted: false,
        deviceID,
        lastLogin: new Date(0).toISOString(),
        name: deviceID,
        owner,
        signKey,
    };
}

function hex32(character: string): string {
    return `0x${character.repeat(64)}`;
}

function identity(
    accountId: string,
    homeserverId: string,
    deviceKey: string,
    username: string,
): RegistryIdentityResolution {
    return {
        account: {
            accountId,
            activeDeviceCount: 1,
            deviceThreshold: 1,
            epoch: "1",
            homeserverId,
            nonce: "0",
            recoveryCommitment: hex32("0"),
        },
        devices: [
            {
                accountId,
                active: true,
                addedAtEpoch: "1",
                deviceKey: `0x${deviceKey}`,
                keyAlgorithm: "Ed25519",
                revokedAtEpoch: null,
            },
        ],
        homeserver: {
            active: true,
            endpoint: `https://${homeserverId === LOCAL_SERVER ? "local" : "remote"}.example`,
            epoch: "1",
            homeserverId,
            keyAlgorithm: "Ed25519",
            nonce: "0",
            signingKey: hex32("e"),
        },
        position: POSITION,
        username: {
            accountId,
            nameHash: hex32("f"),
            username,
        },
    };
}

function mail(
    sender: string,
    authorID: string,
    readerID: string,
    recipient = "remote-device",
): MailWS {
    return {
        authorID,
        cipher: new Uint8Array([1]),
        extra: new Uint8Array([2]),
        forward: false,
        group: null,
        mailID: crypto.randomUUID(),
        mailType: 1,
        nonce: new Uint8Array(24),
        readerID,
        recipient,
        sender,
    };
}

function permission(
    userID: string,
    resourceID: string,
    powerLevel: number,
): Permission {
    return {
        permissionID: crypto.randomUUID(),
        powerLevel,
        resourceID,
        resourceType: "server",
        userID,
    };
}

function roomSnapshot(
    serverId: string,
    homeserverId: string,
    roomPermission: Permission,
): FederationRoomSnapshot {
    return {
        channels: [channel(crypto.randomUUID(), serverId)],
        members: [
            {
                permissionId: roomPermission.permissionID,
                powerLevel: roomPermission.powerLevel,
                userId: roomPermission.userID,
            },
        ],
        revision: "2",
        server: {
            homeserverId,
            name: "Federated room",
            revision: "2",
            serverID: serverId,
        },
    };
}

function serviceFixture(
    identities: RegistryIdentityResolution[],
    clientOverrides: Partial<FederationServiceOptions["client"]> = {},
    dbOverrides: Partial<FederationServiceOptions["db"]> = {},
) {
    const resolver = new TestResolver(identities);
    const client: FederationServiceOptions["client"] = {
        authorizeRoomMail: vi.fn(() =>
            Promise.reject(new Error("Unexpected room authorization request.")),
        ),
        deliverMail: vi.fn(() => Promise.resolve({ duplicate: false })),
        getAvatar: vi.fn(() =>
            Promise.reject(new Error("Unexpected avatar request.")),
        ),
        getKeyBundle: vi.fn(() =>
            Promise.reject(new Error("Unexpected key-bundle request.")),
        ),
        getServerIcon: vi.fn(() =>
            Promise.reject(new Error("Unexpected room icon request.")),
        ),
        mutateRoom: vi.fn(() =>
            Promise.reject(new Error("Unexpected room mutation request.")),
        ),
        previewInvite: vi.fn(() =>
            Promise.reject(new Error("Unexpected invite preview request.")),
        ),
        pushRoomDeletion: vi.fn(() =>
            Promise.reject(new Error("Unexpected room deletion push.")),
        ),
        pushRoomSnapshot: vi.fn(() =>
            Promise.reject(new Error("Unexpected room snapshot push.")),
        ),
        queryAccount: vi.fn(() =>
            Promise.reject(new Error("Unexpected account request.")),
        ),
        queryRoom: vi.fn(() =>
            Promise.reject(new Error("Unexpected room request.")),
        ),
        queryRoomInvites: vi.fn(() =>
            Promise.reject(new Error("Unexpected room invites request.")),
        ),
        redeemInvite: vi.fn(() =>
            Promise.reject(new Error("Unexpected invite redemption request.")),
        ),
        ...clientOverrides,
    };
    const db: FederationServiceOptions["db"] = {
        applyFederatedRoomDeletion: vi.fn(() => Promise.resolve(false)),
        completeFederationRoomOutbox: vi.fn(() => Promise.resolve()),
        deleteServer: vi.fn(() => Promise.resolve()),
        enqueueFederationRoomOutbox: vi.fn(() => Promise.resolve()),
        failFederationRoomOutbox: vi.fn(() => Promise.resolve()),
        getKeyBundle: vi.fn(() => Promise.resolve(null)),
        removeFederatedRoomMirror: vi.fn(() => Promise.resolve(false)),
        retrieveChannel: vi.fn(() => Promise.resolve(null)),
        retrieveDevice: vi.fn(() => Promise.resolve(null)),
        retrieveFederationRoomOutbox: vi.fn(() => Promise.resolve([])),
        retrieveFederationRoomTombstone: vi.fn(() => Promise.resolve(null)),
        retrievePermissions: vi.fn(() => Promise.resolve([])),
        retrievePermissionsByResourceID: vi.fn(() => Promise.resolve([])),
        retrieveRoomSnapshot: vi.fn(() => Promise.resolve(null)),
        retrieveServer: vi.fn(() => Promise.resolve(null)),
        retrieveServerByIcon: vi.fn(() => Promise.resolve(null)),
        retrieveUser: vi.fn(() => Promise.resolve(null)),
        retrieveUserDeviceList: vi.fn(() => Promise.resolve([])),
        saveFederatedRoom: vi.fn(() => Promise.resolve()),
        saveMail: vi.fn(() => Promise.resolve()),
        ...dbOverrides,
    };
    const notify = vi.fn();
    return {
        client,
        db,
        notify,
        service: new FederationService({
            client,
            db,
            homeserverId: LOCAL_SERVER,
            notify,
            resolver,
            signKeys: xSignKeyPair(),
        }),
    };
}

function user(userID: string, username: string): User {
    return { lastSeen: new Date(0).toISOString(), userID, username };
}

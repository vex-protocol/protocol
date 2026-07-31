/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { MailWS, RegistrationPayload } from "@vex-chat/types";
import type { Server } from "node:http";

import express from "express";

import { xSignKeyPair, XUtils } from "@vex-chat/crypto";
import {
    FederationAccountResultSchema,
    FederationInviteRedeemResultSchema,
    FederationKeyBundleResultSchema,
    FederationMailResultSchema,
    FederationRoomMailAuthorizationSchema,
    FederationRoomMutationResultSchema,
    MailType,
} from "@vex-chat/types";

import { parse as uuidParse } from "uuid";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Database } from "../Database.ts";
import {
    createFederationRequestHeaders,
    FederationHeaders,
    verifyFederationResponseSignature,
} from "../federation/signatures.ts";
import { getFederationRouter } from "../server/federation.ts";
import { msgpack } from "../utils/msgpack.ts";

const ACCOUNT = hex32("a");
const DESTINATION = hex32("b");
const ORIGIN = hex32("c");
const SOURCE = "test:federation-router";

describe("federation router", () => {
    const databases: Database[] = [];
    const servers: Server[] = [];

    afterEach(async () => {
        for (const server of servers.splice(0)) await close(server);
        for (const database of databases.splice(0)) await database.close();
    });

    it("authenticates, signs an account response, and rejects replay", async () => {
        const database = new Database({ dbType: "sqlite3mem" });
        databases.push(database);
        await ready(database);

        const originKeys = xSignKeyPair();
        const destinationKeys = xSignKeyPair();
        const deviceKeys = xSignKeyPair();
        const originDeviceKeys = xSignKeyPair();
        const originAccount = hex32("f");
        const resolver = database.createRegistryStore(SOURCE);
        await resolver.applyBatch(
            [
                {
                    endpoint: "https://origin.example",
                    epoch: "1",
                    homeserverId: ORIGIN,
                    signingKey: registryKey(originKeys.publicKey),
                    type: "homeserver-registered",
                },
                {
                    endpoint: "https://destination.example",
                    epoch: "1",
                    homeserverId: DESTINATION,
                    signingKey: registryKey(destinationKeys.publicKey),
                    type: "homeserver-registered",
                },
                {
                    accountId: ACCOUNT,
                    epoch: "1",
                    genesisDeviceKey: registryKey(deviceKeys.publicKey),
                    homeserverId: DESTINATION,
                    recoveryCommitment: hex32("0"),
                    type: "account-registered",
                },
                {
                    accountId: originAccount,
                    epoch: "1",
                    genesisDeviceKey: registryKey(originDeviceKeys.publicKey),
                    homeserverId: ORIGIN,
                    recoveryCommitment: hex32("0"),
                    type: "account-registered",
                },
                {
                    accountId: ACCOUNT,
                    nameHash: hex32("d"),
                    type: "username-registered",
                    username: "alice",
                },
            ],
            { checkpoint: "checkpoint-1", sequence: "1", source: SOURCE },
        );

        const payload: RegistrationPayload = {
            deviceName: "Alice's device",
            intent: "create-account",
            password: "a sufficiently long password",
            preKey: "11".repeat(32),
            preKeyIndex: 1,
            preKeySignature: "22".repeat(64),
            signed: "33".repeat(64),
            signKey: XUtils.encodeHex(deviceKeys.publicKey),
            username: "alice",
        };
        const [user, createError] = await database.createUser(
            new Uint8Array(16),
            payload,
            ACCOUNT,
        );
        expect(createError).toBeNull();
        expect(user?.userID).toBe(ACCOUNT);

        const app = express();
        app.use(
            "/_vex/federation/v1",
            getFederationRouter({
                db: database,
                homeserverId: DESTINATION,
                notify: vi.fn(),
                resolver,
                signKeys: destinationKeys,
            }),
        );
        const server = await listen(app);
        servers.push(server);

        const body = msgpack.encode({ accountId: ACCOUNT });
        const path = "/_vex/federation/v1/account";
        const nonce = hex32("e");
        const headers = createFederationRequestHeaders(
            {
                body,
                destination: DESTINATION,
                method: "POST",
                nonce,
                origin: ORIGIN,
                path,
                timestamp: Date.now(),
            },
            originKeys.secretKey,
        );
        const first = await fetch(`${serverOrigin(server)}${path}`, {
            body,
            headers: {
                ...headers,
                "Content-Type": "application/msgpack",
            },
            method: "POST",
        });
        expect(first.status).toBe(200);
        const responseBody = new Uint8Array(await first.arrayBuffer());
        const responseSignature = first.headers.get(
            FederationHeaders.signature,
        );
        expect(responseSignature).not.toBeNull();
        expect(
            verifyFederationResponseSignature(
                {
                    body: responseBody,
                    destination: ORIGIN,
                    origin: DESTINATION,
                    requestNonce: nonce,
                    status: 200,
                },
                responseSignature ?? "",
                registryKey(destinationKeys.publicKey),
            ),
        ).toBe(true);
        const decodedAccount: unknown = msgpack.decode(responseBody);
        expect(decodedAccount).not.toHaveProperty("user.passwordHash");
        expect(decodedAccount).not.toHaveProperty("devices.0.name");
        expect(decodedAccount).not.toHaveProperty("devices.0.lastLogin");
        const account = FederationAccountResultSchema.parse(decodedAccount);
        expect(account.user).toMatchObject({
            userID: ACCOUNT,
            username: "alice",
        });
        expect(account.devices).toHaveLength(1);

        const replay = await fetch(`${serverOrigin(server)}${path}`, {
            body,
            headers: {
                ...headers,
                "Content-Type": "application/msgpack",
            },
            method: "POST",
        });
        expect(replay.status).toBe(409);

        const keyBundlePath = "/_vex/federation/v1/key-bundle";
        const keyBundleQuery = {
            accountId: ACCOUNT,
            deviceId: account.devices[0]!.deviceID,
            requesterAccountId: originAccount,
        };
        const spoofedRequester = await signedPost(
            server,
            keyBundlePath,
            { ...keyBundleQuery, requesterAccountId: ACCOUNT },
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(spoofedRequester.status).toBe(403);

        const keyBundleResponse = await signedPost(
            server,
            keyBundlePath,
            keyBundleQuery,
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(keyBundleResponse.status).toBe(200);
        const decodedKeyBundle: unknown = msgpack.decode(
            new Uint8Array(await keyBundleResponse.arrayBuffer()),
        );
        expect(decodedKeyBundle).not.toHaveProperty("device.name");
        expect(decodedKeyBundle).not.toHaveProperty("device.lastLogin");
        expect(
            FederationKeyBundleResultSchema.parse(decodedKeyBundle).device
                .deviceID,
        ).toBe(account.devices[0]!.deviceID);

        for (let requestCount = 1; requestCount < 30; requestCount += 1) {
            const allowed = await signedPost(
                server,
                keyBundlePath,
                keyBundleQuery,
                ORIGIN,
                DESTINATION,
                originKeys.secretKey,
            );
            expect(allowed.status).toBe(200);
        }
        const rateLimited = await signedPost(
            server,
            keyBundlePath,
            keyBundleQuery,
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(rateLimited.status).toBe(429);
    });

    it("redeems a remote invite and authorizes federated room mail", async () => {
        const database = new Database({ dbType: "sqlite3mem" });
        databases.push(database);
        await ready(database);

        const originKeys = xSignKeyPair();
        const destinationKeys = xSignKeyPair();
        const localDeviceKeys = xSignKeyPair();
        const remoteDeviceKeys = xSignKeyPair();
        const remoteAccount = hex32("f");
        const resolver = database.createRegistryStore(SOURCE);
        await resolver.applyBatch(
            [
                {
                    endpoint: "https://origin.example",
                    epoch: "1",
                    homeserverId: ORIGIN,
                    signingKey: registryKey(originKeys.publicKey),
                    type: "homeserver-registered",
                },
                {
                    endpoint: "https://destination.example",
                    epoch: "1",
                    homeserverId: DESTINATION,
                    signingKey: registryKey(destinationKeys.publicKey),
                    type: "homeserver-registered",
                },
                {
                    accountId: ACCOUNT,
                    epoch: "1",
                    genesisDeviceKey: registryKey(localDeviceKeys.publicKey),
                    homeserverId: DESTINATION,
                    recoveryCommitment: hex32("0"),
                    type: "account-registered",
                },
                {
                    accountId: remoteAccount,
                    epoch: "1",
                    genesisDeviceKey: registryKey(remoteDeviceKeys.publicKey),
                    homeserverId: ORIGIN,
                    recoveryCommitment: hex32("0"),
                    type: "account-registered",
                },
            ],
            { checkpoint: "checkpoint-1", sequence: "1", source: SOURCE },
        );

        const [localUser, createError] = await database.createUser(
            new Uint8Array(16),
            registrationPayload("alice", localDeviceKeys.publicKey),
            ACCOUNT,
        );
        expect(createError).toBeNull();
        expect(localUser).not.toBeNull();
        const [localDevice] = await database.retrieveUserDeviceList([ACCOUNT]);
        expect(localDevice).toBeDefined();

        const room = await database.createServer(
            "Federated room",
            ACCOUNT,
            DESTINATION,
        );
        const [channel] = await database.retrieveChannels(room.serverID);
        expect(channel).toBeDefined();
        const inviteId = crypto.randomUUID();
        await database.createInvite(
            inviteId,
            room.serverID,
            ACCOUNT,
            new Date(Date.now() + 60_000).toISOString(),
        );
        const roomChanged = vi.fn(() => Promise.resolve());

        const app = express();
        app.use(
            "/_vex/federation/v1",
            getFederationRouter({
                db: database,
                homeserverId: DESTINATION,
                notify: vi.fn(),
                resolver,
                roomChanged,
                signKeys: destinationKeys,
            }),
        );
        const server = await listen(app);
        servers.push(server);

        const redeemedResponse = await signedPost(
            server,
            "/_vex/federation/v1/invite/redeem",
            { accountId: remoteAccount, inviteId },
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(redeemedResponse.status).toBe(200);
        const redeemed = FederationInviteRedeemResultSchema.parse(
            msgpack.decode(
                new Uint8Array(await redeemedResponse.arrayBuffer()),
            ),
        );
        expect(redeemed.permission.userID).toBe(remoteAccount);
        expect(redeemed.snapshot).toMatchObject({
            revision: "2",
            server: { homeserverId: DESTINATION },
        });
        expect(redeemed.snapshot.members).toHaveLength(2);
        expect(roomChanged).toHaveBeenCalledWith(
            redeemed.snapshot,
            expect.objectContaining({
                members: [
                    expect.objectContaining({ userId: ACCOUNT }),
                ] as unknown[],
                revision: "1",
            }),
        );

        const deniedMutation = await signedPost(
            server,
            "/_vex/federation/v1/room/mutate",
            {
                accountId: remoteAccount,
                mutation: { name: "Denied", type: "rename-server" },
                serverId: room.serverID,
            },
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(deniedMutation.status).toBe(403);

        const authorizationResponse = await signedPost(
            server,
            "/_vex/federation/v1/room/authorize-mail",
            {
                channelId: channel!.channelID,
                recipientAccountId: ACCOUNT,
                senderAccountId: remoteAccount,
                serverId: room.serverID,
            },
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(authorizationResponse.status).toBe(200);
        const authorization = FederationRoomMailAuthorizationSchema.parse(
            msgpack.decode(
                new Uint8Array(await authorizationResponse.arrayBuffer()),
            ),
        );

        const federatedMail: MailWS = {
            authorID: remoteAccount,
            cipher: new Uint8Array([1, 2, 3]),
            extra: remoteDeviceKeys.publicKey,
            forward: false,
            group: uuidParse(channel!.channelID),
            mailID: crypto.randomUUID(),
            mailType: MailType.initial,
            nonce: crypto.getRandomValues(new Uint8Array(24)),
            readerID: ACCOUNT,
            recipient: localDevice!.deviceID,
            sender: "remote-device",
        };
        const mailResponse = await signedPost(
            server,
            "/_vex/federation/v1/mail",
            {
                header: new Uint8Array(32),
                mail: federatedMail,
                registrySequence: "1",
                roomAuthorization: authorization,
                senderDeviceKey: registryKey(remoteDeviceKeys.publicKey),
            },
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(mailResponse.status).toBe(200);
        expect(
            FederationMailResultSchema.parse(
                msgpack.decode(
                    new Uint8Array(await mailResponse.arrayBuffer()),
                ),
            ),
        ).toEqual({ duplicate: false });
        expect(await database.retrieveMail(localDevice!.deviceID)).toHaveLength(
            1,
        );

        await database.bumpServerRevision(room.serverID);
        const staleMailResponse = await signedPost(
            server,
            "/_vex/federation/v1/mail",
            {
                header: new Uint8Array(32),
                mail: { ...federatedMail, mailID: crypto.randomUUID() },
                registrySequence: "1",
                roomAuthorization: authorization,
                senderDeviceKey: registryKey(remoteDeviceKeys.publicKey),
            },
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(staleMailResponse.status).toBe(403);

        await database.updatePermissionPowerLevel(
            redeemed.permission.permissionID,
            50,
        );
        const mutationResponse = await signedPost(
            server,
            "/_vex/federation/v1/room/mutate",
            {
                accountId: remoteAccount,
                mutation: { name: "Renamed remotely", type: "rename-server" },
                serverId: room.serverID,
            },
            ORIGIN,
            DESTINATION,
            originKeys.secretKey,
        );
        expect(mutationResponse.status).toBe(200);
        const mutation = FederationRoomMutationResultSchema.parse(
            msgpack.decode(
                new Uint8Array(await mutationResponse.arrayBuffer()),
            ),
        );
        expect(mutation).toMatchObject({
            resultType: "server",
            server: { name: "Renamed remotely" },
            snapshot: { server: { name: "Renamed remotely" } },
        });
    });
});

function close(server: Server): Promise<void> {
    return new Promise((resolve, reject) => {
        server.close((error) => {
            if (error) reject(error);
            else resolve();
        });
    });
}

function hex32(character: string): string {
    return `0x${character.repeat(64)}`;
}

function listen(app: express.Application): Promise<Server> {
    return new Promise((resolve) => {
        const server = app.listen(0, "127.0.0.1", () => {
            resolve(server);
        });
    });
}

function ready(database: Database): Promise<void> {
    return new Promise((resolve) => database.once("ready", resolve));
}

function registrationPayload(
    username: string,
    publicKey: Uint8Array,
): RegistrationPayload {
    return {
        deviceName: `${username}'s device`,
        intent: "create-account",
        password: "a sufficiently long password",
        preKey: "11".repeat(32),
        preKeyIndex: 1,
        preKeySignature: "22".repeat(64),
        signed: "33".repeat(64),
        signKey: XUtils.encodeHex(publicKey),
        username,
    };
}

function registryKey(value: Uint8Array): string {
    return `0x${XUtils.encodeHex(value)}`;
}

function serverOrigin(server: Server): string {
    const address = server.address();
    if (!address || typeof address === "string") {
        throw new Error("Expected an IP listener.");
    }
    return `http://127.0.0.1:${String(address.port)}`;
}

async function signedPost(
    server: Server,
    path: string,
    value: unknown,
    origin: string,
    destination: string,
    secretKey: Uint8Array,
): Promise<Response> {
    const body = msgpack.encode(value);
    const headers = createFederationRequestHeaders(
        {
            body,
            destination,
            method: "POST",
            nonce: `0x${XUtils.encodeHex(crypto.getRandomValues(new Uint8Array(32)))}`,
            origin,
            path,
            timestamp: Date.now(),
        },
        secretKey,
    );
    return fetch(`${serverOrigin(server)}${path}`, {
        body,
        headers: { ...headers, "Content-Type": "application/msgpack" },
        method: "POST",
    });
}

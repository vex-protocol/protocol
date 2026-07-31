/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Database } from "../Database.ts";
import {
    RegistryCacheUnavailableError,
    RegistryCheckpointMismatchError,
    RegistryPositionUnavailableError,
    type RegistryStore,
} from "../registry/RegistryStore.ts";

const SOURCE = "eip155:84532/0x1111111111111111111111111111111111111111";
const ACCOUNT = hex32("a");
const DEVICE_ONE = hex32("1");
const DEVICE_TWO = hex32("2");
const HOMESERVER = hex32("b");
const NAME_HASH = hex32("c");
const RECOVERY = hex32("0");
const SERVER_KEY = hex32("d");

describe("RegistryStore", () => {
    let database: Database;
    let store: RegistryStore;

    beforeEach(async () => {
        database = new Database({ dbType: "sqlite3mem" });
        await ready(database);
        store = database.createRegistryStore(SOURCE);
    });

    afterEach(async () => {
        await database.close();
    });

    it("resolves an atomic identity snapshot from replayed events", async () => {
        await store.applyBatch(
            [
                {
                    endpoint: "https://one.example",
                    epoch: "1",
                    homeserverId: HOMESERVER,
                    signingKey: SERVER_KEY,
                    type: "homeserver-registered",
                },
                {
                    accountId: ACCOUNT,
                    epoch: "1",
                    genesisDeviceKey: DEVICE_ONE,
                    homeserverId: HOMESERVER,
                    recoveryCommitment: RECOVERY,
                    type: "account-registered",
                },
                {
                    accountId: ACCOUNT,
                    deviceKey: DEVICE_ONE,
                    epoch: "1",
                    type: "device-added",
                },
                {
                    accountId: ACCOUNT,
                    nameHash: NAME_HASH,
                    type: "username-registered",
                    username: "computer",
                },
            ],
            position("10", hex32("e")),
        );

        const identity = await store.resolveIdentity(ACCOUNT);
        expect(identity).toMatchObject({
            account: {
                accountId: ACCOUNT,
                activeDeviceCount: 1,
                deviceThreshold: 1,
                epoch: "1",
                homeserverId: HOMESERVER,
                nonce: "0",
            },
            devices: [{ active: true, deviceKey: DEVICE_ONE }],
            homeserver: {
                endpoint: "https://one.example",
                signingKey: SERVER_KEY,
            },
            position: position("10", hex32("e")),
            username: { accountId: ACCOUNT, username: "computer" },
        });
    });

    it("rejects homeserver endpoints that are not bare HTTPS origins", async () => {
        await store.applyBatch(
            [
                {
                    endpoint: "https://one.example/federation",
                    epoch: "1",
                    homeserverId: HOMESERVER,
                    signingKey: SERVER_KEY,
                    type: "homeserver-registered",
                },
            ],
            position("1", hex32("e")),
        );

        await expect(store.resolveHomeserver(HOMESERVER)).rejects.toThrow(
            "bare HTTPS origin",
        );
    });

    it("tracks active devices and permanent revocation tombstones", async () => {
        await seedIdentity(store);
        await store.applyBatch(
            [
                {
                    accountId: ACCOUNT,
                    deviceKey: DEVICE_TWO,
                    epoch: "2",
                    type: "device-added",
                },
                {
                    accountId: ACCOUNT,
                    deviceKey: DEVICE_ONE,
                    epoch: "3",
                    type: "device-revoked",
                },
            ],
            position("11", hex32("f")),
        );

        const identity = await store.resolveIdentity(ACCOUNT);
        expect(identity?.account.activeDeviceCount).toBe(1);
        expect(identity?.devices.map((device) => device.deviceKey)).toEqual([
            DEVICE_TWO,
        ]);

        const revoked = await store.resolveDevice(ACCOUNT, DEVICE_ONE);
        expect(revoked?.record).toMatchObject({
            active: false,
            revokedAtEpoch: "3",
        });
    });

    it("enforces checkpoints, minimum positions, and rebuilds", async () => {
        await seedIdentity(store);

        await expect(
            store.resolveAccount(ACCOUNT, { minimumSequence: "11" }),
        ).rejects.toBeInstanceOf(RegistryPositionUnavailableError);
        await expect(
            store.applyBatch([], position("10", hex32("f"))),
        ).rejects.toBeInstanceOf(RegistryCheckpointMismatchError);

        await store.reset();
        expect(await store.currentPosition()).toBeNull();
        await seedIdentity(store);
        expect((await store.resolveAccount(ACCOUNT))?.record.accountId).toBe(
            ACCOUNT,
        );
    });

    it("fails resolver reads closed when finalized sync is stale", async () => {
        await seedIdentity(store);
        store.setAvailabilityCheck(() => false);

        await expect(store.resolveIdentity(ACCOUNT)).rejects.toBeInstanceOf(
            RegistryCacheUnavailableError,
        );
        await expect(
            store.resolveHomeserver(HOMESERVER),
        ).rejects.toBeInstanceOf(RegistryCacheUnavailableError);
        await expect(store.currentPosition()).resolves.toEqual(
            position("10", hex32("e")),
        );
    });
});

function hex32(character: string): string {
    return `0x${character.repeat(64)}`;
}

function position(sequence: string, checkpoint: string) {
    return { checkpoint, sequence, source: SOURCE };
}

async function ready(database: Database): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        database.once("ready", resolve);
        database.once("error", reject);
    });
}

async function seedIdentity(store: RegistryStore): Promise<void> {
    await store.applyBatch(
        [
            {
                endpoint: "https://one.example",
                epoch: "1",
                homeserverId: HOMESERVER,
                signingKey: SERVER_KEY,
                type: "homeserver-registered",
            },
            {
                accountId: ACCOUNT,
                epoch: "1",
                genesisDeviceKey: DEVICE_ONE,
                homeserverId: HOMESERVER,
                recoveryCommitment: RECOVERY,
                type: "account-registered",
            },
            {
                accountId: ACCOUNT,
                deviceKey: DEVICE_ONE,
                epoch: "1",
                type: "device-added",
            },
        ],
        position("10", hex32("e")),
    );
}

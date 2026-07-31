/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Database } from "../Database.ts";

describe("federation replay cache", () => {
    let database: Database;

    beforeEach(async () => {
        database = new Database({ dbType: "sqlite3mem" });
        await ready(database);
    });

    afterEach(async () => {
        await database.close();
    });

    it("atomically consumes a nonce once and permits it after expiry", async () => {
        const origin = `0x${"1".repeat(64)}`;
        const nonce = `0x${"2".repeat(64)}`;

        const first = await database.consumeFederationNonce(
            origin,
            nonce,
            2_000,
            1_000,
        );
        const replay = await database.consumeFederationNonce(
            origin,
            nonce,
            2_000,
            1_001,
        );
        const afterExpiry = await database.consumeFederationNonce(
            origin,
            nonce,
            3_000,
            2_001,
        );

        expect(first).toBe(true);
        expect(replay).toBe(false);
        expect(afterExpiry).toBe(true);
    });
});

async function ready(database: Database): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        database.once("ready", resolve);
        database.once("error", reject);
    });
}

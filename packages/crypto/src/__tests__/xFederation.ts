/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { describe, expect, it } from "vitest";

import { xFederationMigrationAuthorizationDigest } from "../index.ts";

describe("federation migration authorization", () => {
    it("binds account, route, device, expiry, and nonce", () => {
        const input = {
            accountId: hex32("1"),
            destinationHomeserverId: hex32("3"),
            deviceKey: hex32("4"),
            expiresAt: 1_900_000_000_000,
            nonce: hex32("5"),
            sourceHomeserverId: hex32("2"),
        };
        const digest = xFederationMigrationAuthorizationDigest(input);

        expect(digest).toHaveLength(32);
        expect(
            xFederationMigrationAuthorizationDigest({
                ...input,
                destinationHomeserverId: hex32("6"),
            }),
        ).not.toEqual(digest);
    });
});

function hex32(character: string): string {
    return `0x${character.repeat(64)}`;
}

/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { DeviceSchema } from "@vex-chat/types";

import { describe, expect, it } from "vitest";

import { publicPeerDevice } from "../server/publicDevice.ts";

describe("publicPeerDevice", () => {
    it("preserves the client codec without exposing private metadata", () => {
        const device = publicPeerDevice({
            deviceID: "f9fe82c2-74ec-4c00-bad3-924f106de228",
            owner: `0x${"a".repeat(64)}`,
            signKey: "B".repeat(64),
        });

        expect(DeviceSchema.parse(device)).toEqual({
            deleted: false,
            deviceID: "f9fe82c2-74ec-4c00-bad3-924f106de228",
            lastLogin: "1970-01-01T00:00:00.000Z",
            name: "Device",
            owner: `0x${"a".repeat(64)}`,
            signKey: "b".repeat(64),
        });
    });
});

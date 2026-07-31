/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Device } from "@vex-chat/types";

/** Preserve the legacy client shape without exposing private device metadata. */
export function publicPeerDevice(
    device: Pick<Device, "deviceID" | "owner" | "signKey">,
): Device {
    return {
        deleted: false,
        deviceID: device.deviceID,
        lastLogin: new Date(0).toISOString(),
        name: "Device",
        owner: device.owner,
        signKey: device.signKey.toLowerCase(),
    };
}

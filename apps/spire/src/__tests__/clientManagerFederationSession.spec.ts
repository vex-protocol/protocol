/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Device } from "@vex-chat/types";

import { describe, expect, it, vi } from "vitest";

import { ClientManager } from "../ClientManager.ts";

interface ManagerHarness {
    authed: boolean;
    device: Device;
    fail: ReturnType<typeof vi.fn>;
    federation: {
        authorizeLocalSession: ReturnType<typeof vi.fn>;
    };
    lastFederationAuthorizationAt: number;
    reauthorizeFederatedSession: (now: number) => Promise<boolean>;
    sendAuthError: ReturnType<typeof vi.fn>;
    user: { userID: string };
}

function createManagerHarness(
    authorizeLocalSession: ReturnType<typeof vi.fn>,
): ManagerHarness {
    const manager = Object.create(
        ClientManager.prototype,
    ) as unknown as ManagerHarness;
    manager.authed = true;
    manager.device = {
        deleted: false,
        deviceID: "device-a",
        lastLogin: new Date(0).toISOString(),
        name: "Desktop",
        owner: "account-a",
        signKey: "11".repeat(32),
    };
    manager.fail = vi.fn();
    manager.federation = { authorizeLocalSession };
    manager.lastFederationAuthorizationAt = 0;
    manager.sendAuthError = vi.fn();
    manager.user = { userID: "account-a" };
    return manager;
}

describe("ClientManager federation session authorization", () => {
    it("periodically reauthorizes an active device", async () => {
        const authorizeLocalSession = vi.fn(() => Promise.resolve(true));
        const manager = createManagerHarness(authorizeLocalSession);

        await expect(manager.reauthorizeFederatedSession(60_000)).resolves.toBe(
            true,
        );

        expect(authorizeLocalSession).toHaveBeenCalledWith(
            "account-a",
            manager.device,
        );
        expect(manager.lastFederationAuthorizationAt).toBe(60_000);
        expect(manager.fail).not.toHaveBeenCalled();
    });

    it.each([
        ["revoked", vi.fn(() => Promise.resolve(false))],
        [
            "registry unavailable",
            vi.fn(() => Promise.reject(new Error("stale"))),
        ],
    ])("closes a %s federated session", async (_reason, authorize) => {
        const manager = createManagerHarness(authorize);

        await expect(manager.reauthorizeFederatedSession(60_000)).resolves.toBe(
            false,
        );

        expect(manager.sendAuthError).toHaveBeenCalledOnce();
        expect(manager.fail).toHaveBeenCalledOnce();
    });
});

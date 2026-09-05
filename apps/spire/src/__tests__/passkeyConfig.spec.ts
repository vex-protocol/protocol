/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
    getPasskeyRpConfig,
    sanitizePasskeyTransports,
} from "../server/passkeyConfig.ts";

afterEach(() => {
    vi.unstubAllEnvs();
});

describe("getPasskeyRpConfig", () => {
    it("normalizes and deduplicates configured origins", () => {
        vi.stubEnv("SPIRE_PASSKEY_RP_ID", " example.com ");
        vi.stubEnv("SPIRE_PASSKEY_RP_NAME", " Example ");
        vi.stubEnv(
            "SPIRE_PASSKEY_ORIGINS",
            "https://example.com, https://example.com, https://login.example.com ",
        );

        expect(getPasskeyRpConfig()).toEqual({
            expectedOrigin: [
                "https://example.com",
                "https://login.example.com",
            ],
            rpID: "example.com",
            rpName: "Example",
        });
    });

    it("rejects missing relying-party configuration", () => {
        vi.stubEnv("SPIRE_PASSKEY_RP_ID", "");
        vi.stubEnv("SPIRE_PASSKEY_ORIGINS", "https://example.com");

        expect(() => getPasskeyRpConfig()).toThrow(
            "SPIRE_PASSKEY_RP_ID is unset",
        );
    });
});

describe("sanitizePasskeyTransports", () => {
    it("retains known transports and removes unknown values", () => {
        expect(
            sanitizePasskeyTransports(["internal", "future-transport", "usb"]),
        ).toEqual(["internal", "usb"]);
    });
});

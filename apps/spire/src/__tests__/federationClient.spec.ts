/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { describe, expect, it } from "vitest";

import { federationEndpoint } from "../federation/FederationClient.ts";

describe("federationEndpoint", () => {
    it.each([
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        "https://[fc00::1]",
    ])("rejects a non-public literal address: %s", (endpoint) => {
        expect(() => federationEndpoint(endpoint)).toThrow("non-public");
    });

    it("allows a private literal only with the development override", () => {
        expect(federationEndpoint("https://127.0.0.1:8443", true).origin).toBe(
            "https://127.0.0.1:8443",
        );
    });

    it.each([
        "https://federation.example",
        "https://8.8.8.8",
        "https://[2606:4700:4700::1111]",
    ])("accepts a bare public HTTPS origin: %s", (endpoint) => {
        expect(federationEndpoint(endpoint).origin).toBe(endpoint);
    });
});

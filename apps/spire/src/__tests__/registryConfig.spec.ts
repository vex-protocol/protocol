/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { describe, expect, it } from "vitest";

import { evmRegistryOptionsFromEnv } from "../registry/config.ts";

const REGISTRY = "0x1111111111111111111111111111111111111111";
const HOMESERVER = `0x${"2".repeat(64)}`;

describe("evmRegistryOptionsFromEnv", () => {
    it("leaves the registry disabled unless explicitly enabled", () => {
        expect(evmRegistryOptionsFromEnv({})).toBeNull();
        expect(
            evmRegistryOptionsFromEnv({ SPIRE_REGISTRY_ENABLED: "false" }),
        ).toBeNull();
    });

    it("parses a finalized multi-provider configuration", () => {
        expect(
            evmRegistryOptionsFromEnv({
                SPIRE_HOMESERVER_ID: HOMESERVER,
                SPIRE_REGISTRY_CHAIN_ID: "84532",
                SPIRE_REGISTRY_CONTRACT: REGISTRY,
                SPIRE_REGISTRY_DEPLOYMENT_BLOCK: "1234",
                SPIRE_REGISTRY_ENABLED: "true",
                SPIRE_REGISTRY_RPC_URLS:
                    "https://one.example/rpc, https://two.example/rpc",
            }),
        ).toEqual({
            allowPrivateFederationAddresses: false,
            chainId: 84_532,
            deploymentBlock: 1234n,
            finality: "finalized",
            homeserverId: HOMESERVER,
            registryAddress: REGISTRY,
            rpcUrls: ["https://one.example/rpc", "https://two.example/rpc"],
        });
    });

    it("supports an explicit confirmation policy for development chains", () => {
        const options = evmRegistryOptionsFromEnv({
            SPIRE_HOMESERVER_ID: HOMESERVER,
            SPIRE_REGISTRY_CHAIN_ID: "31337",
            SPIRE_REGISTRY_CONTRACT: REGISTRY,
            SPIRE_REGISTRY_DEPLOYMENT_BLOCK: "0",
            SPIRE_REGISTRY_ENABLED: "true",
            SPIRE_REGISTRY_FINALITY: "confirmations:2",
            SPIRE_REGISTRY_MAX_STALENESS_MS: "30000",
            SPIRE_REGISTRY_RPC_URLS: "http://127.0.0.1:8545",
        });
        expect(options?.finality).toEqual({ confirmations: 2 });
        expect(options?.maximumStalenessMs).toBe(30_000);
    });

    it("rejects incomplete or insecure enabled configurations", () => {
        expect(() =>
            evmRegistryOptionsFromEnv({ SPIRE_REGISTRY_ENABLED: "true" }),
        ).toThrow("SPIRE_REGISTRY_CHAIN_ID is required");
        expect(() =>
            evmRegistryOptionsFromEnv({
                SPIRE_HOMESERVER_ID: HOMESERVER,
                SPIRE_REGISTRY_CHAIN_ID: "84532",
                SPIRE_REGISTRY_CONTRACT: REGISTRY,
                SPIRE_REGISTRY_DEPLOYMENT_BLOCK: "1",
                SPIRE_REGISTRY_ENABLED: "true",
                SPIRE_REGISTRY_RPC_URLS: "http://rpc.example",
            }),
        ).toThrow("must use HTTPS");
        expect(() =>
            evmRegistryOptionsFromEnv({
                SPIRE_HOMESERVER_ID: "not-a-homeserver-id",
                SPIRE_REGISTRY_CHAIN_ID: "84532",
                SPIRE_REGISTRY_CONTRACT: REGISTRY,
                SPIRE_REGISTRY_DEPLOYMENT_BLOCK: "1",
                SPIRE_REGISTRY_ENABLED: "true",
                SPIRE_REGISTRY_RPC_URLS: "https://rpc.example",
            }),
        ).toThrow("SPIRE_HOMESERVER_ID must be a 32-byte");
        expect(() =>
            evmRegistryOptionsFromEnv({
                SPIRE_HOMESERVER_ID: HOMESERVER,
                SPIRE_REGISTRY_CHAIN_ID: "84532",
                SPIRE_REGISTRY_CONTRACT: REGISTRY,
                SPIRE_REGISTRY_DEPLOYMENT_BLOCK: "1",
                SPIRE_REGISTRY_ENABLED: "true",
                SPIRE_REGISTRY_MAX_STALENESS_MS: "999",
                SPIRE_REGISTRY_RPC_URLS: "https://rpc.example",
            }),
        ).toThrow("SPIRE_REGISTRY_MAX_STALENESS_MS must be at least 1000");
    });
});

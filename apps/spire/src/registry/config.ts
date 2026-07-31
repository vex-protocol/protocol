/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { EvmRegistryIndexerOptions } from "./EvmRegistryIndexer.ts";
import type { Address } from "viem";

import { isAddress } from "viem";

export interface SpireIdentityRegistryOptions extends EvmRegistryIndexerOptions {
    allowPrivateFederationAddresses: boolean;
    homeserverId: string;
}

export const REGISTRY_ENV_VARS = [
    "SPIRE_FEDERATION_ALLOW_PRIVATE_ADDRESSES",
    "SPIRE_HOMESERVER_ID",
    "SPIRE_REGISTRY_ENABLED",
    "SPIRE_REGISTRY_CHAIN_ID",
    "SPIRE_REGISTRY_CONTRACT",
    "SPIRE_REGISTRY_DEPLOYMENT_BLOCK",
    "SPIRE_REGISTRY_FINALITY",
    "SPIRE_REGISTRY_MAX_BLOCK_RANGE",
    "SPIRE_REGISTRY_MAX_STALENESS_MS",
    "SPIRE_REGISTRY_POLL_INTERVAL_MS",
    "SPIRE_REGISTRY_RPC_URLS",
    "SPIRE_REGISTRAR_CONTRACT",
] as const;

export function evmRegistryOptionsFromEnv(
    env: Record<string, string | undefined>,
): null | SpireIdentityRegistryOptions {
    const enabled = parseEnabled(env["SPIRE_REGISTRY_ENABLED"]);
    if (!enabled) return null;

    const chainId = parsePositiveNumber(
        required(env, "SPIRE_REGISTRY_CHAIN_ID"),
        "SPIRE_REGISTRY_CHAIN_ID",
    );
    const deploymentBlock = parseNonNegativeBigInt(
        required(env, "SPIRE_REGISTRY_DEPLOYMENT_BLOCK"),
        "SPIRE_REGISTRY_DEPLOYMENT_BLOCK",
    );
    const registryAddress = parseAddress(
        required(env, "SPIRE_REGISTRY_CONTRACT"),
        "SPIRE_REGISTRY_CONTRACT",
    );
    const rpcUrls = required(env, "SPIRE_REGISTRY_RPC_URLS")
        .split(",")
        .map((value) => value.trim())
        .filter((value) => value.length > 0);
    if (rpcUrls.length === 0) {
        throw new Error(
            "SPIRE_REGISTRY_RPC_URLS must contain at least one URL.",
        );
    }
    for (const rpcUrl of rpcUrls) validateRpcUrl(rpcUrl);

    const registrarRaw = env["SPIRE_REGISTRAR_CONTRACT"]?.trim();
    const maximumBlockRangeRaw = env["SPIRE_REGISTRY_MAX_BLOCK_RANGE"]?.trim();
    const maximumStalenessRaw = env["SPIRE_REGISTRY_MAX_STALENESS_MS"]?.trim();
    const pollIntervalRaw = env["SPIRE_REGISTRY_POLL_INTERVAL_MS"]?.trim();

    return {
        allowPrivateFederationAddresses: parseBoolean(
            env["SPIRE_FEDERATION_ALLOW_PRIVATE_ADDRESSES"],
            "SPIRE_FEDERATION_ALLOW_PRIVATE_ADDRESSES",
        ),
        chainId,
        deploymentBlock,
        finality: parseFinality(env["SPIRE_REGISTRY_FINALITY"]),
        homeserverId: parseBytes32(
            required(env, "SPIRE_HOMESERVER_ID"),
            "SPIRE_HOMESERVER_ID",
        ),
        ...(maximumBlockRangeRaw
            ? {
                  maximumBlockRange: parsePositiveBigInt(
                      maximumBlockRangeRaw,
                      "SPIRE_REGISTRY_MAX_BLOCK_RANGE",
                  ),
              }
            : {}),
        ...(maximumStalenessRaw
            ? {
                  maximumStalenessMs: parseNumberAtLeast(
                      maximumStalenessRaw,
                      "SPIRE_REGISTRY_MAX_STALENESS_MS",
                      1_000,
                  ),
              }
            : {}),
        ...(pollIntervalRaw
            ? {
                  pollIntervalMs: parseNumberAtLeast(
                      pollIntervalRaw,
                      "SPIRE_REGISTRY_POLL_INTERVAL_MS",
                      1_000,
                  ),
              }
            : {}),
        ...(registrarRaw
            ? {
                  registrarAddress: parseAddress(
                      registrarRaw,
                      "SPIRE_REGISTRAR_CONTRACT",
                  ),
              }
            : {}),
        registryAddress,
        rpcUrls,
    };
}

function parseAddress(value: string, name: string): Address {
    if (!isAddress(value, { strict: true })) {
        throw new Error(`${name} must be a 20-byte 0x-prefixed EVM address.`);
    }
    return value;
}

function parseBoolean(value: string | undefined, name: string): boolean {
    const normalized = value?.trim().toLowerCase();
    if (
        normalized === undefined ||
        normalized === "" ||
        normalized === "false"
    ) {
        return false;
    }
    if (normalized === "true") return true;
    throw new Error(`${name} must be true or false.`);
}

function parseBytes32(value: string, name: string): string {
    const normalized = value.toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
        throw new Error(`${name} must be a 32-byte 0x-prefixed hex value.`);
    }
    return normalized;
}

function parseEnabled(value: string | undefined): boolean {
    const normalized = value?.trim().toLowerCase();
    if (
        normalized === undefined ||
        normalized === "" ||
        normalized === "false"
    ) {
        return false;
    }
    if (normalized === "true") return true;
    throw new Error("SPIRE_REGISTRY_ENABLED must be true or false.");
}

function parseFinality(
    value: string | undefined,
): "finalized" | { confirmations: number } {
    const normalized = value?.trim().toLowerCase() ?? "finalized";
    if (normalized === "finalized") return "finalized";
    const match = /^confirmations:([1-9][0-9]*)$/.exec(normalized);
    if (!match?.[1]) {
        throw new Error(
            "SPIRE_REGISTRY_FINALITY must be finalized or confirmations:<count>.",
        );
    }
    return {
        confirmations: parsePositiveNumber(
            match[1],
            "SPIRE_REGISTRY_FINALITY confirmations",
        ),
    };
}

function parseNonNegativeBigInt(value: string, name: string): bigint {
    if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
        throw new Error(`${name} must be a non-negative decimal integer.`);
    }
    return BigInt(value);
}

function parseNumberAtLeast(
    value: string,
    name: string,
    minimum: number,
): number {
    const parsed = parsePositiveNumber(value, name);
    if (parsed < minimum) {
        throw new Error(`${name} must be at least ${String(minimum)}.`);
    }
    return parsed;
}

function parsePositiveBigInt(value: string, name: string): bigint {
    const parsed = parseNonNegativeBigInt(value, name);
    if (parsed === 0n) throw new Error(`${name} must be positive.`);
    return parsed;
}

function parsePositiveNumber(value: string, name: string): number {
    if (!/^[1-9][0-9]*$/.test(value)) {
        throw new Error(`${name} must be a positive decimal integer.`);
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) {
        throw new Error(`${name} exceeds the JavaScript safe integer range.`);
    }
    return parsed;
}

function required(
    env: Record<string, string | undefined>,
    name: string,
): string {
    const value = env[name]?.trim();
    if (!value)
        throw new Error(`${name} is required when the registry is enabled.`);
    return value;
}

function validateRpcUrl(value: string): void {
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new Error("SPIRE_REGISTRY_RPC_URLS contains an invalid URL.");
    }
    const local = url.hostname === "127.0.0.1" || url.hostname === "localhost";
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
        throw new Error(
            "SPIRE_REGISTRY_RPC_URLS must use HTTPS unless the RPC is local.",
        );
    }
    if (url.username || url.password) {
        throw new Error(
            "SPIRE_REGISTRY_RPC_URLS cannot embed basic-auth credentials.",
        );
    }
}

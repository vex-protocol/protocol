/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { z } from "zod/v4";

/** Read-only boundary between Vex protocol behavior and an identity registry. */
export interface IdentityResolver {
    resolveAccount(
        accountId: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryAccount>>;
    resolveDevice(
        accountId: string,
        deviceKey: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryDevice>>;
    resolveHomeserver(
        homeserverId: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryHomeserver>>;
    resolveIdentity(
        accountId: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryIdentityResolution>;
    resolveUsername(
        username: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryUsername>>;
    readonly source: string;
}

/** Stable account state resolved from a finalized identity registry position. */
export interface RegistryAccount {
    accountId: string;
    activeDeviceCount: number;
    deviceThreshold: number;
    epoch: string;
    homeserverId: string;
    nonce: string;
    recoveryCommitment: string;
}

/** Device-authority state resolved from an identity registry. */
export interface RegistryDevice {
    accountId: string;
    active: boolean;
    addedAtEpoch: string;
    deviceKey: string;
    keyAlgorithm: "Ed25519";
    revokedAtEpoch: null | string;
}

/** Current homeserver routing and federation-signing state. */
export interface RegistryHomeserver {
    active: boolean;
    endpoint: string;
    epoch: string;
    homeserverId: string;
    keyAlgorithm: "Ed25519";
    nonce: string;
    signingKey: string;
}

/** Account, device, routing, and optional username state at one position. */
export interface RegistryIdentityResolution {
    account: RegistryAccount;
    devices: RegistryDevice[];
    homeserver: RegistryHomeserver;
    position: RegistryPosition;
    username: null | RegistryUsername;
}

/** Opaque, finalized position in a chain-neutral registry source. */
export interface RegistryPosition {
    checkpoint: string;
    sequence: string;
    source: string;
}

/** A single registry record paired with the finalized position it came from. */
export interface RegistryResolution<T> {
    position: RegistryPosition;
    record: T;
}

/** Optional consistency requirement supplied to an identity resolver. */
export interface RegistryResolveOptions {
    minimumSequence?: string | undefined;
}

/** Paid human-readable alias for a stable account ID. */
export interface RegistryUsername {
    accountId: string;
    nameHash: string;
    username: string;
}

const decimalInteger = z
    .string()
    .max(78)
    .regex(/^(?:0|[1-9][0-9]*)$/)
    .describe("Non-negative decimal integer");

const bareHttpsOrigin = /^https:\/\/[^/?#@]+\/?$/;

/** Canonical lowercase 0x-prefixed 32-byte value. */
export const RegistryBytes32Schema: z.ZodType<string> = z
    .string()
    .regex(/^0x[0-9a-f]{64}$/)
    .describe("Canonical lowercase 32-byte hex value");

/** Finalized source position used for cache consistency and reorg handling. */
export const RegistryPositionSchema: z.ZodType<RegistryPosition> = z
    .object({
        checkpoint: z
            .string()
            .min(1)
            .max(255)
            .describe("Source-specific immutable checkpoint identifier"),
        sequence: decimalInteger.describe(
            "Source-specific monotonically increasing position",
        ),
        source: z
            .string()
            .min(1)
            .max(255)
            .describe("Registry source identifier"),
    })
    .strict()
    .describe("Finalized identity registry position");

/** Stable account registry state. */
export const RegistryAccountSchema: z.ZodType<RegistryAccount> = z
    .object({
        accountId: RegistryBytes32Schema,
        activeDeviceCount: z.number().int().min(1).max(20),
        deviceThreshold: z.number().int().min(1).max(20),
        epoch: decimalInteger,
        homeserverId: RegistryBytes32Schema,
        nonce: decimalInteger,
        recoveryCommitment: RegistryBytes32Schema,
    })
    .strict()
    .refine(
        (account) => account.deviceThreshold <= account.activeDeviceCount,
        "Device threshold cannot exceed the active device count",
    )
    .describe("Stable Vex account registry state");

/** Device-authority registry state. */
export const RegistryDeviceSchema: z.ZodType<RegistryDevice> = z
    .object({
        accountId: RegistryBytes32Schema,
        active: z.boolean(),
        addedAtEpoch: decimalInteger,
        deviceKey: RegistryBytes32Schema,
        keyAlgorithm: z.literal("Ed25519"),
        revokedAtEpoch: decimalInteger.nullable(),
    })
    .strict()
    .refine(
        (device) => device.active === (device.revokedAtEpoch === null),
        "Active devices cannot have a revocation epoch",
    )
    .describe("Vex device-authority registry state");

/** Homeserver registry and federation routing state. */
export const RegistryHomeserverSchema: z.ZodType<RegistryHomeserver> = z
    .object({
        active: z.boolean(),
        endpoint: z
            .url()
            .refine(
                (value) => bareHttpsOrigin.test(value),
                "Federation endpoint must be a bare HTTPS origin",
            ),
        epoch: decimalInteger,
        homeserverId: RegistryBytes32Schema,
        keyAlgorithm: z.literal("Ed25519"),
        nonce: decimalInteger,
        signingKey: RegistryBytes32Schema,
    })
    .strict()
    .describe("Vex homeserver registry state");

/** Paid username registry state. */
export const RegistryUsernameSchema: z.ZodType<RegistryUsername> = z
    .object({
        accountId: RegistryBytes32Schema,
        nameHash: RegistryBytes32Schema,
        username: z.string().regex(/^[a-z0-9_]{3,19}$/),
    })
    .strict()
    .describe("Paid Vex username registry state");

/** Atomically resolved identity and homeserver routing snapshot. */
export const RegistryIdentityResolutionSchema: z.ZodType<RegistryIdentityResolution> =
    z
        .object({
            account: RegistryAccountSchema,
            devices: z.array(RegistryDeviceSchema).min(1).max(20),
            homeserver: RegistryHomeserverSchema,
            position: RegistryPositionSchema,
            username: RegistryUsernameSchema.nullable(),
        })
        .strict()
        .refine(
            (identity) =>
                identity.account.homeserverId ===
                identity.homeserver.homeserverId,
            "Resolved homeserver does not match the account route",
        )
        .refine(
            (identity) =>
                identity.devices.every(
                    (device) => device.accountId === identity.account.accountId,
                ),
            "Resolved device belongs to another account",
        )
        .refine(
            (identity) =>
                identity.devices.length === identity.account.activeDeviceCount,
            "Resolved active-device count does not match the account",
        )
        .refine(
            (identity) => identity.devices.every((device) => device.active),
            "Resolved identity contains an inactive device",
        )
        .refine(
            (identity) =>
                new Set(identity.devices.map((device) => device.deviceKey))
                    .size === identity.devices.length,
            "Resolved identity contains duplicate devices",
        )
        .refine(
            (identity) =>
                identity.username === null ||
                identity.username.accountId === identity.account.accountId,
            "Resolved username belongs to another account",
        )
        .describe("Atomic finalized Vex identity resolution");

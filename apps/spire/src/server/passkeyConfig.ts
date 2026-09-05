/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { AuthenticatorTransportFuture } from "@simplewebauthn/server";

import { AppError } from "./errors.ts";
import { buildAndroidApkKeyHashOrigins } from "./wellKnown.ts";

const KNOWN_TRANSPORTS: ReadonlySet<string> = new Set([
    "ble",
    "cable",
    "hybrid",
    "internal",
    "nfc",
    "smart-card",
    "usb",
] satisfies readonly AuthenticatorTransportFuture[]);

/**
 * Read and validate the WebAuthn relying-party configuration.
 *
 * Android APK-hash origins advertised by the server are included alongside
 * the explicit web-origin allowlist because Android Credential Manager uses
 * the application certificate rather than the RP host as its origin.
 */
export function getPasskeyRpConfig(): {
    expectedOrigin: string[];
    rpID: string;
    rpName: string;
} {
    const rpID = process.env["SPIRE_PASSKEY_RP_ID"]?.trim();
    const originsRaw = process.env["SPIRE_PASSKEY_ORIGINS"]?.trim();
    if (!rpID) {
        throw new AppError(
            500,
            "Passkeys are not configured on this server (SPIRE_PASSKEY_RP_ID is unset).",
        );
    }
    if (!originsRaw) {
        throw new AppError(
            500,
            "Passkeys are not configured on this server (SPIRE_PASSKEY_ORIGINS is unset).",
        );
    }

    const explicitOrigins = originsRaw
        .split(",")
        .map((origin) => origin.trim())
        .filter(Boolean);
    if (explicitOrigins.length === 0) {
        throw new AppError(500, "SPIRE_PASSKEY_ORIGINS is empty.");
    }

    return {
        expectedOrigin: [
            ...new Set([
                ...explicitOrigins,
                ...buildAndroidApkKeyHashOrigins(),
            ]),
        ],
        rpID,
        rpName: process.env["SPIRE_PASSKEY_RP_NAME"]?.trim() || "Vex",
    };
}

/** Remove transport values not understood by SimpleWebAuthn. */
export function sanitizePasskeyTransports(
    input: readonly string[],
): AuthenticatorTransportFuture[] {
    return input.filter(
        (transport): transport is AuthenticatorTransportFuture =>
            KNOWN_TRANSPORTS.has(transport),
    );
}

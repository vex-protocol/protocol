/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { FederationMigrationAuthorizationInput } from "@vex-chat/types";

import { sha256 } from "@noble/hashes/sha2.js";

const encoder = new TextEncoder();

/** Canonical device-signed consent for moving an account between homeservers. */
export function xFederationMigrationAuthorizationDigest(
    input: FederationMigrationAuthorizationInput,
): Uint8Array {
    validateBytes32(input.accountId, "account ID");
    validateBytes32(input.sourceHomeserverId, "source homeserver ID");
    validateBytes32(input.destinationHomeserverId, "destination homeserver ID");
    validateBytes32(input.deviceKey, "device key");
    validateBytes32(input.nonce, "nonce");
    if (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= 0) {
        throw new Error(
            "Migration expiration must be a positive safe integer.",
        );
    }
    return sha256(
        encoder.encode(
            [
                "vex:homeserver-migration:v1",
                `account:${input.accountId}`,
                `source:${input.sourceHomeserverId}`,
                `destination:${input.destinationHomeserverId}`,
                `device:${input.deviceKey}`,
                `expires:${String(input.expiresAt)}`,
                `nonce:${input.nonce}`,
            ].join("\n"),
        ),
    );
}

function validateBytes32(value: string, name: string): void {
    if (!/^0x[0-9a-f]{64}$/.test(value)) {
        throw new Error(`Migration ${name} must be a canonical bytes32 value.`);
    }
}

/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { FederationRoomMailAuthorization } from "@vex-chat/types";

import { createHash } from "node:crypto";

import { xSignDetached, xSignVerifyDetached, XUtils } from "@vex-chat/crypto";

export const FEDERATION_REQUEST_MAX_SKEW_MS = 5 * 60 * 1_000;
export const FEDERATION_REQUEST_NONCE_TTL_MS = 10 * 60 * 1_000;
export const FEDERATION_VERSION = "1";

export const FederationHeaders = {
    destination: "x-vex-federation-destination",
    nonce: "x-vex-federation-nonce",
    origin: "x-vex-federation-origin",
    requestNonce: "x-vex-federation-request-nonce",
    signature: "x-vex-federation-signature",
    timestamp: "x-vex-federation-timestamp",
    version: "x-vex-federation-version",
} as const;

export interface FederationRequestDigestInput {
    body: Uint8Array;
    destination: string;
    method: string;
    nonce: string;
    origin: string;
    path: string;
    timestamp: number;
}

export interface FederationResponseDigestInput {
    body: Uint8Array;
    destination: string;
    origin: string;
    requestNonce: string;
    status: number;
}

export type FederationRoomMailAuthorizationInput = Omit<
    FederationRoomMailAuthorization,
    "signature"
>;

export function createFederationRequestHeaders(
    input: FederationRequestDigestInput,
    secretKey: Uint8Array,
): Record<string, string> {
    const signature = xSignDetached(federationRequestDigest(input), secretKey);
    return {
        [FederationHeaders.destination]: input.destination,
        [FederationHeaders.nonce]: input.nonce,
        [FederationHeaders.origin]: input.origin,
        [FederationHeaders.signature]: XUtils.encodeHex(signature),
        [FederationHeaders.timestamp]: String(input.timestamp),
        [FederationHeaders.version]: FEDERATION_VERSION,
    };
}

export function createFederationResponseHeaders(
    input: FederationResponseDigestInput,
    secretKey: Uint8Array,
): Record<string, string> {
    const signature = xSignDetached(federationResponseDigest(input), secretKey);
    return {
        [FederationHeaders.destination]: input.destination,
        [FederationHeaders.origin]: input.origin,
        [FederationHeaders.requestNonce]: input.requestNonce,
        [FederationHeaders.signature]: XUtils.encodeHex(signature),
        [FederationHeaders.version]: FEDERATION_VERSION,
    };
}

export function createFederationRoomMailAuthorization(
    input: FederationRoomMailAuthorizationInput,
    secretKey: Uint8Array,
): FederationRoomMailAuthorization {
    return {
        ...input,
        signature: XUtils.encodeHex(
            xSignDetached(
                federationRoomMailAuthorizationDigest(input),
                secretKey,
            ),
        ),
    };
}

export function federationRequestDigest(
    input: FederationRequestDigestInput,
): Uint8Array {
    validateRequestInput(input);
    return digest([
        "vex:federation-request:v1",
        `origin:${input.origin}`,
        `destination:${input.destination}`,
        `timestamp:${String(input.timestamp)}`,
        `nonce:${input.nonce}`,
        `method:${input.method}`,
        `path:${input.path}`,
        `body-sha256:${sha256Hex(input.body)}`,
    ]);
}

export function federationResponseDigest(
    input: FederationResponseDigestInput,
): Uint8Array {
    validateIdentifier(input.origin, "origin");
    validateIdentifier(input.destination, "destination");
    validateNonce(input.requestNonce);
    if (
        !Number.isSafeInteger(input.status) ||
        input.status < 100 ||
        input.status > 599
    ) {
        throw new Error("Federation response status is invalid.");
    }
    return digest([
        "vex:federation-response:v1",
        `origin:${input.origin}`,
        `destination:${input.destination}`,
        `request-nonce:${input.requestNonce}`,
        `status:${String(input.status)}`,
        `body-sha256:${sha256Hex(input.body)}`,
    ]);
}

export function federationRoomMailAuthorizationDigest(
    input: FederationRoomMailAuthorizationInput,
): Uint8Array {
    validateIdentifier(input.originHomeserverId, "room origin");
    validateIdentifier(input.senderAccountId, "room sender");
    validateIdentifier(input.recipientAccountId, "room recipient");
    validateOpaqueIdentifier(input.serverId, "server ID");
    validateOpaqueIdentifier(input.channelId, "channel ID");
    if (
        !Number.isSafeInteger(input.expiresAt) ||
        input.expiresAt < 0 ||
        !/^(?:0|[1-9][0-9]*)$/.test(input.revision)
    ) {
        throw new Error("Federation room authorization state is invalid.");
    }
    return digest([
        "vex:federation-room-mail:v1",
        `origin:${input.originHomeserverId}`,
        `server:${input.serverId}`,
        `channel:${input.channelId}`,
        `revision:${input.revision}`,
        `sender:${input.senderAccountId}`,
        `recipient:${input.recipientAccountId}`,
        `expires:${String(input.expiresAt)}`,
    ]);
}

export function verifyFederationRequestSignature(
    input: FederationRequestDigestInput,
    signature: string,
    publicKey: string,
): boolean {
    return verify(federationRequestDigest(input), signature, publicKey);
}

export function verifyFederationResponseSignature(
    input: FederationResponseDigestInput,
    signature: string,
    publicKey: string,
): boolean {
    return verify(federationResponseDigest(input), signature, publicKey);
}

export function verifyFederationRoomMailAuthorization(
    authorization: FederationRoomMailAuthorization,
    publicKey: string,
): boolean {
    const { signature, ...input } = authorization;
    return verify(
        federationRoomMailAuthorizationDigest(input),
        signature,
        publicKey,
    );
}

function decodeHex(value: string, bytes: number): Uint8Array {
    const normalized = value.startsWith("0x") ? value.slice(2) : value;
    if (normalized.length !== bytes * 2 || !/^[0-9a-fA-F]+$/.test(normalized)) {
        throw new Error(`Expected ${String(bytes)} bytes of hexadecimal data.`);
    }
    return XUtils.decodeHex(normalized);
}

function digest(lines: readonly string[]): Uint8Array {
    return createHash("sha256").update(lines.join("\n"), "utf8").digest();
}

function sha256Hex(value: Uint8Array): string {
    return createHash("sha256").update(value).digest("hex");
}

function validateIdentifier(value: string, name: string): void {
    if (!/^0x[0-9a-f]{64}$/.test(value)) {
        throw new Error(
            `Federation ${name} must be a canonical bytes32 value.`,
        );
    }
}

function validateNonce(value: string): void {
    if (!/^0x[0-9a-f]{64}$/.test(value)) {
        throw new Error("Federation nonce must contain 32 random bytes.");
    }
}

function validateOpaqueIdentifier(value: string, name: string): void {
    if (
        value.length < 1 ||
        value.length > 255 ||
        /[\u0000-\u001f\u007f]/.test(value)
    ) {
        throw new Error(`Federation ${name} is invalid.`);
    }
}

function validateRequestInput(input: FederationRequestDigestInput): void {
    validateIdentifier(input.origin, "origin");
    validateIdentifier(input.destination, "destination");
    validateNonce(input.nonce);
    if (!Number.isSafeInteger(input.timestamp) || input.timestamp < 0) {
        throw new Error("Federation timestamp is invalid.");
    }
    if (!/^[A-Z]+$/.test(input.method)) {
        throw new Error("Federation method must be uppercase ASCII.");
    }
    if (
        !input.path.startsWith("/") ||
        /[\u0000-\u001f\u007f]/.test(input.path) ||
        input.path.includes("?") ||
        input.path.includes("#")
    ) {
        throw new Error(
            "Federation path must be an absolute path without a query.",
        );
    }
}

function verify(
    digestValue: Uint8Array,
    signature: string,
    publicKey: string,
): boolean {
    try {
        return xSignVerifyDetached(
            digestValue,
            decodeHex(signature, 64),
            decodeHex(publicKey, 32),
        );
    } catch {
        return false;
    }
}

/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { xSignKeyPair, XUtils } from "@vex-chat/crypto";
import {
    formatFederationInviteReference,
    parseFederationInviteReference,
} from "@vex-chat/types";

import { describe, expect, it } from "vitest";

import {
    createFederationRequestHeaders,
    createFederationResponseHeaders,
    createFederationRoomMailAuthorization,
    FederationHeaders,
    type FederationRequestDigestInput,
    verifyFederationRequestSignature,
    verifyFederationResponseSignature,
    verifyFederationRoomMailAuthorization,
} from "../federation/signatures.ts";

const ORIGIN = `0x${"1".repeat(64)}`;
const DESTINATION = `0x${"2".repeat(64)}`;
const NONCE = `0x${"3".repeat(64)}`;

describe("federation signatures", () => {
    it("round-trips portable invite references without embedding an endpoint", () => {
        const inviteId = "550e8400-e29b-41d4-a716-446655440000";
        const reference = formatFederationInviteReference(ORIGIN, inviteId);

        expect(reference).toBe(`v1.${"1".repeat(64)}.${inviteId}`);
        expect(parseFederationInviteReference(reference)).toEqual({
            homeserverId: ORIGIN,
            inviteId,
        });
        expect(parseFederationInviteReference(inviteId)).toEqual({
            homeserverId: null,
            inviteId,
        });
        expect(parseFederationInviteReference("v1.invalid")).toBeNull();
    });

    it("binds request signatures to routing, freshness, path, and body", () => {
        const keys = xSignKeyPair();
        const request: FederationRequestDigestInput = {
            body: new TextEncoder().encode("ciphertext"),
            destination: DESTINATION,
            method: "POST",
            nonce: NONCE,
            origin: ORIGIN,
            path: "/_vex/federation/v1/mail",
            timestamp: 1_700_000_000_000,
        };
        const headers = createFederationRequestHeaders(request, keys.secretKey);
        const signature = headers[FederationHeaders.signature];
        expect(signature).toBeDefined();
        expect(
            verifyFederationRequestSignature(
                request,
                signature ?? "",
                `0x${XUtils.encodeHex(keys.publicKey)}`,
            ),
        ).toBe(true);
        expect(
            verifyFederationRequestSignature(
                {
                    ...request,
                    body: new TextEncoder().encode("changed"),
                },
                signature ?? "",
                XUtils.encodeHex(keys.publicKey),
            ),
        ).toBe(false);
    });

    it("signs responses against the request nonce and status", () => {
        const keys = xSignKeyPair();
        const response = {
            body: new Uint8Array([1, 2, 3]),
            destination: ORIGIN,
            origin: DESTINATION,
            requestNonce: NONCE,
            status: 200,
        };
        const headers = createFederationResponseHeaders(
            response,
            keys.secretKey,
        );
        const signature = headers[FederationHeaders.signature] ?? "";
        expect(
            verifyFederationResponseSignature(
                response,
                signature,
                XUtils.encodeHex(keys.publicKey),
            ),
        ).toBe(true);
        expect(
            verifyFederationResponseSignature(
                { ...response, status: 201 },
                signature,
                XUtils.encodeHex(keys.publicKey),
            ),
        ).toBe(false);
    });

    it("rejects ambiguous canonical paths", () => {
        const keys = xSignKeyPair();
        expect(() =>
            createFederationRequestHeaders(
                {
                    body: new Uint8Array(),
                    destination: DESTINATION,
                    method: "POST",
                    nonce: NONCE,
                    origin: ORIGIN,
                    path: "/mail?next=/admin",
                    timestamp: Date.now(),
                },
                keys.secretKey,
            ),
        ).toThrow("without a query");
    });

    it("creates portable room membership authorizations", () => {
        const keys = xSignKeyPair();
        const authorization = createFederationRoomMailAuthorization(
            {
                channelId: "channel-id",
                expiresAt: 1_700_000_060_000,
                originHomeserverId: DESTINATION,
                recipientAccountId: `0x${"4".repeat(64)}`,
                revision: "7",
                senderAccountId: `0x${"5".repeat(64)}`,
                serverId: "server-id",
            },
            keys.secretKey,
        );
        expect(
            verifyFederationRoomMailAuthorization(
                authorization,
                XUtils.encodeHex(keys.publicKey),
            ),
        ).toBe(true);
        expect(
            verifyFederationRoomMailAuthorization(
                { ...authorization, revision: "8" },
                XUtils.encodeHex(keys.publicKey),
            ),
        ).toBe(false);
    });
});

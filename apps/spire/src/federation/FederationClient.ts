/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type {
    FederationAccountResult,
    FederationInvitePreview,
    FederationInviteRedeemResult,
    FederationKeyBundleResult,
    FederationMailEnvelope,
    FederationMailResult,
    FederationMigrationBlobResult,
    FederationMigrationCompleteResult,
    FederationMigrationFileQuery,
    FederationMigrationMailPage,
    FederationMigrationMailQuery,
    FederationMigrationManifest,
    FederationMigrationQuery,
    FederationRoomDeletion,
    FederationRoomInvitesQuery,
    FederationRoomMailAuthorization,
    FederationRoomMailAuthorizationQuery,
    FederationRoomMutation,
    FederationRoomMutationResult,
    FederationRoomPushResult,
    FederationRoomSnapshot,
    IdentityResolver,
    Invite,
    RegistryHomeserver,
} from "@vex-chat/types";
import type { LookupFunction } from "node:net";
import type { ZodType } from "zod/v4";

import { lookup } from "node:dns";
import { BlockList, isIP } from "node:net";

import { xRandomBytes, XUtils } from "@vex-chat/crypto";
import {
    FederationAccountResultSchema,
    FederationInvitePreviewSchema,
    FederationInviteRedeemResultSchema,
    FederationKeyBundleResultSchema,
    FederationMailResultSchema,
    FederationMigrationBlobResultSchema,
    FederationMigrationCompleteResultSchema,
    FederationMigrationMailPageSchema,
    FederationMigrationManifestSchema,
    FederationRoomInvitesResultSchema,
    FederationRoomMailAuthorizationSchema,
    FederationRoomMutationResultSchema,
    FederationRoomPushResultSchema,
    FederationRoomSnapshotSchema,
} from "@vex-chat/types";

import { Agent, request } from "undici";

import { msgpack } from "../utils/msgpack.ts";

import {
    createFederationRequestHeaders,
    FEDERATION_VERSION,
    FederationHeaders,
    verifyFederationResponseSignature,
} from "./signatures.ts";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ICON_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_ROOM_SNAPSHOT_RESPONSE_BYTES = 6 * 1024 * 1024;
const MAX_MIGRATION_MANIFEST_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_MIGRATION_BLOB_RESPONSE_BYTES = 25 * 1024 * 1024 + 4 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;

export interface FederationClientOptions {
    allowPrivateAddresses?: boolean | undefined;
    requestTimeoutMs?: number | undefined;
}

export class FederationClient {
    private readonly agent: Agent;
    private readonly allowPrivateAddresses: boolean;
    private readonly homeserverId: string;
    private readonly requestTimeoutMs: number;
    private readonly resolver: IdentityResolver;
    private readonly secretKey: Uint8Array;

    constructor(
        resolver: IdentityResolver,
        homeserverId: string,
        secretKey: Uint8Array,
        options: FederationClientOptions = {},
    ) {
        this.resolver = resolver;
        this.homeserverId = homeserverId;
        this.secretKey = new Uint8Array(secretKey);
        this.requestTimeoutMs = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
        if (
            !Number.isSafeInteger(this.requestTimeoutMs) ||
            this.requestTimeoutMs < 1_000 ||
            this.requestTimeoutMs > 60_000
        ) {
            throw new Error(
                "Federation request timeout must be between 1 and 60 seconds.",
            );
        }
        this.allowPrivateAddresses = options.allowPrivateAddresses ?? false;
        this.agent = new Agent({
            connect: {
                lookup: createSecureLookup(this.allowPrivateAddresses),
            },
        });
    }

    public async authorizeRoomMail(
        originHomeserverId: string,
        query: FederationRoomMailAuthorizationQuery,
    ): Promise<FederationRoomMailAuthorization> {
        const destination =
            await this.resolveHomeserverDestination(originHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/room/authorize-mail",
            query,
            FederationRoomMailAuthorizationSchema,
        );
    }

    public async close(): Promise<void> {
        await this.agent.close();
    }

    public async completeMigration(
        sourceHomeserverId: string,
        query: FederationMigrationQuery,
    ): Promise<FederationMigrationCompleteResult> {
        const destination =
            await this.resolveHomeserverDestination(sourceHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/migration/complete",
            query,
            FederationMigrationCompleteResultSchema,
        );
    }

    public async deliverMail(
        envelope: FederationMailEnvelope,
    ): Promise<FederationMailResult> {
        const destination = await this.resolveDestination(
            envelope.mail.readerID,
        );
        return this.post(
            destination,
            "/_vex/federation/v1/mail",
            envelope,
            FederationMailResultSchema,
        );
    }

    public getAvatar(
        originHomeserverId: string,
        accountId: string,
    ): Promise<{ contentType: string; data: Uint8Array }> {
        if (!/^0x[0-9a-f]{64}$/.test(accountId)) {
            return Promise.reject(
                new Error("Federated account ID is invalid."),
            );
        }
        return this.getPublicImage(
            originHomeserverId,
            `/avatar/${encodeURIComponent(accountId)}`,
        );
    }

    public async getKeyBundle(
        requesterAccountId: string,
        accountId: string,
        deviceId: string,
    ): Promise<FederationKeyBundleResult> {
        const destination = await this.resolveDestination(accountId);
        return this.post(
            destination,
            "/_vex/federation/v1/key-bundle",
            { accountId, deviceId, requesterAccountId },
            FederationKeyBundleResultSchema,
        );
    }

    public async getMigrationAvatar(
        sourceHomeserverId: string,
        query: FederationMigrationQuery,
    ): Promise<FederationMigrationBlobResult> {
        const destination =
            await this.resolveHomeserverDestination(sourceHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/migration/avatar",
            query,
            FederationMigrationBlobResultSchema,
            MAX_ICON_RESPONSE_BYTES + 4 * 1024,
        );
    }

    public async getMigrationFile(
        sourceHomeserverId: string,
        query: FederationMigrationFileQuery,
    ): Promise<FederationMigrationBlobResult> {
        const destination =
            await this.resolveHomeserverDestination(sourceHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/migration/file",
            query,
            FederationMigrationBlobResultSchema,
            MAX_MIGRATION_BLOB_RESPONSE_BYTES,
        );
    }

    public async getMigrationMail(
        sourceHomeserverId: string,
        query: FederationMigrationMailQuery,
    ): Promise<FederationMigrationMailPage> {
        const destination =
            await this.resolveHomeserverDestination(sourceHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/migration/mail",
            query,
            FederationMigrationMailPageSchema,
        );
    }

    public async getMigrationManifest(
        sourceHomeserverId: string,
        query: FederationMigrationQuery,
    ): Promise<FederationMigrationManifest> {
        const destination =
            await this.resolveHomeserverDestination(sourceHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/migration/manifest",
            query,
            FederationMigrationManifestSchema,
            MAX_MIGRATION_MANIFEST_RESPONSE_BYTES,
        );
    }

    public async getServerIcon(
        originHomeserverId: string,
        iconId: string,
    ): Promise<{ contentType: string; data: Uint8Array }> {
        if (!/^[a-zA-Z0-9._-]{1,255}$/.test(iconId)) {
            throw new Error("Federated room icon ID is invalid.");
        }
        return this.getPublicImage(
            originHomeserverId,
            `/server-icon/${encodeURIComponent(iconId)}`,
        );
    }

    public async mutateRoom(
        originHomeserverId: string,
        accountId: string,
        serverId: string,
        mutation: FederationRoomMutation,
    ): Promise<FederationRoomMutationResult> {
        const destination =
            await this.resolveHomeserverDestination(originHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/room/mutate",
            { accountId, mutation, serverId },
            FederationRoomMutationResultSchema,
        );
    }

    public async previewInvite(
        originHomeserverId: string,
        inviteId: string,
    ): Promise<FederationInvitePreview> {
        const destination =
            await this.resolveHomeserverDestination(originHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/invite/preview",
            { inviteId },
            FederationInvitePreviewSchema,
        );
    }

    public async pushRoomDeletion(
        destinationHomeserverId: string,
        deletion: FederationRoomDeletion,
    ): Promise<FederationRoomPushResult> {
        const destination = await this.resolveHomeserverDestination(
            destinationHomeserverId,
        );
        return this.post(
            destination,
            "/_vex/federation/v1/room/deleted",
            deletion,
            FederationRoomPushResultSchema,
        );
    }

    public async pushRoomSnapshot(
        destinationHomeserverId: string,
        snapshot: FederationRoomSnapshot,
    ): Promise<FederationRoomPushResult> {
        const destination = await this.resolveHomeserverDestination(
            destinationHomeserverId,
        );
        return this.post(
            destination,
            "/_vex/federation/v1/room/update",
            snapshot,
            FederationRoomPushResultSchema,
        );
    }

    public async queryAccount(
        accountId: string,
    ): Promise<FederationAccountResult> {
        const destination = await this.resolveDestination(accountId);
        return this.post(
            destination,
            "/_vex/federation/v1/account",
            { accountId },
            FederationAccountResultSchema,
        );
    }

    public async queryRoom(
        originHomeserverId: string,
        accountId: string,
        serverId: string,
    ): Promise<FederationRoomSnapshot> {
        const destination =
            await this.resolveHomeserverDestination(originHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/room",
            { accountId, serverId },
            FederationRoomSnapshotSchema,
            MAX_ROOM_SNAPSHOT_RESPONSE_BYTES,
        );
    }

    public async queryRoomInvites(
        originHomeserverId: string,
        query: FederationRoomInvitesQuery,
    ): Promise<Invite[]> {
        const destination =
            await this.resolveHomeserverDestination(originHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/room/invites",
            query,
            FederationRoomInvitesResultSchema,
        );
    }

    public async redeemInvite(
        originHomeserverId: string,
        accountId: string,
        inviteId: string,
    ): Promise<FederationInviteRedeemResult> {
        const destination =
            await this.resolveHomeserverDestination(originHomeserverId);
        return this.post(
            destination,
            "/_vex/federation/v1/invite/redeem",
            { accountId, inviteId },
            FederationInviteRedeemResultSchema,
        );
    }

    private async getPublicImage(
        originHomeserverId: string,
        path: string,
    ): Promise<{ contentType: string; data: Uint8Array }> {
        const destination =
            await this.resolveHomeserverDestination(originHomeserverId);
        const endpoint = federationEndpoint(
            destination.homeserver.endpoint,
            this.allowPrivateAddresses,
        );
        const url = new URL(path, endpoint);
        const response = await request(url, {
            dispatcher: this.agent,
            headersTimeout: this.requestTimeoutMs,
            method: "GET",
            signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        const data = await readLimitedBody(
            response.body,
            MAX_ICON_RESPONSE_BYTES,
        );
        if (response.statusCode !== 200) {
            throw new Error(
                `Federated image request failed with status ${String(response.statusCode)}.`,
            );
        }
        const contentType = singleHeader(
            response.headers,
            "content-type",
        )?.split(";", 1)[0];
        if (
            !contentType ||
            !/^image\/(?:jpeg|png|gif|apng|avif|webp)$/.test(contentType)
        ) {
            throw new Error("Federated image returned an invalid media type.");
        }
        return { contentType, data };
    }

    private async post<T>(
        destination: { homeserver: RegistryHomeserver },
        path: string,
        value: unknown,
        schema: ZodType<T>,
        maximumResponseBytes = MAX_RESPONSE_BYTES,
    ): Promise<T> {
        const endpoint = federationEndpoint(
            destination.homeserver.endpoint,
            this.allowPrivateAddresses,
        );
        const url = new URL(path, endpoint);
        const body = msgpack.encode(value);
        const nonce = `0x${XUtils.encodeHex(xRandomBytes(32))}`;
        const headers = createFederationRequestHeaders(
            {
                body,
                destination: destination.homeserver.homeserverId,
                method: "POST",
                nonce,
                origin: this.homeserverId,
                path,
                timestamp: Date.now(),
            },
            this.secretKey,
        );
        const response = await request(url, {
            body,
            dispatcher: this.agent,
            headers: {
                ...headers,
                accept: "application/msgpack",
                "content-type": "application/msgpack",
            },
            headersTimeout: this.requestTimeoutMs,
            method: "POST",
            signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        const responseBody = await readLimitedBody(
            response.body,
            maximumResponseBytes,
        );
        verifyResponse({
            body: responseBody,
            destination: this.homeserverId,
            expectedOrigin: destination.homeserver.homeserverId,
            headers: response.headers,
            publicKey: destination.homeserver.signingKey,
            requestNonce: nonce,
            status: response.statusCode,
        });
        if (response.statusCode < 200 || response.statusCode >= 300) {
            throw new Error(
                `Federation request failed with status ${String(response.statusCode)}.`,
            );
        }
        return schema.parse(msgpack.decode(responseBody));
    }

    private async resolveDestination(
        accountId: string,
    ): Promise<{ homeserver: RegistryHomeserver }> {
        const destination = await this.resolver.resolveIdentity(accountId);
        if (!destination || !destination.homeserver.active) {
            throw new Error("Federation destination is not registered.");
        }
        if (destination.homeserver.homeserverId === this.homeserverId) {
            throw new Error("Federation destination is local.");
        }
        return { homeserver: destination.homeserver };
    }

    private async resolveHomeserverDestination(
        homeserverId: string,
    ): Promise<{ homeserver: RegistryHomeserver }> {
        const destination = await this.resolver.resolveHomeserver(homeserverId);
        if (!destination?.record.active) {
            throw new Error("Federation destination is not registered.");
        }
        if (destination.record.homeserverId === this.homeserverId) {
            throw new Error("Federation destination is local.");
        }
        return { homeserver: destination.record };
    }
}

export function federationEndpoint(
    value: string,
    allowPrivateAddresses = false,
): URL {
    const endpoint = new URL(value);
    if (
        endpoint.protocol !== "https:" ||
        endpoint.username ||
        endpoint.password ||
        endpoint.search ||
        endpoint.hash ||
        endpoint.pathname !== "/"
    ) {
        throw new Error("Federation endpoints must be bare HTTPS origins.");
    }
    const hostname = endpoint.hostname.startsWith("[")
        ? endpoint.hostname.slice(1, -1)
        : endpoint.hostname;
    const family = isIP(hostname);
    if (
        !allowPrivateAddresses &&
        family !== 0 &&
        blockedAddress(hostname, family)
    ) {
        throw new Error(
            "Federation endpoint must not use a non-public IP address.",
        );
    }
    return endpoint;
}

function createSecureLookup(allowPrivateAddresses: boolean): LookupFunction {
    if (allowPrivateAddresses) return lookup;
    return (hostname, options, callback) => {
        lookup(
            hostname,
            { ...options, all: true, verbatim: true },
            (error, addresses) => {
                if (error) {
                    callback(error, "", 0);
                    return;
                }
                if (!Array.isArray(addresses) || addresses.length === 0) {
                    callback(
                        new Error("Federation endpoint did not resolve."),
                        "",
                        0,
                    );
                    return;
                }
                if (
                    addresses.some((entry) =>
                        blockedAddress(entry.address, entry.family),
                    )
                ) {
                    callback(
                        new Error(
                            "Federation endpoint resolved to a non-public address.",
                        ),
                        "",
                        0,
                    );
                    return;
                }
                const requestedFamily = Number(options.family ?? 0);
                const selected =
                    addresses.find(
                        (entry) =>
                            requestedFamily === 0 ||
                            entry.family === requestedFamily,
                    ) ?? addresses[0];
                if (!selected) {
                    callback(
                        new Error("Federation endpoint did not resolve."),
                        "",
                        0,
                    );
                    return;
                }
                callback(null, selected.address, selected.family);
            },
        );
    };
}

async function readLimitedBody(
    body: AsyncIterable<unknown>,
    maximumBytes: number,
): Promise<Uint8Array> {
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of body) {
        if (!(chunk instanceof Uint8Array)) {
            throw new Error(
                "Federation response contained an invalid body chunk.",
            );
        }
        length += chunk.byteLength;
        if (length > maximumBytes) {
            throw new Error("Federation response exceeded the size limit.");
        }
        chunks.push(Buffer.from(chunk));
    }
    return new Uint8Array(Buffer.concat(chunks, length));
}

function singleHeader(
    headers: Record<string, string | string[] | undefined>,
    name: string,
): string | undefined {
    const value = headers[name];
    return typeof value === "string" ? value : undefined;
}

function verifyResponse(input: {
    body: Uint8Array;
    destination: string;
    expectedOrigin: string;
    headers: Record<string, string | string[] | undefined>;
    publicKey: string;
    requestNonce: string;
    status: number;
}): void {
    const version = singleHeader(input.headers, FederationHeaders.version);
    const origin = singleHeader(input.headers, FederationHeaders.origin);
    const destination = singleHeader(
        input.headers,
        FederationHeaders.destination,
    );
    const requestNonce = singleHeader(
        input.headers,
        FederationHeaders.requestNonce,
    );
    const signature = singleHeader(input.headers, FederationHeaders.signature);
    if (
        version !== FEDERATION_VERSION ||
        origin !== input.expectedOrigin ||
        destination !== input.destination ||
        requestNonce !== input.requestNonce ||
        !signature ||
        !verifyFederationResponseSignature(
            {
                body: input.body,
                destination,
                origin,
                requestNonce,
                status: input.status,
            },
            signature,
            input.publicKey,
        )
    ) {
        throw new Error("Federation response signature is invalid.");
    }
}

const blockedIpv4Networks = new BlockList();
for (const [network, prefix] of [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
] as const) {
    blockedIpv4Networks.addSubnet(network, prefix, "ipv4");
}
const blockedIpv6Networks = new BlockList();
for (const [network, prefix] of [
    ["::", 128],
    ["::1", 128],
    ["::ffff:0:0", 96],
    ["64:ff9b::", 96],
    ["100::", 64],
    ["2001:db8::", 32],
    ["fc00::", 7],
    ["fe80::", 10],
    ["ff00::", 8],
] as const) {
    blockedIpv6Networks.addSubnet(network, prefix, "ipv6");
}

function blockedAddress(address: string, family: number): boolean {
    return family === 6
        ? blockedIpv6Networks.check(address, "ipv6")
        : blockedIpv4Networks.check(address, "ipv4");
}

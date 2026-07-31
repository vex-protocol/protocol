/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { ServerDatabase } from "../db/schema.ts";
import type { RegistryEvent } from "./events.ts";
import type {
    IdentityResolver,
    RegistryAccount,
    RegistryDevice,
    RegistryHomeserver,
    RegistryIdentityResolution,
    RegistryPosition,
    RegistryResolution,
    RegistryResolveOptions,
    RegistryUsername,
} from "@vex-chat/types";
import type { Kysely, Transaction } from "kysely";

import {
    RegistryAccountSchema,
    RegistryDeviceSchema,
    RegistryHomeserverSchema,
    RegistryIdentityResolutionSchema,
    RegistryPositionSchema,
    RegistryUsernameSchema,
} from "@vex-chat/types";

export class RegistryCacheUnavailableError extends Error {
    constructor(source: string) {
        super(`Identity registry cache is not ready for ${source}.`);
        this.name = "RegistryCacheUnavailableError";
    }
}

export class RegistryCheckpointMismatchError extends Error {
    constructor(sequence: string) {
        super(`Identity registry checkpoint changed at sequence ${sequence}.`);
        this.name = "RegistryCheckpointMismatchError";
    }
}

export class RegistryPositionUnavailableError extends Error {
    constructor(minimum: string, available: string) {
        super(
            `Identity registry position ${minimum} was requested, but only ${available} is available.`,
        );
        this.name = "RegistryPositionUnavailableError";
    }
}

export class RegistryStore implements IdentityResolver {
    public readonly source: string;

    private readonly db: Kysely<ServerDatabase>;
    constructor(db: Kysely<ServerDatabase>, source: string) {
        if (source.length === 0 || source.length > 255) {
            throw new Error(
                "Registry source must contain 1 through 255 characters.",
            );
        }
        this.db = db;
        this.source = source;
    }

    public async applyBatch(
        events: readonly RegistryEvent[],
        positionInput: RegistryPosition,
    ): Promise<void> {
        const position = RegistryPositionSchema.parse(positionInput);
        if (position.source !== this.source) {
            throw new Error("Registry position belongs to a different source.");
        }

        await this.db.transaction().execute(async (transaction) => {
            const current = await this.readPosition(transaction);
            if (current) {
                const comparison = compareSequences(
                    position.sequence,
                    current.sequence,
                );
                if (comparison < 0) {
                    throw new Error("Registry cursor cannot move backwards.");
                }
                if (comparison === 0) {
                    if (position.checkpoint !== current.checkpoint) {
                        throw new RegistryCheckpointMismatchError(
                            position.sequence,
                        );
                    }
                    return;
                }
            }

            for (const event of events) {
                await this.applyEvent(transaction, event);
            }
            await transaction
                .insertInto("registry_cursors")
                .values(position)
                .onConflict((conflict) =>
                    conflict.column("source").doUpdateSet({
                        checkpoint: position.checkpoint,
                        sequence: position.sequence,
                    }),
                )
                .execute();
        });
    }

    public async currentPosition(): Promise<null | RegistryPosition> {
        const row = await this.db
            .selectFrom("registry_cursors")
            .selectAll()
            .where("source", "=", this.source)
            .executeTakeFirst();
        return row ? RegistryPositionSchema.parse(row) : null;
    }

    public async reset(): Promise<void> {
        await this.db.transaction().execute(async (transaction) => {
            await transaction
                .deleteFrom("registry_usernames")
                .where("source", "=", this.source)
                .execute();
            await transaction
                .deleteFrom("registry_devices")
                .where("source", "=", this.source)
                .execute();
            await transaction
                .deleteFrom("registry_accounts")
                .where("source", "=", this.source)
                .execute();
            await transaction
                .deleteFrom("registry_homeservers")
                .where("source", "=", this.source)
                .execute();
            await transaction
                .deleteFrom("registry_cursors")
                .where("source", "=", this.source)
                .execute();
        });
    }

    public async resolveAccount(
        accountId: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryAccount>> {
        return this.resolveRecord(options, async (transaction) => {
            const row = await transaction
                .selectFrom("registry_accounts")
                .select([
                    "accountId",
                    "activeDeviceCount",
                    "deviceThreshold",
                    "epoch",
                    "homeserverId",
                    "nonce",
                    "recoveryCommitment",
                ])
                .where("source", "=", this.source)
                .where("accountId", "=", accountId)
                .executeTakeFirst();
            return row ? RegistryAccountSchema.parse(row) : null;
        });
    }

    public async resolveDevice(
        accountId: string,
        deviceKey: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryDevice>> {
        return this.resolveRecord(options, async (transaction) => {
            const row = await transaction
                .selectFrom("registry_devices")
                .selectAll()
                .where("source", "=", this.source)
                .where("accountId", "=", accountId)
                .where("deviceKey", "=", deviceKey)
                .executeTakeFirst();
            return row
                ? RegistryDeviceSchema.parse({
                      accountId: row.accountId,
                      active: row.active === 1,
                      addedAtEpoch: row.addedAtEpoch,
                      deviceKey: row.deviceKey,
                      keyAlgorithm: "Ed25519",
                      revokedAtEpoch: row.revokedAtEpoch,
                  })
                : null;
        });
    }

    public async resolveHomeserver(
        homeserverId: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryHomeserver>> {
        return this.resolveRecord(options, async (transaction) => {
            const row = await transaction
                .selectFrom("registry_homeservers")
                .selectAll()
                .where("source", "=", this.source)
                .where("homeserverId", "=", homeserverId)
                .executeTakeFirst();
            return row
                ? RegistryHomeserverSchema.parse({
                      active: row.active === 1,
                      endpoint: row.endpoint,
                      epoch: row.epoch,
                      homeserverId: row.homeserverId,
                      keyAlgorithm: "Ed25519",
                      nonce: row.nonce,
                      signingKey: row.signingKey,
                  })
                : null;
        });
    }

    public async resolveIdentity(
        accountId: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryIdentityResolution> {
        this.requireAvailable();
        return this.db.transaction().execute(async (transaction) => {
            const position = await this.requirePosition(transaction, options);
            const accountRow = await transaction
                .selectFrom("registry_accounts")
                .selectAll()
                .where("source", "=", this.source)
                .where("accountId", "=", accountId)
                .executeTakeFirst();
            if (!accountRow) return null;

            const [deviceRows, homeserverRow, usernameRow] = await Promise.all([
                transaction
                    .selectFrom("registry_devices")
                    .selectAll()
                    .where("source", "=", this.source)
                    .where("accountId", "=", accountId)
                    .where("active", "=", 1)
                    .orderBy("deviceKey")
                    .execute(),
                transaction
                    .selectFrom("registry_homeservers")
                    .selectAll()
                    .where("source", "=", this.source)
                    .where("homeserverId", "=", accountRow.homeserverId)
                    .executeTakeFirst(),
                transaction
                    .selectFrom("registry_usernames")
                    .selectAll()
                    .where("source", "=", this.source)
                    .where("accountId", "=", accountId)
                    .executeTakeFirst(),
            ]);
            if (!homeserverRow) {
                throw new Error(
                    `Registry cache is missing homeserver ${accountRow.homeserverId}.`,
                );
            }

            return RegistryIdentityResolutionSchema.parse({
                account: {
                    accountId: accountRow.accountId,
                    activeDeviceCount: accountRow.activeDeviceCount,
                    deviceThreshold: accountRow.deviceThreshold,
                    epoch: accountRow.epoch,
                    homeserverId: accountRow.homeserverId,
                    nonce: accountRow.nonce,
                    recoveryCommitment: accountRow.recoveryCommitment,
                },
                devices: deviceRows.map((row) => ({
                    accountId: row.accountId,
                    active: true,
                    addedAtEpoch: row.addedAtEpoch,
                    deviceKey: row.deviceKey,
                    keyAlgorithm: "Ed25519" as const,
                    revokedAtEpoch: null,
                })),
                homeserver: {
                    active: homeserverRow.active === 1,
                    endpoint: homeserverRow.endpoint,
                    epoch: homeserverRow.epoch,
                    homeserverId: homeserverRow.homeserverId,
                    keyAlgorithm: "Ed25519",
                    nonce: homeserverRow.nonce,
                    signingKey: homeserverRow.signingKey,
                },
                position,
                username: usernameRow
                    ? {
                          accountId: usernameRow.accountId,
                          nameHash: usernameRow.nameHash,
                          username: usernameRow.username,
                      }
                    : null,
            });
        });
    }

    public async resolveUsername(
        username: string,
        options?: RegistryResolveOptions,
    ): Promise<null | RegistryResolution<RegistryUsername>> {
        return this.resolveRecord(options, async (transaction) => {
            const row = await transaction
                .selectFrom("registry_usernames")
                .select(["accountId", "nameHash", "username"])
                .where("source", "=", this.source)
                .where("username", "=", username)
                .executeTakeFirst();
            return row ? RegistryUsernameSchema.parse(row) : null;
        });
    }

    public setAvailabilityCheck(check: () => boolean): void {
        this.availabilityCheck = check;
    }

    private async applyEvent(
        transaction: Transaction<ServerDatabase>,
        event: RegistryEvent,
    ): Promise<void> {
        switch (event.type) {
            case "account-registered":
                await transaction
                    .insertInto("registry_accounts")
                    .values({
                        accountId: event.accountId,
                        activeDeviceCount: 1,
                        deviceThreshold: 1,
                        epoch: event.epoch,
                        homeserverId: event.homeserverId,
                        nonce: nonceForEpoch(event.epoch),
                        recoveryCommitment: event.recoveryCommitment,
                        source: this.source,
                    })
                    .onConflict((conflict) =>
                        conflict.columns(["source", "accountId"]).doUpdateSet({
                            activeDeviceCount: 1,
                            deviceThreshold: 1,
                            epoch: event.epoch,
                            homeserverId: event.homeserverId,
                            nonce: nonceForEpoch(event.epoch),
                            recoveryCommitment: event.recoveryCommitment,
                        }),
                    )
                    .execute();
                await this.upsertDevice(
                    transaction,
                    event.accountId,
                    event.genesisDeviceKey,
                    event.epoch,
                );
                return;
            case "device-added":
                await this.upsertDevice(
                    transaction,
                    event.accountId,
                    event.deviceKey,
                    event.epoch,
                );
                await this.updateAccountEpoch(
                    transaction,
                    event.accountId,
                    event.epoch,
                );
                await this.refreshActiveDeviceCount(
                    transaction,
                    event.accountId,
                );
                return;
            case "device-revoked":
                await this.requireUpdated(
                    transaction
                        .updateTable("registry_devices")
                        .set({ active: 0, revokedAtEpoch: event.epoch })
                        .where("source", "=", this.source)
                        .where("accountId", "=", event.accountId)
                        .where("deviceKey", "=", event.deviceKey)
                        .executeTakeFirst(),
                    "device revocation",
                );
                await this.updateAccountEpoch(
                    transaction,
                    event.accountId,
                    event.epoch,
                );
                await this.refreshActiveDeviceCount(
                    transaction,
                    event.accountId,
                );
                return;
            case "device-threshold-changed":
                await this.requireUpdated(
                    transaction
                        .updateTable("registry_accounts")
                        .set({
                            deviceThreshold: event.threshold,
                            epoch: event.epoch,
                            nonce: nonceForEpoch(event.epoch),
                        })
                        .where("source", "=", this.source)
                        .where("accountId", "=", event.accountId)
                        .executeTakeFirst(),
                    "device threshold change",
                );
                return;
            case "homeserver-changed":
                await this.requireUpdated(
                    transaction
                        .updateTable("registry_accounts")
                        .set({
                            epoch: event.epoch,
                            homeserverId: event.homeserverId,
                            nonce: nonceForEpoch(event.epoch),
                        })
                        .where("source", "=", this.source)
                        .where("accountId", "=", event.accountId)
                        .executeTakeFirst(),
                    "homeserver change",
                );
                return;
            case "homeserver-endpoint-changed":
                await this.requireUpdated(
                    transaction
                        .updateTable("registry_homeservers")
                        .set({
                            endpoint: event.endpoint,
                            epoch: event.epoch,
                            nonce: nonceForEpoch(event.epoch),
                        })
                        .where("source", "=", this.source)
                        .where("homeserverId", "=", event.homeserverId)
                        .executeTakeFirst(),
                    "homeserver endpoint change",
                );
                return;
            case "homeserver-key-rotated":
                await this.requireUpdated(
                    transaction
                        .updateTable("registry_homeservers")
                        .set({
                            epoch: event.epoch,
                            nonce: nonceForEpoch(event.epoch),
                            signingKey: event.signingKey,
                        })
                        .where("source", "=", this.source)
                        .where("homeserverId", "=", event.homeserverId)
                        .executeTakeFirst(),
                    "homeserver key rotation",
                );
                return;
            case "homeserver-registered":
                await transaction
                    .insertInto("registry_homeservers")
                    .values({
                        active: 1,
                        endpoint: event.endpoint,
                        epoch: event.epoch,
                        homeserverId: event.homeserverId,
                        nonce: nonceForEpoch(event.epoch),
                        signingKey: event.signingKey,
                        source: this.source,
                    })
                    .onConflict((conflict) =>
                        conflict
                            .columns(["source", "homeserverId"])
                            .doUpdateSet({
                                active: 1,
                                endpoint: event.endpoint,
                                epoch: event.epoch,
                                nonce: nonceForEpoch(event.epoch),
                                signingKey: event.signingKey,
                            }),
                    )
                    .execute();
                return;
            case "recovery-commitment-changed":
                await this.requireUpdated(
                    transaction
                        .updateTable("registry_accounts")
                        .set({
                            epoch: event.epoch,
                            nonce: nonceForEpoch(event.epoch),
                            recoveryCommitment: event.recoveryCommitment,
                        })
                        .where("source", "=", this.source)
                        .where("accountId", "=", event.accountId)
                        .executeTakeFirst(),
                    "recovery commitment change",
                );
                return;
            case "username-registered":
                await transaction
                    .insertInto("registry_usernames")
                    .values({
                        accountId: event.accountId,
                        nameHash: event.nameHash,
                        source: this.source,
                        username: event.username,
                    })
                    .onConflict((conflict) =>
                        conflict.columns(["source", "username"]).doUpdateSet({
                            accountId: event.accountId,
                            nameHash: event.nameHash,
                        }),
                    )
                    .execute();
                return;
        }
    }

    private availabilityCheck: () => boolean = () => true;

    private async readPosition(
        transaction: Transaction<ServerDatabase>,
    ): Promise<null | RegistryPosition> {
        const row = await transaction
            .selectFrom("registry_cursors")
            .selectAll()
            .where("source", "=", this.source)
            .executeTakeFirst();
        return row ? RegistryPositionSchema.parse(row) : null;
    }

    private async refreshActiveDeviceCount(
        transaction: Transaction<ServerDatabase>,
        accountId: string,
    ): Promise<void> {
        const row = await transaction
            .selectFrom("registry_devices")
            .select((builder) => builder.fn.countAll().as("count"))
            .where("source", "=", this.source)
            .where("accountId", "=", accountId)
            .where("active", "=", 1)
            .executeTakeFirstOrThrow();
        await this.requireUpdated(
            transaction
                .updateTable("registry_accounts")
                .set({ activeDeviceCount: Number(row.count) })
                .where("source", "=", this.source)
                .where("accountId", "=", accountId)
                .executeTakeFirst(),
            "active device count refresh",
        );
    }

    private requireAvailable(): void {
        if (!this.availabilityCheck()) {
            throw new RegistryCacheUnavailableError(this.source);
        }
    }

    private async requirePosition(
        transaction: Transaction<ServerDatabase>,
        options?: RegistryResolveOptions,
    ): Promise<RegistryPosition> {
        const position = await this.readPosition(transaction);
        if (!position) throw new RegistryCacheUnavailableError(this.source);
        if (
            options?.minimumSequence !== undefined &&
            compareSequences(position.sequence, options.minimumSequence) < 0
        ) {
            throw new RegistryPositionUnavailableError(
                options.minimumSequence,
                position.sequence,
            );
        }
        return position;
    }

    private async requireUpdated(
        result: Promise<{ numUpdatedRows: bigint }>,
        operation: string,
    ): Promise<void> {
        const update = await result;
        if (update.numUpdatedRows !== 1n) {
            throw new Error(`Registry cache could not apply ${operation}.`);
        }
    }

    private async resolveRecord<T>(
        options: RegistryResolveOptions | undefined,
        resolve: (
            transaction: Transaction<ServerDatabase>,
        ) => Promise<null | T>,
    ): Promise<null | RegistryResolution<T>> {
        this.requireAvailable();
        return this.db.transaction().execute(async (transaction) => {
            const position = await this.requirePosition(transaction, options);
            const record = await resolve(transaction);
            return record ? { position, record } : null;
        });
    }

    private async updateAccountEpoch(
        transaction: Transaction<ServerDatabase>,
        accountId: string,
        epoch: string,
    ): Promise<void> {
        await this.requireUpdated(
            transaction
                .updateTable("registry_accounts")
                .set({ epoch, nonce: nonceForEpoch(epoch) })
                .where("source", "=", this.source)
                .where("accountId", "=", accountId)
                .executeTakeFirst(),
            "account epoch update",
        );
    }

    private async upsertDevice(
        transaction: Transaction<ServerDatabase>,
        accountId: string,
        deviceKey: string,
        epoch: string,
    ): Promise<void> {
        await transaction
            .insertInto("registry_devices")
            .values({
                accountId,
                active: 1,
                addedAtEpoch: epoch,
                deviceKey,
                revokedAtEpoch: null,
                source: this.source,
            })
            .onConflict((conflict) =>
                conflict
                    .columns(["source", "accountId", "deviceKey"])
                    .doUpdateSet({
                        active: 1,
                        addedAtEpoch: epoch,
                        revokedAtEpoch: null,
                    }),
            )
            .execute();
    }
}

function compareSequences(left: string, right: string): number {
    const leftValue = BigInt(left);
    const rightValue = BigInt(right);
    return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function nonceForEpoch(epoch: string): string {
    const value = BigInt(epoch);
    if (value < 1n) throw new Error("Registry epochs start at one.");
    return (value - 1n).toString();
}

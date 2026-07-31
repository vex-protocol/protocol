/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { PasskeyRow, ServerDatabase } from "./db/schema.ts";
import type { SpireOptions } from "./Spire.ts";
import type {
    AccountEntitlements,
    AccountEntitlementSource,
    AccountTier,
    BillingAccountState,
    BillingEnvironment,
    BillingPlatform,
    BillingSubscription,
    BillingSubscriptionStatus,
    Channel,
    Device,
    DevicePayload,
    Emoji,
    FederationRoomDeletion,
    FederationRoomSnapshot,
    FileSQL,
    Invite,
    KeyBundle,
    MailSQL,
    MailWS,
    Passkey,
    Permission,
    PreKeysSQL,
    PreKeysWS,
    RegistrationPayload,
    Server,
    UserRecord,
} from "@vex-chat/types";
import type { Migration, MigrationProvider, Transaction } from "kysely";

import { EventEmitter } from "events";
import { createHash } from "node:crypto";
import { statSync } from "node:fs";
import * as fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { XUtils } from "@vex-chat/crypto";
import {
    ACCOUNT_PASSWORD_MAX_LENGTH,
    ACCOUNT_PASSWORD_MIN_LENGTH,
    AccountEntitlementSourceSchema,
    AccountTierSchema,
    BillingEnvironmentSchema,
    BillingPlatformSchema,
    BillingSubscriptionStatusSchema,
    buildAccountEntitlements,
    MailType,
} from "@vex-chat/types";

import argon2 from "argon2";

import { serverMailRetentionCutoffIso } from "./mailRetention.ts";
import { RegistryStore } from "./registry/RegistryStore.ts";

export interface FederationRoomOutboxEntry {
    attempts: number;
    createdAt: number;
    destinationHomeserverId: string;
    eventId: string;
    kind: "deletion" | "snapshot";
    nextAttemptAt: number;
    payload: string;
}

export interface FederationRoomTombstone {
    deletedAt: number;
    homeserverId: string;
    permanent: boolean;
    revision: string;
    serverId: string;
}

export interface StoredHomeserverMigration {
    accountId: string;
    authorization: string;
    completedAt: null | number;
    createdAt: number;
    destinationHomeserverId: string;
    deviceKey: string;
    mailCutoffAt: null | number;
    manifest: null | string;
    migrationId: string;
    nonce: string;
    sourceHomeserverId: string;
    transferExpiresAt: number;
}

export interface StoreSubscriptionUpsertInput {
    environment: BillingEnvironment;
    expiresAt: null | string;
    externalOriginalID?: null | string | undefined;
    externalTransactionID?: null | string | undefined;
    platform: BillingPlatform;
    productID: string;
    purchaseToken?: null | string | undefined;
    rawPayload: unknown;
    status: BillingSubscriptionStatus;
    storeProductID: string;
    tier: AccountTier;
    userID: string;
}

export interface StoreTransactionRecordInput {
    eventType: string;
    externalTransactionID?: null | string | undefined;
    rawPayload: unknown;
    subscriptionID: string;
    userID: string;
}

/**
 * Narrow a plain integer from the `mailType` SQL column to the
 * `MailType` union (0 = initial, 1 = subsequent). Throws if the
 * database contains an unexpected value, catching row corruption
 * at read time instead of propagating an invalid literal into
 * application code.
 */
function parseMailType(n: number): MailType {
    if (n === MailType.initial) return MailType.initial;
    if (n === MailType.subsequent) return MailType.subsequent;
    throw new Error(`Invalid mailType in database row: ${String(n)}`);
}

import BetterSqlite3 from "better-sqlite3";
import { Kysely, Migrator, sql, SqliteDialect } from "kysely";
import {
    parse as uuidParse,
    stringify as uuidStringify,
    validate as uuidValidate,
} from "uuid";

export const MAX_ACTIVE_DEVICES_PER_USER = 20;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationFolder = path.join(__dirname, "migrations");

/**
 * Cross-platform Kysely migration provider.
 *
 * Replaces Kysely's built-in `FileMigrationProvider`, which on Windows
 * fails with `ERR_UNSUPPORTED_ESM_URL_SCHEME` because it does
 * `await import(joinedPath)` where `joinedPath` is a Windows absolute
 * path like `D:\\spire\\src\\migrations\\schema.ts`. Node's ESM loader
 * requires `file://` URLs for absolute paths on Windows.
 *
 * This implementation uses `pathToFileURL` to convert each migration
 * file's absolute path to a `file://` URL before passing it to
 * `import()`. Works on Linux, macOS, and Windows. Filters out `.d.ts`
 * declaration files and accepts both `.ts` and `.js` source files for
 * spire's `--experimental-strip-types` runtime.
 */
class CrossPlatformMigrationProvider implements MigrationProvider {
    private readonly folder: string;

    constructor(folder: string) {
        this.folder = folder;
    }

    async getMigrations(): Promise<Record<string, Migration>> {
        const files = await fs.readdir(this.folder);
        const migrations: Record<string, Migration> = {};
        for (const file of files.sort()) {
            if (file.endsWith(".d.ts")) continue;
            if (!file.endsWith(".ts") && !file.endsWith(".js")) continue;
            const fullPath = path.join(this.folder, file);
            const fileUrl = pathToFileURL(fullPath).href;
            const mod: unknown = await import(fileUrl);
            if (!isMigration(mod)) {
                throw new Error(
                    `Invalid migration ${file}: expected an exported \`up\` function`,
                );
            }
            const name = file.replace(/\.(ts|js)$/, "");
            migrations[name] = mod;
        }
        return migrations;
    }
}

function isMigration(mod: unknown): mod is Migration {
    return (
        typeof mod === "object" &&
        mod !== null &&
        "up" in mod &&
        typeof (mod as { up: unknown }).up === "function"
    );
}

const pubkeyRegex = /^(?:[0-9a-fA-F]{2}){32,4096}$/;
const accountIdRegex = /^0x[0-9a-fA-F]{64}$/;
const DUMMY_PASSWORD_HASH =
    "$argon2id$v=19$m=65536,t=3,p=1$SZlCYiWwt450ZWt2zRvDIw$QZdY/EtG81hEAXYRLVDvqtpJbajXL1/QRM91ZT9DQPk";
const ARGON2_OPTIONS = {
    memoryCost: 65_536,
    parallelism: 1,
    timeCost: 3,
    type: argon2.argon2id,
} as const;

const COMMON_ACCOUNT_PASSWORDS = new Set([
    "123456789012345",
    "adminadminadminadmin",
    "letmeinletmeinletmein",
    "passwordpassword",
    "passwordpasswordpassword",
    "qwertyuiopasdfgh",
]);

export type InternalUserRecord = UserRecord;

// ── Row-to-interface converters ─────────────────────────────────────────
// SQLite stores booleans as integers and dates as strings, but the
// @vex-chat/types interfaces expect boolean / Date.

export interface NotificationSubscription {
    channel: "expo";
    createdAt: string;
    deviceID: string;
    enabled: boolean;
    events: string[];
    platform: null | string;
    subscriptionID: string;
    token: string;
    updatedAt: string;
    userID: string;
}

export interface SaveNotificationSubscriptionInput {
    channel: "expo";
    deviceID: string;
    events: string[];
    platform?: null | string;
    token: string;
    userID: string;
}

interface DevicePasskeyApprovalInput {
    approvedByDeviceID?: null | string;
    approvedByPasskeyID: string;
}

export class Database extends EventEmitter {
    private static readonly EMOJI_LIST_CACHE_TTL_MS = 10_000;

    private db: Kysely<ServerDatabase>;

    /**
     * Short TTL cache for {@link retrieveEmojiList} (key = server id, stored as
     * `emojis.owner`). The noise harness fires `emoji.retrieveList` as a
     * follow-up on ~1/25 successful ops, so this path can contend on SQLite
     * before heavier surfaces. Invalidated on emoji create/delete.
     */
    private readonly emojiListByServerCache = new Map<
        string,
        { rows: Emoji[]; until: number }
    >();

    /** Underlying better-sqlite3 handle (file or :memory:). */
    private readonly rawSqlite: InstanceType<typeof BetterSqlite3>;

    constructor(options?: SpireOptions) {
        super();

        const dbType = options?.dbType || "sqlite3";

        let filename: string;
        switch (dbType) {
            case "sqlite":
            case "sqlite3":
                filename = "spire.sqlite";
                break;
            case "sqlite3mem":
                filename = ":memory:";
                break;
            default:
                filename = "spire.sqlite";
                break;
        }

        this.rawSqlite = new BetterSqlite3(filename);
        this.rawSqlite.pragma("journal_mode = WAL");
        this.rawSqlite.pragma("synchronous = NORMAL");
        this.rawSqlite.pragma("busy_timeout = 5000");
        this.rawSqlite.pragma("cache_size = -64000");
        this.rawSqlite.pragma("temp_store = memory");
        this.rawSqlite.pragma("foreign_keys = ON");

        this.db = new Kysely<ServerDatabase>({
            dialect: new SqliteDialect({ database: this.rawSqlite }),
        });

        void this.init();
    }

    public async applyFederatedRoomDeletion(
        deletion: FederationRoomDeletion,
        deletedAt = Date.now(),
    ): Promise<boolean> {
        return this.applyFederatedRoomAbsence(
            {
                homeserverId: deletion.originHomeserverId,
                revision: deletion.revision,
                serverId: deletion.serverId,
            },
            true,
            deletedAt,
        );
    }

    public async bumpServerRevision(serverID: string): Promise<string> {
        return this.incrementServerRevision(this.db, serverID);
    }

    public async close(): Promise<void> {
        this.emojiListByServerCache.clear();
        await this.db.destroy();
    }

    public async completeFederationRoomOutbox(eventId: string): Promise<void> {
        await this.db
            .deleteFrom("federation_room_outbox")
            .where("eventId", "=", eventId)
            .execute();
    }

    public async consumeFederationNonce(
        originHomeserverId: string,
        nonce: string,
        expiresAt: number,
        now = Date.now(),
    ): Promise<boolean> {
        return this.db.transaction().execute(async (transaction) => {
            await transaction
                .deleteFrom("federation_nonces")
                .where("expiresAt", "<=", now)
                .execute();
            const result = await transaction
                .insertInto("federation_nonces")
                .values({ expiresAt, nonce, originHomeserverId })
                .onConflict((conflict) => conflict.doNothing())
                .executeTakeFirst();
            return result.numInsertedOrUpdatedRows === 1n;
        });
    }

    public async createChannel(
        name: string,
        serverID: string,
    ): Promise<Channel> {
        const channel: Channel = {
            channelID: crypto.randomUUID(),
            name,
            serverID,
        };
        await this.db.transaction().execute(async (transaction) => {
            await transaction.insertInto("channels").values(channel).execute();
            await this.incrementServerRevision(transaction, serverID);
        });
        return channel;
    }

    public async createDevice(
        owner: string,
        payload: DevicePayload,
        passkeyApproval?: DevicePasskeyApprovalInput,
    ): Promise<Device> {
        return this.db
            .transaction()
            .execute(async (trx) =>
                this.insertDevice(trx, owner, payload, passkeyApproval),
            );
    }

    public async createEmoji(emoji: Emoji): Promise<void> {
        await this.db.insertInto("emojis").values(emoji).execute();
        this.emojiListByServerCache.delete(emoji.owner);
    }

    public async createFile(file: FileSQL): Promise<void> {
        await this.db.insertInto("files").values(file).execute();
    }

    public async createHomeserverMigration(
        migration: Omit<
            StoredHomeserverMigration,
            "completedAt" | "mailCutoffAt"
        >,
    ): Promise<StoredHomeserverMigration> {
        return this.db.transaction().execute(async (transaction) => {
            const row: StoredHomeserverMigration = {
                ...migration,
                completedAt: null,
                mailCutoffAt: null,
            };
            await transaction
                .insertInto("homeserver_migrations")
                .values(row)
                .onConflict((conflict) => conflict.column("nonce").doNothing())
                .execute();
            const stored = await transaction
                .selectFrom("homeserver_migrations")
                .selectAll()
                .where("nonce", "=", migration.nonce)
                .executeTakeFirst();
            if (!stored) throw new Error("Homeserver migration disappeared.");
            return stored;
        });
    }

    public async createInvite(
        inviteID: string,
        serverID: string,
        ownerID: string,
        expiration: string,
    ): Promise<Invite> {
        const invite: Invite = {
            expiration,
            inviteID,
            owner: ownerID,
            serverID,
        };

        await this.db.insertInto("invites").values(invite).execute();
        return invite;
    }

    /**
     * Insert a new passkey for `userID`. Caller is responsible for
     * having verified the WebAuthn attestation and serialised the
     * credential public key as hex (typically the COSE_Key bytes
     * returned by the authenticator). Returns the public passkey
     * shape — never the credentialID/publicKey/algorithm internals,
     * which stay server-private.
     */
    public async createPasskey(
        userID: string,
        name: string,
        credentialID: string,
        publicKeyHex: string,
        algorithm: number,
        transports: string[],
    ): Promise<Passkey> {
        const passkeyID = crypto.randomUUID();
        const createdAt = new Date().toISOString();
        await this.db
            .insertInto("passkeys")
            .values({
                algorithm,
                createdAt,
                credentialID,
                lastUsedAt: null,
                name,
                passkeyID,
                publicKey: publicKeyHex,
                signCount: 0,
                transports: transports.join(","),
                userID,
            })
            .execute();

        return {
            createdAt,
            lastUsedAt: null,
            name,
            passkeyID,
            transports,
            userID,
        };
    }

    public async createPermission(
        userID: string,
        resourceType: string,
        resourceID: string,
        powerLevel: number,
    ): Promise<Permission> {
        // Atomic check-then-insert inside a transaction so two concurrent
        // callers cannot both find "no existing" and insert duplicates.
        return this.db.transaction().execute(async (trx) => {
            const checkPermission = await trx
                .selectFrom("permissions")
                .selectAll()
                .where("userID", "=", userID)
                .where("resourceID", "=", resourceID)
                .execute();
            const existing = checkPermission[0];
            if (existing) {
                return existing;
            }

            const permission: Permission = {
                permissionID: crypto.randomUUID(),
                powerLevel,
                resourceID,
                resourceType,
                userID,
            };

            await trx.insertInto("permissions").values(permission).execute();
            if (resourceType === "server") {
                await this.incrementServerRevision(trx, resourceID);
            }
            return permission;
        });
    }

    public createRegistryStore(source: string): RegistryStore {
        return new RegistryStore(this.db, source);
    }

    public async createServer(
        name: string,
        ownerID: string,
        homeserverId?: string,
    ): Promise<Server> {
        // create the server
        const server: Server = {
            ...(homeserverId ? { homeserverId } : {}),
            name,
            revision: "1",
            serverID: crypto.randomUUID(),
        };
        await this.db.transaction().execute(async (transaction) => {
            await transaction
                .insertInto("servers")
                .values({
                    homeserverId: server.homeserverId ?? null,
                    icon: null,
                    name: server.name,
                    revision: 1,
                    serverID: server.serverID,
                })
                .execute();
            await transaction
                .insertInto("permissions")
                .values({
                    permissionID: crypto.randomUUID(),
                    powerLevel: 100,
                    resourceID: server.serverID,
                    resourceType: "server",
                    userID: ownerID,
                })
                .execute();
            await transaction
                .insertInto("channels")
                .values({
                    channelID: crypto.randomUUID(),
                    name: "general",
                    serverID: server.serverID,
                })
                .execute();
        });
        return server;
    }

    public async createUser(
        regKey: Uint8Array,
        regPayload: RegistrationPayload,
        registryAccountId?: string,
    ): Promise<[null | UserRecord, Error | null]> {
        try {
            const userID = registryAccountId ?? uuidStringify(regKey);
            const username = normalizeRegistrationUsername(regPayload.username);
            if (
                typeof regPayload.password !== "string" ||
                regPayload.password.trim().length === 0
            ) {
                throw new Error(
                    "Password is required to register a new account.",
                );
            }
            const passwordError = validateAccountPassword(
                regPayload.password,
                username,
            );
            if (passwordError) {
                throw new Error(passwordError);
            }
            const passwordHash = await hashPasswordArgon2(regPayload.password);

            const user: UserRecord = {
                lastSeen: new Date().toISOString(),
                passwordHash,
                userID,
                username,
            };

            await this.db.transaction().execute(async (trx) => {
                await trx
                    .insertInto("users")
                    .values({
                        ...user,
                        lastSeen: user.lastSeen,
                    })
                    .execute();
                await this.insertDevice(trx, user.userID, regPayload);
            });

            return [user, null];
        } catch (err: unknown) {
            return [null, err instanceof Error ? err : new Error(String(err))];
        }
    }

    public async deleteChannel(channelID: string): Promise<void> {
        await this.db.transaction().execute(async (transaction) => {
            await transaction
                .deleteFrom("permissions")
                .where("resourceID", "=", channelID)
                .execute();
            await transaction
                .deleteFrom("mail")
                .where("group", "=", mailGroupForChannel(channelID))
                .execute();
            await transaction
                .deleteFrom("channels")
                .where("channelID", "=", channelID)
                .execute();
        });
    }

    /** Delete a channel while preserving the invariant that a server has one. */
    public async deleteChannelIfNotLast(channelID: string): Promise<boolean> {
        return this.db.transaction().execute(async (trx) => {
            const channel = await trx
                .selectFrom("channels")
                .selectAll()
                .where("channelID", "=", channelID)
                .executeTakeFirst();
            if (!channel) {
                return false;
            }

            const siblings = await trx
                .selectFrom("channels")
                .select("channelID")
                .where("serverID", "=", channel.serverID)
                .limit(2)
                .execute();
            if (siblings.length <= 1) {
                return false;
            }

            await trx
                .deleteFrom("permissions")
                .where("resourceID", "=", channelID)
                .execute();
            await trx
                .deleteFrom("mail")
                .where("group", "=", mailGroupForChannel(channelID))
                .execute();
            await trx
                .deleteFrom("channels")
                .where("channelID", "=", channelID)
                .execute();
            await this.incrementServerRevision(trx, channel.serverID);
            return true;
        });
    }

    public async deleteDevice(deviceID: string): Promise<void> {
        await this.db.transaction().execute(async (trx) => {
            await trx
                .deleteFrom("preKeys")
                .where("deviceID", "=", deviceID)
                .execute();

            await trx
                .deleteFrom("oneTimeKeys")
                .where("deviceID", "=", deviceID)
                .execute();

            await trx
                .deleteFrom("notification_subscriptions")
                .where("deviceID", "=", deviceID)
                .execute();

            await trx
                .deleteFrom("device_passkey_approvals")
                .where("deviceID", "=", deviceID)
                .execute();

            await trx
                .updateTable("devices")
                .set({ deleted: 1 })
                .where("deviceID", "=", deviceID)
                .execute();
        });
    }

    public async deleteEmoji(emojiID: string): Promise<void> {
        const existing = await this.retrieveEmoji(emojiID);
        await this.db
            .deleteFrom("emojis")
            .where("emojiID", "=", emojiID)
            .execute();
        if (existing) {
            this.emojiListByServerCache.delete(existing.owner);
        }
    }

    public async deleteInvite(inviteID: string): Promise<void> {
        await this.db
            .deleteFrom("invites")
            .where("inviteID", "=", inviteID)
            .execute();
    }

    public async deleteMail(nonce: Uint8Array, userID: string): Promise<void> {
        await this.db
            .deleteFrom("mail")
            .where("nonce", "=", XUtils.encodeHex(nonce))
            .where((expression) =>
                expression.or([
                    expression("deliveryDeviceID", "=", userID),
                    expression.and([
                        expression("deliveryDeviceID", "is", null),
                        expression("recipient", "=", userID),
                    ]),
                ]),
            )
            .execute();
    }

    public async deletePasskey(passkeyID: string): Promise<void> {
        await this.db
            .deleteFrom("passkeys")
            .where("passkeyID", "=", passkeyID)
            .execute();
    }

    public async deletePermission(permissionID: string): Promise<void> {
        await this.db.transaction().execute(async (transaction) => {
            const permission = await transaction
                .selectFrom("permissions")
                .selectAll()
                .where("permissionID", "=", permissionID)
                .executeTakeFirst();
            if (!permission) return;
            await transaction
                .deleteFrom("permissions")
                .where("permissionID", "=", permissionID)
                .execute();
            if (permission.resourceType === "server") {
                await this.incrementServerRevision(
                    transaction,
                    permission.resourceID,
                );
            }
        });
    }

    public async deletePermissions(resourceID: string): Promise<void> {
        await this.db
            .deleteFrom("permissions")
            .where("resourceID", "=", resourceID)
            .execute();
    }

    public async deleteServer(serverID: string): Promise<void> {
        await this.db
            .transaction()
            .execute((transaction) =>
                this.deleteServerInTransaction(transaction, serverID),
            );
        this.emojiListByServerCache.delete(serverID);
    }

    public async enqueueFederationRoomOutbox(
        entry: Omit<FederationRoomOutboxEntry, "attempts">,
    ): Promise<void> {
        await this.db
            .insertInto("federation_room_outbox")
            .values({ ...entry, attempts: 0 })
            .onConflict((conflict) => conflict.column("eventId").doNothing())
            .execute();
    }

    public async failFederationRoomOutbox(
        eventId: string,
        attempts: number,
        nextAttemptAt: number,
    ): Promise<void> {
        await this.db
            .updateTable("federation_room_outbox")
            .set({ attempts, nextAttemptAt })
            .where("eventId", "=", eventId)
            .execute();
    }

    /**
     * Dev-only snapshot of SQLite files + pragmas (same process as Spire).
     * Not for production callers.
     */
    public getDevSqliteMonitor(): Record<string, unknown> {
        const openedAs = this.rawSqlite.name;
        const absPath =
            openedAs === ":memory:"
                ? ":memory:"
                : path.isAbsolute(openedAs)
                  ? openedAs
                  : path.resolve(process.cwd(), openedAs);

        const journalMode = this.rawSqlite.pragma("journal_mode", {
            simple: true,
        });
        const synchronous = this.rawSqlite.pragma("synchronous", {
            simple: true,
        });
        const busyTimeout = this.rawSqlite.pragma("busy_timeout", {
            simple: true,
        });
        const cacheSize = this.rawSqlite.pragma("cache_size", { simple: true });
        const pageCount = this.rawSqlite.pragma("page_count", { simple: true });
        const pageSize = this.rawSqlite.pragma("page_size", { simple: true });
        const freelistCount = this.rawSqlite.pragma("freelist_count", {
            simple: true,
        });

        const out: Record<string, unknown> = {
            absPath,
            busyTimeout,
            cacheSize,
            freelistCount,
            journalMode,
            openedAs,
            pageCount,
            pageSize,
            synchronous,
        };

        if (openedAs !== ":memory:") {
            const filePaths = {
                main: absPath,
                shm: `${absPath}-shm`,
                wal: `${absPath}-wal`,
            };
            out["filePaths"] = filePaths;
            const sizes: Record<string, number> = {};
            for (const [label, fp] of Object.entries(filePaths)) {
                try {
                    sizes[label] = statSync(fp).size;
                } catch {
                    sizes[label] = 0;
                }
            }
            out["fileBytes"] = sizes;
        }

        return out;
    }

    public async getKeyBundle(deviceID: string): Promise<KeyBundle | null> {
        const device = await this.retrieveDevice(deviceID);
        if (!device) {
            throw new Error("DeviceID not found.");
        }
        const otk = (await this.getOTK(deviceID)) || undefined;
        const preKey = await this.getPreKeys(deviceID);
        if (!preKey) {
            throw new Error("Failed to get prekey.");
        }
        const keyBundle: KeyBundle = {
            otk,
            preKey,
            signKey: XUtils.decodeHex(device.signKey),
        };
        return keyBundle;
    }

    public async getOTK(deviceID: string): Promise<null | PreKeysWS> {
        // Atomic select-then-delete inside a transaction so two concurrent
        // callers cannot dispense the same one-time key.
        return this.db.transaction().execute(async (trx) => {
            const rows: PreKeysSQL[] = await trx
                .selectFrom("oneTimeKeys")
                .selectAll()
                .where("deviceID", "=", deviceID)
                .orderBy("index")
                .limit(1)
                .execute();
            const otkInfo = rows[0];
            if (!otkInfo) {
                return null;
            }

            await trx
                .deleteFrom("oneTimeKeys")
                .where("deviceID", "=", deviceID)
                .where("index", "=", otkInfo.index)
                .execute();

            return {
                deviceID: otkInfo.deviceID,
                index: otkInfo.index,
                publicKey: XUtils.decodeHex(otkInfo.publicKey),
                signature: XUtils.decodeHex(otkInfo.signature),
            };
        });
    }

    public async getOTKCount(deviceID: string): Promise<number> {
        const result = await this.db
            .selectFrom("oneTimeKeys")
            .select((eb) => eb.fn.countAll().as("count"))
            .where("deviceID", "=", deviceID)
            .executeTakeFirst();
        return Number(result?.count ?? 0);
    }

    public async getPreKeys(deviceID: string): Promise<null | PreKeysWS> {
        const rows: PreKeysSQL[] = await this.db
            .selectFrom("preKeys")
            .selectAll()
            .where("deviceID", "=", deviceID)
            .execute();
        const preKeyInfo = rows[0];
        if (!preKeyInfo) {
            return null;
        }
        const preKey: PreKeysWS = {
            deviceID: preKeyInfo.deviceID,
            index: preKeyInfo.index,
            publicKey: XUtils.decodeHex(preKeyInfo.publicKey),
            signature: XUtils.decodeHex(preKeyInfo.signature),
        };
        return preKey;
    }

    public async getRequestsTotal(): Promise<number> {
        const row = await this.db
            .selectFrom("service_metrics")
            .select("metric_value")
            .where("metric_key", "=", "requests_total")
            .executeTakeFirst();
        const raw = row?.metric_value;
        const count = Number(raw);
        if (!Number.isFinite(count) || count < 0) {
            return 0;
        }
        return count;
    }

    public async hasMail(
        nonce: Uint8Array,
        deviceID: string,
    ): Promise<boolean> {
        const row = await this.db
            .selectFrom("mail")
            .select("nonce")
            .where("nonce", "=", XUtils.encodeHex(nonce))
            .where((expression) =>
                expression.or([
                    expression("deliveryDeviceID", "=", deviceID),
                    expression.and([
                        expression("deliveryDeviceID", "is", null),
                        expression("recipient", "=", deviceID),
                    ]),
                ]),
            )
            .limit(1)
            .executeTakeFirst();
        return row !== undefined;
    }

    public async incrementRequestsTotal(by = 1): Promise<void> {
        if (!Number.isFinite(by) || by <= 0) {
            return;
        }
        await this.db
            .updateTable("service_metrics")
            .set({
                metric_value: sql`metric_value + ${Math.floor(by)}`,
            })
            .where("metric_key", "=", "requests_total")
            .execute();
    }

    public async initializeHomeserverMigrationManifest(
        migrationId: string,
        manifest: string,
        mailCutoffAt: number,
    ): Promise<StoredHomeserverMigration> {
        return this.db.transaction().execute(async (transaction) => {
            await transaction
                .updateTable("homeserver_migrations")
                .set({ mailCutoffAt, manifest })
                .where("migrationId", "=", migrationId)
                .where("manifest", "is", null)
                .execute();
            const row = await transaction
                .selectFrom("homeserver_migrations")
                .selectAll()
                .where("migrationId", "=", migrationId)
                .executeTakeFirst();
            if (!row) throw new Error("Homeserver migration disappeared.");
            return row;
        });
    }

    public async isDevicePasskeyApproved(
        userID: string,
        deviceID: string,
    ): Promise<boolean> {
        const row = await this.db
            .selectFrom("device_passkey_approvals")
            .select("deviceID")
            .where("userID", "=", userID)
            .where("deviceID", "=", deviceID)
            .limit(1)
            .executeTakeFirst();
        return row !== undefined;
    }

    public async isHealthy(): Promise<boolean> {
        try {
            await sql`select 1 as ok`.execute(this.db);
            return true;
        } catch (_err: unknown) {
            // debugger: health check failed
            return false;
        }
    }

    public async markDeviceLogin(device: Device): Promise<void> {
        await this.db
            .updateTable("devices")
            .set({ lastLogin: new Date().toISOString() })
            .where("deviceID", "=", device.deviceID)
            .execute();
    }

    /**
     * Bump the WebAuthn signature counter and lastUsedAt timestamp
     * after a successful assertion. The counter is monotonic per the
     * WebAuthn spec (FIDO authenticators that report 0 signal they
     * don't track a counter — callers should treat 0→0 as legitimate).
     */
    public async markPasskeyUsed(
        passkeyID: string,
        expectedSignCount: number,
        signCount: number,
    ): Promise<boolean> {
        const result = await this.db
            .updateTable("passkeys")
            .set({
                lastUsedAt: new Date().toISOString(),
                signCount,
            })
            .where("passkeyID", "=", passkeyID)
            .where("signCount", "=", expectedSignCount)
            .executeTakeFirst();
        return Number(result.numUpdatedRows) > 0;
    }

    public async markUserSeen(user: UserRecord): Promise<void> {
        await this.db
            .updateTable("users")
            .set({ lastSeen: new Date().toISOString() })
            .where("userID", "=", user.userID)
            .execute();
    }

    /** Deletes server-side mail older than the configured retention window. */
    public async pruneExpiredMail(): Promise<void> {
        const cutoff = serverMailRetentionCutoffIso();
        await this.db
            .deleteFrom("mail")
            .where("time", "<", cutoff)
            .executeTakeFirst();
    }

    public async recalculateStoreEntitlements(
        userID: string,
    ): Promise<AccountEntitlements> {
        const subscriptions = await this.retrieveBillingSubscriptions(userID);
        const nowMs = Date.now();
        const active = subscriptions
            .filter((subscription) =>
                billingStatusCarriesEntitlement(subscription.status),
            )
            .filter((subscription) => {
                if (!subscription.expiresAt) {
                    return true;
                }
                const expiresAtMs = Date.parse(subscription.expiresAt);
                return Number.isFinite(expiresAtMs) && expiresAtMs > nowMs;
            })
            .sort((a, b) => {
                const tierDelta =
                    accountTierRank(b.tier) - accountTierRank(a.tier);
                if (tierDelta !== 0) {
                    return tierDelta;
                }
                return expiryRank(b.expiresAt) - expiryRank(a.expiresAt);
            });

        const best = active[0];
        if (best) {
            return this.setAccountEntitlementTier(userID, best.tier, {
                expiresAt: best.expiresAt,
                source: "store",
            });
        }

        const current = await this.retrieveAccountEntitlements(userID);
        if (current.source !== "store") {
            return current;
        }

        return this.setAccountEntitlementTier(userID, "free", {
            expiresAt: null,
            source: "store",
        });
    }

    public async recordStoreTransaction(
        input: StoreTransactionRecordInput,
    ): Promise<void> {
        const subscription = await this.db
            .selectFrom("billing_store_subscriptions")
            .selectAll()
            .where("subscriptionID", "=", input.subscriptionID)
            .limit(1)
            .executeTakeFirstOrThrow();

        await this.db
            .insertInto("billing_store_transactions")
            .values({
                environment: subscription.environment,
                eventType: input.eventType,
                externalTransactionID: input.externalTransactionID ?? null,
                platform: subscription.platform,
                processedAt: new Date().toISOString(),
                purchaseTokenHash: subscription.purchaseTokenHash,
                rawPayload: JSON.stringify(input.rawPayload),
                storeProductID: subscription.storeProductID,
                subscriptionID: input.subscriptionID,
                transactionID: crypto.randomUUID(),
                userID: input.userID,
            })
            .execute();
    }

    public async recoverDevice(
        owner: string,
        payload: DevicePayload,
        passkeyApproval?: DevicePasskeyApprovalInput,
    ): Promise<{ device: Device; revokedDeviceIDs: string[] }> {
        const now = new Date().toISOString();
        const device = {
            deleted: 0,
            deviceID: crypto.randomUUID(),
            lastLogin: now,
            name: payload.deviceName,
            owner,
            signKey: payload.signKey,
        };
        const medPreKeys = {
            deviceID: device.deviceID,
            index: payload.preKeyIndex,
            keyID: crypto.randomUUID(),
            publicKey: payload.preKey,
            signature: payload.preKeySignature,
            userID: owner,
        };

        return this.db.transaction().execute(async (trx) => {
            const activeRows = await trx
                .selectFrom("devices")
                .select("deviceID")
                .where("owner", "=", owner)
                .where("deleted", "=", 0)
                .execute();
            const revokedDeviceIDs = activeRows.map((row) => row.deviceID);

            await trx.insertInto("devices").values(device).execute();
            await trx.insertInto("preKeys").values(medPreKeys).execute();
            if (passkeyApproval) {
                await trx
                    .insertInto("device_passkey_approvals")
                    .values({
                        approvedAt: now,
                        approvedByDeviceID:
                            passkeyApproval.approvedByDeviceID ?? null,
                        approvedByPasskeyID:
                            passkeyApproval.approvedByPasskeyID,
                        deviceID: device.deviceID,
                        userID: owner,
                    })
                    .onConflict((oc) =>
                        oc.column("deviceID").doUpdateSet({
                            approvedAt: now,
                            approvedByDeviceID:
                                passkeyApproval.approvedByDeviceID ?? null,
                            approvedByPasskeyID:
                                passkeyApproval.approvedByPasskeyID,
                            userID: owner,
                        }),
                    )
                    .execute();
            }

            if (revokedDeviceIDs.length > 0) {
                await trx
                    .deleteFrom("preKeys")
                    .where("deviceID", "in", revokedDeviceIDs)
                    .execute();
                await trx
                    .deleteFrom("oneTimeKeys")
                    .where("deviceID", "in", revokedDeviceIDs)
                    .execute();
                await trx
                    .deleteFrom("notification_subscriptions")
                    .where("deviceID", "in", revokedDeviceIDs)
                    .execute();
                await trx
                    .deleteFrom("device_passkey_approvals")
                    .where("deviceID", "in", revokedDeviceIDs)
                    .execute();
                await trx
                    .updateTable("devices")
                    .set({ deleted: 1 })
                    .where("deviceID", "in", revokedDeviceIDs)
                    .execute();
            }

            return {
                device: toDevice(device),
                revokedDeviceIDs,
            };
        });
    }

    public async rehashPassword(
        userID: string,
        newHash: string,
    ): Promise<void> {
        await this.db
            .updateTable("users")
            .set({
                passwordHash: newHash,
            })
            .where("userID", "=", userID)
            .execute();
    }

    public async removeFederatedRoomMirror(
        marker: {
            homeserverId: string;
            revision: string;
            serverId: string;
        },
        removedAt = Date.now(),
    ): Promise<boolean> {
        return this.applyFederatedRoomAbsence(marker, false, removedAt);
    }

    public async removeNotificationSubscription(args: {
        deviceID: string;
        subscriptionID: string;
        userID: string;
    }): Promise<boolean> {
        const result = await this.db
            .deleteFrom("notification_subscriptions")
            .where("subscriptionID", "=", args.subscriptionID)
            .where("deviceID", "=", args.deviceID)
            .where("userID", "=", args.userID)
            .executeTakeFirst();

        return Number(result.numDeletedRows) > 0;
    }

    public async replacePreKey(
        userID: string,
        deviceID: string,
        preKey: PreKeysWS,
    ): Promise<void> {
        const newPreKey = {
            deviceID,
            index: preKey.index ?? 0,
            keyID: crypto.randomUUID(),
            publicKey: XUtils.encodeHex(preKey.publicKey),
            signature: XUtils.encodeHex(preKey.signature),
            userID,
        };
        await this.db.transaction().execute(async (trx) => {
            await trx
                .deleteFrom("preKeys")
                .where("deviceID", "=", deviceID)
                .execute();
            await trx.insertInto("preKeys").values(newPreKey).execute();
        });
    }

    public async retrieveAccountEntitlements(
        userID: string,
    ): Promise<AccountEntitlements> {
        const row = await this.db
            .selectFrom("account_entitlements")
            .selectAll()
            .where("userID", "=", userID)
            .limit(1)
            .executeTakeFirst();

        if (!row) {
            return buildAccountEntitlements({ userID });
        }

        return buildAccountEntitlements({
            expiresAt: row.expiresAt,
            refreshedAt: row.updatedAt,
            source: parseAccountEntitlementSource(row.source),
            tier: parseAccountTier(row.tier),
            userID,
        });
    }

    /**
     * Retrives a list of users that should be notified when a specific resourceID
     * experiences changes.
     *
     * @param resourceID
     */
    public async retrieveAffectedUsers(
        resourceID: string,
    ): Promise<UserRecord[]> {
        const permissionList =
            await this.retrievePermissionsByResourceID(resourceID);

        const users: UserRecord[] = [];
        for (const permission of permissionList) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                users.push(user);
            }
        }

        return users;
    }

    public async retrieveBillingAccountState(
        userID: string,
    ): Promise<BillingAccountState> {
        return {
            entitlements: await this.retrieveAccountEntitlements(userID),
            subscriptions: await this.retrieveBillingSubscriptions(userID),
        };
    }

    public async retrieveBillingSubscriptions(
        userID: string,
    ): Promise<BillingSubscription[]> {
        const rows = await this.db
            .selectFrom("billing_store_subscriptions")
            .selectAll()
            .where("userID", "=", userID)
            .orderBy("updatedAt", "desc")
            .execute();

        return rows.map(toBillingSubscription);
    }

    public async retrieveChannel(channelID: string): Promise<Channel | null> {
        const channels: Channel[] = await this.db
            .selectFrom("channels")
            .selectAll()
            .where("channelID", "=", channelID)
            .limit(1)
            .execute();

        return channels[0] ?? null;
    }

    public async retrieveChannels(serverID: string): Promise<Channel[]> {
        const channels: Channel[] = await this.db
            .selectFrom("channels")
            .selectAll()
            .where("serverID", "=", serverID)
            .execute();
        return channels;
    }

    public async retrieveDevice(deviceID: string): Promise<Device | null> {
        if (uuidValidate(deviceID)) {
            const rows = await this.db
                .selectFrom("devices")
                .selectAll()
                .where("deviceID", "=", deviceID)
                .where("deleted", "=", 0)
                .execute();

            const device = rows[0];
            return device ? toDevice(device) : null;
        }
        if (pubkeyRegex.test(deviceID)) {
            const rows = await this.db
                .selectFrom("devices")
                .selectAll()
                .where("signKey", "=", deviceID)
                .where("deleted", "=", 0)
                .execute();
            const device = rows[0];
            return device ? toDevice(device) : null;
        }
        return null;
    }

    public async retrieveEmoji(emojiID: string): Promise<Emoji | null> {
        const rows = await this.db
            .selectFrom("emojis")
            .selectAll()
            .where("emojiID", "=", emojiID)
            .execute();
        return rows[0] ?? null;
    }

    public async retrieveEmojiList(serverID: string): Promise<Emoji[]> {
        const now = Date.now();
        const hit = this.emojiListByServerCache.get(serverID);
        if (hit && hit.until > now) {
            return hit.rows.map((r) => ({ ...r }));
        }

        const rows: Emoji[] = await this.db
            .selectFrom("emojis")
            .selectAll()
            .where("owner", "=", serverID)
            .execute();

        this.emojiListByServerCache.set(serverID, {
            rows: rows.map((r) => ({ ...r })),
            until: now + Database.EMOJI_LIST_CACHE_TTL_MS,
        });

        return rows.map((r) => ({ ...r }));
    }

    public async retrieveFederationRoomOutbox(
        now: number,
        limit = 50,
    ): Promise<FederationRoomOutboxEntry[]> {
        const rows = await this.db
            .selectFrom("federation_room_outbox")
            .selectAll()
            .where("nextAttemptAt", "<=", now)
            .orderBy("createdAt", "asc")
            .limit(limit)
            .execute();
        return rows.flatMap((row) =>
            row.kind === "deletion" || row.kind === "snapshot"
                ? [{ ...row, kind: row.kind }]
                : [],
        );
    }

    public async retrieveFederationRoomTombstone(
        serverId: string,
    ): Promise<FederationRoomTombstone | null> {
        const row = await this.db
            .selectFrom("federation_room_tombstones")
            .selectAll()
            .where("serverId", "=", serverId)
            .executeTakeFirst();
        return row
            ? {
                  ...row,
                  permanent: row.permanent === 1,
                  revision: String(row.revision),
              }
            : null;
    }

    public async retrieveFile(fileID: string): Promise<FileSQL | null> {
        const file = await this.db
            .selectFrom("files")
            .selectAll()
            .where("fileID", "=", fileID)
            .execute();
        return file[0] ?? null;
    }

    public async retrieveFilesByOwners(ownerIDs: string[]): Promise<FileSQL[]> {
        if (ownerIDs.length === 0) return [];
        return this.db
            .selectFrom("files")
            .selectAll()
            .where("owner", "in", ownerIDs)
            .orderBy("fileID")
            .execute();
    }

    public async retrieveGroupMembers(
        channelID: string,
    ): Promise<UserRecord[]> {
        const channel = await this.retrieveChannel(channelID);
        if (!channel) {
            return [];
        }
        const permissions: Permission[] = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("resourceID", "=", channel.serverID)
            .execute();

        const groupMembers: UserRecord[] = [];
        for (const permission of permissions) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                groupMembers.push(user);
            }
        }

        return groupMembers;
    }

    public async retrieveHomeserverMigration(
        migrationId: string,
    ): Promise<null | StoredHomeserverMigration> {
        return (
            (await this.db
                .selectFrom("homeserver_migrations")
                .selectAll()
                .where("migrationId", "=", migrationId)
                .executeTakeFirst()) ?? null
        );
    }

    public async retrieveInvite(inviteID: string): Promise<Invite | null> {
        const rows = await this.db
            .selectFrom("invites")
            .selectAll()
            .where("inviteID", "=", inviteID)
            .execute();
        return rows[0] ?? null;
    }

    public async retrieveMail(
        deviceID: string,
    ): Promise<[Uint8Array, MailWS, string][]> {
        const cutoff = serverMailRetentionCutoffIso();
        const rawRows = await this.db
            .selectFrom("mail")
            .selectAll()
            .where((expression) =>
                expression.or([
                    expression("deliveryDeviceID", "=", deviceID),
                    expression.and([
                        expression("deliveryDeviceID", "is", null),
                        expression("recipient", "=", deviceID),
                    ]),
                ]),
            )
            .where("time", ">=", cutoff)
            .orderBy("time", "asc")
            .orderBy("sender", "asc")
            .orderBy("mailType", "asc")
            .execute();
        const rows: MailSQL[] = rawRows.map(toMailSQL);

        const fixMail: (mail: MailSQL) => [Uint8Array, MailWS, string] = (
            mail,
        ) => {
            const msgb: MailWS = {
                authorID: mail.authorID,
                cipher: XUtils.decodeHex(mail.cipher),
                extra: XUtils.decodeHex(mail.extra),
                forward: mail.forward,
                group: mail.group ? XUtils.decodeHex(mail.group) : null,
                mailID: mail.mailID,
                mailType: mail.mailType,
                nonce: XUtils.decodeHex(mail.nonce),
                readerID: mail.readerID,
                recipient: mail.recipient,
                sender: mail.sender,
            };

            const msgh = XUtils.decodeHex(mail.header);
            return [msgh, msgb, mail.time];
        };

        const allMail = rows.map(fixMail);

        return allMail;
    }

    public async retrieveMigrationDevices(
        accountId: string,
    ): Promise<Device[]> {
        const rows = await this.db
            .selectFrom("devices")
            .selectAll()
            .where("owner", "=", accountId)
            .execute();
        return rows.map(toDevice);
    }

    public async retrieveMigrationMail(
        accountId: string,
        recipientDeviceIds: string[],
        createdBefore: string,
        offset: number,
        limit: number,
    ): Promise<
        {
            deliveryDeviceId: string;
            header: Uint8Array;
            mail: MailWS;
            time: string;
        }[]
    > {
        if (recipientDeviceIds.length === 0) return [];
        const rows = await this.db
            .selectFrom("mail")
            .selectAll()
            .where("readerID", "=", accountId)
            .where((expression) =>
                expression.or([
                    expression("deliveryDeviceID", "in", recipientDeviceIds),
                    expression.and([
                        expression("deliveryDeviceID", "is", null),
                        expression("recipient", "in", recipientDeviceIds),
                    ]),
                ]),
            )
            .where("time", ">=", serverMailRetentionCutoffIso())
            .where("time", "<=", createdBefore)
            .orderBy("time", "asc")
            .orderBy("mailID", "asc")
            .offset(offset)
            .limit(limit)
            .execute();
        return rows.map((row) => {
            const mail = toMailSQL(row);
            return {
                deliveryDeviceId: row.deliveryDeviceID ?? mail.recipient,
                header: XUtils.decodeHex(mail.header),
                mail: {
                    authorID: mail.authorID,
                    cipher: XUtils.decodeHex(mail.cipher),
                    extra: XUtils.decodeHex(mail.extra),
                    forward: mail.forward,
                    group: mail.group ? XUtils.decodeHex(mail.group) : null,
                    mailID: mail.mailID,
                    mailType: mail.mailType,
                    nonce: XUtils.decodeHex(mail.nonce),
                    readerID: mail.readerID,
                    recipient: mail.recipient,
                    sender: mail.sender,
                },
                time: mail.time,
            };
        });
    }

    public async retrieveNotificationSubscriptions(args: {
        deviceID?: string;
        event: string;
        userID: string;
    }): Promise<NotificationSubscription[]> {
        let query = this.db
            .selectFrom("notification_subscriptions")
            .selectAll()
            .where("userID", "=", args.userID)
            .where("enabled", "=", 1);

        if (args.deviceID) {
            query = query.where("deviceID", "=", args.deviceID);
        }

        const rows = await query.execute();
        return rows
            .map(toNotificationSubscription)
            .filter(
                (sub) =>
                    sub.events.includes("*") || sub.events.includes(args.event),
            );
    }

    /**
     * Look up a passkey row by its WebAuthn credentialID. Used during
     * the assertion verification step of `/auth/passkey/finish`.
     */
    public async retrievePasskeyByCredentialID(
        credentialID: string,
    ): Promise<null | PasskeyRow> {
        const rows = await this.db
            .selectFrom("passkeys")
            .selectAll()
            .where("credentialID", "=", credentialID)
            .limit(1)
            .execute();
        return rows[0] ?? null;
    }

    /**
     * Look up a passkey row including server-only fields (publicKey,
     * algorithm, signCount). For listing back to clients prefer
     * {@link retrievePasskeysByUser}, which only returns the public
     * shape.
     */
    public async retrievePasskeyInternal(
        passkeyID: string,
    ): Promise<null | PasskeyRow> {
        const rows = await this.db
            .selectFrom("passkeys")
            .selectAll()
            .where("passkeyID", "=", passkeyID)
            .limit(1)
            .execute();
        return rows[0] ?? null;
    }

    /**
     * List all passkeys belonging to `userID` in their public form
     * (no key material).
     */
    public async retrievePasskeysByUser(userID: string): Promise<Passkey[]> {
        const rows = await this.db
            .selectFrom("passkeys")
            .selectAll()
            .where("userID", "=", userID)
            .execute();
        return rows.map(toPasskey);
    }

    public async retrievePermission(
        permissionID: string,
    ): Promise<null | Permission> {
        const rows = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("permissionID", "=", permissionID)
            .execute();

        return rows[0] ?? null;
    }

    public async retrievePermissions(
        userID: string,
        resourceType: string,
    ): Promise<Permission[]> {
        if (resourceType === "all") {
            const sList = await this.db
                .selectFrom("permissions")
                .selectAll()
                .where("userID", "=", userID)
                .execute();
            return sList;
        }
        const serverList = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("userID", "=", userID)
            .where("resourceType", "=", resourceType)
            .execute();
        return serverList;
    }

    public async retrievePermissionsByResourceID(
        resourceID: string,
    ): Promise<Permission[]> {
        return this.db
            .selectFrom("permissions")
            .selectAll()
            .where("resourceID", "=", resourceID)
            .execute();
    }

    public async retrieveRoomSnapshot(
        serverID: string,
    ): Promise<FederationRoomSnapshot | null> {
        const server = await this.retrieveServer(serverID);
        if (!server?.homeserverId || !server.revision) return null;
        const [channels, permissions] = await Promise.all([
            this.retrieveChannels(serverID),
            this.retrievePermissionsByResourceID(serverID),
        ]);
        const members = new Map<string, Permission>();
        for (const permission of permissions) {
            const current = members.get(permission.userID);
            if (!current || current.powerLevel < permission.powerLevel) {
                members.set(permission.userID, permission);
            }
        }
        return {
            channels,
            members: [...members.values()].map((permission) => ({
                permissionId: permission.permissionID,
                powerLevel: permission.powerLevel,
                userId: permission.userID,
            })),
            revision: server.revision,
            server,
        };
    }

    public async retrieveServer(serverID: string): Promise<null | Server> {
        const rows = await this.db
            .selectFrom("servers")
            .selectAll()
            .where("serverID", "=", serverID)
            .limit(1)
            .execute();
        const row = rows[0];
        return row ? toServer(row) : null;
    }

    public async retrieveServerByIcon(icon: string): Promise<null | Server> {
        const row = await this.db
            .selectFrom("servers")
            .selectAll()
            .where("icon", "=", icon)
            .limit(1)
            .executeTakeFirst();
        return row ? toServer(row) : null;
    }

    public async retrieveServerChannelBootstrap(userID: string): Promise<{
        channelsByServer: Record<string, Channel[]>;
        servers: Server[];
    }> {
        const serverPerms = await this.retrievePermissions(userID, "server");
        const serverIDs = [
            ...new Set(serverPerms.map((perm) => perm.resourceID)),
        ];
        if (serverIDs.length === 0) {
            return { channelsByServer: {}, servers: [] };
        }

        const [serverRows, channels] = await Promise.all([
            this.db
                .selectFrom("servers")
                .selectAll()
                .where("serverID", "in", serverIDs)
                .execute(),
            this.db
                .selectFrom("channels")
                .selectAll()
                .where("serverID", "in", serverIDs)
                .execute(),
        ]);

        const servers = serverRows.map(toServer);
        const channelsByServer: Record<string, Channel[]> = {};
        for (const serverID of serverIDs) {
            channelsByServer[serverID] = [];
        }
        for (const channel of channels) {
            const existing = channelsByServer[channel.serverID];
            if (existing) {
                existing.push(channel);
            } else {
                channelsByServer[channel.serverID] = [channel];
            }
        }

        return { channelsByServer, servers };
    }

    public async retrieveServerInvites(serverID: string): Promise<Invite[]> {
        const rows = await this.db
            .selectFrom("invites")
            .selectAll()
            .where("serverID", "=", serverID)
            .execute();

        const nowMs = Date.now();
        const expiredIds: string[] = [];
        const valid: Invite[] = [];
        for (const row of rows) {
            const expMs = new Date(row.expiration).getTime();
            if (!Number.isFinite(expMs) || expMs <= nowMs) {
                expiredIds.push(row.inviteID);
                continue;
            }
            valid.push(row);
        }
        if (expiredIds.length > 0) {
            await this.db
                .deleteFrom("invites")
                .where("serverID", "=", serverID)
                .where("inviteID", "in", expiredIds)
                .execute();
        }
        return valid;
    }

    public async retrieveServers(userID: string): Promise<Server[]> {
        const serverPerms = await this.retrievePermissions(userID, "server");
        const serverIDs = [
            ...new Set(serverPerms.map((perm) => perm.resourceID)),
        ];
        if (serverIDs.length === 0) {
            return [];
        }
        const rows = await this.db
            .selectFrom("servers")
            .selectAll()
            .where("serverID", "in", serverIDs)
            .execute();
        return rows.map(toServer);
    }

    public async retrieveStoreSubscriptionOwner(args: {
        environment: BillingEnvironment;
        externalOriginalID?: null | string | undefined;
        platform: BillingPlatform;
        purchaseToken?: null | string | undefined;
    }): Promise<null | string> {
        const purchaseTokenHash = args.purchaseToken
            ? billingPurchaseTokenHash(
                  args.platform,
                  args.environment,
                  args.purchaseToken,
              )
            : null;
        const existing = await this.findExistingStoreSubscription({
            environment: args.environment,
            externalOriginalID: args.externalOriginalID ?? null,
            platform: args.platform,
            purchaseTokenHash,
        });
        if (!existing) {
            return null;
        }
        const row = await this.db
            .selectFrom("billing_store_subscriptions")
            .select(["userID"])
            .where("subscriptionID", "=", existing.subscriptionID)
            .limit(1)
            .executeTakeFirst();
        return row?.userID ?? null;
    }

    // The identifier is matched as either a userID or the canonical lowercase
    // username stored by `normalizeRegistrationUsername`.
    public async retrieveUser(
        userIdentifier: string,
    ): Promise<InternalUserRecord | null> {
        let rows;
        if (
            uuidValidate(userIdentifier) ||
            accountIdRegex.test(userIdentifier)
        ) {
            rows = await this.db
                .selectFrom("users")
                .selectAll()
                .where(
                    "userID",
                    "=",
                    accountIdRegex.test(userIdentifier)
                        ? userIdentifier.toLowerCase()
                        : userIdentifier,
                )
                .limit(1)
                .execute();
        } else {
            const normalized = userIdentifier.trim().toLowerCase();
            rows = await this.db
                .selectFrom("users")
                .selectAll()
                .where("username", "=", normalized)
                .limit(1)
                .execute();
        }

        const row = rows[0];
        return row ? toUserRecord(row) : null;
    }

    /**
     * All devices for the given user ID(s), **no in-process cache** — a prior
     * 10s TTL was removed: concurrent GET + POST could end with a stale
     * snapshot overwriting the map after a new device was inserted (automation
     * and `POST /user/:id/devices` must see a fresh list on the next read).
     */
    public async retrieveUserDeviceList(userIDs: string[]): Promise<Device[]> {
        const rows = await this.db
            .selectFrom("devices")
            .selectAll()
            .where("owner", "in", userIDs)
            .where("deleted", "=", 0)
            .execute();
        return rows.map(toDevice);
    }

    public async retrieveUsers(): Promise<InternalUserRecord[]> {
        const rows = await this.db.selectFrom("users").selectAll().execute();
        return rows.map(toUserRecord);
    }

    public async saveFederatedMail(
        mail: MailWS,
        header: Uint8Array,
    ): Promise<boolean> {
        const entry = this.mailSqlEntry(
            mail,
            header,
            mail.sender,
            mail.authorID,
        );
        const result = await this.db
            .insertInto("mail")
            .values({
                ...entry,
                forward: entry.forward ? 1 : 0,
                time: entry.time,
            })
            .onConflict((conflict) => conflict.column("nonce").doNothing())
            .executeTakeFirst();
        return result.numInsertedOrUpdatedRows === 1n;
    }

    public async saveFederatedRoom(
        snapshot: FederationRoomSnapshot,
        permission: Permission,
    ): Promise<void> {
        const { homeserverId, revision } = snapshot.server;
        if (!homeserverId || !revision) {
            throw new Error("Federated room authority is missing.");
        }
        if (
            permission.resourceType !== "server" ||
            permission.resourceID !== snapshot.server.serverID ||
            snapshot.members.find(
                (member) => member.userId === permission.userID,
            )?.permissionId !== permission.permissionID ||
            snapshot.members.find(
                (member) => member.userId === permission.userID,
            )?.powerLevel !== permission.powerLevel
        ) {
            throw new Error(
                "Federated room permission does not match the server.",
            );
        }
        const incomingRevision = Number(revision);
        if (!Number.isSafeInteger(incomingRevision) || incomingRevision < 1) {
            throw new Error("Federated room revision is invalid.");
        }

        await this.db.transaction().execute(async (transaction) => {
            const tombstone = await transaction
                .selectFrom("federation_room_tombstones")
                .selectAll()
                .where("serverId", "=", snapshot.server.serverID)
                .executeTakeFirst();
            if (tombstone) {
                if (tombstone.homeserverId !== homeserverId) {
                    throw new Error(
                        "Federated room tombstone authority changed.",
                    );
                }
                if (tombstone.permanent === 1) {
                    throw new Error("Federated room was permanently deleted.");
                }
                if (incomingRevision <= tombstone.revision) return;
            }
            const existingServer = await transaction
                .selectFrom("servers")
                .selectAll()
                .where("serverID", "=", snapshot.server.serverID)
                .executeTakeFirst();
            if (
                existingServer &&
                existingServer.homeserverId !== homeserverId
            ) {
                throw new Error(
                    "Federated room authority cannot change off-chain.",
                );
            }
            const shouldApplySnapshot =
                !existingServer || existingServer.revision < incomingRevision;
            if (!shouldApplySnapshot) return;
            if (tombstone) {
                await transaction
                    .deleteFrom("federation_room_tombstones")
                    .where("serverId", "=", snapshot.server.serverID)
                    .execute();
            }
            await transaction
                .insertInto("servers")
                .values({
                    homeserverId,
                    icon: snapshot.server.icon ?? null,
                    name: snapshot.server.name,
                    revision: incomingRevision,
                    serverID: snapshot.server.serverID,
                })
                .onConflict((conflict) =>
                    conflict.column("serverID").doUpdateSet({
                        homeserverId,
                        icon: snapshot.server.icon ?? null,
                        name: snapshot.server.name,
                        revision: incomingRevision,
                    }),
                )
                .execute();
            await transaction
                .deleteFrom("channels")
                .where("serverID", "=", snapshot.server.serverID)
                .execute();
            if (snapshot.channels.length > 0) {
                await transaction
                    .insertInto("channels")
                    .values(snapshot.channels)
                    .execute();
            }

            await transaction
                .deleteFrom("permissions")
                .where("resourceType", "=", "server")
                .where("resourceID", "=", snapshot.server.serverID)
                .execute();
            await transaction
                .insertInto("permissions")
                .values(
                    snapshot.members.map((member) => ({
                        permissionID: member.permissionId,
                        powerLevel: member.powerLevel,
                        resourceID: snapshot.server.serverID,
                        resourceType: "server",
                        userID: member.userId,
                    })),
                )
                .execute();
        });
    }

    public async saveMail(
        mail: MailWS,
        header: Uint8Array,
        deviceID: string,
        userID: string,
    ): Promise<void> {
        const entry = this.mailSqlEntry(mail, header, deviceID, userID);

        await this.db
            .insertInto("mail")
            .values({
                ...entry,
                forward: entry.forward ? 1 : 0,
                time: entry.time,
            })
            .execute();
    }

    public async saveMailBatch(
        entries: {
            header: Uint8Array;
            mail: MailWS;
            senderDeviceID: string;
            userID: string;
        }[],
    ): Promise<void> {
        if (entries.length === 0) {
            return;
        }

        const now = new Date().toISOString();
        const values = entries.map((entry) => {
            const mail = this.mailSqlEntry(
                entry.mail,
                entry.header,
                entry.senderDeviceID,
                entry.userID,
                now,
            );
            return {
                ...mail,
                forward: mail.forward ? 1 : 0,
                time: mail.time,
            };
        });

        await this.db.insertInto("mail").values(values).execute();
    }

    public async saveMigratedMail(
        mail: MailWS,
        header: Uint8Array,
        time: string,
        deliveryDeviceId: string,
    ): Promise<boolean> {
        const entry = this.mailSqlEntry(
            mail,
            header,
            mail.sender,
            mail.authorID,
            time,
            deliveryDeviceId,
        );
        const result = await this.db
            .insertInto("mail")
            .values({ ...entry, forward: entry.forward ? 1 : 0 })
            .onConflict((conflict) => conflict.column("nonce").doNothing())
            .executeTakeFirst();
        return result.numInsertedOrUpdatedRows === 1n;
    }

    public async saveNotificationSubscription(
        input: SaveNotificationSubscriptionInput,
    ): Promise<NotificationSubscription> {
        const now = new Date().toISOString();
        const events = encodeNotificationEvents(input.events);
        const row = {
            channel: input.channel,
            createdAt: now,
            deviceID: input.deviceID,
            enabled: 1,
            events,
            platform: input.platform ?? null,
            subscriptionID: crypto.randomUUID(),
            token: input.token,
            updatedAt: now,
            userID: input.userID,
        };

        await this.db
            .insertInto("notification_subscriptions")
            .values(row)
            .onConflict((oc) =>
                oc.columns(["channel", "deviceID", "token"]).doUpdateSet({
                    enabled: 1,
                    events,
                    platform: input.platform ?? null,
                    updatedAt: now,
                    userID: input.userID,
                }),
            )
            .execute();

        const saved = await this.db
            .selectFrom("notification_subscriptions")
            .selectAll()
            .where("channel", "=", input.channel)
            .where("deviceID", "=", input.deviceID)
            .where("token", "=", input.token)
            .executeTakeFirstOrThrow();
        return toNotificationSubscription(saved);
    }

    public async saveOTK(
        userID: string,
        deviceID: string,
        otks: PreKeysWS[],
    ): Promise<void> {
        for (const otk of otks) {
            const newOTK = {
                deviceID: otk.deviceID,
                index: otk.index ?? 0,
                keyID: crypto.randomUUID(),
                publicKey: XUtils.encodeHex(otk.publicKey),
                signature: XUtils.encodeHex(otk.signature),
                userID,
            };
            await this.db.insertInto("oneTimeKeys").values(newOTK).execute();
        }
    }

    public async setAccountEntitlementTier(
        userID: string,
        tier: AccountTier,
        options?: {
            expiresAt?: null | string | undefined;
            source?: AccountEntitlementSource | undefined;
        },
    ): Promise<AccountEntitlements> {
        const parsedTier = AccountTierSchema.parse(tier);
        const source = AccountEntitlementSourceSchema.parse(
            options?.source ?? "dev_override",
        );
        const expiresAt = options?.expiresAt ?? null;
        const updatedAt = new Date().toISOString();

        await this.db
            .insertInto("account_entitlements")
            .values({
                expiresAt,
                source,
                tier: parsedTier,
                updatedAt,
                userID,
            })
            .onConflict((oc) =>
                oc.column("userID").doUpdateSet({
                    expiresAt,
                    source,
                    tier: parsedTier,
                    updatedAt,
                }),
            )
            .execute();

        return buildAccountEntitlements({
            expiresAt,
            refreshedAt: updatedAt,
            source,
            tier: parsedTier,
            userID,
        });
    }

    public async updateChannel(
        channelID: string,
        name: string,
    ): Promise<Channel | null> {
        const updated = await this.db
            .transaction()
            .execute(async (transaction) => {
                const channel = await transaction
                    .selectFrom("channels")
                    .selectAll()
                    .where("channelID", "=", channelID)
                    .executeTakeFirst();
                if (!channel) return false;
                await transaction
                    .updateTable("channels")
                    .set({ name })
                    .where("channelID", "=", channelID)
                    .execute();
                await this.incrementServerRevision(
                    transaction,
                    channel.serverID,
                );
                return true;
            });
        if (!updated) return null;
        return this.retrieveChannel(channelID);
    }

    public async updateHomeserverMigrationCompleted(
        migrationId: string,
        completedAt: number,
    ): Promise<void> {
        await this.db
            .updateTable("homeserver_migrations")
            .set({ completedAt })
            .where("migrationId", "=", migrationId)
            .execute();
    }

    public async updatePermissionPowerLevel(
        permissionID: string,
        powerLevel: number,
    ): Promise<null | Permission> {
        const updated = await this.db
            .transaction()
            .execute(async (transaction) => {
                const permission = await transaction
                    .selectFrom("permissions")
                    .selectAll()
                    .where("permissionID", "=", permissionID)
                    .executeTakeFirst();
                if (!permission) return false;
                await transaction
                    .updateTable("permissions")
                    .set({ powerLevel })
                    .where("permissionID", "=", permissionID)
                    .execute();
                if (permission.resourceType === "server") {
                    await this.incrementServerRevision(
                        transaction,
                        permission.resourceID,
                    );
                }
                return true;
            });
        if (!updated) return null;
        return this.retrievePermission(permissionID);
    }

    public async updateServer(
        serverID: string,
        update: { icon?: null | string; name?: string },
    ): Promise<null | Server> {
        const result = await this.db
            .updateTable("servers")
            .set({ ...update, revision: sql<number>`revision + 1` })
            .where("serverID", "=", serverID)
            .executeTakeFirst();
        if (Number(result.numUpdatedRows) === 0) {
            return null;
        }
        return this.retrieveServer(serverID);
    }

    public async upsertMigratedFile(file: FileSQL): Promise<boolean> {
        const result = await this.db
            .insertInto("files")
            .values(file)
            .onConflict((conflict) => conflict.column("fileID").doNothing())
            .executeTakeFirst();
        return result.numInsertedOrUpdatedRows === 1n;
    }

    public async upsertStoreSubscription(
        input: StoreSubscriptionUpsertInput,
    ): Promise<BillingSubscription> {
        const now = new Date().toISOString();
        const purchaseTokenHash = input.purchaseToken
            ? billingPurchaseTokenHash(
                  input.platform,
                  input.environment,
                  input.purchaseToken,
              )
            : null;
        const existing = await this.findExistingStoreSubscription({
            environment: input.environment,
            externalOriginalID: input.externalOriginalID ?? null,
            platform: input.platform,
            purchaseTokenHash,
        });
        const subscriptionID = existing?.subscriptionID ?? crypto.randomUUID();
        const row = {
            environment: input.environment,
            expiresAt: input.expiresAt,
            externalOriginalID: input.externalOriginalID ?? null,
            externalTransactionID: input.externalTransactionID ?? null,
            platform: input.platform,
            productID: input.productID,
            purchaseToken: input.purchaseToken ?? null,
            purchaseTokenHash,
            rawPayload: JSON.stringify(input.rawPayload),
            status: input.status,
            storeProductID: input.storeProductID,
            tier: input.tier,
            updatedAt: now,
            userID: input.userID,
        };

        if (existing) {
            await this.db
                .updateTable("billing_store_subscriptions")
                .set(row)
                .where("subscriptionID", "=", subscriptionID)
                .execute();
        } else {
            await this.db
                .insertInto("billing_store_subscriptions")
                .values({
                    ...row,
                    createdAt: now,
                    subscriptionID,
                })
                .execute();
        }

        const saved = await this.db
            .selectFrom("billing_store_subscriptions")
            .selectAll()
            .where("subscriptionID", "=", subscriptionID)
            .executeTakeFirstOrThrow();

        return toBillingSubscription(saved);
    }

    private async applyFederatedRoomAbsence(
        marker: {
            homeserverId: string;
            revision: string;
            serverId: string;
        },
        permanent: boolean,
        deletedAt: number,
    ): Promise<boolean> {
        const incomingRevision = Number(marker.revision);
        if (!Number.isSafeInteger(incomingRevision) || incomingRevision < 1) {
            throw new Error("Federated room absence revision is invalid.");
        }
        const deleted = await this.db
            .transaction()
            .execute(async (transaction) => {
                const tombstone = await transaction
                    .selectFrom("federation_room_tombstones")
                    .selectAll()
                    .where("serverId", "=", marker.serverId)
                    .executeTakeFirst();
                if (
                    tombstone &&
                    tombstone.homeserverId !== marker.homeserverId
                ) {
                    throw new Error(
                        "Federated room tombstone authority changed.",
                    );
                }

                const server = await transaction
                    .selectFrom("servers")
                    .selectAll()
                    .where("serverID", "=", marker.serverId)
                    .executeTakeFirst();
                if (server && server.homeserverId !== marker.homeserverId) {
                    throw new Error("Federated room authority changed.");
                }
                const currentRevision = Math.max(
                    server?.revision ?? 0,
                    tombstone?.revision ?? 0,
                );
                if (
                    incomingRevision <= currentRevision ||
                    (!permanent && tombstone?.permanent === 1)
                ) {
                    return false;
                }

                const nextPermanent =
                    permanent || tombstone?.permanent === 1 ? 1 : 0;
                await transaction
                    .insertInto("federation_room_tombstones")
                    .values({
                        deletedAt,
                        homeserverId: marker.homeserverId,
                        permanent: nextPermanent,
                        revision: incomingRevision,
                        serverId: marker.serverId,
                    })
                    .onConflict((conflict) =>
                        conflict.column("serverId").doUpdateSet({
                            deletedAt,
                            permanent: nextPermanent,
                            revision: incomingRevision,
                        }),
                    )
                    .execute();
                if (!server) return false;
                await this.deleteServerInTransaction(
                    transaction,
                    marker.serverId,
                );
                return true;
            });
        if (deleted) this.emojiListByServerCache.delete(marker.serverId);
        return deleted;
    }

    private async deleteServerInTransaction(
        transaction: Transaction<ServerDatabase>,
        serverID: string,
    ): Promise<void> {
        const channels = await transaction
            .selectFrom("channels")
            .select("channelID")
            .where("serverID", "=", serverID)
            .execute();
        const channelIDs = channels.map((channel) => channel.channelID);

        await transaction
            .deleteFrom("permissions")
            .where("resourceID", "=", serverID)
            .execute();
        if (channelIDs.length > 0) {
            await transaction
                .deleteFrom("permissions")
                .where("resourceID", "in", channelIDs)
                .execute();
            await transaction
                .deleteFrom("mail")
                .where("group", "in", channelIDs.map(mailGroupForChannel))
                .execute();
        }
        await transaction
            .deleteFrom("invites")
            .where("serverID", "=", serverID)
            .execute();
        await transaction
            .deleteFrom("emojis")
            .where("owner", "=", serverID)
            .execute();
        await transaction
            .deleteFrom("channels")
            .where("serverID", "=", serverID)
            .execute();
        await transaction
            .deleteFrom("servers")
            .where("serverID", "=", serverID)
            .execute();
    }

    private async findExistingStoreSubscription(args: {
        environment: BillingEnvironment;
        externalOriginalID: null | string;
        platform: BillingPlatform;
        purchaseTokenHash: null | string;
    }): Promise<null | { subscriptionID: string }> {
        if (args.externalOriginalID) {
            const byOriginal = await this.db
                .selectFrom("billing_store_subscriptions")
                .select(["subscriptionID"])
                .where("platform", "=", args.platform)
                .where("environment", "=", args.environment)
                .where("externalOriginalID", "=", args.externalOriginalID)
                .limit(1)
                .executeTakeFirst();
            if (byOriginal) {
                return byOriginal;
            }
        }

        if (args.purchaseTokenHash) {
            const byToken = await this.db
                .selectFrom("billing_store_subscriptions")
                .select(["subscriptionID"])
                .where("platform", "=", args.platform)
                .where("environment", "=", args.environment)
                .where("purchaseTokenHash", "=", args.purchaseTokenHash)
                .limit(1)
                .executeTakeFirst();
            if (byToken) {
                return byToken;
            }
        }

        return null;
    }

    private async incrementServerRevision(
        executor: Kysely<ServerDatabase> | Transaction<ServerDatabase>,
        serverID: string,
    ): Promise<string> {
        const result = await executor
            .updateTable("servers")
            .set({ revision: sql<number>`revision + 1` })
            .where("serverID", "=", serverID)
            .returning("revision")
            .executeTakeFirst();
        if (!result) throw new Error("Server not found.");
        return String(result.revision);
    }

    private async init(): Promise<void> {
        const migrator = new Migrator({
            db: this.db,
            provider: new CrossPlatformMigrationProvider(migrationFolder),
        });
        const { error } = await migrator.migrateToLatest();
        if (error) {
            this.emit("error", error);
            return;
        }
        this.emit("ready");
    }

    private async insertDevice(
        trx: Transaction<ServerDatabase>,
        owner: string,
        payload: DevicePayload,
        passkeyApproval?: DevicePasskeyApprovalInput,
    ): Promise<Device> {
        const activeDeviceCount = await trx
            .selectFrom("devices")
            .select((eb) => eb.fn.countAll().as("count"))
            .where("owner", "=", owner)
            .where("deleted", "=", 0)
            .executeTakeFirst();
        if (
            Number(activeDeviceCount?.count ?? 0) >= MAX_ACTIVE_DEVICES_PER_USER
        ) {
            throw new Error(
                `Each account is limited to ${String(MAX_ACTIVE_DEVICES_PER_USER)} active devices.`,
            );
        }

        const now = new Date().toISOString();
        const device = {
            deleted: 0,
            deviceID: crypto.randomUUID(),
            lastLogin: now,
            name: payload.deviceName,
            owner,
            signKey: payload.signKey,
        };

        const medPreKeys = {
            deviceID: device.deviceID,
            index: payload.preKeyIndex,
            keyID: crypto.randomUUID(),
            publicKey: payload.preKey,
            signature: payload.preKeySignature,
            userID: owner,
        };

        await trx.insertInto("devices").values(device).execute();
        await trx.insertInto("preKeys").values(medPreKeys).execute();
        if (passkeyApproval) {
            await trx
                .insertInto("device_passkey_approvals")
                .values({
                    approvedAt: now,
                    approvedByDeviceID:
                        passkeyApproval.approvedByDeviceID ?? null,
                    approvedByPasskeyID: passkeyApproval.approvedByPasskeyID,
                    deviceID: device.deviceID,
                    userID: owner,
                })
                .onConflict((oc) =>
                    oc.column("deviceID").doUpdateSet({
                        approvedAt: now,
                        approvedByDeviceID:
                            passkeyApproval.approvedByDeviceID ?? null,
                        approvedByPasskeyID:
                            passkeyApproval.approvedByPasskeyID,
                        userID: owner,
                    }),
                )
                .execute();
        }

        return toDevice(device);
    }

    private mailSqlEntry(
        mail: MailWS,
        header: Uint8Array,
        deviceID: string,
        userID: string,
        time = new Date().toISOString(),
        deliveryDeviceID = mail.recipient,
    ): MailSQL & { deliveryDeviceID: string } {
        return {
            authorID: userID,
            cipher: XUtils.encodeHex(mail.cipher),
            deliveryDeviceID,
            // Opaque transport metadata (X3DH initial payload or ratchet header).
            extra: XUtils.encodeHex(mail.extra),
            forward: mail.forward,
            group: mail.group ? XUtils.encodeHex(mail.group) : null,
            header: XUtils.encodeHex(header),
            mailID: mail.mailID,
            mailType: mail.mailType,
            nonce: XUtils.encodeHex(mail.nonce),
            readerID: mail.readerID,
            recipient: mail.recipient,
            sender: deviceID,
            time,
        };
    }
}

/**
 * Hash a password with Argon2id (new default).
 * Returns the encoded hash string which embeds salt, params, and digest.
 */
export async function hashPasswordArgon2(password: string): Promise<string> {
    if (
        password.length === 0 ||
        password.length > ACCOUNT_PASSWORD_MAX_LENGTH
    ) {
        throw new Error("Password length is outside the supported range.");
    }
    return argon2.hash(password, ARGON2_OPTIONS);
}

/**
 * Validate new account passwords without imposing composition rules. Passwords
 * are hashed exactly as supplied; normalization is used only for comparisons
 * against account-specific and common-password deny lists.
 */
export function validateAccountPassword(
    password: string,
    username?: string,
): null | string {
    if (
        password.trim().length === 0 ||
        password.length < ACCOUNT_PASSWORD_MIN_LENGTH
    ) {
        return `Password must be at least ${String(ACCOUNT_PASSWORD_MIN_LENGTH)} characters.`;
    }
    if (password.length > ACCOUNT_PASSWORD_MAX_LENGTH) {
        return `Password must be at most ${String(ACCOUNT_PASSWORD_MAX_LENGTH)} characters.`;
    }

    const comparable = password.normalize("NFKC").toLowerCase();
    const comparableUsername = username?.trim().normalize("NFKC").toLowerCase();
    const characters = Array.from(comparable);
    const repeatedSingleCharacter = characters.every(
        (character) => character === characters[0],
    );
    if (
        COMMON_ACCOUNT_PASSWORDS.has(comparable) ||
        repeatedSingleCharacter ||
        (comparableUsername !== undefined && comparable === comparableUsername)
    ) {
        return "Choose a less common password.";
    }

    return null;
}

/**
 * Verify an Argon2id password hash. Unknown hash formats fail closed.
 */
export async function verifyPassword(
    password: string,
    stored: null | {
        passwordHash: string;
    },
): Promise<{ needsRehash: boolean; valid: boolean }> {
    if (stored === null) {
        await argon2.verify(DUMMY_PASSWORD_HASH, password);
        return { needsRehash: false, valid: false };
    }
    try {
        const valid = await argon2.verify(stored.passwordHash, password);
        return {
            needsRehash:
                valid &&
                argon2.needsRehash(stored.passwordHash, ARGON2_OPTIONS),
            valid,
        };
    } catch {
        // Keep malformed rows on the same expensive path as a missing user.
        await argon2.verify(DUMMY_PASSWORD_HASH, password).catch(() => false);
        return { needsRehash: false, valid: false };
    }
}

function accountTierRank(tier: AccountTier): number {
    switch (tier) {
        case "free":
            return 0;
        case "plus":
            return 1;
        case "pro":
            return 2;
    }
}

function billingEnvironmentFromRow(environment: string): BillingEnvironment {
    const parsed = BillingEnvironmentSchema.safeParse(environment);
    return parsed.success ? parsed.data : "production";
}

function billingPlatformFromRow(platform: string): BillingPlatform {
    const parsed = BillingPlatformSchema.safeParse(platform);
    return parsed.success ? parsed.data : "apple_app_store";
}

function billingPurchaseTokenHash(
    platform: BillingPlatform,
    environment: BillingEnvironment,
    token: string,
): string {
    return createHash("sha256")
        .update(`${platform}:${environment}:${token}`)
        .digest("hex");
}

function billingStatusCarriesEntitlement(
    status: BillingSubscriptionStatus,
): boolean {
    return (
        status === "active" ||
        status === "billing_retry" ||
        status === "grace_period"
    );
}

function billingSubscriptionStatusFromRow(
    status: string,
): BillingSubscriptionStatus {
    const parsed = BillingSubscriptionStatusSchema.safeParse(status);
    return parsed.success ? parsed.data : "pending";
}

function decodeNotificationEvents(events: string): string[] {
    try {
        const parsed: unknown = JSON.parse(events);
        if (
            Array.isArray(parsed) &&
            parsed.every((event) => typeof event === "string")
        ) {
            return parsed.length > 0 ? [...new Set(parsed)] : ["mail"];
        }
    } catch {
        // Fall through to the safe default.
    }
    return ["mail"];
}

function encodeNotificationEvents(events: string[]): string {
    const unique = [...new Set(events.map((event) => event.trim()))].filter(
        (event) => event.length > 0,
    );
    return JSON.stringify(unique.length > 0 ? unique : ["mail"]);
}

function expiryRank(expiresAt: null | string): number {
    if (!expiresAt) {
        return Number.MAX_SAFE_INTEGER;
    }
    const value = Date.parse(expiresAt);
    return Number.isFinite(value) ? value : 0;
}

function mailGroupForChannel(channelID: string): string {
    return uuidValidate(channelID)
        ? XUtils.encodeHex(uuidParse(channelID))
        : channelID;
}

// Mirrors `Spire.normalizeRegistrationUsername` — kept in sync so a
// caller invoking `createUser` directly (e.g. tests, future internal
// flows) gets the same lowercase canonicalization the public
// `POST /register` route applies. Usernames are case-insensitive at
// the protocol level.
function normalizeRegistrationUsername(providedUsername: string): string {
    return providedUsername.trim().toLowerCase();
}

function parseAccountEntitlementSource(
    source: string,
): AccountEntitlementSource {
    const parsed = AccountEntitlementSourceSchema.safeParse(source);
    return parsed.success ? parsed.data : "default";
}

function parseAccountTier(tier: string): AccountTier {
    const parsed = AccountTierSchema.safeParse(tier);
    return parsed.success ? parsed.data : "free";
}

function toBillingSubscription(row: {
    environment: string;
    expiresAt: null | string;
    platform: string;
    productID: string;
    status: string;
    storeProductID: string;
    subscriptionID: string;
    tier: string;
    updatedAt: string;
}): BillingSubscription {
    return {
        environment: billingEnvironmentFromRow(row.environment),
        expiresAt: row.expiresAt,
        platform: billingPlatformFromRow(row.platform),
        productID: row.productID,
        status: billingSubscriptionStatusFromRow(row.status),
        storeProductID: row.storeProductID,
        subscriptionID: row.subscriptionID,
        tier: parseAccountTier(row.tier),
        updatedAt: row.updatedAt,
    };
}

function toDevice(row: {
    deleted: number;
    deviceID: string;
    lastLogin: string;
    name: string;
    owner: string;
    signKey: string;
}): Device {
    return { ...row, deleted: Boolean(row.deleted) };
}

function toMailSQL(row: {
    authorID: string;
    cipher: string;
    extra: null | string;
    forward: number;
    group: null | string;
    header: string;
    mailID: string;
    mailType: number;
    nonce: string;
    readerID: string;
    recipient: string;
    sender: string;
    time: string;
}): MailSQL {
    return {
        ...row,
        extra: row.extra ?? "",
        forward: Boolean(row.forward),
        mailType: parseMailType(row.mailType),
        time: row.time,
    };
}

function toNotificationSubscription(row: {
    channel: string;
    createdAt: string;
    deviceID: string;
    enabled: number;
    events: string;
    platform: null | string;
    subscriptionID: string;
    token: string;
    updatedAt: string;
    userID: string;
}): NotificationSubscription {
    return {
        ...row,
        channel: "expo",
        enabled: Boolean(row.enabled),
        events: decodeNotificationEvents(row.events),
    };
}

function toPasskey(row: PasskeyRow): Passkey {
    return {
        createdAt: row.createdAt,
        lastUsedAt: row.lastUsedAt,
        name: row.name,
        passkeyID: row.passkeyID,
        transports:
            row.transports.length > 0
                ? row.transports.split(",").filter((s) => s.length > 0)
                : [],
        userID: row.userID,
    };
}

function toServer(row: {
    homeserverId: null | string;
    icon: null | string;
    name: string;
    revision: number;
    serverID: string;
}): Server {
    return {
        ...(row.homeserverId ? { homeserverId: row.homeserverId } : {}),
        icon: row.icon ?? undefined,
        name: row.name,
        revision: String(row.revision),
        serverID: row.serverID,
    };
}

function toUserRecord(row: {
    lastSeen: string;
    passwordHash: string;
    userID: string;
    username: string;
}): InternalUserRecord {
    return { ...row };
}

/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Kysely } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema.dropTable("registry_usernames").ifExists().execute();
    await db.schema.dropTable("registry_devices").ifExists().execute();
    await db.schema.dropTable("registry_accounts").ifExists().execute();
    await db.schema.dropTable("registry_homeservers").ifExists().execute();
    await db.schema.dropTable("registry_cursors").ifExists().execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .createTable("registry_cursors")
        .ifNotExists()
        .addColumn("source", "varchar(255)", (column) =>
            column.primaryKey().notNull(),
        )
        .addColumn("sequence", "text", (column) => column.notNull())
        .addColumn("checkpoint", "text", (column) => column.notNull())
        .execute();

    await db.schema
        .createTable("registry_homeservers")
        .ifNotExists()
        .addColumn("source", "varchar(255)", (column) => column.notNull())
        .addColumn("homeserverId", "varchar(66)", (column) => column.notNull())
        .addColumn("signingKey", "varchar(66)", (column) => column.notNull())
        .addColumn("endpoint", "text", (column) => column.notNull())
        .addColumn("epoch", "text", (column) => column.notNull())
        .addColumn("nonce", "text", (column) => column.notNull())
        .addColumn("active", "integer", (column) => column.notNull())
        .addPrimaryKeyConstraint("registry_homeservers_pk", [
            "source",
            "homeserverId",
        ])
        .execute();

    await db.schema
        .createTable("registry_accounts")
        .ifNotExists()
        .addColumn("source", "varchar(255)", (column) => column.notNull())
        .addColumn("accountId", "varchar(66)", (column) => column.notNull())
        .addColumn("homeserverId", "varchar(66)", (column) => column.notNull())
        .addColumn("recoveryCommitment", "varchar(66)", (column) =>
            column.notNull(),
        )
        .addColumn("epoch", "text", (column) => column.notNull())
        .addColumn("nonce", "text", (column) => column.notNull())
        .addColumn("activeDeviceCount", "integer", (column) => column.notNull())
        .addColumn("deviceThreshold", "integer", (column) => column.notNull())
        .addPrimaryKeyConstraint("registry_accounts_pk", [
            "source",
            "accountId",
        ])
        .execute();

    await db.schema
        .createIndex("registry_accounts_homeserver_idx")
        .ifNotExists()
        .on("registry_accounts")
        .columns(["source", "homeserverId"])
        .execute();

    await db.schema
        .createTable("registry_devices")
        .ifNotExists()
        .addColumn("source", "varchar(255)", (column) => column.notNull())
        .addColumn("accountId", "varchar(66)", (column) => column.notNull())
        .addColumn("deviceKey", "varchar(66)", (column) => column.notNull())
        .addColumn("addedAtEpoch", "text", (column) => column.notNull())
        .addColumn("revokedAtEpoch", "text")
        .addColumn("active", "integer", (column) => column.notNull())
        .addPrimaryKeyConstraint("registry_devices_pk", [
            "source",
            "accountId",
            "deviceKey",
        ])
        .execute();

    await db.schema
        .createIndex("registry_devices_active_idx")
        .ifNotExists()
        .on("registry_devices")
        .columns(["source", "accountId", "active"])
        .execute();

    await db.schema
        .createTable("registry_usernames")
        .ifNotExists()
        .addColumn("source", "varchar(255)", (column) => column.notNull())
        .addColumn("username", "varchar(19)", (column) => column.notNull())
        .addColumn("nameHash", "varchar(66)", (column) => column.notNull())
        .addColumn("accountId", "varchar(66)", (column) => column.notNull())
        .addPrimaryKeyConstraint("registry_usernames_pk", [
            "source",
            "username",
        ])
        .addUniqueConstraint("registry_usernames_name_hash_unique", [
            "source",
            "nameHash",
        ])
        .addUniqueConstraint("registry_usernames_account_unique", [
            "source",
            "accountId",
        ])
        .execute();
}

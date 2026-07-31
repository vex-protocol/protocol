/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Kysely } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema.dropTable("homeserver_migrations").ifExists().execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .createTable("homeserver_migrations")
        .ifNotExists()
        .addColumn("migrationId", "varchar(255)", (column) =>
            column.primaryKey().notNull(),
        )
        .addColumn("nonce", "varchar(255)", (column) =>
            column.notNull().unique(),
        )
        .addColumn("accountId", "varchar(255)", (column) => column.notNull())
        .addColumn("sourceHomeserverId", "varchar(255)", (column) =>
            column.notNull(),
        )
        .addColumn("destinationHomeserverId", "varchar(255)", (column) =>
            column.notNull(),
        )
        .addColumn("deviceKey", "varchar(255)", (column) => column.notNull())
        .addColumn("authorization", "text", (column) => column.notNull())
        .addColumn("manifest", "text")
        .addColumn("createdAt", "integer", (column) => column.notNull())
        .addColumn("transferExpiresAt", "integer", (column) => column.notNull())
        .addColumn("mailCutoffAt", "integer")
        .addColumn("completedAt", "integer")
        .execute();
    await db.schema
        .createIndex("homeserver_migrations_account_idx")
        .ifNotExists()
        .on("homeserver_migrations")
        .columns(["accountId", "createdAt"])
        .execute();
}

/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Kysely } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema.dropTable("federation_room_outbox").ifExists().execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .createTable("federation_room_outbox")
        .ifNotExists()
        .addColumn("eventId", "varchar(255)", (column) =>
            column.primaryKey().notNull(),
        )
        .addColumn("destinationHomeserverId", "varchar(255)", (column) =>
            column.notNull(),
        )
        .addColumn("kind", "varchar(32)", (column) => column.notNull())
        .addColumn("payload", "text", (column) => column.notNull())
        .addColumn("attempts", "integer", (column) =>
            column.notNull().defaultTo(0),
        )
        .addColumn("nextAttemptAt", "integer", (column) => column.notNull())
        .addColumn("createdAt", "integer", (column) => column.notNull())
        .execute();
    await db.schema
        .createIndex("federation_room_outbox_due_idx")
        .ifNotExists()
        .on("federation_room_outbox")
        .columns(["nextAttemptAt", "createdAt"])
        .execute();
}

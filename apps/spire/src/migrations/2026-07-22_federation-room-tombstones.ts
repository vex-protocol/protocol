/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Kysely } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .dropTable("federation_room_tombstones")
        .ifExists()
        .execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .createTable("federation_room_tombstones")
        .ifNotExists()
        .addColumn("serverId", "varchar(255)", (column) =>
            column.primaryKey().notNull(),
        )
        .addColumn("homeserverId", "varchar(255)", (column) => column.notNull())
        .addColumn("permanent", "integer", (column) =>
            column.notNull().defaultTo(1),
        )
        .addColumn("revision", "integer", (column) => column.notNull())
        .addColumn("deletedAt", "integer", (column) => column.notNull())
        .execute();
}

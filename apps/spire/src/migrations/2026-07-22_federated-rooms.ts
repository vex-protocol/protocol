/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Kysely } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema.dropIndex("servers_homeserver_idx").ifExists().execute();
    await db.schema.alterTable("servers").dropColumn("revision").execute();
    await db.schema.alterTable("servers").dropColumn("homeserverId").execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .alterTable("servers")
        .addColumn("homeserverId", "varchar(255)")
        .execute();
    await db.schema
        .alterTable("servers")
        .addColumn("revision", "integer", (column) =>
            column.notNull().defaultTo(1),
        )
        .execute();
    await db.schema
        .createIndex("servers_homeserver_idx")
        .ifNotExists()
        .on("servers")
        .column("homeserverId")
        .execute();
}

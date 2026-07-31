/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Kysely } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema.dropTable("federation_nonces").ifExists().execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .createTable("federation_nonces")
        .ifNotExists()
        .addColumn("originHomeserverId", "varchar(66)", (column) =>
            column.notNull(),
        )
        .addColumn("nonce", "varchar(66)", (column) => column.notNull())
        .addColumn("expiresAt", "bigint", (column) => column.notNull())
        .addPrimaryKeyConstraint("federation_nonces_pk", [
            "originHomeserverId",
            "nonce",
        ])
        .execute();

    await db.schema
        .createIndex("federation_nonces_expiry_idx")
        .ifNotExists()
        .on("federation_nonces")
        .column("expiresAt")
        .execute();
}

/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Kysely } from "kysely";

import { sql } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema.dropIndex("mail_delivery_device_idx").ifExists().execute();
    await db.schema.alterTable("mail").dropColumn("deliveryDeviceID").execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .alterTable("mail")
        .addColumn("deliveryDeviceID", "varchar(255)")
        .execute();
    await sql`
        UPDATE mail
        SET deliveryDeviceID = recipient
        WHERE deliveryDeviceID IS NULL
    `.execute(db);
    await db.schema
        .createIndex("mail_delivery_device_idx")
        .ifNotExists()
        .on("mail")
        .column("deliveryDeviceID")
        .execute();
}

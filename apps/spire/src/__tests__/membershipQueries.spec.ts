import { once } from "node:events";

import { describe, expect, it, vi } from "vitest";

import { Database } from "../Database.ts";

describe("membership queries", () => {
    it("retrieves each existing member once and keeps query counts independent of group size", async () => {
        const db = new Database({ dbType: "sqlite3mem" });
        await once(db, "ready");
        try {
            const members = Array.from({ length: 30 }, (_, index) => ({
                lastSeen: new Date(0).toISOString(),
                passwordHash: "unused",
                userID: crypto.randomUUID(),
                username: `member-${String(index)}`,
            }));
            await db["db"].insertInto("users").values(members).execute();
            const serverID = crypto.randomUUID();
            const channel = await db.createChannel("general", serverID);
            await db["db"]
                .insertInto("permissions")
                .values(
                    [
                        ...members.map((member) => member.userID),
                        members[0]!.userID,
                        crypto.randomUUID(),
                    ].map((userID) => ({
                        permissionID: crypto.randomUUID(),
                        powerLevel: 0,
                        resourceID: serverID,
                        resourceType: "server",
                        userID,
                    })),
                )
                .execute();
            const selectFrom = vi.spyOn(db["db"], "selectFrom");

            const affected = await db.retrieveAffectedUsers(serverID);
            expect(affected).toHaveLength(members.length);
            expect(affected).toEqual(expect.arrayContaining(members));
            expect(selectFrom).toHaveBeenCalledTimes(1);

            selectFrom.mockClear();
            expect(await db.retrieveGroupMembers(channel.channelID)).toEqual(
                affected,
            );
            expect(selectFrom).toHaveBeenCalledTimes(2);

            expect(await db.retrieveAffectedUsers("missing-server")).toEqual(
                [],
            );
            expect(await db.retrieveGroupMembers("missing-channel")).toEqual(
                [],
            );
        } finally {
            await db.close();
        }
    });
});

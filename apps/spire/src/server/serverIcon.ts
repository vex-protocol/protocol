/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database } from "../Database.ts";
import type { FederationService } from "../federation/FederationService.ts";
import type { Server } from "@vex-chat/types";

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";

import express from "express";

import { XUtils } from "@vex-chat/crypto";

import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import multer from "multer";
import { z } from "zod/v4";

import { POWER_LEVELS } from "../ClientManager.ts";
import { msgpack } from "../utils/msgpack.ts";

import { isAllowedImageType } from "./imageTypes.ts";
import { hasPermission } from "./permissions.ts";
import { uploadLimiter } from "./rateLimit.ts";
import { getParam, getUser } from "./utils.ts";

import { protect } from "./index.ts";

const SERVER_ICON_DIR = "server-icons";
export const MAX_SERVER_ICON_BYTES = 5 * 1024 * 1024;
const safePathParam = z.string().regex(/^[a-zA-Z0-9._-]+$/);
const serverIconUpload = multer({
    limits: { fields: 1, files: 1, fileSize: MAX_SERVER_ICON_BYTES, parts: 2 },
});
const serverIconJsonPayload = z.object({
    file: z
        .string()
        .min(1)
        .max(Math.ceil((MAX_SERVER_ICON_BYTES * 4) / 3) + 4),
});

type NotifyServerChange = (serverID: string) => Promise<void>;

interface ServerIconFederationOptions {
    homeserverId: string;
    service: FederationService;
}

export class ServerIconError extends Error {
    public readonly status: number;

    constructor(status: number, message: string) {
        super(message);
        this.name = "ServerIconError";
        this.status = status;
    }
}

export async function deleteServerIconFile(iconID: string): Promise<void> {
    const safeID = safePathParam.safeParse(iconID);
    if (!safeID.success) return;
    await fsp
        .unlink(`${SERVER_ICON_DIR}/${safeID.data}`)
        .catch(() => undefined);
}

export const getServerIconRouter = (
    db: Database,
    notifyServerChange: NotifyServerChange,
    federation?: ServerIconFederationOptions,
) => {
    const router = express.Router();

    router.get("/:iconID", async (req, res) => {
        const safeID = safePathParam.safeParse(getParam(req, "iconID"));
        if (!safeID.success) {
            res.sendStatus(400);
            return;
        }

        const filePath = `${SERVER_ICON_DIR}/${safeID.data}`;
        const typeDetails = await fileTypeFromFile(filePath).catch(() => null);
        if (!typeDetails) {
            if (!federation) {
                res.sendStatus(404);
                return;
            }
            try {
                const icon = await federation.service.retrieveServerIcon(
                    safeID.data,
                );
                if (!icon) {
                    res.sendStatus(404);
                    return;
                }
                res.set("Content-Type", icon.contentType);
                res.set("Cache-Control", "public, max-age=31536000, immutable");
                res.set("Cross-Origin-Resource-Policy", "cross-origin");
                res.send(Buffer.from(icon.data));
            } catch {
                res.sendStatus(502);
            }
            return;
        }

        res.set("Content-Type", typeDetails.mime);
        res.set("Cache-Control", "public, max-age=31536000, immutable");
        res.set("Cross-Origin-Resource-Policy", "cross-origin");
        const stream = fs.createReadStream(filePath);
        stream.on("error", () => {
            if (!res.headersSent) res.sendStatus(500);
            else res.destroy();
        });
        stream.pipe(res);
    });

    router.post("/:serverID/json", uploadLimiter, protect, async (req, res) => {
        const parsed = serverIconJsonPayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid server icon payload",
                issues: parsed.error.issues,
            });
            return;
        }

        let buffer: Buffer;
        try {
            buffer = Buffer.from(XUtils.decodeBase64(parsed.data.file));
        } catch {
            res.status(400).json({ error: "Icon must be valid base64." });
            return;
        }
        await saveIcon(req, res, db, notifyServerChange, buffer, federation);
    });

    router.post(
        "/:serverID",
        uploadLimiter,
        protect,
        serverIconUpload.single("icon"),
        async (req, res) => {
            if (!req.file) {
                res.sendStatus(400);
                return;
            }
            await saveIcon(
                req,
                res,
                db,
                notifyServerChange,
                req.file.buffer,
                federation,
            );
        },
    );

    router.delete("/:serverID", protect, async (req, res) => {
        const serverID = getParam(req, "serverID");
        if (!(await canManageServer(db, getUser(req).userID, serverID))) {
            res.sendStatus(403);
            return;
        }

        const existing = await db.retrieveServer(serverID);
        if (!existing) {
            res.sendStatus(404);
            return;
        }
        if (
            federation &&
            existing.homeserverId !== undefined &&
            existing.homeserverId !== federation.homeserverId
        ) {
            try {
                const result = await federation.service.mutateRoom(
                    serverID,
                    getUser(req).userID,
                    { type: "remove-icon" },
                );
                if (result.resultType !== "server") {
                    throw new Error("Unexpected room mutation result.");
                }
                res.send(msgpack.encode(result.server));
            } catch {
                res.sendStatus(502);
            }
            return;
        }
        try {
            const updated = await removeServerIcon(db, serverID);
            await notifyServerChange(serverID);
            res.send(msgpack.encode(updated));
        } catch (error: unknown) {
            sendIconError(res, error);
        }
    });

    return router;
};

export async function removeServerIcon(
    db: Pick<Database, "retrieveServer" | "updateServer">,
    serverID: string,
): Promise<Server> {
    const existing = await db.retrieveServer(serverID);
    if (!existing) throw new ServerIconError(404, "Room not found.");
    const updated = await db.updateServer(serverID, { icon: null });
    if (!updated) throw new ServerIconError(404, "Room not found.");
    if (existing.icon) await deleteServerIconFile(existing.icon);
    return updated;
}

export async function saveServerIcon(
    db: Pick<Database, "retrieveServer" | "updateServer">,
    serverID: string,
    data: Uint8Array,
): Promise<Server> {
    if (data.byteLength > MAX_SERVER_ICON_BYTES) {
        throw new ServerIconError(413, "Room icon exceeds 5 MiB.");
    }
    const typeDetails = await fileTypeFromBuffer(data);
    if (!isAllowedImageType(typeDetails?.mime ?? "")) {
        throw new ServerIconError(
            400,
            "Unsupported icon type. Use JPEG, PNG, GIF, APNG, AVIF, or WebP.",
        );
    }
    const existing = await db.retrieveServer(serverID);
    if (!existing) throw new ServerIconError(404, "Room not found.");

    const iconID = crypto.randomUUID();
    const filePath = `${SERVER_ICON_DIR}/${iconID}`;
    try {
        await fsp.writeFile(filePath, data, { flag: "wx" });
        const updated = await db.updateServer(serverID, { icon: iconID });
        if (!updated) {
            throw new Error("Room disappeared while its icon was updating.");
        }
        if (existing.icon) await deleteServerIconFile(existing.icon);
        return updated;
    } catch (error: unknown) {
        await fsp.unlink(filePath).catch(() => undefined);
        throw error;
    }
}

async function canManageServer(
    db: Database,
    userID: string,
    serverID: string,
): Promise<boolean> {
    const permissions = await db.retrievePermissions(userID, "server");
    return hasPermission(permissions, serverID, POWER_LEVELS.CREATE);
}

async function saveIcon(
    req: express.Request,
    res: express.Response,
    db: Database,
    notifyServerChange: NotifyServerChange,
    buffer: Buffer,
    federation?: ServerIconFederationOptions,
): Promise<void> {
    const serverID = getParam(req, "serverID");
    if (!(await canManageServer(db, getUser(req).userID, serverID))) {
        res.sendStatus(403);
        return;
    }
    const existing = await db.retrieveServer(serverID);
    if (!existing) {
        res.sendStatus(404);
        return;
    }
    if (
        federation &&
        existing.homeserverId !== undefined &&
        existing.homeserverId !== federation.homeserverId
    ) {
        try {
            const result = await federation.service.mutateRoom(
                serverID,
                getUser(req).userID,
                { file: new Uint8Array(buffer), type: "set-icon" },
            );
            if (result.resultType !== "server") {
                throw new Error("Unexpected room mutation result.");
            }
            res.send(msgpack.encode(result.server));
        } catch {
            res.sendStatus(502);
        }
        return;
    }
    try {
        const updated = await saveServerIcon(db, serverID, buffer);
        await notifyServerChange(serverID);
        res.send(msgpack.encode(updated satisfies Server));
    } catch (error: unknown) {
        sendIconError(res, error);
    }
}

function sendIconError(response: express.Response, error: unknown): void {
    if (error instanceof ServerIconError) {
        response.status(error.status).json({ error: error.message });
        return;
    }
    throw error;
}

/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { FederationService } from "../federation/FederationService.ts";

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";

import express from "express";

import { XUtils } from "@vex-chat/crypto";

import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import multer from "multer";
import { z } from "zod/v4";

import { ALLOWED_IMAGE_TYPES } from "./imageTypes.ts";
import { uploadLimiter } from "./rateLimit.ts";
import { getParam, getUser } from "./utils.ts";

import { protect } from "./index.ts";

const safePathParam = z.string().regex(/^[a-zA-Z0-9._-]+$/);
const MAX_AVATAR_BYTES = 5 * 1024 * 1024;
const avatarUpload = multer({
    limits: { fields: 1, files: 1, fileSize: MAX_AVATAR_BYTES, parts: 2 },
});

// Avatars are public, unencrypted images. The body for the JSON path is just a
// base64-encoded image; nothing else. Do NOT reuse FilePayloadSchema here —
// that schema is for encrypted user-file uploads and requires nonce/owner/signed,
// which the avatar client never sends (and shouldn't).
const avatarJsonPayload = z.object({
    file: z
        .string()
        .min(1)
        .max(Math.ceil((MAX_AVATAR_BYTES * 4) / 3) + 4),
});

export const getAvatarRouter = (federation?: FederationService) => {
    const router = express.Router();

    router.get("/:userID", async (req, res) => {
        const safeId = safePathParam.safeParse(getParam(req, "userID"));
        if (!safeId.success) {
            res.sendStatus(400);
            return;
        }
        const filePath = "./avatars/" + safeId.data;
        const typeDetails = await fileTypeFromFile(filePath).catch(() => null);
        if (!typeDetails) {
            if (!federation) {
                res.sendStatus(404);
                return;
            }
            try {
                const avatar = await federation.retrieveAvatar(safeId.data);
                if (!avatar) {
                    res.sendStatus(404);
                    return;
                }
                res.set("Content-type", avatar.contentType);
                res.set("Cache-control", "public, max-age=300");
                res.set("Cross-Origin-Resource-Policy", "cross-origin");
                res.send(Buffer.from(avatar.data));
            } catch {
                res.sendStatus(502);
            }
            return;
        }
        res.set("Content-type", typeDetails.mime);
        res.set("Cache-control", "public, max-age=31536000");
        res.set("Cross-Origin-Resource-Policy", "cross-origin");

        const stream = fs.createReadStream(filePath);
        stream.on("error", (_err) => {
            // debugger: avatar stream read error
            res.sendStatus(500);
        });
        stream.pipe(res);
    });

    router.post("/:userID/json", uploadLimiter, protect, async (req, res) => {
        const parsed = avatarJsonPayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid avatar payload",
                issues: parsed.error.issues,
            });
            return;
        }
        const payload = parsed.data;
        const userDetails = getUser(req);
        const deviceDetails = req.device;

        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }
        if (getParam(req, "userID") !== userDetails.userID) {
            res.sendStatus(403);
            return;
        }

        let buf: Buffer;
        try {
            buf = Buffer.from(XUtils.decodeBase64(payload.file));
        } catch {
            res.status(400).send({ error: "Avatar must be valid base64." });
            return;
        }
        if (buf.byteLength > MAX_AVATAR_BYTES) {
            res.sendStatus(413);
            return;
        }
        const mimeType = await fileTypeFromBuffer(buf);
        if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, avif, or webp but received " +
                    String(mimeType?.ext),
            });
            return;
        }

        try {
            // write the file to disk
            await fsp.writeFile("avatars/" + userDetails.userID, buf);
            res.sendStatus(200);
        } catch (_err: unknown) {
            // debugger: avatar write failed
            res.sendStatus(500);
        }
    });

    router.post(
        "/:userID",
        uploadLimiter,
        protect,
        avatarUpload.single("avatar"),
        async (req, res) => {
            const userDetails = getUser(req);
            const deviceDetails = req.device;

            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }
            if (getParam(req, "userID") !== userDetails.userID) {
                res.sendStatus(403);
                return;
            }

            if (!req.file) {
                res.sendStatus(400);
                return;
            }

            const mimeType = await fileTypeFromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, avif, or webp but received " +
                        String(mimeType?.ext),
                });
                return;
            }

            try {
                // write the file to disk
                await fsp.writeFile(
                    "avatars/" + userDetails.userID,
                    req.file.buffer,
                );
                res.sendStatus(200);
            } catch (_err: unknown) {
                // debugger: avatar write failed
                res.sendStatus(500);
            }
        },
    );

    return router;
};

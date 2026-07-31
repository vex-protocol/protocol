/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { HomeserverMigrationService } from "../federation/HomeserverMigrationService.ts";

import express from "express";

import {
    FederationMigrationAuthorizationSchema,
    FederationMigrationImportRequestSchema,
    RegistryBytes32Schema,
} from "@vex-chat/types";

import { z } from "zod/v4";

import { FederationServiceError } from "../federation/FederationService.ts";
import { msgpack } from "../utils/msgpack.ts";

import { migrationLimiter } from "./rateLimit.ts";
import { getUser } from "./utils.ts";

import { protect } from "./index.ts";

const migrationChallengeSchema = z
    .object({ destinationHomeserverId: RegistryBytes32Schema })
    .strict();

export function getMigrationRouter(
    service: HomeserverMigrationService,
): express.Router {
    const router = express.Router();

    router.post(
        "/migration/challenge",
        protect,
        migrationLimiter,
        async (request, response) => {
            const parsed = migrationChallengeSchema.safeParse(request.body);
            if (!parsed.success) {
                response
                    .status(400)
                    .json({ error: "Invalid migration destination." });
                return;
            }
            if (!request.device) {
                response.sendStatus(401);
                return;
            }
            try {
                const result = await service.createChallenge(
                    getUser(request).userID,
                    request.device,
                    parsed.data.destinationHomeserverId,
                );
                response
                    .type("application/msgpack")
                    .send(msgpack.encode(result));
            } catch (error: unknown) {
                sendMigrationError(response, error);
            }
        },
    );

    router.post(
        "/migration/import",
        protect,
        migrationLimiter,
        async (request, response) => {
            const parsed = FederationMigrationImportRequestSchema.safeParse(
                request.body,
            );
            if (!parsed.success) {
                response
                    .status(400)
                    .json({ error: "Invalid migration request." });
                return;
            }
            if (!request.device) {
                response.sendStatus(401);
                return;
            }
            try {
                const result = await service.importMigration(
                    getUser(request).userID,
                    request.device,
                    parsed.data.sourceHomeserverId,
                    parsed.data.migrationId,
                );
                response
                    .type("application/msgpack")
                    .send(msgpack.encode(result));
            } catch (error: unknown) {
                sendMigrationError(response, error);
            }
        },
    );

    router.post(
        "/migration/prepare",
        protect,
        migrationLimiter,
        async (request, response) => {
            const parsed = FederationMigrationAuthorizationSchema.safeParse(
                request.body,
            );
            if (!parsed.success) {
                response
                    .status(400)
                    .json({ error: "Invalid migration authorization." });
                return;
            }
            if (!request.device) {
                response.sendStatus(401);
                return;
            }
            try {
                const result = await service.prepareMigration(
                    parsed.data,
                    getUser(request).userID,
                    request.device,
                );
                response
                    .type("application/msgpack")
                    .send(msgpack.encode(result));
            } catch (error: unknown) {
                sendMigrationError(response, error);
            }
        },
    );

    return router;
}

function sendMigrationError(response: express.Response, error: unknown): void {
    if (error instanceof FederationServiceError) {
        response.status(error.status).json({ error: error.message });
        return;
    }
    response.status(500).json({ error: "Homeserver migration failed." });
}

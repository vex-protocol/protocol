/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database } from "../Database.ts";
import type { FederationService } from "../federation/FederationService.ts";
import type {
    FederationRoomSnapshot,
    Invite,
    TokenScopes,
} from "@vex-chat/types";

import express from "express";

import {
    formatFederationInviteReference,
    parseFederationInviteReference,
} from "@vex-chat/types";

import { FederationServiceError } from "../federation/FederationService.ts";
import { msgpack } from "../utils/msgpack.ts";

import { getParam, getUser } from "./utils.ts";

import { protect } from "./index.ts";

interface InviteFederationOptions {
    homeserverId: string;
    service: FederationService;
}

export const getInviteRouter = (
    db: Database,
    tokenValidator: (key: string, scope: TokenScopes) => boolean,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void,
    notifyServerChange: (
        serverID: string,
        additionalUserIDs?: readonly string[],
        previousSnapshot?: FederationRoomSnapshot,
    ) => Promise<void>,
    federation?: InviteFederationOptions,
) => {
    const router = express.Router();
    router.patch("/:inviteID", protect, async (req, res) => {
        const userDetails = getUser(req);
        const reference = parseFederationInviteReference(
            getParam(req, "inviteID"),
        );
        if (!reference) {
            res.sendStatus(400);
            return;
        }
        if (
            reference.homeserverId &&
            reference.homeserverId !== federation?.homeserverId
        ) {
            if (!federation) {
                res.sendStatus(404);
                return;
            }
            try {
                const result = await federation.service.redeemInvite(
                    reference.homeserverId,
                    reference.inviteId,
                    userDetails.userID,
                );
                res.send(msgpack.encode(result.permission));
                notify(
                    userDetails.userID,
                    "permission",
                    crypto.randomUUID(),
                    result.permission,
                );
                notify(
                    userDetails.userID,
                    "serverChange",
                    crypto.randomUUID(),
                    result.snapshot.server.serverID,
                );
            } catch (error: unknown) {
                sendFederationError(res, error);
            }
            return;
        }

        const invite = await db.retrieveInvite(reference.inviteId);
        if (!invite) {
            res.sendStatus(404);
            return;
        }

        if (new Date(invite.expiration).getTime() < Date.now()) {
            res.sendStatus(401);
            return;
        }

        const previousSnapshot = await db.retrieveRoomSnapshot(invite.serverID);
        const permission = await db.createPermission(
            userDetails.userID,
            "server",
            invite.serverID,
            0,
        );
        notify(
            userDetails.userID,
            "permission",
            crypto.randomUUID(),
            permission,
        );
        await notifyServerChange(
            invite.serverID,
            [userDetails.userID],
            previousSnapshot ?? undefined,
        );
        res.send(msgpack.encode(permission));
    });

    router.get("/:inviteID/preview", protect, async (req, res) => {
        const reference = parseFederationInviteReference(
            getParam(req, "inviteID"),
        );
        if (!reference) {
            res.sendStatus(400);
            return;
        }
        if (
            reference.homeserverId &&
            reference.homeserverId !== federation?.homeserverId
        ) {
            if (!federation) {
                res.sendStatus(404);
                return;
            }
            try {
                const preview = await federation.service.previewInvite(
                    reference.homeserverId,
                    reference.inviteId,
                );
                res.send(
                    msgpack.encode({
                        ...preview,
                        invite: clientInvite(
                            preview.invite,
                            reference.homeserverId,
                        ),
                    }),
                );
            } catch (error: unknown) {
                sendFederationError(res, error);
            }
            return;
        }

        const invite = await db.retrieveInvite(reference.inviteId);
        if (!invite) {
            res.sendStatus(404);
            return;
        }

        if (new Date(invite.expiration).getTime() < Date.now()) {
            res.sendStatus(401);
            return;
        }

        const server = await db.retrieveServer(invite.serverID);
        if (!server) {
            res.sendStatus(404);
            return;
        }

        const channels = await db.retrieveChannels(invite.serverID);
        res.send(
            msgpack.encode({
                channels,
                invite: clientInvite(invite, federation?.homeserverId),
                server,
            }),
        );
    });

    router.get("/:inviteID", protect, async (req, res) => {
        const reference = parseFederationInviteReference(
            getParam(req, "inviteID"),
        );
        if (!reference) {
            res.sendStatus(400);
            return;
        }
        if (
            reference.homeserverId &&
            reference.homeserverId !== federation?.homeserverId
        ) {
            if (!federation) {
                res.sendStatus(404);
                return;
            }
            try {
                const preview = await federation.service.previewInvite(
                    reference.homeserverId,
                    reference.inviteId,
                );
                res.send(
                    msgpack.encode(
                        clientInvite(preview.invite, reference.homeserverId),
                    ),
                );
            } catch (error: unknown) {
                sendFederationError(res, error);
            }
            return;
        }

        const invite = await db.retrieveInvite(reference.inviteId);
        if (!invite) {
            res.sendStatus(404);
            return;
        }
        res.send(
            msgpack.encode(clientInvite(invite, federation?.homeserverId)),
        );
    });

    return router;
};

function clientInvite(invite: Invite, homeserverId?: string): Invite {
    return homeserverId
        ? {
              ...invite,
              inviteID: formatFederationInviteReference(
                  homeserverId,
                  invite.inviteID,
              ),
          }
        : invite;
}

function sendFederationError(response: express.Response, error: unknown): void {
    if (error instanceof FederationServiceError) {
        response.status(error.status).json({ error: error.message });
        return;
    }
    response
        .status(502)
        .json({ error: "The invite homeserver could not be reached." });
}

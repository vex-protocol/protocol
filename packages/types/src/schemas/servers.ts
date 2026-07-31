/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { z } from "zod/v4";

// ── Interfaces ──────────────────────────────────────────────────────────────

/** Server channel. */
export interface Channel {
    channelID: string;
    name: string;
    serverID: string;
}

/** Server invitation. */
export interface Invite {
    expiration: string;
    inviteID: string;
    owner: string;
    serverID: string;
}

/** Permission grant. */
export interface Permission {
    permissionID: string;
    powerLevel: number;
    resourceID: string;
    resourceType: string;
    userID: string;
}

/** Chat server. */
export interface Server {
    homeserverId?: string | undefined;
    icon?: string | undefined;
    name: string;
    revision?: string | undefined;
    serverID: string;
}

/** Combined server list + per-server channel index for fast app bootstrap. */
export interface ServerChannelBootstrap {
    channelsByServer: Record<string, Channel[]>;
    servers: Server[];
}

// ── Schemas ─────────────────────────────────────────────────────────────────

/** Chat server. */
export const ServerSchema: z.ZodType<Server> = z
    .object({
        homeserverId: z
            .string()
            .optional()
            .describe("Authoritative homeserver ID"),
        icon: z.string().optional().describe("Server icon file ID"),
        name: z.string().describe("Server display name"),
        revision: z
            .string()
            .max(16)
            .regex(/^(?:0|[1-9][0-9]*)$/)
            .optional()
            .describe("Monotonic room state revision"),
        serverID: z.string().describe("Unique server identifier"),
    })
    .describe("Chat server");

/** Server channel. */
export const ChannelSchema: z.ZodType<Channel> = z
    .object({
        channelID: z.string().describe("Unique channel identifier"),
        name: z.string().describe("Channel display name"),
        serverID: z.string().describe("Parent server ID"),
    })
    .describe("Server channel");

/** Combined server list + per-server channel index for fast app bootstrap. */
export const ServerChannelBootstrapSchema: z.ZodType<ServerChannelBootstrap> = z
    .object({
        channelsByServer: z.record(z.string(), z.array(ChannelSchema)),
        servers: z.array(ServerSchema),
    })
    .describe("Server/channel bootstrap payload");

/** Permission grant. */
export const PermissionSchema: z.ZodType<Permission> = z
    .object({
        permissionID: z.string().describe("Unique permission identifier"),
        powerLevel: z.number().describe("Permission level (0-100)"),
        resourceID: z.string().describe("Resource being accessed"),
        resourceType: z.string().describe("Resource type (e.g. server)"),
        userID: z.string().describe("Grantee user ID"),
    })
    .describe("Permission grant");

/** Server invitation. */
export const InviteSchema: z.ZodType<Invite> = z
    .object({
        expiration: z.string().describe("Expiration datetime"),
        inviteID: z.string().describe("Unique invite identifier"),
        owner: z.string().describe("Inviter user ID"),
        serverID: z.string().describe("Target server ID"),
    })
    .describe("Server invitation");

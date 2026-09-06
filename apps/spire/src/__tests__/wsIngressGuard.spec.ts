/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { CallManager } from "../CallManager.ts";
import type { Database } from "../Database.ts";
import type { Device, User } from "@vex-chat/types";
import type WebSocket from "ws";

import { EventEmitter } from "events";

import { xSignAsync, xSignKeyPair, XUtils } from "@vex-chat/crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import { ClientManager } from "../ClientManager.ts";
import { TOKEN_EXPIRY } from "../Spire.ts";
import { msgpack } from "../utils/msgpack.ts";

const userDetails: User = {
    lastSeen: new Date(0).toISOString(),
    userID: "user-a",
    username: "alice",
};
const clients: ClientManager[] = [];

afterEach(() => {
    for (const client of clients.splice(0)) client.disconnect();
    vi.useRealTimers();
});

interface MockConn {
    close: () => void;
    closed: () => boolean;
    frames: () => Record<string, unknown>[];
    raw: WebSocket;
}

function errorFrames(conn: MockConn): Record<string, unknown>[] {
    return conn.frames().filter((f) => f["type"] === "error");
}

/** A well-formed client→server frame: 32-byte header + msgpack body. */
function frame(body: unknown): Buffer {
    return Buffer.concat([
        Buffer.alloc(32),
        Uint8Array.from(msgpack.encode(body)),
    ]);
}

function makeClient(
    conn: MockConn,
    dbOverrides: Partial<Database> = {},
): ClientManager {
    const db = {
        markDeviceLogin: () => Promise.resolve(),
        retrieveUser: () => Promise.resolve(null),
        retrieveUserDeviceList: () => Promise.resolve([]),
        ...dbOverrides,
    } as unknown as Database;
    const client = new ClientManager(
        conn.raw,
        db,
        {} as CallManager,
        () => {},
        userDetails,
    );
    clients.push(client);
    return client;
}

/**
 * A WebSocket stand-in: an EventEmitter for inbound frames plus capture of
 * every outbound frame, decoded for assertions.
 */
function makeConn(): MockConn {
    const emitter = new EventEmitter();
    const sent: Record<string, unknown>[] = [];
    let closed = false;
    const raw = {
        close: () => {
            closed = true;
        },
        emit: emitter.emit.bind(emitter),
        off: emitter.off.bind(emitter),
        on: emitter.on.bind(emitter),
        send: (data: Uint8Array) => {
            const decoded: unknown = msgpack.decode(
                Uint8Array.from(data).slice(32),
            );
            if (typeof decoded === "object" && decoded !== null) {
                sent.push(decoded as Record<string, unknown>);
            }
        },
    } as unknown as WebSocket;
    return {
        close: () => {
            emitter.emit("close");
        },
        closed: () => closed,
        frames: () => sent,
        raw,
    };
}

describe("websocket ingress hardening", () => {
    it("starts heartbeats on an already-open socket and cleans up dead clients", () => {
        vi.useFakeTimers();
        const conn = makeConn();
        const client = makeClient(conn);
        const failed = vi.fn();
        client.on("fail", failed);

        vi.advanceTimersByTime(20_000);

        expect(conn.frames().filter((f) => f["type"] === "ping")).toHaveLength(
            3,
        );
        expect(conn.closed()).toBe(true);
        expect(failed).toHaveBeenCalledOnce();
        expect(vi.getTimerCount()).toBe(0);
    });

    it("expires an unanswered challenge even when the socket answers heartbeats", () => {
        vi.useFakeTimers();
        const conn = makeConn();
        makeClient(conn);
        for (let elapsed = 0; elapsed < TOKEN_EXPIRY; elapsed += 5000) {
            conn.raw.emit(
                "message",
                frame({
                    transmissionID: crypto.randomUUID(),
                    type: "pong",
                }),
            );
            vi.advanceTimersByTime(5000);
        }
        expect(conn.closed()).toBe(true);
        expect(vi.getTimerCount()).toBe(0);
    });

    it("contains socket errors and ignores frames after disconnect", () => {
        const conn = makeConn();
        const retrieveUser = vi.fn(() => Promise.resolve(null));
        makeClient(conn, { retrieveUser });

        expect(() =>
            conn.raw.emit("error", new Error("invalid frame")),
        ).not.toThrow();
        conn.raw.emit(
            "message",
            frame({
                signed: new Uint8Array(96),
                transmissionID: crypto.randomUUID(),
                type: "response",
            }),
        );

        expect(conn.closed()).toBe(true);
        expect(retrieveUser).not.toHaveBeenCalled();
    });

    it("drops the connection on a malformed msgpack frame without throwing", () => {
        const conn = makeConn();
        makeClient(conn);

        const socket = conn.raw as unknown as EventEmitter;
        const badFrames = [
            // never-valid msgpack type byte behind a valid header
            Buffer.concat([Buffer.alloc(32), Buffer.from([0xc1])]),
            // truncated array behind a valid header
            Buffer.concat([Buffer.alloc(32), Buffer.from([0x92, 0x01])]),
            // msgpack `nil` — decodes fine, but dereferencing it would throw
            Buffer.concat([Buffer.alloc(32), Buffer.from([0xc0])]),
            // a primitive body is not a message object either
            frame(42),
            Buffer.alloc(64, 0xff),
        ];
        for (const bad of badFrames) {
            expect(() => {
                socket.emit("message", bad);
            }).not.toThrow();
        }

        expect(conn.closed()).toBe(true);
        const errors = errorFrames(conn);
        expect(errors.length).toBeGreaterThan(0);
        expect(
            errors.some((f) =>
                String(f["error"]).includes("Malformed message frame."),
            ),
        ).toBe(true);
    });

    it("rejects typeless message objects without killing the connection", () => {
        const conn = makeConn();
        makeClient(conn);

        const socket = conn.raw as unknown as EventEmitter;
        expect(() => {
            socket.emit(
                "message",
                frame({ transmissionID: crypto.randomUUID() }),
            );
        }).not.toThrow();

        // A real message object with no type: error reply, no teardown.
        expect(conn.closed()).toBe(false);
        expect(
            errorFrames(conn).some((f) =>
                String(f["error"]).includes("Message type is required."),
            ),
        ).toBe(true);
    });

    it("fails the connection (not the process) when auth lookups reject", async () => {
        const conn = makeConn();
        makeClient(conn, {
            retrieveUser: () => Promise.reject(new Error("database is gone")),
        });

        const socket = conn.raw as unknown as EventEmitter;
        socket.emit(
            "message",
            frame({
                signed: new Uint8Array(96),
                transmissionID: crypto.randomUUID(),
                type: "response",
            }),
        );

        // verifyResponse is async — let it settle.
        await new Promise((resolve) => {
            setImmediate(resolve);
        });
        await new Promise((resolve) => {
            setImmediate(resolve);
        });

        expect(conn.closed()).toBe(true);
        expect(
            errorFrames(conn).some((f) =>
                String(f["error"]).includes("Authentication failed."),
            ),
        ).toBe(true);
    });

    it("authenticates once even if the signed response is sent concurrently or replayed", async () => {
        vi.useFakeTimers();
        const conn = makeConn();
        const signKeys = xSignKeyPair();
        const device: Device = {
            deleted: false,
            deviceID: "device-a",
            lastLogin: new Date(0).toISOString(),
            name: "desktop",
            owner: userDetails.userID,
            signKey: XUtils.encodeHex(signKeys.publicKey),
        };
        const retrieveUser = vi.fn(() =>
            Promise.resolve({ ...userDetails, passwordHash: "x" }),
        );
        const client = makeClient(conn, {
            retrieveUser,
            retrieveUserDeviceList: () => Promise.resolve([device]),
        });

        const authed = new Promise<void>((resolve) => {
            client.on("authed", () => {
                resolve();
            });
        });

        // The constructor emitted the challenge frame; extract and sign it.
        const challengeFrame = conn
            .frames()
            .find((f) => f["type"] === "challenge");
        expect(challengeFrame).toBeDefined();
        const signed = await xSignAsync(
            Uint8Array.from(challengeFrame?.["challenge"] as Uint8Array),
            signKeys.secretKey,
        );

        const socket = conn.raw as unknown as EventEmitter;
        const response = frame({
            signed,
            transmissionID: crypto.randomUUID(),
            type: "response",
        });
        socket.emit("message", response);
        socket.emit("message", response);

        await authed;
        socket.emit("message", response);
        expect(conn.closed()).toBe(false);
        expect(
            conn.frames().filter((f) => f["type"] === "authorized"),
        ).toHaveLength(1);
        expect(retrieveUser).toHaveBeenCalledOnce();
        expect(client.getDeviceID()).toBe(device.deviceID);
        expect(vi.getTimerCount()).toBe(1);
        for (let elapsed = 0; elapsed < TOKEN_EXPIRY; elapsed += 5000) {
            socket.emit(
                "message",
                frame({ transmissionID: crypto.randomUUID(), type: "pong" }),
            );
            vi.advanceTimersByTime(5000);
        }
        expect(conn.closed()).toBe(false);
    });

    it("never authenticates a disconnected client after a pending lookup resolves", async () => {
        const conn = makeConn();
        const keys = xSignKeyPair();
        let resolveDevices: (devices: Device[]) => void = () => {};
        const devices = new Promise<Device[]>((resolve) => {
            resolveDevices = resolve;
        });
        const retrieveUserDeviceList = vi.fn(() => devices);
        const client = makeClient(conn, {
            retrieveUser: () =>
                Promise.resolve({ ...userDetails, passwordHash: "x" }),
            retrieveUserDeviceList,
        });
        const challenge = conn.frames().find((f) => f["type"] === "challenge");
        const signed = await xSignAsync(
            challenge?.["challenge"] as Uint8Array,
            keys.secretKey,
        );
        conn.raw.emit(
            "message",
            frame({
                signed,
                transmissionID: crypto.randomUUID(),
                type: "response",
            }),
        );
        await Promise.resolve();
        expect(retrieveUserDeviceList).toHaveBeenCalledOnce();
        client.disconnect();
        resolveDevices([
            {
                deleted: false,
                deviceID: "device-a",
                lastLogin: new Date(0).toISOString(),
                name: "desktop",
                owner: userDetails.userID,
                signKey: XUtils.encodeHex(keys.publicKey),
            },
        ]);
        await new Promise((resolve) => {
            setImmediate(resolve);
        });

        expect(
            conn.frames().filter((f) => f["type"] === "authorized"),
        ).toHaveLength(0);
        expect(client.getDeviceID()).toBeNull();
        expect(client.getUserID()).toBeNull();
    });

    it("does not expose a device after a valid signature of the wrong challenge", async () => {
        const conn = makeConn();
        const keys = xSignKeyPair();
        const client = makeClient(conn, {
            retrieveUser: () =>
                Promise.resolve({ ...userDetails, passwordHash: "x" }),
            retrieveUserDeviceList: () =>
                Promise.resolve([
                    {
                        deleted: false,
                        deviceID: "device-a",
                        lastLogin: new Date(0).toISOString(),
                        name: "desktop",
                        owner: userDetails.userID,
                        signKey: XUtils.encodeHex(keys.publicKey),
                    },
                ]),
        });
        const signed = await xSignAsync(new Uint8Array(16), keys.secretKey);
        conn.raw.emit(
            "message",
            frame({
                signed,
                transmissionID: crypto.randomUUID(),
                type: "response",
            }),
        );
        await new Promise((resolve) => {
            setImmediate(resolve);
        });

        expect(conn.closed()).toBe(true);
        expect(client.getDeviceID()).toBeNull();
        expect(
            conn.frames().filter((f) => f["type"] === "authorized"),
        ).toHaveLength(0);
    });
});

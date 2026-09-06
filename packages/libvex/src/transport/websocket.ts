/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Adapts the standard WebSocket API (addEventListener/MessageEvent) to the
 * EventEmitter-style .on()/.off() interface used internally by Client.
 *
 * Works everywhere: Node 22+, browsers, Tauri, React Native.
 */
import type { WebSocketLike } from "./types.js";

type SocketListener =
    | (() => void)
    | ((data: Uint8Array) => void)
    | ((error: Error) => void);

export class WebSocketAdapter implements WebSocketLike {
    onerror: ((err: Error | Event) => void) | null = null;
    get readyState() {
        return this.ws.readyState;
    }
    private readonly listeners = new Map<
        string,
        Map<SocketListener, EventListener[]>
    >();

    private readonly ws: WebSocket;

    constructor(url: string, _options?: object) {
        this.ws = new globalThis.WebSocket(url);
        this.ws.binaryType = "arraybuffer";
        this.ws.onerror = (ev) => this.onerror?.(ev);
    }

    close() {
        this.ws.close();
    }

    off(event: "close" | "open", listener: () => void): void;
    off(event: "error", listener: (error: Error) => void): void;
    off(event: "message", listener: (data: Uint8Array) => void): void;
    off(event: string, listener: never): void {
        const eventListeners = this.listeners.get(event);
        const wrappers = eventListeners?.get(listener);
        const wrapped = wrappers?.pop();
        if (wrapped) {
            this.ws.removeEventListener(event, wrapped);
            if (wrappers?.length === 0) {
                eventListeners?.delete(listener);
            }
            if (eventListeners?.size === 0) {
                this.listeners.delete(event);
            }
        }
    }

    on(event: "close" | "open", listener: () => void): void;
    on(event: "error", listener: (error: Error) => void): void;
    on(event: "message", listener: (data: Uint8Array) => void): void;
    on(event: string, listener: never): void {
        let wrapped: EventListener;
        if (event === "message") {
            const typedListener: (data: Uint8Array) => void = listener;
            wrapped = (ev: Event) => {
                if (!("data" in ev)) return;
                const { data } = ev;
                if (data instanceof ArrayBuffer) {
                    typedListener(new Uint8Array(data));
                }
            };
        } else if (event === "error") {
            const typedListener: (error: Error) => void = listener;
            wrapped = (ev: Event) => {
                typedListener(
                    ev instanceof Error ? ev : new Error("WebSocket error"),
                );
            };
        } else {
            // "open" | "close"
            const typedListener: () => void = listener;
            wrapped = () => {
                typedListener();
            };
        }
        // Keep each registration separately, as EventEmitter does. Sharing a
        // callback across events must not overwrite another event's wrapper.
        let eventListeners = this.listeners.get(event);
        if (!eventListeners) {
            eventListeners = new Map();
            this.listeners.set(event, eventListeners);
        }
        const wrappers = eventListeners.get(listener) ?? [];
        wrappers.push(wrapped);
        eventListeners.set(listener, wrappers);
        this.ws.addEventListener(event, wrapped);
    }

    /**
     * Forward `data` to the underlying socket if and only if it's
     * OPEN. Throws `WebSocketNotOpenError` (a typed, named error)
     * otherwise, so callers can distinguish a teardown race from a
     * protocol error and either retry on the next socket or drop
     * the frame.
     *
     * Without this guard a transient teardown surfaces as
     * `DOMException("INVALID_STATE_ERR")` from the platform WebSocket
     * — opaque, hard to catch by name, and surfaced by React Native
     * as an unhandled promise rejection (red box / "frozen UI") any
     * time a `void this.send(...)` callsite (ping / pong / queued
     * notify reply) is in flight when the close event lands.
     */
    send(data: Uint8Array) {
        if (this.ws.readyState !== 1) {
            throw new WebSocketNotOpenError(this.ws.readyState);
        }
        try {
            this.ws.send(new Uint8Array(data));
        } catch (err: unknown) {
            // Handles the TOCTOU between the readyState check above
            // and the actual `ws.send` call. React Native's bridge
            // can dispatch a `websocketMessage` and a
            // `websocketClosed` back-to-back in the same JS turn:
            // our message listener observes readyState=1 because
            // the close event hasn't been processed yet, but the
            // underlying WebSocket has already transitioned native-
            // side and `send` throws INVALID_STATE_ERR.
            if (
                err instanceof Error &&
                /invalid_state|INVALID_STATE_ERR/i.test(err.message)
            ) {
                throw new WebSocketNotOpenError(this.ws.readyState);
            }
            throw err;
        }
    }

    terminate() {
        this.ws.close();
    }
}

/**
 * Thrown when `send()` is called on a socket that's not in the OPEN
 * state. Surfaced as a named, recognisable type so callers can
 * distinguish "transient teardown race" from a real protocol error
 * and either drop the frame (pings) or wait for reconnect (real
 * payloads).
 *
 * Replaces the bare `DOMException("INVALID_STATE_ERR")` that the
 * underlying WebSocket throws — that one is opaque, gets reported
 * by RN's dev console as a red unhandled rejection, and freezes the
 * passkey/foreground/network-swap recovery flow because every code
 * path that voids the resulting promise leaks the rejection.
 */
export class WebSocketNotOpenError extends Error {
    public readonly readyState: number;

    constructor(readyState: number) {
        super(`WebSocket is not open (readyState=${readyState.toString()})`);
        this.name = "WebSocketNotOpenError";
        this.readyState = readyState;
    }
}

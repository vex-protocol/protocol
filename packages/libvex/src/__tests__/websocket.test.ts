import { afterEach, describe, expect, it, vi } from "vitest";

import { WebSocketAdapter } from "../transport/websocket.js";

class FakeWebSocket extends EventTarget {
    static latest: FakeWebSocket;
    binaryType = "blob";
    onerror: ((event: Event) => void) | null = null;
    readyState = 1;

    constructor(_url: string) {
        super();
        FakeWebSocket.latest = this;
    }

    close() {}
    send(_data: Uint8Array) {}
}

afterEach(() => {
    vi.unstubAllGlobals();
});

function createAdapter() {
    vi.stubGlobal("WebSocket", FakeWebSocket);
    const adapter = new WebSocketAdapter("wss://example.test");
    return { adapter, socket: FakeWebSocket.latest };
}

describe("WebSocketAdapter listener ownership", () => {
    it("removes a callback independently from open and close", () => {
        const { adapter, socket } = createAdapter();
        const listener = vi.fn();
        adapter.on("open", listener);
        adapter.on("close", listener);

        adapter.off("open", listener);
        socket.dispatchEvent(new Event("open"));
        expect(listener).not.toHaveBeenCalled();
        socket.dispatchEvent(new Event("close"));
        expect(listener).toHaveBeenCalledOnce();

        adapter.off("close", listener);
        socket.dispatchEvent(new Event("close"));
        expect(listener).toHaveBeenCalledOnce();
    });

    it.each(["open", "close", "error", "message"] as const)(
        "removes duplicate %s registrations one at a time",
        (event) => {
            const { adapter, socket } = createAdapter();
            const listener = vi.fn();
            const frame = () =>
                event === "message"
                    ? new MessageEvent("message", {
                          data: new Uint8Array([1, 2]).buffer,
                      })
                    : new Event(event);
            if (event === "message") {
                adapter.on(event, listener);
                adapter.on(event, listener);
            } else if (event === "error") {
                adapter.on(event, listener);
                adapter.on(event, listener);
            } else {
                adapter.on(event, listener);
                adapter.on(event, listener);
            }
            socket.dispatchEvent(frame());
            expect(listener).toHaveBeenCalledTimes(2);

            if (event === "message") adapter.off(event, listener);
            else if (event === "error") adapter.off(event, listener);
            else adapter.off(event, listener);
            socket.dispatchEvent(frame());
            expect(listener).toHaveBeenCalledTimes(3);

            if (event === "message") adapter.off(event, listener);
            else if (event === "error") adapter.off(event, listener);
            else adapter.off(event, listener);
            socket.dispatchEvent(frame());
            expect(listener).toHaveBeenCalledTimes(3);
        },
    );

    it("ignores removal of an unregistered callback", () => {
        const { adapter, socket } = createAdapter();
        const listener = vi.fn();
        adapter.on("open", listener);
        adapter.off("open", vi.fn());
        adapter.off("close", listener);

        socket.dispatchEvent(new Event("open"));

        expect(listener).toHaveBeenCalledOnce();
    });
});

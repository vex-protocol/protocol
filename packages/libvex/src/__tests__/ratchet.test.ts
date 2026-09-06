/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { XUtils } from "@vex-chat/crypto";

import { describe, expect, it } from "vitest";

import {
    decodeRatchetHeader,
    deriveBootstrapSendChain,
    encodeRatchetHeader,
    hasRemoteDhChanged,
    initRatchetSession,
    MAX_SKIP_MESSAGE_GAP,
    MAX_SKIPPED_KEYS,
    parseSkippedKeysStrict,
    ratchetStepReceive,
    ratchetStepSend,
    sessionToSqlPatch,
    takeReceiveMessageKey,
    takeSendMessageKey,
} from "../utils/ratchet.js";
import { sqlSessionToCrypto } from "../utils/sqlSessionToCrypto.js";

describe("double ratchet helpers", () => {
    it("derives matching message keys for first exchange and reply", async () => {
        const sk = XUtils.decodeHex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        const alice = await initRatchetSession(sk, "initiator");
        const bob = await initRatchetSession(sk, "receiver");

        const aliceState = {
            CKr: alice.CKr ? XUtils.decodeHex(alice.CKr) : null,
            CKs: alice.CKs ? XUtils.decodeHex(alice.CKs) : null,
            DHr: alice.DHr ? XUtils.decodeHex(alice.DHr) : null,
            DHsPrivate: XUtils.decodeHex(alice.DHsPrivate),
            DHsPublic: XUtils.decodeHex(alice.DHsPublic),
            Nr: alice.Nr,
            Ns: alice.Ns,
            PN: alice.PN,
            RK: XUtils.decodeHex(alice.RK),
            skippedKeys: {} as Record<string, string>,
        };
        const bobState = {
            CKr: bob.CKr ? XUtils.decodeHex(bob.CKr) : null,
            CKs: bob.CKs ? XUtils.decodeHex(bob.CKs) : null,
            DHr: bob.DHr ? XUtils.decodeHex(bob.DHr) : null,
            DHsPrivate: XUtils.decodeHex(bob.DHsPrivate),
            DHsPublic: XUtils.decodeHex(bob.DHsPublic),
            Nr: bob.Nr,
            Ns: bob.Ns,
            PN: bob.PN,
            RK: XUtils.decodeHex(bob.RK),
            skippedKeys: {} as Record<string, string>,
        };

        if (!aliceState.CKs) {
            await ratchetStepSend(aliceState);
        }
        const a1 = takeSendMessageKey(aliceState);
        const h1 = decodeRatchetHeader(
            encodeRatchetHeader({
                dhPub: aliceState.DHsPublic,
                n: a1.n,
                pn: aliceState.PN,
                version: 1,
            }),
        );

        expect(hasRemoteDhChanged(bobState.DHr, h1.dhPub)).toBe(true);
        if (!bobState.DHr && bobState.CKr) {
            bobState.DHr = h1.dhPub;
        } else {
            await ratchetStepReceive(bobState, h1.dhPub, h1.pn);
        }
        const b1 = takeReceiveMessageKey(bobState, h1.dhPub, h1.n);
        expect(XUtils.bytesEqual(a1.messageKey, b1)).toBe(true);

        if (!bobState.CKs) {
            await ratchetStepSend(bobState);
        }
        const bReply = takeSendMessageKey(bobState);
        const h2 = decodeRatchetHeader(
            encodeRatchetHeader({
                dhPub: bobState.DHsPublic,
                n: bReply.n,
                pn: bobState.PN,
                version: 1,
            }),
        );
        if (!aliceState.DHr && aliceState.CKr) {
            aliceState.DHr = h2.dhPub;
        } else if (hasRemoteDhChanged(aliceState.DHr, h2.dhPub)) {
            await ratchetStepReceive(aliceState, h2.dhPub, h2.pn);
        }
        const aReply = takeReceiveMessageKey(aliceState, h2.dhPub, h2.n);
        expect(XUtils.bytesEqual(aReply, bReply.messageKey)).toBe(true);
    });

    it("supports skipped keys for out-of-order messages", async () => {
        const sk = XUtils.decodeHex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        const initiator = await initRatchetSession(sk, "initiator");
        const receiver = await initRatchetSession(sk, "receiver");

        const s = {
            CKr: initiator.CKr ? XUtils.decodeHex(initiator.CKr) : null,
            CKs: initiator.CKs ? XUtils.decodeHex(initiator.CKs) : null,
            DHr: initiator.DHr ? XUtils.decodeHex(initiator.DHr) : null,
            DHsPrivate: XUtils.decodeHex(initiator.DHsPrivate),
            DHsPublic: XUtils.decodeHex(initiator.DHsPublic),
            Nr: initiator.Nr,
            Ns: initiator.Ns,
            PN: initiator.PN,
            RK: XUtils.decodeHex(initiator.RK),
            skippedKeys: {} as Record<string, string>,
        };
        const r = {
            CKr: receiver.CKr ? XUtils.decodeHex(receiver.CKr) : null,
            CKs: receiver.CKs ? XUtils.decodeHex(receiver.CKs) : null,
            DHr: receiver.DHr ? XUtils.decodeHex(receiver.DHr) : null,
            DHsPrivate: XUtils.decodeHex(receiver.DHsPrivate),
            DHsPublic: XUtils.decodeHex(receiver.DHsPublic),
            Nr: receiver.Nr,
            Ns: receiver.Ns,
            PN: receiver.PN,
            RK: XUtils.decodeHex(receiver.RK),
            skippedKeys: {} as Record<string, string>,
        };

        if (!s.CKs) {
            await ratchetStepSend(s);
        }
        const m0 = takeSendMessageKey(s);
        const m1 = takeSendMessageKey(s);
        const h0 = {
            dhPub: s.DHsPublic,
            n: m0.n,
            pn: s.PN,
            version: 1 as const,
        };
        const h1 = {
            dhPub: s.DHsPublic,
            n: m1.n,
            pn: s.PN,
            version: 1 as const,
        };

        if (!r.DHr && r.CKr) {
            r.DHr = h1.dhPub;
        } else {
            await ratchetStepReceive(r, h1.dhPub, h1.pn);
        }
        const r1 = takeReceiveMessageKey(r, h1.dhPub, h1.n);
        expect(XUtils.bytesEqual(r1, m1.messageKey)).toBe(true);

        const r0 = takeReceiveMessageKey(r, h0.dhPub, h0.n);
        expect(XUtils.bytesEqual(r0, m0.messageKey)).toBe(true);
    });

    it("advances sending chain for every message within same DH epoch", async () => {
        const sk = XUtils.decodeHex(
            "5555555555555555555555555555555555555555555555555555555555555555",
        );
        const initiator = await initRatchetSession(sk, "initiator");
        const sender = {
            CKr: initiator.CKr ? XUtils.decodeHex(initiator.CKr) : null,
            CKs: initiator.CKs ? XUtils.decodeHex(initiator.CKs) : null,
            DHr: initiator.DHr ? XUtils.decodeHex(initiator.DHr) : null,
            DHsPrivate: XUtils.decodeHex(initiator.DHsPrivate),
            DHsPublic: XUtils.decodeHex(initiator.DHsPublic),
            Nr: initiator.Nr,
            Ns: initiator.Ns,
            PN: initiator.PN,
            RK: XUtils.decodeHex(initiator.RK),
            skippedKeys: {} as Record<string, string>,
        };

        if (!sender.CKs) {
            await ratchetStepSend(sender);
        }
        const dhPubBefore = XUtils.encodeHex(sender.DHsPublic);

        const m0 = takeSendMessageKey(sender);
        const m1 = takeSendMessageKey(sender);
        const m2 = takeSendMessageKey(sender);

        expect(m0.n).toBe(0);
        expect(m1.n).toBe(1);
        expect(m2.n).toBe(2);
        expect(sender.Ns).toBe(3);
        expect(XUtils.bytesEqual(m0.messageKey, m1.messageKey)).toBe(false);
        expect(XUtils.bytesEqual(m1.messageKey, m2.messageKey)).toBe(false);
        expect(XUtils.encodeHex(sender.DHsPublic)).toBe(dhPubBefore);
    });

    it("decrypts first subsequent reply after initial mail via bootstrap chain", async () => {
        const sk = XUtils.decodeHex(
            "6666666666666666666666666666666666666666666666666666666666666666",
        );
        const initiator = await initRatchetSession(sk, "initiator");
        const receiver = await initRatchetSession(sk, "receiver");

        const alice = {
            CKr: initiator.CKr ? XUtils.decodeHex(initiator.CKr) : null,
            CKs: initiator.CKs ? XUtils.decodeHex(initiator.CKs) : null,
            DHr: initiator.DHr ? XUtils.decodeHex(initiator.DHr) : null,
            DHsPrivate: XUtils.decodeHex(initiator.DHsPrivate),
            DHsPublic: XUtils.decodeHex(initiator.DHsPublic),
            Nr: initiator.Nr,
            Ns: initiator.Ns,
            PN: initiator.PN,
            RK: XUtils.decodeHex(initiator.RK),
            skippedKeys: {} as Record<string, string>,
        };
        const bob = {
            CKr: receiver.CKr ? XUtils.decodeHex(receiver.CKr) : null,
            CKs: receiver.CKs ? XUtils.decodeHex(receiver.CKs) : null,
            DHr: receiver.DHr ? XUtils.decodeHex(receiver.DHr) : null,
            DHsPrivate: XUtils.decodeHex(receiver.DHsPrivate),
            DHsPublic: XUtils.decodeHex(receiver.DHsPublic),
            Nr: receiver.Nr,
            Ns: receiver.Ns,
            PN: receiver.PN,
            RK: XUtils.decodeHex(receiver.RK),
            skippedKeys: {} as Record<string, string>,
        };

        if (!bob.CKs) {
            await ratchetStepSend(bob);
        }
        const outbound = takeSendMessageKey(bob);
        const header = decodeRatchetHeader(
            encodeRatchetHeader({
                dhPub: bob.DHsPublic,
                n: outbound.n,
                pn: bob.PN,
                version: 1,
            }),
        );

        if (!alice.DHr) {
            alice.DHr = header.dhPub;
            if (!alice.CKr) {
                alice.CKr = deriveBootstrapSendChain(alice.RK);
            }
        }
        const inbound = takeReceiveMessageKey(alice, header.dhPub, header.n);
        expect(XUtils.bytesEqual(inbound, outbound.messageKey)).toBe(true);
    });

    it("keeps sessions robust over long back-and-forth with persistence", async () => {
        const sk = XUtils.decodeHex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        );
        const initiator = await initRatchetSession(sk, "initiator");
        const receiver = await initRatchetSession(sk, "receiver");

        let alice = {
            CKr: initiator.CKr ? XUtils.decodeHex(initiator.CKr) : null,
            CKs: initiator.CKs ? XUtils.decodeHex(initiator.CKs) : null,
            DHr: initiator.DHr ? XUtils.decodeHex(initiator.DHr) : null,
            DHsPrivate: XUtils.decodeHex(initiator.DHsPrivate),
            DHsPublic: XUtils.decodeHex(initiator.DHsPublic),
            Nr: initiator.Nr,
            Ns: initiator.Ns,
            PN: initiator.PN,
            RK: XUtils.decodeHex(initiator.RK),
            skippedKeys: {} as Record<string, string>,
        };
        let bob = {
            CKr: receiver.CKr ? XUtils.decodeHex(receiver.CKr) : null,
            CKs: receiver.CKs ? XUtils.decodeHex(receiver.CKs) : null,
            DHr: receiver.DHr ? XUtils.decodeHex(receiver.DHr) : null,
            DHsPrivate: XUtils.decodeHex(receiver.DHsPrivate),
            DHsPublic: XUtils.decodeHex(receiver.DHsPublic),
            Nr: receiver.Nr,
            Ns: receiver.Ns,
            PN: receiver.PN,
            RK: XUtils.decodeHex(receiver.RK),
            skippedKeys: {} as Record<string, string>,
        };

        const rounds = 120;
        for (let i = 0; i < rounds; i += 1) {
            if (!alice.CKs) {
                await ratchetStepSend(alice);
            }
            const aOut = takeSendMessageKey(alice);
            const aHdr = decodeRatchetHeader(
                encodeRatchetHeader({
                    dhPub: alice.DHsPublic,
                    n: aOut.n,
                    pn: alice.PN,
                    version: 1,
                }),
            );
            if (!bob.DHr && bob.CKr) {
                bob.DHr = aHdr.dhPub;
            } else if (hasRemoteDhChanged(bob.DHr, aHdr.dhPub)) {
                await ratchetStepReceive(bob, aHdr.dhPub, aHdr.pn);
            }
            const bIn = takeReceiveMessageKey(bob, aHdr.dhPub, aHdr.n);
            expect(XUtils.bytesEqual(aOut.messageKey, bIn)).toBe(true);

            if (!bob.CKs) {
                await ratchetStepSend(bob);
            }
            const bOut = takeSendMessageKey(bob);
            const bHdr = decodeRatchetHeader(
                encodeRatchetHeader({
                    dhPub: bob.DHsPublic,
                    n: bOut.n,
                    pn: bob.PN,
                    version: 1,
                }),
            );
            if (!alice.DHr && alice.CKr) {
                alice.DHr = bHdr.dhPub;
            } else if (hasRemoteDhChanged(alice.DHr, bHdr.dhPub)) {
                await ratchetStepReceive(alice, bHdr.dhPub, bHdr.pn);
            }
            const aIn = takeReceiveMessageKey(alice, bHdr.dhPub, bHdr.n);
            expect(XUtils.bytesEqual(aIn, bOut.messageKey)).toBe(true);

            // Simulate periodic app restarts by serializing and reloading session state.
            if (i > 0 && i % 10 === 0) {
                alice = hydrateState(alice, "alice-session");
                bob = hydrateState(bob, "bob-session");
            }
        }

        expect(alice.Nr + alice.Ns).toBeGreaterThan(0);
        expect(bob.Nr + bob.Ns).toBeGreaterThan(0);
        expect(alice.CKr ?? alice.CKs).not.toBeNull();
        expect(bob.CKr ?? bob.CKs).not.toBeNull();
    });

    it("nightly: survives 1000-message randomized streaks with persistence", async () => {
        if (process.env["LIBVEX_NIGHTLY_STRESS"] !== "1") {
            return;
        }
        const sk = XUtils.decodeHex(
            "4444444444444444444444444444444444444444444444444444444444444444",
        );
        const initiator = await initRatchetSession(sk, "initiator");
        const receiver = await initRatchetSession(sk, "receiver");

        let alice = {
            CKr: initiator.CKr ? XUtils.decodeHex(initiator.CKr) : null,
            CKs: initiator.CKs ? XUtils.decodeHex(initiator.CKs) : null,
            DHr: initiator.DHr ? XUtils.decodeHex(initiator.DHr) : null,
            DHsPrivate: XUtils.decodeHex(initiator.DHsPrivate),
            DHsPublic: XUtils.decodeHex(initiator.DHsPublic),
            Nr: initiator.Nr,
            Ns: initiator.Ns,
            PN: initiator.PN,
            RK: XUtils.decodeHex(initiator.RK),
            skippedKeys: {} as Record<string, string>,
        };
        let bob = {
            CKr: receiver.CKr ? XUtils.decodeHex(receiver.CKr) : null,
            CKs: receiver.CKs ? XUtils.decodeHex(receiver.CKs) : null,
            DHr: receiver.DHr ? XUtils.decodeHex(receiver.DHr) : null,
            DHsPrivate: XUtils.decodeHex(receiver.DHsPrivate),
            DHsPublic: XUtils.decodeHex(receiver.DHsPublic),
            Nr: receiver.Nr,
            Ns: receiver.Ns,
            PN: receiver.PN,
            RK: XUtils.decodeHex(receiver.RK),
            skippedKeys: {} as Record<string, string>,
        };

        const rng = mulberry32(0xdecafbad);
        const totalMessages = 1000;
        for (let i = 0; i < totalMessages; i += 1) {
            const aliceSends = rng() < 0.5;
            const sender = aliceSends ? alice : bob;
            const receiverState = aliceSends ? bob : alice;

            if (!sender.CKs) {
                await ratchetStepSend(sender);
            }
            const outbound = takeSendMessageKey(sender);
            const header = decodeRatchetHeader(
                encodeRatchetHeader({
                    dhPub: sender.DHsPublic,
                    n: outbound.n,
                    pn: sender.PN,
                    version: 1,
                }),
            );

            if (!receiverState.DHr && receiverState.CKr) {
                receiverState.DHr = header.dhPub;
            } else if (hasRemoteDhChanged(receiverState.DHr, header.dhPub)) {
                await ratchetStepReceive(
                    receiverState,
                    header.dhPub,
                    header.pn,
                );
            }
            const inbound = takeReceiveMessageKey(
                receiverState,
                header.dhPub,
                header.n,
            );
            expect(XUtils.bytesEqual(outbound.messageKey, inbound)).toBe(true);

            if (i > 0 && i % 25 === 0) {
                alice = hydrateState(alice, "alice-nightly");
                bob = hydrateState(bob, "bob-nightly");
            }
        }

        expect(alice.Nr + alice.Ns + bob.Nr + bob.Ns).toBeGreaterThan(500);
    });

    it("rejects excessive receive message gap", () => {
        const state = {
            CKr: XUtils.decodeHex(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            DHr: XUtils.decodeHex(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            Nr: 0,
            skippedKeys: {} as Record<string, string>,
        };

        expect(() =>
            takeReceiveMessageKey(state, state.DHr, MAX_SKIP_MESSAGE_GAP + 1),
        ).toThrow("Ratchet skip window exceeded");
    });

    it.each([0, 1, 31, 33, 64])(
        "rejects %i-byte DH keys in ratchet headers",
        (length) => {
            const wire = new Uint8Array(11 + length);
            const view = new DataView(wire.buffer);
            view.setUint8(0, 1);
            view.setUint16(1, length, false);

            expect(() => decodeRatchetHeader(wire)).toThrow(/32-byte DH key/);
            expect(() =>
                encodeRatchetHeader({
                    dhPub: new Uint8Array(length),
                    n: 0,
                    pn: 0,
                    version: 1,
                }),
            ).toThrow(/32-byte DH key/);
        },
    );

    it.each([-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 0x100000000])(
        "rejects invalid message index %s before advancing the send chain",
        (index) => {
            const state = { CKs: new Uint8Array(32).fill(1), Ns: index };
            const before = new Uint8Array(state.CKs);
            expect(() => takeSendMessageKey(state)).toThrow(/unsigned 32-bit/);
            expect(state.CKs).toEqual(before);
            expect(() =>
                encodeRatchetHeader({
                    dhPub: new Uint8Array(32),
                    n: index,
                    pn: 0,
                    version: 1,
                }),
            ).toThrow(/unsigned 32-bit/);
            expect(() =>
                encodeRatchetHeader({
                    dhPub: new Uint8Array(32),
                    n: 0,
                    pn: index,
                    version: 1,
                }),
            ).toThrow(/unsigned 32-bit/);
        },
    );

    it("retains the newest skipped keys across consecutive maximum gaps", () => {
        const chain = new Uint8Array(32).fill(1);
        const dh = new Uint8Array(32).fill(2);
        const sender = { CKs: chain, Ns: 0 };
        const receiver = {
            CKr: chain,
            DHr: dh,
            Nr: 0,
            skippedKeys: {} as Record<string, string>,
        };
        const messages = Array.from(
            { length: MAX_SKIP_MESSAGE_GAP * 2 + 2 },
            () => takeSendMessageKey(sender).messageKey,
        );

        expect(
            takeReceiveMessageKey(receiver, dh, MAX_SKIP_MESSAGE_GAP),
        ).toEqual(messages[MAX_SKIP_MESSAGE_GAP]);
        expect(
            takeReceiveMessageKey(receiver, dh, MAX_SKIP_MESSAGE_GAP * 2 + 1),
        ).toEqual(messages[MAX_SKIP_MESSAGE_GAP * 2 + 1]);
        const prefix = XUtils.encodeHex(dh);
        expect(Object.keys(receiver.skippedKeys)).toHaveLength(
            MAX_SKIPPED_KEYS,
        );
        expect(receiver.skippedKeys[`${prefix}:0`]).toBeUndefined();
        expect(
            takeReceiveMessageKey(receiver, dh, MAX_SKIP_MESSAGE_GAP + 1),
        ).toEqual(messages[MAX_SKIP_MESSAGE_GAP + 1]);
        expect(receiver.Nr).toBe(MAX_SKIP_MESSAGE_GAP * 2 + 2);
        expect(Object.keys(receiver.skippedKeys)).toHaveLength(
            MAX_SKIPPED_KEYS - 1,
        );
    });

    it("sanitizes skipped-keys payload bounds and format", () => {
        const validDh = "aa".repeat(32);
        const validValue = "bb".repeat(32);
        const oversized = Object.fromEntries(
            Array.from({ length: MAX_SKIPPED_KEYS + 50 }, (_v, i) => [
                `${validDh}:${String(i)}`,
                validValue,
            ]),
        ) as Record<string, string>;
        const bounded = parseSkippedKeysStrict(JSON.stringify(oversized));
        expect(Object.keys(bounded).length).toBe(MAX_SKIPPED_KEYS);

        const filtered = parseSkippedKeysStrict(
            JSON.stringify({
                [`${validDh}:0`]: "not-hex",
                [`${validDh}:1`]: validValue,
                [`${validDh}:2`]: "ff",
                [`${validDh}:4294967296`]: validValue,
                "aa:3": validValue,
                "bad-key-format": validValue,
            }),
        );
        expect(filtered["bad-key-format"]).toBeUndefined();
        expect(filtered[`${validDh}:0`]).toBeUndefined();
        expect(filtered).toEqual({ [`${validDh}:1`]: validValue });
    });
});

function hydrateState(
    state: {
        CKr: null | Uint8Array;
        CKs: null | Uint8Array;
        DHr: null | Uint8Array;
        DHsPrivate: Uint8Array;
        DHsPublic: Uint8Array;
        Nr: number;
        Ns: number;
        PN: number;
        RK: Uint8Array;
        skippedKeys: Record<string, string>;
    },
    sessionID: string,
) {
    const sql = sessionToSqlPatch(state);
    const roundTripped = sqlSessionToCrypto({
        CKr: sql.CKr,
        CKs: sql.CKs,
        deviceID: "device",
        DHr: sql.DHr,
        DHsPrivate: sql.DHsPrivate,
        DHsPublic: sql.DHsPublic,
        fingerprint: "00",
        lastUsed: new Date().toISOString(),
        mode: "initiator",
        Nr: sql.Nr,
        Ns: sql.Ns,
        PN: sql.PN,
        publicKey: "00",
        RK: sql.RK,
        sessionID,
        SK: "00",
        skippedKeys: sql.skippedKeys,
        userID: "user",
        verified: false,
    });
    return {
        CKr: roundTripped.CKr,
        CKs: roundTripped.CKs,
        DHr: roundTripped.DHr,
        DHsPrivate: roundTripped.DHsPrivate,
        DHsPublic: roundTripped.DHsPublic,
        Nr: roundTripped.Nr,
        Ns: roundTripped.Ns,
        PN: roundTripped.PN,
        RK: roundTripped.RK,
        skippedKeys: roundTripped.skippedKeys,
    };
}

function mulberry32(seed: number): () => number {
    let t = seed >>> 0;
    return () => {
        t = (t + 0x6d2b79f5) | 0;
        let x = Math.imul(t ^ (t >>> 15), 1 | t);
        x ^= x + Math.imul(x ^ (x >>> 7), 61 | x);
        return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
    };
}

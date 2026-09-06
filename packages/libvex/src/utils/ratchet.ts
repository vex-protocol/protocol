/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { SessionCrypto } from "../types/crypto.js";
import type { RatchetHeader, SessionSQL } from "@vex-chat/types";

import {
    xBoxKeyPairAsync,
    xConcat,
    xDHAsync,
    xHMAC,
    xKDF,
    XUtils,
} from "@vex-chat/crypto";

const VERSION = 1;
const DH_PUBLIC_KEY_BYTES = 32;
const MAX_MESSAGE_INDEX = 0xffffffff;

type RatchetState = Pick<
    SessionCrypto,
    | "CKr"
    | "CKs"
    | "DHr"
    | "DHsPrivate"
    | "DHsPublic"
    | "Nr"
    | "Ns"
    | "PN"
    | "RK"
    | "skippedKeys"
>;
type ReceiveChainState = Pick<
    RatchetState,
    "CKr" | "DHr" | "Nr" | "skippedKeys"
>;

// Per-message derivation guard: do not derive more than this many skipped
// message keys from a single ratchet header jump.
export const MAX_SKIP_MESSAGE_GAP = 1024;

// Per-session retention guard: keep this close to Signal's recommended
// skipped-message-key cache bound so delayed messages work without retaining
// excessive decryptable past message keys.
export const MAX_SKIPPED_KEYS = 1024;

const encoder = new TextEncoder();

export function decodeRatchetHeader(extra: Uint8Array): RatchetHeader {
    if (extra.length < 11) {
        throw new Error("Malformed ratchet header: too short.");
    }
    const view = new DataView(extra.buffer, extra.byteOffset, extra.byteLength);
    const version = view.getUint8(0);
    if (version !== VERSION) {
        throw new Error("Unsupported ratchet header version.");
    }
    const dhLen = view.getUint16(1, false);
    if (dhLen !== DH_PUBLIC_KEY_BYTES) {
        throw new Error("Malformed ratchet header: expected a 32-byte DH key.");
    }
    const expected = 3 + dhLen + 8;
    if (extra.length !== expected) {
        throw new Error("Malformed ratchet header length.");
    }
    const dhPub = extra.slice(3, 3 + dhLen);
    const pn = view.getUint32(3 + dhLen, false);
    const n = view.getUint32(7 + dhLen, false);
    return { dhPub, n, pn, version: 1 };
}

export function deriveBootstrapSendChain(rootKey: Uint8Array): Uint8Array {
    return xHMAC({ label: "bootstrap-send-chain", version: VERSION }, rootKey);
}

export function deriveInitialRootKey(sk: Uint8Array): Uint8Array {
    return xKDF(xConcat(sk, encoder.encode("dr-root-v1")));
}

export function encodeRatchetHeader(header: RatchetHeader): Uint8Array {
    if (header.dhPub.length !== DH_PUBLIC_KEY_BYTES) {
        throw new Error("Ratchet header requires a 32-byte DH key.");
    }
    validateMessageIndex(header.n);
    validateMessageIndex(header.pn);
    const out = new Uint8Array(3 + header.dhPub.length + 8);
    const view = new DataView(out.buffer);
    view.setUint8(0, VERSION);
    view.setUint16(1, header.dhPub.length, false);
    out.set(header.dhPub, 3);
    view.setUint32(3 + header.dhPub.length, header.pn, false);
    view.setUint32(7 + header.dhPub.length, header.n, false);
    return out;
}

export function hasRemoteDhChanged(
    current: null | Uint8Array,
    incoming: Uint8Array,
): boolean {
    if (!current) {
        return true;
    }
    return !XUtils.bytesEqual(current, incoming);
}

export async function initRatchetSession(
    sk: Uint8Array,
    mode: "initiator" | "receiver",
): Promise<{
    CKr: null | string;
    CKs: null | string;
    DHr: null | string;
    DHsPrivate: string;
    DHsPublic: string;
    Nr: number;
    Ns: number;
    PN: number;
    RK: string;
    skippedKeys: string;
}> {
    const RK = deriveInitialRootKey(sk);
    const DHs = await xBoxKeyPairAsync();
    const initialChain = xHMAC({ label: "init-chain", version: VERSION }, RK);
    return {
        CKr: mode === "receiver" ? XUtils.encodeHex(initialChain) : null,
        CKs: mode === "initiator" ? XUtils.encodeHex(initialChain) : null,
        DHr: null,
        DHsPrivate: XUtils.encodeHex(DHs.secretKey),
        DHsPublic: XUtils.encodeHex(DHs.publicKey),
        Nr: 0,
        Ns: 0,
        PN: 0,
        RK: XUtils.encodeHex(RK),
        skippedKeys: "{}",
    };
}

export function parseSkippedKeysStrict(raw: string): Record<string, string> {
    try {
        const parsed: unknown = JSON.parse(raw);
        if (
            typeof parsed !== "object" ||
            parsed === null ||
            Array.isArray(parsed)
        ) {
            return {};
        }
        const entries = Object.entries(parsed).slice(0, MAX_SKIPPED_KEYS);
        const out: Record<string, string> = {};
        for (const [k, v] of entries) {
            if (
                typeof v === "string" &&
                isKeyHex(v) &&
                isSkippedKeyIdFormat(k)
            ) {
                out[k] = v;
            }
        }
        return out;
    } catch {
        return {};
    }
}

export async function ratchetStepReceive(
    state: RatchetState,
    remoteDhPub: Uint8Array,
    pn: number,
): Promise<void> {
    validateMessageIndex(pn);
    if (state.CKr && state.DHr) {
        skipReceiveMessageKeys(state, pn);
    }

    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.CKs = null;
    state.DHr = remoteDhPub;

    const dhOut = await xDHAsync(state.DHsPrivate, remoteDhPub);
    const recv = kdfRoot(state.RK, dhOut);
    state.RK = recv.rootKey;
    state.CKr = recv.chainKey;
}

export async function ratchetStepSend(state: RatchetState): Promise<void> {
    if (!state.DHr) {
        if (!state.CKs) {
            state.CKs = deriveBootstrapSendChain(state.RK);
        }
        return;
    }
    const nextDh = await xBoxKeyPairAsync();
    state.PN = state.Ns;
    state.Ns = 0;
    state.DHsPrivate = nextDh.secretKey;
    state.DHsPublic = nextDh.publicKey;
    const dhOut = await xDHAsync(state.DHsPrivate, state.DHr);
    const send = kdfRoot(state.RK, dhOut);
    state.RK = send.rootKey;
    state.CKs = send.chainKey;
}

export function sessionToSqlPatch(
    session: RatchetState,
): Pick<
    SessionSQL,
    | "CKr"
    | "CKs"
    | "DHr"
    | "DHsPrivate"
    | "DHsPublic"
    | "Nr"
    | "Ns"
    | "PN"
    | "RK"
    | "skippedKeys"
> {
    return {
        CKr: session.CKr ? XUtils.encodeHex(session.CKr) : null,
        CKs: session.CKs ? XUtils.encodeHex(session.CKs) : null,
        DHr: session.DHr ? XUtils.encodeHex(session.DHr) : null,
        DHsPrivate: XUtils.encodeHex(session.DHsPrivate),
        DHsPublic: XUtils.encodeHex(session.DHsPublic),
        Nr: session.Nr,
        Ns: session.Ns,
        PN: session.PN,
        RK: XUtils.encodeHex(session.RK),
        skippedKeys: JSON.stringify(session.skippedKeys),
    };
}

export function takeReceiveMessageKey(
    state: ReceiveChainState,
    remoteDhPub: Uint8Array,
    n: number,
): Uint8Array {
    validateMessageIndex(n);
    const skippedId = skippedKeyId(remoteDhPub, n);
    const skipped = state.skippedKeys[skippedId];
    if (skipped) {
        const { [skippedId]: _discarded, ...rest } = state.skippedKeys;
        state.skippedKeys = rest;
        return XUtils.decodeHex(skipped);
    }

    if (!state.CKr) {
        throw new Error("Missing receiving chain key.");
    }

    skipReceiveMessageKeys(state, n);

    const { chainKey, messageKey } = kdfChain(state.CKr);
    state.CKr = chainKey;
    state.Nr += 1;
    return messageKey;
}

export function takeSendMessageKey(state: {
    CKs: null | Uint8Array;
    Ns: number;
}): { messageKey: Uint8Array; n: number } {
    if (!state.CKs) {
        throw new Error("Missing sending chain key.");
    }
    const n = state.Ns;
    validateMessageIndex(n);
    const { chainKey, messageKey } = kdfChain(state.CKs);
    state.CKs = chainKey;
    state.Ns += 1;
    return { messageKey, n };
}

function isKeyHex(value: string): boolean {
    return (
        value.length === DH_PUBLIC_KEY_BYTES * 2 && /^[0-9a-fA-F]+$/.test(value)
    );
}

function isSkippedKeyIdFormat(value: string): boolean {
    const idx = value.lastIndexOf(":");
    if (idx <= 0 || idx === value.length - 1) {
        return false;
    }
    const dhHex = value.slice(0, idx);
    const nPart = value.slice(idx + 1);
    return (
        isKeyHex(dhHex) &&
        /^(0|[1-9][0-9]*)$/.test(nPart) &&
        Number(nPart) <= MAX_MESSAGE_INDEX
    );
}

function kdfChain(ck: Uint8Array): {
    chainKey: Uint8Array;
    messageKey: Uint8Array;
} {
    return {
        chainKey: xHMAC({ label: "ck-next", version: VERSION }, ck),
        messageKey: xHMAC({ label: "msg-key", version: VERSION }, ck),
    };
}

function kdfRoot(
    rootKey: Uint8Array,
    dhOut: Uint8Array,
): { chainKey: Uint8Array; rootKey: Uint8Array } {
    const material = xKDF(xConcat(rootKey, dhOut, encoder.encode("dr-v1")));
    return {
        chainKey: xHMAC({ label: "chain", version: VERSION }, material),
        rootKey: xHMAC({ label: "root", version: VERSION }, material),
    };
}

function skippedKeyId(dhPub: Uint8Array, n: number): string {
    return `${XUtils.encodeHex(dhPub)}:${String(n)}`;
}

function skipReceiveMessageKeys(state: ReceiveChainState, until: number): void {
    if (until - state.Nr > MAX_SKIP_MESSAGE_GAP) {
        throw new Error("Ratchet skip window exceeded.");
    }
    if (until <= state.Nr) {
        return;
    }
    if (!state.CKr || !state.DHr) {
        throw new Error(
            "Missing receiving chain or DH key when storing skipped keys.",
        );
    }

    // Build the cache once per gap instead of copying up to 1024 entries for
    // every skipped message. Map preserves insertion order for oldest eviction.
    const skippedKeys = new Map(Object.entries(state.skippedKeys));
    const dhHex = XUtils.encodeHex(state.DHr);
    while (state.Nr < until) {
        const { chainKey, messageKey } = kdfChain(state.CKr);
        state.CKr = chainKey;
        const id = `${dhHex}:${String(state.Nr)}`;
        skippedKeys.delete(id);
        skippedKeys.set(id, XUtils.encodeHex(messageKey));
        state.Nr += 1;
    }
    state.skippedKeys = Object.fromEntries(
        [...skippedKeys].slice(-MAX_SKIPPED_KEYS),
    );
}

function validateMessageIndex(index: number): void {
    if (!Number.isInteger(index) || index < 0 || index > MAX_MESSAGE_INDEX) {
        throw new Error(
            "Ratchet message index must be an unsigned 32-bit integer.",
        );
    }
}

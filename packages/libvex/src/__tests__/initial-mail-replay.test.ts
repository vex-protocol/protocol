/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Message } from "../index.js";
import type { XKeyRing } from "../types/index.js";
import type { KeyPair } from "@vex-chat/crypto";
import type { Device, KeyBundle, MailWS, User } from "@vex-chat/types";

import {
    xBoxKeyPairAsync,
    xBoxKeyPairFromSecretAsync,
    xConcat,
    xConstants,
    xDHAsync,
    xEncode,
    xHMAC,
    xKDF,
    XKeyConvert,
    xMakeNonce,
    xMessageKeySubkeys,
    xPreKeySignaturePayload,
    xSecretboxAsync,
    xSignAsync,
    xSignKeyPair,
    XUtils,
} from "@vex-chat/crypto";
import { MailType } from "@vex-chat/types";

import { EventEmitter } from "eventemitter3";
import { describe, expect, it, vi } from "vitest";

import { Client } from "../Client.js";
import { encodeRatchetHeader } from "../utils/ratchet.js";

import { MemoryStorage } from "./harness/memory-storage.js";

interface Identity {
    idKeys: KeyPair;
    signKeys: KeyPair;
}

const clientMethods = Client.prototype as unknown as {
    acknowledgeInboundMail: (mail: MailWS) => void;
    createSession: (
        device: Device,
        user: User,
        message: Uint8Array,
        group: null | Uint8Array,
        mailID: null | string,
        forward: boolean,
    ) => Promise<Message | null>;
    readMail: (
        header: Uint8Array,
        mail: MailWS,
        timestamp: string,
    ) => Promise<void>;
};

const NOW = "2026-07-14T00:00:00.000Z";

/**
 * Replicates the sender side of createSession() X3DH (signed-prekey-only
 * path, preKeyIndex 0) to produce a wire-valid initial mail + HMAC header.
 */
async function craftInitialMail(opts: {
    mailID?: string;
    plaintext: string;
    receiverRing: XKeyRing;
    recipientDeviceID: string;
    recipientUserID: string;
    sender: Identity;
    senderDeviceID: string;
    senderUserID: string;
}): Promise<{ header: Uint8Array; mail: MailWS }> {
    const ephemeralKeys = await xBoxKeyPairAsync();
    const IK_B = opts.receiverRing.identityKeys.publicKey;
    const SPK_B = opts.receiverRing.preKeys.keyPair.publicKey;

    const DH1 = await xDHAsync(opts.sender.idKeys.secretKey, SPK_B);
    const DH2 = await xDHAsync(ephemeralKeys.secretKey, IK_B);
    const DH3 = await xDHAsync(ephemeralKeys.secretKey, SPK_B);

    const SK = xKDF(xConcat(DH1, DH2, DH3));
    const subkeys = xMessageKeySubkeys(SK);
    const PK = (await xBoxKeyPairFromSecretAsync(SK)).publicKey;
    const AD = xConcat(
        xEncode(xConstants.CURVE, opts.sender.idKeys.publicKey),
        xEncode(xConstants.CURVE, IK_B),
    );
    const IDX = XUtils.numberToUint8Arr(0);
    const extra = xConcat(
        opts.sender.signKeys.publicKey,
        ephemeralKeys.publicKey,
        PK,
        AD,
        IDX,
    );

    const nonce = xMakeNonce();
    const cipher = await xSecretboxAsync(
        XUtils.decodeUTF8(opts.plaintext),
        nonce,
        subkeys.encryptionKey,
    );

    // Field order matches createSession() so the HMAC covers identical bytes.
    const mail: MailWS = {
        authorID: opts.senderUserID,
        cipher,
        extra,
        forward: false,
        group: null,
        mailID: opts.mailID ?? crypto.randomUUID(),
        mailType: MailType.initial,
        nonce,
        readerID: opts.recipientUserID,
        recipient: opts.recipientDeviceID,
        sender: opts.senderDeviceID,
    };
    return { header: xHMAC(mail, subkeys.authenticationKey), mail };
}

function makeDevice(
    deviceID: string,
    owner: string,
    signKeys: KeyPair,
): Device {
    return {
        deleted: false,
        deviceID,
        lastLogin: NOW,
        name: deviceID,
        owner,
        signKey: XUtils.encodeHex(signKeys.publicKey),
    };
}

function makeIdentity(): Identity {
    const signKeys = xSignKeyPair();
    const idKeys = XKeyConvert.convertKeyPair(signKeys);
    if (!idKeys) {
        throw new Error("Could not convert signing keys.");
    }
    return { idKeys, signKeys };
}

async function makeKeyBundle(
    identity: Identity,
    deviceID: string,
): Promise<KeyBundle> {
    const preKey = await xBoxKeyPairAsync();
    return {
        preKey: {
            deviceID,
            index: 1,
            publicKey: preKey.publicKey,
            signature: await xSignAsync(
                xPreKeySignaturePayload(preKey.publicKey, "signed"),
                identity.signKeys.secretKey,
            ),
        },
        signKey: identity.signKeys.publicKey,
    };
}

async function makeKeyRing(identity: Identity): Promise<XKeyRing> {
    const preKeyPair = await xBoxKeyPairAsync();
    return {
        ephemeralKeys: await xBoxKeyPairAsync(),
        identityKeys: identity.idKeys,
        preKeys: {
            index: 1,
            keyPair: preKeyPair,
            signature: await xSignAsync(
                xPreKeySignaturePayload(preKeyPair.publicKey, "signed"),
                identity.signKeys.secretKey,
            ),
        },
    };
}

async function makeReceiverFixture() {
    const storage = new MemoryStorage(new Uint8Array(32).fill(3));
    await storage.init();

    const sender = makeIdentity();
    const receiver = makeIdentity();
    const receiverRing = await makeKeyRing(receiver);

    const senderUser = makeUser("user-a", "alice");
    const receiverUser = makeUser("user-b", "bob");
    const senderDevice = makeDevice(
        "device-a-1",
        senderUser.userID,
        sender.signKeys,
    );
    const receiverDevice = makeDevice(
        "device-b-1",
        receiverUser.userID,
        receiver.signKeys,
    );

    const { emitter, harness, sendReceipt } = makeReceiverHarness({
        receiverDevice,
        receiverRing,
        senderDevice,
        senderUser,
        storage,
    });
    const messages: Message[] = [];
    emitter.on("message", (m: Message) => {
        messages.push(m);
    });

    const readMail = (header: Uint8Array, mail: MailWS): Promise<void> =>
        clientMethods.readMail.call(harness, header, mail, NOW);

    const craft = (plaintext: string): ReturnType<typeof craftInitialMail> =>
        craftInitialMail({
            plaintext,
            receiverRing,
            recipientDeviceID: receiverDevice.deviceID,
            recipientUserID: receiverUser.userID,
            sender,
            senderDeviceID: senderDevice.deviceID,
            senderUserID: senderUser.userID,
        });

    return {
        craft,
        harness,
        messages,
        readMail,
        sender,
        sendReceipt,
        storage,
    };
}

function makeReceiverHarness(opts: {
    receiverDevice: Device;
    receiverRing: XKeyRing;
    senderDevice: Device;
    senderUser: User;
    storage: MemoryStorage;
}) {
    const emitter = new EventEmitter();
    const sendReceipt = vi.fn();
    const harness = {
        acknowledgeInboundMail: clientMethods.acknowledgeInboundMail,
        acknowledgeRepeatedDecryptFailure: vi.fn(),
        database: opts.storage,
        decryptFailureCounts: new Map<string, number>(),
        deviceRecords: {},
        emitter,
        fetchUser: vi.fn(() => Promise.resolve([opts.senderUser, null])),
        getDevice: () => opts.receiverDevice,
        getDeviceByID: vi.fn(() => Promise.resolve(opts.senderDevice)),
        manuallyClosing: false,
        reading: false,
        registerDecryptFailure: vi.fn(() => 2),
        runCrypto: <T>(fn: () => Promise<T>): Promise<T> => {
            return fn();
        },
        seenMailIDs: new Set<string>(),
        sendReceipt,
        sessionHealBackoffUntil: new Map<string, number>(),
        sessionHealInFlight: new Set<string>(),
        sessionRecords: {},
        userRecords: {},
        xKeyRing: opts.receiverRing,
    };
    return { emitter, harness, sendReceipt };
}

function makeUser(userID: string, username: string): User {
    return { lastSeen: NOW, userID, username };
}

describe("initial mail replay guard", () => {
    it("receives delayed mail from an earlier DH epoch without rotating the current session", async () => {
        const f = await makeReceiverFixture();
        const initial = await f.craft("first message");
        await f.readMail(initial.header, initial.mail);
        const initialSession = (await f.storage.getAllSessions())[0];
        if (!initialSession) throw new Error("Expected an initial session.");
        const previousDh = await xBoxKeyPairAsync();
        const currentDh = await xBoxKeyPairAsync();
        const messageKey = new Uint8Array(32).fill(17);
        const skippedID = `${XUtils.encodeHex(previousDh.publicKey)}:1`;
        const currentSession = {
            ...initialSession,
            CKs: "33".repeat(32),
            DHr: XUtils.encodeHex(currentDh.publicKey),
            Nr: 5,
            Ns: 3,
            PN: 2,
            skippedKeys: JSON.stringify({
                [skippedID]: XUtils.encodeHex(messageKey),
            }),
        };
        await f.storage.saveSession(currentSession);
        const nonce = xMakeNonce();
        const subkeys = xMessageKeySubkeys(messageKey);
        const mail: MailWS = {
            ...initial.mail,
            cipher: await xSecretboxAsync(
                XUtils.decodeUTF8("delayed message"),
                nonce,
                subkeys.encryptionKey,
            ),
            extra: encodeRatchetHeader({
                dhPub: previousDh.publicKey,
                n: 1,
                pn: 0,
                version: 1,
            }),
            mailID: crypto.randomUUID(),
            mailType: MailType.subsequent,
            nonce,
        };

        await f.readMail(xHMAC(mail, subkeys.authenticationKey), mail);

        expect(f.messages.map((message) => message.message)).toEqual([
            "first message",
            "delayed message",
        ]);
        const stored = (await f.storage.getAllSessions())[0];
        expect(stored).toEqual({
            ...currentSession,
            lastUsed: expect.any(String),
            skippedKeys: "{}",
        });
    });

    it("ignores a replayed initial mail instead of rolling back the session", async () => {
        const f = await makeReceiverFixture();
        const { header, mail } = await f.craft("hello bob");

        await f.readMail(header, mail);
        expect(f.messages).toHaveLength(1);
        expect(f.messages[0]?.message).toBe("hello bob");
        const first = await f.storage.getAllSessions();
        expect(first).toHaveLength(1);

        // Simulate an app restart: the in-memory seenMailIDs dedup set is
        // gone, and a malicious server redelivers the identical mail bytes.
        f.harness.seenMailIDs.clear();
        f.sendReceipt.mockClear();

        await f.readMail(header, mail);

        // No duplicate message, no fresh session row, no ratchet rollback —
        // but the mail IS acknowledged so the server stops redelivering it.
        expect(f.messages).toHaveLength(1);
        const afterReplay = await f.storage.getAllSessions();
        expect(afterReplay).toHaveLength(1);
        expect(afterReplay[0]?.sessionID).toBe(first[0]?.sessionID);
        expect(f.sendReceipt).toHaveBeenCalledTimes(1);
    });

    it("preserves verified across a re-session with unchanged identity keys", async () => {
        const f = await makeReceiverFixture();

        const first = await f.craft("first session");
        await f.readMail(first.header, first.mail);
        const firstSession = (await f.storage.getAllSessions())[0];
        if (!firstSession) {
            throw new Error("Expected a session after the first mail.");
        }
        await f.storage.markSessionVerified(firstSession.sessionID);

        // A genuine re-session from the same identity uses a fresh ephemeral
        // key, so it derives a fresh SK/PK and must NOT trip the replay guard.
        const second = await f.craft("second session");
        await f.readMail(second.header, second.mail);

        const sessions = await f.storage.getAllSessions();
        expect(sessions).toHaveLength(2);
        const latest = sessions.find(
            (s) => s.sessionID !== firstSession.sessionID,
        );
        expect(latest?.fingerprint).toBe(firstSession.fingerprint);
        expect(latest?.verified).toBe(true);
    });

    it("resets verified when the sender identity key changes", async () => {
        const f = await makeReceiverFixture();

        const first = await f.craft("first session");
        await f.readMail(first.header, first.mail);
        const firstSession = (await f.storage.getAllSessions())[0];
        if (!firstSession) {
            throw new Error("Expected a session after the first mail.");
        }
        await f.storage.markSessionVerified(firstSession.sessionID);

        // Same device/user IDs but a NEW identity key: a real key change.
        // Craft the mail against the receiver ring with a different sender.
        const impostor = makeIdentity();
        const receiverRing = f.harness.xKeyRing;
        const rotated = await craftInitialMail({
            plaintext: "rotated identity",
            receiverRing,
            recipientDeviceID: "device-b-1",
            recipientUserID: "user-b",
            sender: impostor,
            senderDeviceID: "device-a-1",
            senderUserID: "user-a",
        });
        await f.readMail(rotated.header, rotated.mail);

        const sessions = await f.storage.getAllSessions();
        expect(sessions).toHaveLength(2);
        const latest = sessions.find(
            (s) => s.sessionID !== firstSession.sessionID,
        );
        expect(latest?.fingerprint).not.toBe(firstSession.fingerprint);
        expect(latest?.verified).toBe(false);
    });

    it("preserves verified on the initiator side across re-sessions", async () => {
        const storage = new MemoryStorage(new Uint8Array(32).fill(9));
        await storage.init();

        const alice = makeIdentity();
        const aliceRing = await makeKeyRing(alice);
        const aliceUser = makeUser("user-a", "alice");
        const aliceDevice = makeDevice(
            "device-a-1",
            aliceUser.userID,
            alice.signKeys,
        );

        const bob = makeIdentity();
        const bobUser = makeUser("user-b", "bob");
        const bobDevice = makeDevice(
            "device-b-1",
            bobUser.userID,
            bob.signKeys,
        );
        const bobBundle = await makeKeyBundle(bob, bobDevice.deviceID);

        const harness = {
            database: storage,
            deliverMailResource: vi.fn(() => Promise.resolve()),
            emitter: new EventEmitter(),
            getDevice: () => aliceDevice,
            getUser: () => aliceUser,
            manuallyClosing: false,
            retrieveKeyBundle: vi.fn(() => Promise.resolve(bobBundle)),
            runCrypto: <T>(fn: () => Promise<T>): Promise<T> => {
                return fn();
            },
            signKeys: alice.signKeys,
            xKeyRing: aliceRing,
        };
        const createSession = (message: string): Promise<Message | null> =>
            clientMethods.createSession.call(
                harness,
                bobDevice,
                bobUser,
                XUtils.decodeUTF8(message),
                null,
                null,
                false,
            );

        await createSession("hi bob");
        const first = (await storage.getAllSessions())[0];
        if (!first) {
            throw new Error("Expected a session after the first send.");
        }
        expect(first.verified).toBe(false);
        await storage.markSessionVerified(first.sessionID);

        await createSession("hi again");

        const sessions = await storage.getAllSessions();
        expect(sessions).toHaveLength(2);
        const second = sessions.find((s) => s.sessionID !== first.sessionID);
        expect(second?.fingerprint).toBe(first.fingerprint);
        expect(second?.verified).toBe(true);
    });

    it("preserves verified when the peer initiates the re-session (role reversal)", async () => {
        const storage = new MemoryStorage(new Uint8Array(32).fill(5));
        await storage.init();

        const alice = makeIdentity();
        const aliceRing = await makeKeyRing(alice);
        const aliceUser = makeUser("user-a", "alice");
        const aliceDevice = makeDevice(
            "device-a-1",
            aliceUser.userID,
            alice.signKeys,
        );

        const bob = makeIdentity();
        const bobUser = makeUser("user-b", "bob");
        const bobDevice = makeDevice(
            "device-b-1",
            bobUser.userID,
            bob.signKeys,
        );
        const bobBundle = await makeKeyBundle(bob, bobDevice.deviceID);

        // Alice initiates: the stored fingerprint encodes the identities in
        // handshake-role order, alice||bob.
        const initiatorHarness = {
            database: storage,
            deliverMailResource: vi.fn(() => Promise.resolve()),
            emitter: new EventEmitter(),
            getDevice: () => aliceDevice,
            getUser: () => aliceUser,
            manuallyClosing: false,
            retrieveKeyBundle: vi.fn(() => Promise.resolve(bobBundle)),
            runCrypto: <T>(fn: () => Promise<T>): Promise<T> => {
                return fn();
            },
            signKeys: alice.signKeys,
            xKeyRing: aliceRing,
        };
        await clientMethods.createSession.call(
            initiatorHarness,
            bobDevice,
            bobUser,
            XUtils.decodeUTF8("hi bob"),
            null,
            null,
            false,
        );
        const first = (await storage.getAllSessions())[0];
        if (!first) {
            throw new Error("Expected a session after the first send.");
        }
        await storage.markSessionVerified(first.sessionID);

        // Bob initiates the replacement (e.g. healSession after a decrypt
        // failure): the new handshake encodes the same identities in the
        // reverse order, bob||alice.
        const { harness: receiverHarness } = makeReceiverHarness({
            receiverDevice: aliceDevice,
            receiverRing: aliceRing,
            senderDevice: bobDevice,
            senderUser: bobUser,
            storage,
        });
        const bounced = await craftInitialMail({
            plaintext: "heal",
            receiverRing: aliceRing,
            recipientDeviceID: aliceDevice.deviceID,
            recipientUserID: aliceUser.userID,
            sender: bob,
            senderDeviceID: bobDevice.deviceID,
            senderUserID: bobUser.userID,
        });
        await clientMethods.readMail.call(
            receiverHarness,
            bounced.header,
            bounced.mail,
            NOW,
        );

        const sessions = await storage.getAllSessions();
        expect(sessions).toHaveLength(2);
        const second = sessions.find((s) => s.sessionID !== first.sessionID);
        // Role-reversed fingerprint: not byte-identical, but the same
        // identity-key pair, so verification must carry over.
        expect(second?.fingerprint).not.toBe(first.fingerprint);
        expect(second?.verified).toBe(true);
    });
});

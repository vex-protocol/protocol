/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { BaseMsg } from "@vex-chat/types";

import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { pbkdf2 as noblePbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import {
    decode as decodeBase64,
    encode as encodeBase64,
} from "@stablelib/base64";
import { encode as decodeUTF8, decode as encodeUTF8 } from "@stablelib/utf8";
import * as bip39 from "bip39";
import ed2curve from "ed2curve";
import { Packr } from "msgpackr";
import nacl from "tweetnacl";
import { z } from "zod/v4";

export { xFederationMigrationAuthorizationDigest } from "./federation.js";
export {
    xNameCommitment,
    xNameHash,
    xNameRegistrationDigest,
    xRegistryAccountId,
    xRegistryAddDeviceDigest,
    xRegistryHomeserverId,
    xRegistryRegisterAccountDigest,
    xRegistryRegisterHomeserverDigest,
    xRegistryRevokeDeviceDigest,
    xRegistryRotateHomeserverKeyDigest,
    xRegistrySetDeviceThresholdDigest,
    xRegistrySetHomeserverDigest,
    xRegistrySetHomeserverEndpointDigest,
    xRegistrySetRecoveryCommitmentDigest,
} from "./registry.js";
export type {
    EvmNameRegistrarContext,
    EvmRegistryAccountAction,
    EvmRegistryContext,
} from "./registry.js";

const KEY_DATA_HEADER_BYTES = 54;
const KEY_DATA_MAC_BYTES = 16;
const KEY_DATA_PBKDF2_ITERATIONS = 220_000;
const KEY_DATA_PBKDF2_MIN_ITERATIONS = 1_000;
const KEY_DATA_PBKDF2_MAX_ITERATIONS = 2_000_000;

interface CryptoProvider {
    boxBefore(myPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array;
    boxKeyPair(): KeyPair;
    boxKeyPairFromSecret(secretKey: Uint8Array): KeyPair;
    randomBytes(length: number): Uint8Array;
    secretbox(
        plaintext: Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
    ): Uint8Array;
    secretboxOpen(
        ciphertext: Uint8Array,
        nonce: Uint8Array,
        key: Uint8Array,
    ): null | Uint8Array;
    sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
    signKeyPair(): KeyPair;
    signKeyPairFromSecret(secretKey: Uint8Array): KeyPair;
    signOpen(
        signedMessage: Uint8Array,
        publicKey: Uint8Array,
    ): null | Uint8Array;
}

interface WebCryptoLike {
    getRandomValues: Crypto["getRandomValues"];
    subtle: SubtleCrypto;
}

function isWebCryptoLike(value: unknown): value is WebCryptoLike {
    if (typeof value !== "object" || value === null) {
        return false;
    }
    return (
        "getRandomValues" in value &&
        typeof value.getRandomValues === "function" &&
        "subtle" in value &&
        typeof value.subtle === "object" &&
        value.subtle !== null
    );
}

async function pbkdf2Sha512Async(
    password: string,
    salt: Uint8Array,
    iterations: number,
): Promise<Uint8Array> {
    const cryptoCandidate: unknown = globalThis.crypto;
    if (!isWebCryptoLike(cryptoCandidate)) {
        return noblePbkdf2(sha512, password, salt, {
            c: iterations,
            dkLen: 32,
        });
    }

    const passwordKey = await cryptoCandidate.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"],
    );
    const bits = await cryptoCandidate.subtle.deriveBits(
        {
            hash: "SHA-512",
            iterations,
            name: "PBKDF2",
            salt: new Uint8Array(salt),
        },
        passwordKey,
        256,
    );
    return new Uint8Array(bits);
}

const tweetnaclProvider: CryptoProvider = {
    boxBefore: (myPrivateKey, theirPublicKey) =>
        nacl.box.before(theirPublicKey, myPrivateKey),
    boxKeyPair: () => nacl.box.keyPair(),
    boxKeyPairFromSecret: (secretKey) =>
        nacl.box.keyPair.fromSecretKey(secretKey),
    randomBytes: (length) => nacl.randomBytes(length),
    secretbox: (plaintext, nonce, key) => nacl.secretbox(plaintext, nonce, key),
    secretboxOpen: (ciphertext, nonce, key) =>
        nacl.secretbox.open(ciphertext, nonce, key),
    sign: (message, secretKey) => nacl.sign(message, secretKey),
    signKeyPair: () => nacl.sign.keyPair(),
    signKeyPairFromSecret: (secretKey) =>
        nacl.sign.keyPair.fromSecretKey(secretKey),
    signOpen: (signedMessage, publicKey) =>
        nacl.sign.open(signedMessage, publicKey),
};

function provider(): CryptoProvider {
    return tweetnaclProvider;
}

// msgpackr with useRecords:false emits standard msgpack (no nonstandard record extension).
// moreTypes:false keeps the extension set to only what other decoders understand.
// pack() returns Node Buffer (tight view) so HTTP clients send the correct bytes.
const packer = new Packr({ moreTypes: false, useRecords: false });
const msgpackEncode = packer.pack.bind(packer);
const msgpackDecode = packer.unpack.bind(packer);

/**
 * Provides an interface that can map an ed25519 keypair to its equivalent
 * X25519 keypair.
 */
export const XKeyConvert = ed2curve;

/**
 * Provides several methods that are useful in working with bytes and
 * vex messages.
 */
// eslint-disable-next-line @typescript-eslint/no-extraneous-class -- intentional static utility namespace (public API surface)
export class XUtils {
    public static decodeBase64 = decodeBase64;

    public static decodeUTF8 = decodeUTF8;

    public static encodeBase64 = encodeBase64;

    public static encodeUTF8 = encodeUTF8;

    /**
     * Checks if two buffer-like objects are equal.
     * When lengths match, comparison is constant-time in the inputs (no early exit on first differing byte).
     *
     * @param buf1 - First buffer to compare.
     * @param buf2 - Second buffer to compare.
     *
     * @returns True if equal, else false.
     */
    public static bytesEqual(
        buf1: ArrayBuffer | Uint8Array,
        buf2: ArrayBuffer | Uint8Array,
    ) {
        const a = buf1 instanceof Uint8Array ? buf1 : new Uint8Array(buf1);
        const b = buf2 instanceof Uint8Array ? buf2 : new Uint8Array(buf2);
        if (a.byteLength !== b.byteLength) {
            return false;
        }
        let diff = 0;
        for (let i = 0; i !== a.byteLength; i++) {
            const x = a[i];
            const y = b[i];
            if (x === undefined || y === undefined) {
                return false;
            }
            diff |= x ^ y;
        }
        return diff === 0;
    }

    /**
     * Decodes a hex string into a Uint8Array.
     *
     * @returns The Uint8Array.
     */
    public static decodeHex(hexString: string): Uint8Array {
        if (hexString.length === 0) {
            return new Uint8Array();
        }
        if (hexString.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hexString)) {
            throw new Error("Expected an even-length hexadecimal string.");
        }

        const bytes = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < bytes.length; i += 1) {
            bytes[i] = Number.parseInt(hexString.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    /**
     * Decrypts a secret key from the binary format produced by encryptKeyData().
     * No I/O — the caller handles reading the data.
     *
     * @param keyData - The encrypted key data as a Uint8Array.
     * @param password - The password used to encrypt.
     * @returns The hex-encoded secret key.
     */
    public static decryptKeyData = (
        keyData: Uint8Array,
        password: string,
    ): string => {
        const ITERATIONS = XUtils.readKeyDataIterations(keyData);
        const PKBDF_SALT = keyData.slice(6, 30);
        const ENCRYPTION_NONCE = keyData.slice(30, 54);
        const ENCRYPTED_KEY = keyData.slice(54);
        const DERIVED_KEY = noblePbkdf2(sha512, password, PKBDF_SALT, {
            c: ITERATIONS,
            dkLen: 32,
        });
        try {
            const DECRYPTED_SIGNKEY = provider().secretboxOpen(
                ENCRYPTED_KEY,
                ENCRYPTION_NONCE,
                DERIVED_KEY,
            );

            if (DECRYPTED_SIGNKEY === null) {
                throw new Error("Decryption failed. Wrong password?");
            }
            const decryptedHex = XUtils.encodeHex(DECRYPTED_SIGNKEY);
            DECRYPTED_SIGNKEY.fill(0);
            return decryptedHex;
        } finally {
            DERIVED_KEY.fill(0);
        }
    };

    /** Async variant of decryptKeyData for cross-runtime callers. */
    public static decryptKeyDataAsync = async (
        keyData: Uint8Array,
        password: string,
    ): Promise<string> => {
        const ITERATIONS = XUtils.readKeyDataIterations(keyData);
        const PKBDF_SALT = keyData.slice(6, 30);
        const ENCRYPTION_NONCE = keyData.slice(30, 54);
        const ENCRYPTED_KEY = keyData.slice(54);
        const DERIVED_KEY = await pbkdf2Sha512Async(
            password,
            PKBDF_SALT,
            ITERATIONS,
        );
        try {
            const decrypted = xSecretboxOpen(
                ENCRYPTED_KEY,
                ENCRYPTION_NONCE,
                DERIVED_KEY,
            );

            if (decrypted === null) {
                throw new Error("Decryption failed. Wrong password?");
            }
            const decryptedHex = XUtils.encodeHex(decrypted);
            decrypted.fill(0);
            return decryptedHex;
        } finally {
            DERIVED_KEY.fill(0);
        }
    };

    /**
     * Derive a purpose-separated 32-byte key for local at-rest encryption.
     * The result never aliases raw identity-key bytes.
     */
    public static deriveLocalAtRestAesKey(identitySk: Uint8Array): Uint8Array {
        if (identitySk.length < 32) {
            throw new Error("Expected at least 32 bytes of identity secret.");
        }
        return new Uint8Array(
            hkdf(
                sha256,
                identitySk,
                new Uint8Array(0),
                new TextEncoder().encode("vex:at-rest:3:tweetnacl"),
                32,
            ),
        );
    }

    /**
     * Returns the empty header (32 0's)
     *
     * @returns The empty header.
     */
    public static emptyHeader() {
        return new Uint8Array(xConstants.HEADER_SIZE);
    }

    /**
     * Encodes a Uint8Array to a hex string.
     *
     * @returns The hex string.
     */
    public static encodeHex(bytes: Uint8Array): string {
        return bytes.reduce(
            (str, byte) => str + byte.toString(16).padStart(2, "0"),
            "",
        );
    }

    /**
     * Encrypts a secret key into a portable binary format.
     * The result can be written to disk, sent over the network, etc.
     * No I/O — the caller handles persistence.
     *
     * Format: [iterations(6)|salt(24)|nonce(24)|ciphertext(N)]
     *
     * @param password - The password to derive the encryption key from.
     * @param keyToSave - The hex-encoded secret key to encrypt.
     * @param iterationOverride - Optional PBKDF2 iteration count (220,000 if omitted).
     * @returns The encrypted key data as a Uint8Array.
     */
    public static encryptKeyData = (
        password: string,
        keyToSave: string,
        iterationOverride?: number,
    ): Uint8Array => {
        const UNENCRYPTED_SIGNKEY = XUtils.decodeHex(keyToSave);
        const iterations = XUtils.validateKeyDataIterations(
            iterationOverride ?? KEY_DATA_PBKDF2_ITERATIONS,
        );
        const ITERATIONS = XUtils.numberToUint8Arr(iterations);
        const PKBDF_SALT = xMakeNonce();
        const ENCRYPTION_KEY = noblePbkdf2(sha512, password, PKBDF_SALT, {
            c: iterations,
            dkLen: 32,
        });
        const NONCE = xMakeNonce();
        let ENCRYPTED_SIGNKEY: Uint8Array;
        try {
            ENCRYPTED_SIGNKEY = provider().secretbox(
                UNENCRYPTED_SIGNKEY,
                NONCE,
                ENCRYPTION_KEY,
            );
        } finally {
            ENCRYPTION_KEY.fill(0);
            UNENCRYPTED_SIGNKEY.fill(0);
        }

        const result = new Uint8Array(
            ITERATIONS.length +
                PKBDF_SALT.length +
                NONCE.length +
                ENCRYPTED_SIGNKEY.length,
        );
        let offset = 0;
        result.set(ITERATIONS, offset);
        offset += ITERATIONS.length;
        result.set(PKBDF_SALT, offset);
        offset += PKBDF_SALT.length;
        result.set(NONCE, offset);
        offset += NONCE.length;
        result.set(ENCRYPTED_SIGNKEY, offset);
        return result;
    };

    /** Async variant of encryptKeyData for cross-runtime callers. */
    public static encryptKeyDataAsync = async (
        password: string,
        keyToSave: string,
        iterationOverride?: number,
    ): Promise<Uint8Array> => {
        const UNENCRYPTED_SIGNKEY = XUtils.decodeHex(keyToSave);
        const iterations = XUtils.validateKeyDataIterations(
            iterationOverride ?? KEY_DATA_PBKDF2_ITERATIONS,
        );
        const ITERATIONS = XUtils.numberToUint8Arr(iterations);
        const PKBDF_SALT = xMakeNonce();
        const ENCRYPTION_KEY = await pbkdf2Sha512Async(
            password,
            PKBDF_SALT,
            iterations,
        );
        const NONCE = xMakeNonce();
        let ENCRYPTED_SIGNKEY: Uint8Array;
        try {
            ENCRYPTED_SIGNKEY = xSecretbox(
                UNENCRYPTED_SIGNKEY,
                NONCE,
                ENCRYPTION_KEY,
            );
        } finally {
            ENCRYPTION_KEY.fill(0);
            UNENCRYPTED_SIGNKEY.fill(0);
        }

        const result = new Uint8Array(
            ITERATIONS.length +
                PKBDF_SALT.length +
                NONCE.length +
                ENCRYPTED_SIGNKEY.length,
        );
        let offset = 0;
        result.set(ITERATIONS, offset);
        offset += ITERATIONS.length;
        result.set(PKBDF_SALT, offset);
        offset += PKBDF_SALT.length;
        result.set(NONCE, offset);
        offset += NONCE.length;
        result.set(ENCRYPTED_SIGNKEY, offset);
        return result;
    };

    /**
     * Returns a six bit Uint8Array representation of an integer.
     * The integer must be positive, and it must be able to be stored
     * in six bytes.
     *
     * @param n - The number to convert.
     * @returns The Uint8Array representation of n.
     */
    public static numberToUint8Arr(n: number): Uint8Array {
        if (n < 0 || n > 281474976710655) {
            throw new Error(
                "Expected integer 0 < n < 281474976710655, received " +
                    String(n),
            );
        }

        let str = n.toString(16);
        while (str.length < 12) {
            str = "0" + str;
        }
        return XUtils.decodeHex(str);
    }

    /**
     * Packs a javascript object and a 32 byte header into a vex message.
     *
     * @param msg - Message body (msgpack-serialized).
     * @param header - Optional 32-byte header; defaults to an empty header.
     * @returns the packed message.
     */
    public static packMessage(msg: unknown, header?: Uint8Array) {
        const msgb = msgpackEncode(msg);
        const msgh = header ?? XUtils.emptyHeader();
        return xConcat(msgh, msgb);
    }

    /**
     * Converts a Uint8Array representation of an integer back into a number.
     *
     * @param arr - The array to convert.
     * @returns the number representation of arr.
     */
    public static uint8ArrToNumber(arr: Uint8Array) {
        let n = 0;
        for (const byte of arr) {
            n = n * 256 + byte;
        }
        return n;
    }

    /**
     * Takes a vex message and unpacks it into its header and a javascript object
     * representation of its body.
     *
     * @param msg - Full wire message (32-byte header + msgpack body).
     * @returns [32 byte header, message body]
     */
    public static unpackMessage(
        msg: Buffer | Uint8Array,
    ): [Uint8Array, BaseMsg] {
        const msgp = Uint8Array.from(msg);
        const msgh = msgp.slice(0, xConstants.HEADER_SIZE);
        // Validate base fields exist, keep all extra fields for the caller to narrow
        const raw: unknown = msgpackDecode(msgp.slice(xConstants.HEADER_SIZE));
        const msgb = z
            .object({
                transmissionID: z.string(),
                type: z.string(),
            })
            .loose()
            .parse(raw) as BaseMsg;

        return [msgh, msgb];
    }

    private static readKeyDataIterations(keyData: Uint8Array): number {
        if (keyData.length < KEY_DATA_HEADER_BYTES + KEY_DATA_MAC_BYTES) {
            throw new Error("Encrypted key data is truncated.");
        }
        return XUtils.validateKeyDataIterations(
            XUtils.uint8ArrToNumber(keyData.slice(0, 6)),
        );
    }

    private static validateKeyDataIterations(iterations: number): number {
        if (
            !Number.isSafeInteger(iterations) ||
            iterations < KEY_DATA_PBKDF2_MIN_ITERATIONS ||
            iterations > KEY_DATA_PBKDF2_MAX_ITERATIONS
        ) {
            throw new Error(
                `PBKDF2 iterations must be between ${String(KEY_DATA_PBKDF2_MIN_ITERATIONS)} and ${String(KEY_DATA_PBKDF2_MAX_ITERATIONS)}.`,
            );
        }
        return iterations;
    }
}

/**
 * Returns a 32 byte HMAC of a javscript object.
 *
 * @param msg - The message to create the HMAC of.
 * @param SK - The secret key to create the HMAC with.
 */
export function xHMAC(msg: unknown, SK: Uint8Array) {
    const packedMsg = msgpackEncode(msg);
    return hmac(sha256, SK, packedMsg);
}

/** Derive independent payload-encryption and envelope-authentication keys. */
export function xMessageKeySubkeys(messageKey: Uint8Array): {
    authenticationKey: Uint8Array;
    encryptionKey: Uint8Array;
} {
    if (messageKey.length < 32) {
        throw new Error("Message keys must contain at least 32 bytes.");
    }
    return {
        authenticationKey: hmac(
            sha256,
            messageKey,
            XUtils.decodeUTF8("vex:message:auth:v1"),
        ),
        encryptionKey: hmac(
            sha256,
            messageKey,
            XUtils.decodeUTF8("vex:message:encryption:v1"),
        ),
    };
}

/**
 * Gets a word list representation of a byte sequence.
 *
 * @param entropy - The bytes to derive the wordlist from.
 * @param wordList - Optional override for the wordlist. See bip39 docs for details.
 */
export function xMnemonic(entropy: Uint8Array, wordList?: string[]) {
    return bip39.entropyToMnemonic(XUtils.encodeHex(entropy), wordList);
}

/** Domain-separated payload signed for X3DH signed and one-time prekeys. */
export function xPreKeySignaturePayload(
    publicKey: Uint8Array,
    kind: "one-time" | "signed",
): Uint8Array {
    if (publicKey.length === 0) {
        throw new Error("Prekey public key cannot be empty.");
    }
    const separator = new Uint8Array([0]);
    return xConcat(
        XUtils.decodeUTF8("vex:x3dh:prekey:v2"),
        separator,
        XUtils.decodeUTF8("tweetnacl"),
        separator,
        XUtils.decodeUTF8(kind),
        separator,
        publicKey,
    );
}

/**
 * Constants for vex.
 */
export const xConstants: XConstants = {
    CURVE: "X25519",
    HASH: "SHA-512",
    HEADER_SIZE: 32,
    INFO: "xchat",
    KEY_LENGTH: 32,
    MIN_OTK_SUPPLY: 100,
};

/** Ed25519 or X25519 key pair. Structurally identical to nacl.SignKeyPair / nacl.BoxKeyPair. */
export interface KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

/**
 * Derives a 32 byte secret key from some initial key material.
 *
 * @param IKM the initial key material.
 * @returns The generated key.
 */
// export function xKDF(IKM: Uint8Array): Uint8Array {
//     return Uint8Array.from(
//         hkdf(Buffer.from(IKM), xConstants.KEY_LENGTH, {
//             salt: Buffer.from(xMakeSalt(xConstants.CURVE)),
//             info: xConstants.INFO,
//             hash: xConstants.HASH,
//         })
//     );
// }

/** Shape of the {@link xConstants} runtime object. */
export interface XConstants {
    CURVE: "X25519";
    HASH: "SHA-512";
    HEADER_SIZE: 32;
    INFO: string;
    KEY_LENGTH: 32 | 57;
    MIN_OTK_SUPPLY: number;
}

/** Generate a fresh X25519 box key pair. */
export function xBoxKeyPair(): KeyPair {
    return provider().boxKeyPair();
}

/** Async X25519 box keypair generation. */
export function xBoxKeyPairAsync(): Promise<KeyPair> {
    return Promise.resolve(xBoxKeyPair());
}

/** Restore an X25519 box key pair from a 32-byte secret key. */
export function xBoxKeyPairFromSecret(secretKey: Uint8Array): KeyPair {
    return provider().boxKeyPairFromSecret(secretKey);
}

// ── Key pair type ───────────────────────────────────────────────────────────

/** Async X25519 box key restore from private key material. */
export function xBoxKeyPairFromSecretAsync(
    secretKey: Uint8Array,
): Promise<KeyPair> {
    return Promise.resolve(xBoxKeyPairFromSecret(secretKey));
}

// ── Key generation ─────────────────────────────────────────────────────────

/**
 * Concatanates multiple Uint8Arrays.
 *
 * @param arrays - The Uint8Arrays to concatenate.
 */
export function xConcat(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((acc, value) => acc + value.length, 0);

    if (arrays.length === 0) {
        return new Uint8Array();
    }

    const result = new Uint8Array(totalLength);

    // for each array - copy it over result
    // next array is copied right after the previous one
    let length = 0;
    for (const array of arrays) {
        result.set(array, length);
        length += array.length;
    }

    return result;
}

/**
 * Derives a shared Secret Key from a known private key and
 * a peer's known public key.
 *
 * @param myPrivateKey - Your own private key.
 * @param theirPublicKey - Their public key.
 * @returns The derived shared secret, SK.
 */
export function xDH(
    myPrivateKey: Uint8Array,
    theirPublicKey: Uint8Array,
): Uint8Array {
    return provider().boxBefore(myPrivateKey, theirPublicKey);
}

/** Async X25519 DH. */
export function xDHAsync(
    myPrivateKey: Uint8Array,
    theirPublicKey: Uint8Array,
): Promise<Uint8Array> {
    return Promise.resolve(xDH(myPrivateKey, theirPublicKey));
}

// ── Signing ────────────────────────────────────────────────────────────────

/**
 * Encode an X25519 or X448 public key PK into a byte sequence.
 * The encoding consists of 0 or 1 to represent the type of curve, followed by l
 * ittle-endian encoding of the u-coordinate. See [rfc 7748](https://www.ietf.org/rfc/rfc7748.txt) for more
 * details.
 */
export function xEncode(
    curveType: "X448" | "X25519",
    publicKey: Uint8Array,
): Uint8Array {
    if (publicKey.length !== 32) {
        throw new Error(
            "Invalid key length, received key of length " +
                String(publicKey.length) +
                " and expected length 32.",
        );
    }

    const bytes: number[] = [];

    switch (curveType) {
        case "X448":
            bytes.push(1);
            break;
        case "X25519":
            bytes.push(0);
            break;
    }

    const key = BigInt("0x" + XUtils.encodeHex(publicKey));

    if (isEven(key)) {
        bytes.push(0);
    } else {
        bytes.push(1);
    }

    for (const byte of publicKey) {
        bytes.push(byte);
    }

    return Uint8Array.from(bytes);
}

/**
 * Hashes some data.
 *
 * @param data - The data to hash.
 * @returns The hash of the data.
 */
export function xHash(data: Uint8Array) {
    return XUtils.encodeHex(sha512(data));
}

// ── Symmetric encryption (XSalsa20-Poly1305) ──────────────────────────────

export function xKDF(IKM: Uint8Array): Uint8Array {
    return hkdf(
        sha512,
        IKM,
        xMakeSalt(xConstants.CURVE),
        new TextEncoder().encode(xConstants.INFO),
        xConstants.KEY_LENGTH,
    );
}

/**
 * Returns a 24 byte random nonce of cryptographic quality.
 */
export function xMakeNonce(): Uint8Array {
    return provider().randomBytes(24);
}

// ── Random ─────────────────────────────────────────────────────────────────

/** Cryptographically secure random bytes. */
export function xRandomBytes(length: number): Uint8Array {
    return provider().randomBytes(length);
}

/** Encrypt with a shared secret key. */
export function xSecretbox(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
): Uint8Array {
    return provider().secretbox(plaintext, nonce, key);
}

/** Async XSalsa20-Poly1305 encryption. */
export function xSecretboxAsync(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
): Promise<Uint8Array> {
    return Promise.resolve(xSecretbox(plaintext, nonce, key));
}

/** Decrypt with a shared secret key. Returns null if authentication fails. */
export function xSecretboxOpen(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
): null | Uint8Array {
    return provider().secretboxOpen(ciphertext, nonce, key);
}

/** Async XSalsa20-Poly1305 decryption. */
export function xSecretboxOpenAsync(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
): Promise<null | Uint8Array> {
    return Promise.resolve(xSecretboxOpen(ciphertext, nonce, key));
}

/** Sign a message with an Ed25519 secret key. Returns signed message (64-byte signature prefix + message). */
export function xSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return provider().sign(message, secretKey);
}

/** Async Ed25519 signing. */
export function xSignAsync(
    message: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array> {
    return Promise.resolve(xSign(message, secretKey));
}

/** Sign a message and return only its 64-byte Ed25519 signature. */
export function xSignDetached(
    message: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array {
    return xSign(message, secretKey).slice(0, 64);
}

/** Async detached Ed25519 signing. */
export function xSignDetachedAsync(
    message: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array> {
    return Promise.resolve(xSignDetached(message, secretKey));
}

/** Generate a fresh Ed25519 signing key pair. */
export function xSignKeyPair(): KeyPair {
    return provider().signKeyPair();
}

/** Async Ed25519 keypair generation. */
export function xSignKeyPairAsync(): Promise<KeyPair> {
    return Promise.resolve(xSignKeyPair());
}

/** Restore an Ed25519 signing key pair from a 64-byte secret key. */
export function xSignKeyPairFromSecret(secretKey: Uint8Array): KeyPair {
    return provider().signKeyPairFromSecret(secretKey);
}

/** Async restore of an Ed25519 signing keypair. */
export function xSignKeyPairFromSecretAsync(
    secretKey: Uint8Array,
): Promise<KeyPair> {
    return Promise.resolve(xSignKeyPairFromSecret(secretKey));
}

/** Verify and open a signed message. Returns the original message, or null if verification fails. */
export function xSignOpen(
    signedMessage: Uint8Array,
    publicKey: Uint8Array,
): null | Uint8Array {
    return provider().signOpen(signedMessage, publicKey);
}

/** Async Ed25519 verify/open. */
export function xSignOpenAsync(
    signedMessage: Uint8Array,
    publicKey: Uint8Array,
): Promise<null | Uint8Array> {
    return Promise.resolve(xSignOpen(signedMessage, publicKey));
}

/** Verify a detached 64-byte Ed25519 signature. */
export function xSignVerifyDetached(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
): boolean {
    if (signature.length !== 64) return false;
    const signedMessage = new Uint8Array(signature.length + message.length);
    signedMessage.set(signature);
    signedMessage.set(message, signature.length);
    const opened = xSignOpen(signedMessage, publicKey);
    return opened !== null && XUtils.bytesEqual(opened, message);
}

/** Async detached Ed25519 verification. */
export function xSignVerifyDetachedAsync(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
): Promise<boolean> {
    return Promise.resolve(xSignVerifyDetached(message, signature, publicKey));
}

/**
 * @internal
 */
function isEven(value: bigint) {
    if (value % BigInt(2) === BigInt(0)) {
        return true;
    } else {
        return false;
    }
}

/**
 * @internal
 */
function keyLength(curve: "X448" | "X25519"): number {
    return curve === "X25519" ? 32 : 57;
}

/**
 * @internal
 */
function xMakeSalt(curve: "X448" | "X25519"): Uint8Array {
    const salt = new Uint8Array(keyLength(curve));
    salt.fill(0xff);
    return salt;
}

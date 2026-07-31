/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { keccak_256 } from "@noble/hashes/sha3.js";

const ABI_WORD_BYTES = 32;
const ADDRESS_BYTES = 20;
const encoder = new TextEncoder();

const actionTypes = {
    addDevice:
        "AddDevice(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 newDeviceKey,uint64 deadline)",
    registerAccount:
        "RegisterAccount(uint256 chainId,address registry,bytes32 accountId,bytes32 genesisNonce,bytes32 genesisDeviceKey,bytes32 homeserverId,bytes32 recoveryCommitment,uint64 deadline)",
    registerHomeserver:
        "RegisterHomeserver(uint256 chainId,address registry,bytes32 homeserverId,bytes32 genesisNonce,bytes32 signingKey,bytes32 endpointHash,uint64 deadline)",
    registerName:
        "RegisterName(uint256 chainId,address registrar,bytes32 accountId,uint64 registryEpoch,uint64 nonce,bytes32 nameHash,uint64 deadline)",
    revokeDevice:
        "RevokeDevice(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 deviceKey,uint64 deadline)",
    rotateHomeserverKey:
        "RotateHomeserverKey(uint256 chainId,address registry,bytes32 homeserverId,uint64 epoch,uint64 nonce,bytes32 newSigningKey,uint64 deadline)",
    setDeviceThreshold:
        "SetDeviceThreshold(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,uint8 threshold,uint64 deadline)",
    setHomeserver:
        "SetHomeserver(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 homeserverId,uint64 deadline)",
    setHomeserverEndpoint:
        "SetHomeserverEndpoint(uint256 chainId,address registry,bytes32 homeserverId,uint64 epoch,uint64 nonce,bytes32 endpointHash,uint64 deadline)",
    setRecoveryCommitment:
        "SetRecoveryCommitment(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 recoveryCommitment,uint64 deadline)",
} as const;

/** EVM domain that prevents name actions from being replayed elsewhere. */
export interface EvmNameRegistrarContext {
    chainId: bigint | number;
    registrarAddress: string | Uint8Array;
}

/** State-bound fields shared by account mutation signatures. */
export interface EvmRegistryAccountAction {
    accountId: Uint8Array;
    deadline: bigint | number;
    epoch: bigint | number;
    nonce: bigint | number;
}

/** EVM domain that prevents registry actions from being replayed elsewhere. */
export interface EvmRegistryContext {
    chainId: bigint | number;
    registryAddress: string | Uint8Array;
}

const registryDomains = {
    accountId: keccak_256(encoder.encode("vex:account-id:v1")),
    homeserverId: keccak_256(encoder.encode("vex:homeserver-id:v1")),
};

const nameCommitmentDomain = keccak_256(
    encoder.encode("vex:name-commitment:v1"),
);

const registryActionTypeHashes = {
    addDevice: keccak_256(encoder.encode(actionTypes.addDevice)),
    registerAccount: keccak_256(encoder.encode(actionTypes.registerAccount)),
    registerHomeserver: keccak_256(
        encoder.encode(actionTypes.registerHomeserver),
    ),
    revokeDevice: keccak_256(encoder.encode(actionTypes.revokeDevice)),
    rotateHomeserverKey: keccak_256(
        encoder.encode(actionTypes.rotateHomeserverKey),
    ),
    setDeviceThreshold: keccak_256(
        encoder.encode(actionTypes.setDeviceThreshold),
    ),
    setHomeserver: keccak_256(encoder.encode(actionTypes.setHomeserver)),
    setHomeserverEndpoint: keccak_256(
        encoder.encode(actionTypes.setHomeserverEndpoint),
    ),
    setRecoveryCommitment: keccak_256(
        encoder.encode(actionTypes.setRecoveryCommitment),
    ),
};

const registerNameTypeHash = keccak_256(
    encoder.encode(actionTypes.registerName),
);

/** Build a payer-bound commit/reveal value for a paid Vex username. */
export function xNameCommitment(
    context: EvmNameRegistrarContext,
    input: {
        accountId: Uint8Array;
        committerAddress: string | Uint8Array;
        nameHash: Uint8Array;
        salt: Uint8Array;
    },
): Uint8Array {
    return hashWords(
        nameCommitmentDomain,
        uintWord(context.chainId, "chainId"),
        addressWord(context.registrarAddress, "registrarAddress"),
        bytes32Word(input.accountId, "accountId"),
        bytes32Word(input.nameHash, "nameHash"),
        bytes32Word(input.salt, "salt"),
        addressWord(input.committerAddress, "committerAddress"),
    );
}

/** Validate and hash a normalized Vex username for the EVM registrar. */
export function xNameHash(username: string): Uint8Array {
    const value = encoder.encode(username);
    if (value.length < 3 || value.length > 19) {
        throw new Error("username must contain between 3 and 19 ASCII bytes.");
    }
    for (const character of value) {
        const lowercase = character >= 0x61 && character <= 0x7a;
        const digit = character >= 0x30 && character <= 0x39;
        if (!lowercase && !digit && character !== 0x5f) {
            throw new Error(
                "username may contain only lowercase ASCII letters, digits, and underscores.",
            );
        }
    }
    return keccak_256(value);
}

/** Build the account-authorized digest that reveals and registers a Vex username. */
export function xNameRegistrationDigest(
    context: EvmNameRegistrarContext,
    input: {
        accountId: Uint8Array;
        deadline: bigint | number;
        nameHash: Uint8Array;
        nonce: bigint | number;
        registryEpoch: bigint | number;
    },
): Uint8Array {
    return hashWords(
        registerNameTypeHash,
        uintWord(context.chainId, "chainId"),
        addressWord(context.registrarAddress, "registrarAddress"),
        bytes32Word(input.accountId, "accountId"),
        uintWord(input.registryEpoch, "registryEpoch", 64),
        uintWord(input.nonce, "nonce", 64),
        bytes32Word(input.nameHash, "nameHash"),
        uintWord(input.deadline, "deadline", 64),
    );
}

/** Derive a stable account ID from its creation nonce and genesis device key. */
export function xRegistryAccountId(
    genesisNonce: Uint8Array,
    genesisDeviceKey: Uint8Array,
): Uint8Array {
    return hashWords(
        registryDomains.accountId,
        bytes32Word(genesisNonce, "genesisNonce"),
        bytes32Word(genesisDeviceKey, "genesisDeviceKey"),
    );
}

/** Build the EVM digest authorizing a new account device. */
export function xRegistryAddDeviceDigest(
    context: EvmRegistryContext,
    input: EvmRegistryAccountAction & { newDeviceKey: Uint8Array },
): Uint8Array {
    return accountActionDigest(
        registryActionTypeHashes.addDevice,
        context,
        input,
        bytes32Word(input.newDeviceKey, "newDeviceKey"),
    );
}

/** Derive a stable homeserver ID from its creation nonce and genesis signing key. */
export function xRegistryHomeserverId(
    genesisNonce: Uint8Array,
    signingKey: Uint8Array,
): Uint8Array {
    return hashWords(
        registryDomains.homeserverId,
        bytes32Word(genesisNonce, "genesisNonce"),
        bytes32Word(signingKey, "signingKey"),
    );
}

/** Build the EVM digest that registers an account. */
export function xRegistryRegisterAccountDigest(
    context: EvmRegistryContext,
    input: {
        accountId: Uint8Array;
        deadline: bigint | number;
        genesisDeviceKey: Uint8Array;
        genesisNonce: Uint8Array;
        homeserverId: Uint8Array;
        recoveryCommitment: Uint8Array;
    },
): Uint8Array {
    return hashWords(
        registryActionTypeHashes.registerAccount,
        uintWord(context.chainId, "chainId"),
        addressWord(context.registryAddress),
        bytes32Word(input.accountId, "accountId"),
        bytes32Word(input.genesisNonce, "genesisNonce"),
        bytes32Word(input.genesisDeviceKey, "genesisDeviceKey"),
        bytes32Word(input.homeserverId, "homeserverId"),
        bytes32Word(input.recoveryCommitment, "recoveryCommitment"),
        uintWord(input.deadline, "deadline", 64),
    );
}

/** Build the EVM digest that registers a homeserver. */
export function xRegistryRegisterHomeserverDigest(
    context: EvmRegistryContext,
    input: {
        deadline: bigint | number;
        endpoint: string;
        genesisNonce: Uint8Array;
        homeserverId: Uint8Array;
        signingKey: Uint8Array;
    },
): Uint8Array {
    return hashWords(
        registryActionTypeHashes.registerHomeserver,
        uintWord(context.chainId, "chainId"),
        addressWord(context.registryAddress),
        bytes32Word(input.homeserverId, "homeserverId"),
        bytes32Word(input.genesisNonce, "genesisNonce"),
        bytes32Word(input.signingKey, "signingKey"),
        keccak_256(encoder.encode(input.endpoint)),
        uintWord(input.deadline, "deadline", 64),
    );
}

/** Build the EVM digest that permanently revokes an account device. */
export function xRegistryRevokeDeviceDigest(
    context: EvmRegistryContext,
    input: EvmRegistryAccountAction & { deviceKey: Uint8Array },
): Uint8Array {
    return accountActionDigest(
        registryActionTypeHashes.revokeDevice,
        context,
        input,
        bytes32Word(input.deviceKey, "deviceKey"),
    );
}

/** Build the EVM digest that rotates a homeserver signing key. */
export function xRegistryRotateHomeserverKeyDigest(
    context: EvmRegistryContext,
    input: {
        deadline: bigint | number;
        epoch: bigint | number;
        homeserverId: Uint8Array;
        newSigningKey: Uint8Array;
        nonce: bigint | number;
    },
): Uint8Array {
    return homeserverActionDigest(
        registryActionTypeHashes.rotateHomeserverKey,
        context,
        input,
        bytes32Word(input.newSigningKey, "newSigningKey"),
    );
}

/** Build the EVM digest that changes an account's device approval threshold. */
export function xRegistrySetDeviceThresholdDigest(
    context: EvmRegistryContext,
    input: EvmRegistryAccountAction & { threshold: number },
): Uint8Array {
    return accountActionDigest(
        registryActionTypeHashes.setDeviceThreshold,
        context,
        input,
        uintWord(input.threshold, "threshold", 8),
    );
}

/** Build the EVM digest that migrates an account to another homeserver. */
export function xRegistrySetHomeserverDigest(
    context: EvmRegistryContext,
    input: EvmRegistryAccountAction & { homeserverId: Uint8Array },
): Uint8Array {
    return accountActionDigest(
        registryActionTypeHashes.setHomeserver,
        context,
        input,
        bytes32Word(input.homeserverId, "homeserverId"),
    );
}

/** Build the EVM digest that changes a homeserver's HTTPS endpoint. */
export function xRegistrySetHomeserverEndpointDigest(
    context: EvmRegistryContext,
    input: {
        deadline: bigint | number;
        endpoint: string;
        epoch: bigint | number;
        homeserverId: Uint8Array;
        nonce: bigint | number;
    },
): Uint8Array {
    return homeserverActionDigest(
        registryActionTypeHashes.setHomeserverEndpoint,
        context,
        input,
        keccak_256(encoder.encode(input.endpoint)),
    );
}

/** Build the EVM digest that changes an account's recovery-policy commitment. */
export function xRegistrySetRecoveryCommitmentDigest(
    context: EvmRegistryContext,
    input: EvmRegistryAccountAction & { recoveryCommitment: Uint8Array },
): Uint8Array {
    return accountActionDigest(
        registryActionTypeHashes.setRecoveryCommitment,
        context,
        input,
        bytes32Word(input.recoveryCommitment, "recoveryCommitment"),
    );
}

function accountActionDigest(
    typeHash: Uint8Array,
    context: EvmRegistryContext,
    input: EvmRegistryAccountAction,
    changedValue: Uint8Array,
): Uint8Array {
    return hashWords(
        typeHash,
        uintWord(context.chainId, "chainId"),
        addressWord(context.registryAddress),
        bytes32Word(input.accountId, "accountId"),
        uintWord(input.epoch, "epoch", 64),
        uintWord(input.nonce, "nonce", 64),
        changedValue,
        uintWord(input.deadline, "deadline", 64),
    );
}

function addressWord(
    value: string | Uint8Array,
    name = "registryAddress",
): Uint8Array {
    const address =
        typeof value === "string"
            ? decodeAddressHex(value, name)
            : new Uint8Array(value);
    if (address.length !== ADDRESS_BYTES) {
        throw new Error(`${name} must contain exactly 20 bytes.`);
    }
    const word = new Uint8Array(ABI_WORD_BYTES);
    word.set(address, ABI_WORD_BYTES - ADDRESS_BYTES);
    return word;
}

function bytes32Word(value: Uint8Array, name: string): Uint8Array {
    if (value.length !== ABI_WORD_BYTES) {
        throw new Error(`${name} must contain exactly 32 bytes.`);
    }
    return new Uint8Array(value);
}

function decodeAddressHex(value: string, name: string): Uint8Array {
    if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
        throw new Error(`${name} must be a 20-byte 0x-prefixed hex value.`);
    }
    const output = new Uint8Array(ADDRESS_BYTES);
    for (let index = 0; index < output.length; index += 1) {
        output[index] = Number.parseInt(
            value.slice(2 + index * 2, 2 + index * 2 + 2),
            16,
        );
    }
    return output;
}

function hashWords(...words: Uint8Array[]): Uint8Array {
    const encoded = new Uint8Array(words.length * ABI_WORD_BYTES);
    for (const [index, word] of words.entries()) {
        if (word.length !== ABI_WORD_BYTES) {
            throw new Error("EVM ABI words must contain exactly 32 bytes.");
        }
        encoded.set(word, index * ABI_WORD_BYTES);
    }
    return keccak_256(encoded);
}

function homeserverActionDigest(
    typeHash: Uint8Array,
    context: EvmRegistryContext,
    input: {
        deadline: bigint | number;
        epoch: bigint | number;
        homeserverId: Uint8Array;
        nonce: bigint | number;
    },
    changedValue: Uint8Array,
): Uint8Array {
    return hashWords(
        typeHash,
        uintWord(context.chainId, "chainId"),
        addressWord(context.registryAddress),
        bytes32Word(input.homeserverId, "homeserverId"),
        uintWord(input.epoch, "epoch", 64),
        uintWord(input.nonce, "nonce", 64),
        changedValue,
        uintWord(input.deadline, "deadline", 64),
    );
}

function uintWord(
    value: bigint | number,
    name: string,
    bits = 256,
): Uint8Array {
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
        throw new Error(`${name} must be a safe integer or bigint.`);
    }
    const integer = BigInt(value);
    const maximum = 1n << BigInt(bits);
    if (integer < 0n || integer >= maximum) {
        throw new Error(`${name} does not fit in uint${String(bits)}.`);
    }
    const output = new Uint8Array(ABI_WORD_BYTES);
    let remaining = integer;
    for (let index = output.length - 1; index >= 0; index -= 1) {
        output[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return output;
}

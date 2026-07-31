/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import {
    xNameCommitment,
    xNameHash,
    xNameRegistrationDigest,
    xRegistryAccountId,
    xRegistryAddDeviceDigest,
    xRegistryHomeserverId,
    xRegistryRegisterAccountDigest,
    xRegistryRegisterHomeserverDigest,
    xRegistryRotateHomeserverKeyDigest,
    xRegistrySetHomeserverEndpointDigest,
    xSignDetached,
    xSignKeyPair,
    xSignVerifyDetached,
    XUtils,
} from "../index.js";

const ACCOUNT_ID =
    "5416c2ef1cee3998602b779b5eccb7d2d6c1767b554330c87bb5e1a839d6738a";
const ACCOUNT_NONCE = word(1);
const CONTEXT = {
    chainId: 84_532,
    registryAddress: "0x1111111111111111111111111111111111111111",
};
const DEADLINE = 1_700_000_000;
const DEVICE_KEY = word(2);
const HOMESERVER_ID =
    "e3a19d35381a8ea7c52e3fc6c9483ceadd62fc5a012351672e87eb99db98132e";
const HOMESERVER_KEY = word(4);
const HOMESERVER_NONCE = word(3);

test("registry identifiers match Solidity ABI vectors", () => {
    expect(hex(xRegistryAccountId(ACCOUNT_NONCE, DEVICE_KEY))).toBe(ACCOUNT_ID);
    expect(hex(xRegistryHomeserverId(HOMESERVER_NONCE, HOMESERVER_KEY))).toBe(
        HOMESERVER_ID,
    );
});

test("paid-name actions match Solidity ABI vectors", () => {
    const context = {
        chainId: CONTEXT.chainId,
        registrarAddress: "0x2222222222222222222222222222222222222222",
    };
    const nameHash = xNameHash("computer");
    expect(hex(nameHash)).toBe(
        "ddfe31b5955c4a0052761c7d74a79fb94e559df2c362db009cb70344e93c0c55",
    );
    expect(
        hex(
            xNameCommitment(context, {
                accountId: bytes(ACCOUNT_ID),
                committerAddress: "0x3333333333333333333333333333333333333333",
                nameHash,
                salt: word(8),
            }),
        ),
    ).toBe("0d4d2b02e7058f968b19da8fab6a2271132a194a62a11244ef624e1765c85fb0");
    expect(
        hex(
            xNameRegistrationDigest(context, {
                accountId: bytes(ACCOUNT_ID),
                deadline: DEADLINE,
                nameHash,
                nonce: 0,
                registryEpoch: 1,
            }),
        ),
    ).toBe("9d4df0819c38aafeb3e56e6c45cf865d9918abf75c9642154701a9eefed6c7c2");
});

test("paid names share the contract's strict ASCII normalization", () => {
    expect(() => xNameHash("Computer")).toThrow("lowercase ASCII");
    expect(() => xNameHash("ab")).toThrow("between 3 and 19");
    expect(() => xNameHash("cafe\u0301")).toThrow("lowercase ASCII");
});

test("account action digests match Solidity ABI vectors", () => {
    expect(
        hex(
            xRegistryRegisterAccountDigest(CONTEXT, {
                accountId: bytes(ACCOUNT_ID),
                deadline: DEADLINE,
                genesisDeviceKey: DEVICE_KEY,
                genesisNonce: ACCOUNT_NONCE,
                homeserverId: bytes(HOMESERVER_ID),
                recoveryCommitment: word(5),
            }),
        ),
    ).toBe("29ca842334f0d099731a61d313e910059dcd2d0b18d50e0fa4537eb2f548fa9f");

    expect(
        hex(
            xRegistryAddDeviceDigest(CONTEXT, {
                accountId: bytes(ACCOUNT_ID),
                deadline: DEADLINE,
                epoch: 7,
                newDeviceKey: word(6),
                nonce: 9,
            }),
        ),
    ).toBe("a4fb1592d8bd92a5905d63d5e1872385a77b0f868b643903402571a00be217bb");
});

test("homeserver action digests match Solidity ABI vectors", () => {
    const endpoint = "https://spire.example";
    const action = {
        deadline: DEADLINE,
        epoch: 7,
        homeserverId: bytes(HOMESERVER_ID),
        nonce: 9,
    };

    expect(
        hex(
            xRegistryRegisterHomeserverDigest(CONTEXT, {
                deadline: DEADLINE,
                endpoint,
                genesisNonce: HOMESERVER_NONCE,
                homeserverId: bytes(HOMESERVER_ID),
                signingKey: HOMESERVER_KEY,
            }),
        ),
    ).toBe("2c24f01e871142f31746a82e7174c2dc56e12acf03f4ada11ddc7dd4d04b58c4");
    expect(
        hex(
            xRegistrySetHomeserverEndpointDigest(CONTEXT, {
                ...action,
                endpoint,
            }),
        ),
    ).toBe("04663940c7501908bc358715552be30537490450c529ec740c916f6e3a8f50c6");
    expect(
        hex(
            xRegistryRotateHomeserverKeyDigest(CONTEXT, {
                ...action,
                newSigningKey: word(7),
            }),
        ),
    ).toBe("c0e4200917e87923d78097eb25f0b40368ab64f7047d3185cde5cdc9aab59045");
});

test("detached Ed25519 signatures verify only for the exact digest", () => {
    const keyPair = xSignKeyPair();
    const digest = xRegistryAccountId(ACCOUNT_NONCE, DEVICE_KEY);
    const signature = xSignDetached(digest, keyPair.secretKey);

    expect(signature).toHaveLength(64);
    expect(xSignVerifyDetached(digest, signature, keyPair.publicKey)).toBe(
        true,
    );

    const tampered = new Uint8Array(digest);
    tampered[0] ^= 1;
    expect(xSignVerifyDetached(tampered, signature, keyPair.publicKey)).toBe(
        false,
    );
    expect(
        xSignVerifyDetached(digest, signature.slice(1), keyPair.publicKey),
    ).toBe(false);
});

test("registry encoders reject malformed and overflowing values", () => {
    expect(() => xRegistryAccountId(new Uint8Array(31), DEVICE_KEY)).toThrow(
        "genesisNonce",
    );
    expect(() =>
        xRegistryAddDeviceDigest(
            { ...CONTEXT, registryAddress: "0x1234" },
            {
                accountId: bytes(ACCOUNT_ID),
                deadline: DEADLINE,
                epoch: 1,
                newDeviceKey: word(6),
                nonce: 0,
            },
        ),
    ).toThrow("registryAddress");
    expect(() =>
        xRegistryAddDeviceDigest(CONTEXT, {
            accountId: bytes(ACCOUNT_ID),
            deadline: 1n << 64n,
            epoch: 1,
            newDeviceKey: word(6),
            nonce: 0,
        }),
    ).toThrow("uint64");
});

function bytes(value: string): Uint8Array {
    return XUtils.decodeHex(value);
}

function hex(value: Uint8Array): string {
    return XUtils.encodeHex(value);
}

function word(value: number): Uint8Array {
    return bytes(value.toString(16).padStart(64, "0"));
}

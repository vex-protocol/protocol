/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Hex } from "viem";

import {
    encodeAbiParameters,
    encodeEventTopics,
    parseAbi,
    parseAbiParameters,
} from "viem";
import { describe, expect, it } from "vitest";

import {
    decodeEvmRegistryLogs,
    type EvmRegistryLog,
    evmRegistrySource,
} from "../registry/EvmRegistryIndexer.ts";

const REGISTRY = "0x1111111111111111111111111111111111111111";
const REGISTRAR = "0x2222222222222222222222222222222222222222";
const PAYER = "0x3333333333333333333333333333333333333333";
const ACCOUNT = hex32("a");
const DEVICE = hex32("b");
const HOMESERVER = hex32("c");
const NAME_HASH = hex32("d");
const RECOVERY = hex32("0");
const SERVER_KEY = hex32("e");

const accountEvent = parseAbi([
    "event AccountRegistered(bytes32 indexed accountId, bytes32 indexed genesisDeviceKey, bytes32 indexed homeserverId, bytes32 recoveryCommitment, uint64 epoch)",
]);
const homeserverEvent = parseAbi([
    "event HomeserverRegistered(bytes32 indexed homeserverId, bytes32 indexed signingKey, string endpoint, uint64 epoch)",
]);
const nameEvent = parseAbi([
    "event NameRegistered(bytes32 indexed nameHash, bytes32 indexed accountId, string username, address indexed payer, uint256 fee)",
]);
const nameCommitmentEvent = parseAbi([
    "event NameCommitted(bytes32 indexed commitment, address indexed committer, uint64 createdAt)",
]);

describe("EvmRegistryIndexer", () => {
    it("normalizes the CAIP-style registry source", () => {
        expect(evmRegistrySource(84_532, REGISTRY)).toBe(
            "eip155:84532/0x1111111111111111111111111111111111111111",
        );
        expect(evmRegistrySource(84_532, REGISTRY, REGISTRAR)).toBe(
            "eip155:84532/0x1111111111111111111111111111111111111111?registrar=0x2222222222222222222222222222222222222222",
        );
        expect(() => evmRegistrySource(0, REGISTRY)).toThrow("chain ID");
    });

    it("decodes and orders registry and registrar logs", () => {
        const logs: EvmRegistryLog[] = [
            {
                address: REGISTRAR,
                blockNumber: 10n,
                data: encodeAbiParameters(parseAbiParameters("uint64"), [1n]),
                logIndex: 2,
                topics: asTopics(
                    encodeEventTopics({
                        abi: nameCommitmentEvent,
                        args: {
                            commitment: hex32("f"),
                            committer: PAYER,
                        },
                        eventName: "NameCommitted",
                    }),
                ),
                transactionIndex: 0,
            },
            {
                address: REGISTRAR,
                blockNumber: 11n,
                data: encodeAbiParameters(
                    parseAbiParameters("string,uint256"),
                    ["computer", 20_000_000n],
                ),
                logIndex: 0,
                topics: asTopics(
                    encodeEventTopics({
                        abi: nameEvent,
                        args: {
                            accountId: ACCOUNT,
                            nameHash: NAME_HASH,
                            payer: PAYER,
                        },
                        eventName: "NameRegistered",
                    }),
                ),
                transactionIndex: 0,
            },
            {
                address: REGISTRY,
                blockNumber: 10n,
                data: encodeAbiParameters(
                    parseAbiParameters("bytes32,uint64"),
                    [RECOVERY, 1n],
                ),
                logIndex: 1,
                topics: asTopics(
                    encodeEventTopics({
                        abi: accountEvent,
                        args: {
                            accountId: ACCOUNT,
                            genesisDeviceKey: DEVICE,
                            homeserverId: HOMESERVER,
                        },
                        eventName: "AccountRegistered",
                    }),
                ),
                transactionIndex: 0,
            },
            {
                address: REGISTRY,
                blockNumber: 10n,
                data: encodeAbiParameters(parseAbiParameters("string,uint64"), [
                    "https://one.example",
                    1n,
                ]),
                logIndex: 0,
                topics: asTopics(
                    encodeEventTopics({
                        abi: homeserverEvent,
                        args: {
                            homeserverId: HOMESERVER,
                            signingKey: SERVER_KEY,
                        },
                        eventName: "HomeserverRegistered",
                    }),
                ),
                transactionIndex: 0,
            },
        ];

        expect(decodeEvmRegistryLogs(logs, REGISTRY, REGISTRAR)).toEqual([
            {
                endpoint: "https://one.example",
                epoch: "1",
                homeserverId: HOMESERVER,
                signingKey: SERVER_KEY,
                type: "homeserver-registered",
            },
            {
                accountId: ACCOUNT,
                epoch: "1",
                genesisDeviceKey: DEVICE,
                homeserverId: HOMESERVER,
                recoveryCommitment: RECOVERY,
                type: "account-registered",
            },
            {
                accountId: ACCOUNT,
                nameHash: NAME_HASH,
                type: "username-registered",
                username: "computer",
            },
        ]);
    });

    it("rejects logs from contracts outside the configured registry", () => {
        expect(() =>
            decodeEvmRegistryLogs(
                [
                    {
                        address: PAYER,
                        blockNumber: 1n,
                        data: "0x",
                        logIndex: 0,
                        topics: [],
                        transactionIndex: 0,
                    },
                ],
                REGISTRY,
                REGISTRAR,
            ),
        ).toThrow("Unexpected registry log address");
    });
});

function asTopics(
    values: ReturnType<typeof encodeEventTopics>,
): EvmRegistryLog["topics"] {
    if (values.some((value) => value === null || Array.isArray(value))) {
        throw new Error("Expected concrete event topics.");
    }
    return values as EvmRegistryLog["topics"];
}

function hex32(character: string): Hex {
    return `0x${character.repeat(64)}`;
}

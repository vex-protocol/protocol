/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { RegistryEvent } from "./events.ts";
import type { RegistryStore } from "./RegistryStore.ts";
import type { Address, Hex, Log, PublicClient } from "viem";

import {
    createPublicClient,
    decodeEventLog,
    defineChain,
    fallback,
    http,
    isAddress,
    parseAbi,
} from "viem";

const DEFAULT_BLOCK_RANGE = 2_000n;
const DEFAULT_MINIMUM_MAX_STALENESS_MS = 60_000;
const DEFAULT_POLL_INTERVAL_MS = 12_000;

const registryEventAbi = parseAbi([
    "event AccountRegistered(bytes32 indexed accountId, bytes32 indexed genesisDeviceKey, bytes32 indexed homeserverId, bytes32 recoveryCommitment, uint64 epoch)",
    "event DeviceAdded(bytes32 indexed accountId, bytes32 indexed deviceKey, uint64 epoch)",
    "event DeviceRevoked(bytes32 indexed accountId, bytes32 indexed deviceKey, uint64 epoch)",
    "event DeviceThresholdChanged(bytes32 indexed accountId, uint8 threshold, uint64 epoch)",
    "event HomeserverChanged(bytes32 indexed accountId, bytes32 indexed oldHomeserverId, bytes32 indexed newHomeserverId, uint64 epoch)",
    "event HomeserverEndpointChanged(bytes32 indexed homeserverId, string endpoint, uint64 epoch)",
    "event HomeserverKeyRotated(bytes32 indexed homeserverId, bytes32 indexed oldSigningKey, bytes32 indexed newSigningKey, uint64 epoch)",
    "event HomeserverRegistered(bytes32 indexed homeserverId, bytes32 indexed signingKey, string endpoint, uint64 epoch)",
    "event RecoveryCommitmentChanged(bytes32 indexed accountId, bytes32 indexed recoveryCommitment, uint64 epoch)",
]);

const registrarEventAbi = parseAbi([
    "event NameCommitted(bytes32 indexed commitment, address indexed committer, uint64 createdAt)",
    "event NameRegistered(bytes32 indexed nameHash, bytes32 indexed accountId, string username, address indexed payer, uint256 fee)",
]);

export interface EvmRegistryIndexerOptions {
    chainId: number;
    deploymentBlock: bigint;
    finality?: "finalized" | undefined | { confirmations: number };
    maximumBlockRange?: bigint | undefined;
    maximumStalenessMs?: number | undefined;
    pollIntervalMs?: number | undefined;
    registrarAddress?: Address | undefined;
    registryAddress: Address;
    rpcUrls: readonly string[];
}

export interface EvmRegistryLog {
    address: Address;
    blockNumber: bigint;
    data: Hex;
    logIndex: number;
    topics: [] | [Hex, ...Hex[]];
    transactionIndex: number;
}

export class EvmRegistryIndexer {
    public readonly source: string;

    private activeSync: null | Promise<void> = null;
    private readonly client: PublicClient;
    private readonly deploymentBlock: bigint;
    private readonly finality: "finalized" | { confirmations: number };
    private lastSuccessfulSyncAt: null | number = null;
    private readonly maximumBlockRange: bigint;
    private readonly maximumStalenessMs: number;
    private readonly onError: (error: unknown) => void;
    private readonly pollIntervalMs: number;
    private readonly registrarAddress: Address | undefined;
    private readonly registryAddress: Address;
    private stopped = true;
    private readonly store: RegistryStore;
    private timer: null | ReturnType<typeof setTimeout> = null;

    constructor(
        store: RegistryStore,
        options: EvmRegistryIndexerOptions,
        onError: (error: unknown) => void = () => {},
    ) {
        validateOptions(options);
        this.source = evmRegistrySource(
            options.chainId,
            options.registryAddress,
            options.registrarAddress,
        );
        if (store.source !== this.source) {
            throw new Error(
                "Registry store source does not match the EVM indexer.",
            );
        }

        const chain = defineChain({
            id: options.chainId,
            name: `Vex registry ${String(options.chainId)}`,
            nativeCurrency: { decimals: 18, name: "Native", symbol: "ETH" },
            rpcUrls: { default: { http: [...options.rpcUrls] } },
        });
        this.client = createPublicClient({
            chain,
            transport: fallback(
                options.rpcUrls.map((url) => http(url)),
                { rank: true },
            ),
        });
        this.deploymentBlock = options.deploymentBlock;
        this.finality = options.finality ?? "finalized";
        this.maximumBlockRange =
            options.maximumBlockRange ?? DEFAULT_BLOCK_RANGE;
        this.onError = onError;
        this.pollIntervalMs =
            options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
        this.maximumStalenessMs =
            options.maximumStalenessMs ??
            Math.max(DEFAULT_MINIMUM_MAX_STALENESS_MS, this.pollIntervalMs * 5);
        this.registrarAddress = options.registrarAddress;
        this.registryAddress = options.registryAddress;
        this.store = store;
    }

    public isReady(now = Date.now()): boolean {
        return (
            this.lastSuccessfulSyncAt !== null &&
            now - this.lastSuccessfulSyncAt <= this.maximumStalenessMs
        );
    }

    public start(): void {
        if (!this.stopped) return;
        this.stopped = false;
        this.schedule(0);
    }

    public async stop(): Promise<void> {
        this.stopped = true;
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }
        await this.activeSync;
    }

    public async syncOnce(): Promise<void> {
        if (this.activeSync) return this.activeSync;
        const operation = this.performSync();
        this.activeSync = operation;
        try {
            await operation;
            this.lastSuccessfulSyncAt = Date.now();
        } finally {
            if (this.activeSync === operation) this.activeSync = null;
        }
    }

    private async fetchLogs(
        fromBlock: bigint,
        toBlock: bigint,
    ): Promise<EvmRegistryLog[]> {
        const [registryLogs, registrarLogs] = await Promise.all([
            this.client.getLogs({
                address: this.registryAddress,
                fromBlock,
                toBlock,
            }),
            this.registrarAddress
                ? this.client.getLogs({
                      address: this.registrarAddress,
                      fromBlock,
                      toBlock,
                  })
                : Promise.resolve([]),
        ]);
        return [...registryLogs, ...registrarLogs]
            .map(toRegistryLog)
            .sort(compareLogs);
    }

    private async finalizedBlockNumber(): Promise<bigint> {
        if (this.finality === "finalized") {
            const block = await this.client.getBlock({
                blockTag: "finalized",
            });
            return block.number;
        }
        const latest = await this.client.getBlockNumber();
        const confirmations = BigInt(this.finality.confirmations);
        return latest > confirmations ? latest - confirmations : 0n;
    }

    private async performSync(): Promise<void> {
        let cursor = await this.store.currentPosition();
        if (cursor) {
            const block = await this.client.getBlock({
                blockNumber: BigInt(cursor.sequence),
            });
            if (block.hash.toLowerCase() !== cursor.checkpoint.toLowerCase()) {
                await this.store.reset();
                cursor = null;
            }
        }

        const finalized = await this.finalizedBlockNumber();
        let fromBlock = cursor
            ? BigInt(cursor.sequence) + 1n
            : this.deploymentBlock;
        if (fromBlock > finalized) return;

        while (fromBlock <= finalized) {
            const toBlock = minimum(
                finalized,
                fromBlock + this.maximumBlockRange - 1n,
            );
            const [logs, block] = await Promise.all([
                this.fetchLogs(fromBlock, toBlock),
                this.client.getBlock({ blockNumber: toBlock }),
            ]);
            await this.store.applyBatch(
                decodeEvmRegistryLogs(
                    logs,
                    this.registryAddress,
                    this.registrarAddress,
                ),
                {
                    checkpoint: block.hash.toLowerCase(),
                    sequence: toBlock.toString(),
                    source: this.source,
                },
            );
            fromBlock = toBlock + 1n;
        }
    }

    private schedule(delay: number): void {
        if (this.stopped) return;
        this.timer = setTimeout(() => {
            this.timer = null;
            void this.syncOnce()
                .catch(this.onError)
                .finally(() => {
                    this.schedule(this.pollIntervalMs);
                });
        }, delay);
    }
}

export function decodeEvmRegistryLogs(
    logs: readonly EvmRegistryLog[],
    registryAddress: Address,
    registrarAddress?: Address,
): RegistryEvent[] {
    const registry = registryAddress.toLowerCase();
    const registrar = registrarAddress?.toLowerCase();
    return [...logs].sort(compareLogs).flatMap((log) => {
        const address = log.address.toLowerCase();
        if (address === registry) return [decodeRegistryLog(log)];
        if (registrar && address === registrar) {
            const event = decodeRegistrarLog(log);
            return event ? [event] : [];
        }
        throw new Error(`Unexpected registry log address ${log.address}.`);
    });
}

export function evmRegistrySource(
    chainId: number,
    registryAddress: Address,
    registrarAddress?: Address,
): string {
    if (!Number.isSafeInteger(chainId) || chainId <= 0) {
        throw new Error("EVM chain ID must be a positive safe integer.");
    }
    if (!isAddress(registryAddress, { strict: true })) {
        throw new Error("EVM registry address is invalid.");
    }
    if (
        registrarAddress !== undefined &&
        !isAddress(registrarAddress, { strict: true })
    ) {
        throw new Error("EVM registrar address is invalid.");
    }
    const registrar = registrarAddress
        ? `?registrar=${registrarAddress.toLowerCase()}`
        : "";
    return `eip155:${String(chainId)}/${registryAddress.toLowerCase()}${registrar}`;
}

function compareLogs(left: EvmRegistryLog, right: EvmRegistryLog): number {
    if (left.blockNumber !== right.blockNumber) {
        return left.blockNumber < right.blockNumber ? -1 : 1;
    }
    if (left.transactionIndex !== right.transactionIndex) {
        return left.transactionIndex - right.transactionIndex;
    }
    return left.logIndex - right.logIndex;
}

function decodeRegistrarLog(log: EvmRegistryLog): null | RegistryEvent {
    const decoded = decodeEventLog({
        abi: registrarEventAbi,
        data: log.data,
        strict: true,
        topics: log.topics,
    });
    switch (decoded.eventName) {
        case "NameCommitted":
            return null;
        case "NameRegistered":
            return {
                accountId: decoded.args.accountId.toLowerCase(),
                nameHash: decoded.args.nameHash.toLowerCase(),
                type: "username-registered",
                username: decoded.args.username,
            };
    }
}

function decodeRegistryLog(log: EvmRegistryLog): RegistryEvent {
    const decoded = decodeEventLog({
        abi: registryEventAbi,
        data: log.data,
        strict: true,
        topics: log.topics,
    });
    switch (decoded.eventName) {
        case "AccountRegistered":
            return {
                accountId: decoded.args.accountId.toLowerCase(),
                epoch: decoded.args.epoch.toString(),
                genesisDeviceKey: decoded.args.genesisDeviceKey.toLowerCase(),
                homeserverId: decoded.args.homeserverId.toLowerCase(),
                recoveryCommitment:
                    decoded.args.recoveryCommitment.toLowerCase(),
                type: "account-registered",
            };
        case "DeviceAdded":
            return {
                accountId: decoded.args.accountId.toLowerCase(),
                deviceKey: decoded.args.deviceKey.toLowerCase(),
                epoch: decoded.args.epoch.toString(),
                type: "device-added",
            };
        case "DeviceRevoked":
            return {
                accountId: decoded.args.accountId.toLowerCase(),
                deviceKey: decoded.args.deviceKey.toLowerCase(),
                epoch: decoded.args.epoch.toString(),
                type: "device-revoked",
            };
        case "DeviceThresholdChanged":
            return {
                accountId: decoded.args.accountId.toLowerCase(),
                epoch: decoded.args.epoch.toString(),
                threshold: decoded.args.threshold,
                type: "device-threshold-changed",
            };
        case "HomeserverChanged":
            return {
                accountId: decoded.args.accountId.toLowerCase(),
                epoch: decoded.args.epoch.toString(),
                homeserverId: decoded.args.newHomeserverId.toLowerCase(),
                type: "homeserver-changed",
            };
        case "HomeserverEndpointChanged":
            return {
                endpoint: decoded.args.endpoint,
                epoch: decoded.args.epoch.toString(),
                homeserverId: decoded.args.homeserverId.toLowerCase(),
                type: "homeserver-endpoint-changed",
            };
        case "HomeserverKeyRotated":
            return {
                epoch: decoded.args.epoch.toString(),
                homeserverId: decoded.args.homeserverId.toLowerCase(),
                signingKey: decoded.args.newSigningKey.toLowerCase(),
                type: "homeserver-key-rotated",
            };
        case "HomeserverRegistered":
            return {
                endpoint: decoded.args.endpoint,
                epoch: decoded.args.epoch.toString(),
                homeserverId: decoded.args.homeserverId.toLowerCase(),
                signingKey: decoded.args.signingKey.toLowerCase(),
                type: "homeserver-registered",
            };
        case "RecoveryCommitmentChanged":
            return {
                accountId: decoded.args.accountId.toLowerCase(),
                epoch: decoded.args.epoch.toString(),
                recoveryCommitment:
                    decoded.args.recoveryCommitment.toLowerCase(),
                type: "recovery-commitment-changed",
            };
    }
}

function minimum(left: bigint, right: bigint): bigint {
    return left < right ? left : right;
}

function toRegistryLog(log: Log): EvmRegistryLog {
    if (
        log.blockNumber === null ||
        log.logIndex === null ||
        log.transactionIndex === null
    ) {
        throw new Error("Registry RPC returned a pending log.");
    }
    return {
        address: log.address,
        blockNumber: log.blockNumber,
        data: log.data,
        logIndex: log.logIndex,
        topics: log.topics,
        transactionIndex: log.transactionIndex,
    };
}

function validateOptions(options: EvmRegistryIndexerOptions): void {
    evmRegistrySource(options.chainId, options.registryAddress);
    if (
        options.registrarAddress !== undefined &&
        !isAddress(options.registrarAddress, { strict: true })
    ) {
        throw new Error("EVM registrar address is invalid.");
    }
    if (options.deploymentBlock < 0n) {
        throw new Error("Registry deployment block cannot be negative.");
    }
    if (options.rpcUrls.length === 0) {
        throw new Error("At least one registry RPC URL is required.");
    }
    for (const rpcUrl of options.rpcUrls) validateRpcUrl(rpcUrl);
    if (
        options.finality !== undefined &&
        options.finality !== "finalized" &&
        (!Number.isSafeInteger(options.finality.confirmations) ||
            options.finality.confirmations < 1)
    ) {
        throw new Error("Registry confirmations must be a positive integer.");
    }
    if (
        options.maximumBlockRange !== undefined &&
        options.maximumBlockRange < 1n
    ) {
        throw new Error("Registry block range must be positive.");
    }
    if (
        options.maximumStalenessMs !== undefined &&
        (!Number.isSafeInteger(options.maximumStalenessMs) ||
            options.maximumStalenessMs < 1_000)
    ) {
        throw new Error(
            "Registry maximum staleness must be at least one second.",
        );
    }
    if (
        options.pollIntervalMs !== undefined &&
        (!Number.isSafeInteger(options.pollIntervalMs) ||
            options.pollIntervalMs < 1_000)
    ) {
        throw new Error("Registry poll interval must be at least one second.");
    }
}

function validateRpcUrl(value: string): void {
    const url = new URL(value);
    const local = url.hostname === "127.0.0.1" || url.hostname === "localhost";
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
        throw new Error(
            "Registry RPC URLs must use HTTPS unless they are local.",
        );
    }
    if (url.username || url.password) {
        throw new Error("Registry RPC credentials cannot be embedded in URLs.");
    }
}

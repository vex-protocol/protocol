/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { defineConfig } from "vitest/config";

import { poisonNodeImports } from "./src/__tests__/harness/poison-node-imports.js";

export default defineConfig({
    test: {
        projects: [
            {
                test: {
                    globals: true,
                    include: [
                        "src/__tests__/codec.test.ts",
                        "src/__tests__/dm-own-device-forward.test.ts",
                        "src/__tests__/http.test.ts",
                        "src/__tests__/initial-mail-replay.test.ts",
                        "src/__tests__/multi-device-delivery.test.ts",
                        "src/__tests__/ratchet.test.ts",
                        "src/__tests__/retention.test.ts",
                        "src/__tests__/storage-sqlite.test.ts",
                        "src/__tests__/verifyKeyBundle.test.ts",
                        "src/__tests__/websocket.test.ts",
                    ],
                    name: "unit",
                    testTimeout: 10_000,
                },
            },
            {
                test: {
                    fileParallelism: false,
                    globals: true,
                    hookTimeout: 30_000,
                    include: [
                        "src/__tests__/node-keystore.test.ts",
                        "src/__tests__/platform-node.test.ts",
                    ],
                    name: "node",
                    testTimeout: 15_000,
                },
            },
            {
                plugins: [poisonNodeImports()],
                test: {
                    fileParallelism: false,
                    globals: true,
                    hookTimeout: 30_000,
                    include: ["src/__tests__/platform-browser.test.ts"],
                    name: "browser",
                    testTimeout: 15_000,
                },
            },
        ],
    },
});

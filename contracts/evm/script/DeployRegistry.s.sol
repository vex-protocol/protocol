// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { IEd25519Verifier } from "../src/IEd25519Verifier.sol";
import { VexRegistry } from "../src/VexRegistry.sol";
import { ScriptBase } from "./ScriptBase.sol";

contract DeployRegistry is ScriptBase {
    function run() external returns (VexRegistry registry) {
        address verifier = vm.envAddress("ED25519_VERIFIER_ADDRESS");
        requireAuditedVerifier(verifier, vm.envBytes32("ED25519_VERIFIER_CODEHASH"));

        vm.startBroadcast();
        registry = new VexRegistry(IEd25519Verifier(verifier));
        vm.stopBroadcast();
    }
}

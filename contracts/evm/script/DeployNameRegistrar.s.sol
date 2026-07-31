// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { IERC20 } from "../src/IERC20.sol";
import { VexNameRegistrar } from "../src/VexNameRegistrar.sol";
import { VexRegistry } from "../src/VexRegistry.sol";
import { ScriptBase } from "./ScriptBase.sol";

contract DeployNameRegistrar is ScriptBase {
    function run() external returns (VexNameRegistrar registrar) {
        VexRegistry registry = VexRegistry(vm.envAddress("REGISTRY_ADDRESS"));
        address paymentToken = vm.envAddress("PAYMENT_TOKEN_ADDRESS");
        address feeRecipient = vm.envAddress("FEE_RECIPIENT");
        uint256 minimumAge = vm.envUint("MIN_COMMITMENT_AGE");
        uint256 maximumAge = vm.envUint("MAX_COMMITMENT_AGE");

        require(address(registry).code.length > 0, "registry has no code");
        require(paymentToken.code.length > 0, "payment token has no code");
        require(minimumAge <= type(uint64).max, "minimum age exceeds uint64");
        require(maximumAge <= type(uint64).max, "maximum age exceeds uint64");
        requireAuditedVerifier(
            address(registry.ed25519Verifier()), vm.envBytes32("ED25519_VERIFIER_CODEHASH")
        );

        vm.startBroadcast();
        registrar = new VexNameRegistrar(
            registry,
            IERC20(paymentToken),
            feeRecipient,
            vm.envUint("REGISTRATION_FEE"),
            uint64(minimumAge),
            uint64(maximumAge)
        );
        vm.stopBroadcast();
    }
}

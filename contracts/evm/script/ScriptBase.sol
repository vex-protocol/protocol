// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { DeterministicTestVerifier } from "../test/helpers/DeterministicTestVerifier.sol";

interface Vm {
    function envAddress(string calldata name) external returns (address value);
    function envBytes32(string calldata name) external returns (bytes32 value);
    function envUint(string calldata name) external returns (uint256 value);
    function startBroadcast() external;
    function stopBroadcast() external;
}

abstract contract ScriptBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function requireAuditedVerifier(address verifier, bytes32 expectedCodeHash) internal view {
        require(verifier.code.length > 0, "verifier has no code");
        require(expectedCodeHash != bytes32(0), "verifier code hash is required");
        require(verifier.codehash == expectedCodeHash, "verifier code hash mismatch");
        require(
            verifier.codehash != keccak256(type(DeterministicTestVerifier).runtimeCode),
            "test verifier cannot be deployed"
        );
    }
}

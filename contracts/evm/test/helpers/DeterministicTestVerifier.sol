// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { IEd25519Verifier } from "../../src/IEd25519Verifier.sol";

/// @dev Deterministic test plumbing. This is not a cryptographic verifier.
contract DeterministicTestVerifier is IEd25519Verifier {
    function verify(bytes32 publicKey, bytes32 message, bytes calldata signature)
        external
        pure
        returns (bool valid)
    {
        if (signature.length != 64) return false;
        bytes32 left;
        bytes32 right;
        assembly ("memory-safe") {
            left := calldataload(signature.offset)
            right := calldataload(add(signature.offset, 32))
        }
        bytes32 expected = keccak256(abi.encode(publicKey, message));
        return left == expected && right == ~expected;
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

/// @notice Verification boundary for 32-byte Ed25519 public keys.
/// @dev Vex signs the supplied 32-byte digest as the complete Ed25519 message.
///      Production deployments MUST use a separately audited implementation.
interface IEd25519Verifier {
    function verify(bytes32 publicKey, bytes32 message, bytes calldata signature)
        external
        view
        returns (bool valid);
}

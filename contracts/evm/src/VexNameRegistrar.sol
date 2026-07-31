// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { IERC20 } from "./IERC20.sol";
import { IEd25519Verifier } from "./IEd25519Verifier.sol";
import { VexRegistry } from "./VexRegistry.sol";

/// @title VexNameRegistrar
/// @notice Permanent paid aliases for stable Vex account IDs.
/// @dev Registration is authorized by the account's current device threshold, not an EVM wallet.
contract VexNameRegistrar {
    uint8 public constant MAX_NAME_LENGTH = 19;
    uint8 public constant MIN_NAME_LENGTH = 3;

    bytes32 public constant COMMITMENT_DOMAIN = keccak256("vex:name-commitment:v1");
    bytes32 public constant REGISTER_NAME_TYPEHASH = keccak256(
        "RegisterName(uint256 chainId,address registrar,bytes32 accountId,uint64 registryEpoch,uint64 nonce,bytes32 nameHash,uint64 deadline)"
    );

    error ActionExpired(uint64 deadline);
    error CommitmentAlreadyExists(bytes32 commitment);
    error CommitmentExpired(bytes32 commitment);
    error CommitmentNotFound(bytes32 commitment);
    error CommitmentTooNew(bytes32 commitment);
    error DuplicateApproval(bytes32 deviceKey);
    error InvalidApprovalCount(uint256 supplied, uint256 required);
    error InvalidName();
    error InvalidRegistryEpoch(uint64 supplied, uint64 expected);
    error InvalidSignature(bytes32 publicKey);
    error InvalidSignatureLength();
    error NameAlreadyRegistered(bytes32 nameHash);
    error PaymentFailed();
    error ReentrantCall();
    error UsernameAlreadyRegistered(bytes32 accountId);
    error ZeroValue();

    event NameCommitted(bytes32 indexed commitment, address indexed committer, uint64 createdAt);
    event NameRegistered(
        bytes32 indexed nameHash,
        bytes32 indexed accountId,
        string username,
        address indexed payer,
        uint256 fee
    );

    VexRegistry public immutable registry;
    IEd25519Verifier public immutable ed25519Verifier;
    IERC20 public immutable paymentToken;
    address public immutable feeRecipient;
    uint256 public immutable registrationFee;
    uint64 public immutable minimumCommitmentAge;
    uint64 public immutable maximumCommitmentAge;

    mapping(bytes32 commitment => uint64 createdAt) public commitments;
    mapping(bytes32 accountId => uint64 nonce) public nonces;
    mapping(bytes32 nameHash => bytes32 accountId) public accountByNameHash;
    mapping(bytes32 accountId => string username) public nameByAccount;

    uint256 private unlocked = 1;

    modifier nonReentrant() {
        if (unlocked != 1) revert ReentrantCall();
        unlocked = 2;
        _;
        unlocked = 1;
    }

    constructor(
        VexRegistry registry_,
        IERC20 paymentToken_,
        address feeRecipient_,
        uint256 registrationFee_,
        uint64 minimumCommitmentAge_,
        uint64 maximumCommitmentAge_
    ) {
        if (
            address(registry_) == address(0) || address(paymentToken_) == address(0)
                || feeRecipient_ == address(0)
        ) {
            revert ZeroValue();
        }
        if (maximumCommitmentAge_ <= minimumCommitmentAge_) revert ZeroValue();

        registry = registry_;
        ed25519Verifier = registry_.ed25519Verifier();
        paymentToken = paymentToken_;
        feeRecipient = feeRecipient_;
        registrationFee = registrationFee_;
        minimumCommitmentAge = minimumCommitmentAge_;
        maximumCommitmentAge = maximumCommitmentAge_;
    }

    function commit(bytes32 commitment) external {
        if (commitment == bytes32(0)) revert ZeroValue();
        uint64 previous = commitments[commitment];
        if (previous != 0 && block.timestamp <= uint256(previous) + maximumCommitmentAge) {
            revert CommitmentAlreadyExists(commitment);
        }

        uint64 createdAt = uint64(block.timestamp);
        commitments[commitment] = createdAt;
        emit NameCommitted(commitment, msg.sender, createdAt);
    }

    function register(
        string calldata username,
        bytes32 accountId,
        bytes32 salt,
        uint64 registryEpoch,
        uint64 deadline,
        VexRegistry.Approval[] calldata approvals
    ) external nonReentrant {
        if (block.timestamp > deadline) revert ActionExpired(deadline);
        bytes32 nameHash = hashName(username);
        if (accountByNameHash[nameHash] != bytes32(0)) revert NameAlreadyRegistered(nameHash);
        if (bytes(nameByAccount[accountId]).length != 0) {
            revert UsernameAlreadyRegistered(accountId);
        }

        _consumeCommitment(accountId, nameHash, salt);
        _authorizeRegistration(accountId, registryEpoch, nameHash, deadline, approvals);
        accountByNameHash[nameHash] = accountId;
        nameByAccount[accountId] = username;
        _collectFee();

        emit NameRegistered(nameHash, accountId, username, msg.sender, registrationFee);
    }

    function commitmentFor(bytes32 accountId, bytes32 nameHash, bytes32 salt, address committer)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                COMMITMENT_DOMAIN,
                block.chainid,
                address(this),
                accountId,
                nameHash,
                salt,
                committer
            )
        );
    }

    function registrationDigest(
        bytes32 accountId,
        uint64 registryEpoch,
        uint64 nonce,
        bytes32 nameHash,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                REGISTER_NAME_TYPEHASH,
                block.chainid,
                address(this),
                accountId,
                registryEpoch,
                nonce,
                nameHash,
                deadline
            )
        );
    }

    function hashName(string calldata username) public pure returns (bytes32) {
        bytes calldata value = bytes(username);
        if (value.length < MIN_NAME_LENGTH || value.length > MAX_NAME_LENGTH) {
            revert InvalidName();
        }
        for (uint256 index = 0; index < value.length; index++) {
            bytes1 character = value[index];
            bool lowercase = character >= 0x61 && character <= 0x7a;
            bool digit = character >= 0x30 && character <= 0x39;
            if (!lowercase && !digit && character != 0x5f) revert InvalidName();
        }
        return keccak256(value);
    }

    function _authorizeRegistration(
        bytes32 accountId,
        uint64 registryEpoch,
        bytes32 nameHash,
        uint64 deadline,
        VexRegistry.Approval[] calldata approvals
    ) private {
        VexRegistry.Account memory account = registry.getAccount(accountId);
        if (registryEpoch != account.epoch) {
            revert InvalidRegistryEpoch(registryEpoch, account.epoch);
        }
        uint64 nonce = nonces[accountId];
        bytes32 digest = registrationDigest(accountId, registryEpoch, nonce, nameHash, deadline);
        _requireApprovals(accountId, account.deviceThreshold, digest, approvals);
        nonces[accountId] = nonce + 1;
    }

    function _collectFee() private {
        if (registrationFee == 0) return;
        (bool success, bytes memory result) = address(paymentToken).call(
            abi.encodeCall(IERC20.transferFrom, (msg.sender, feeRecipient, registrationFee))
        );
        if (!success || (result.length != 0 && (result.length < 32 || !abi.decode(result, (bool)))))
        {
            revert PaymentFailed();
        }
    }

    function _consumeCommitment(bytes32 accountId, bytes32 nameHash, bytes32 salt) private {
        bytes32 commitment = commitmentFor(accountId, nameHash, salt, msg.sender);
        uint64 createdAt = commitments[commitment];
        if (createdAt == 0) revert CommitmentNotFound(commitment);
        uint256 age = block.timestamp - createdAt;
        if (age < minimumCommitmentAge) revert CommitmentTooNew(commitment);
        if (age > maximumCommitmentAge) revert CommitmentExpired(commitment);
        delete commitments[commitment];
    }

    function _requireApprovals(
        bytes32 accountId,
        uint8 threshold,
        bytes32 digest,
        VexRegistry.Approval[] calldata approvals
    ) private view {
        if (approvals.length != threshold) {
            revert InvalidApprovalCount(approvals.length, threshold);
        }
        for (uint256 index = 0; index < approvals.length; index++) {
            bytes32 deviceKey = approvals[index].deviceKey;
            if (!registry.isDeviceActive(accountId, deviceKey)) {
                revert InvalidSignature(deviceKey);
            }
            for (uint256 previous = 0; previous < index; previous++) {
                if (approvals[previous].deviceKey == deviceKey) {
                    revert DuplicateApproval(deviceKey);
                }
            }
            bytes calldata signature = approvals[index].signature;
            if (signature.length != 64) revert InvalidSignatureLength();
            bool valid;
            try ed25519Verifier.verify(deviceKey, digest, signature) returns (bool result) {
                valid = result;
            } catch { }
            if (!valid) revert InvalidSignature(deviceKey);
        }
    }
}

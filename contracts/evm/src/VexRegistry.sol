// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { IEd25519Verifier } from "./IEd25519Verifier.sol";

/// @title VexRegistry
/// @notice Chain-level account, device-authority, and homeserver directory.
/// @dev Passwords, passkeys, messaging prekeys, and message data never enter this contract.
contract VexRegistry {
    uint8 public constant MAX_ACTIVE_DEVICES = 20;

    bytes32 public constant ACCOUNT_ID_DOMAIN = keccak256("vex:account-id:v1");
    bytes32 public constant HOMESERVER_ID_DOMAIN = keccak256("vex:homeserver-id:v1");

    bytes32 public constant REGISTER_ACCOUNT_TYPEHASH = keccak256(
        "RegisterAccount(uint256 chainId,address registry,bytes32 accountId,bytes32 genesisNonce,bytes32 genesisDeviceKey,bytes32 homeserverId,bytes32 recoveryCommitment,uint64 deadline)"
    );
    bytes32 public constant ADD_DEVICE_TYPEHASH = keccak256(
        "AddDevice(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 newDeviceKey,uint64 deadline)"
    );
    bytes32 public constant REVOKE_DEVICE_TYPEHASH = keccak256(
        "RevokeDevice(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 deviceKey,uint64 deadline)"
    );
    bytes32 public constant SET_HOMESERVER_TYPEHASH = keccak256(
        "SetHomeserver(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 homeserverId,uint64 deadline)"
    );
    bytes32 public constant SET_DEVICE_THRESHOLD_TYPEHASH = keccak256(
        "SetDeviceThreshold(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,uint8 threshold,uint64 deadline)"
    );
    bytes32 public constant SET_RECOVERY_COMMITMENT_TYPEHASH = keccak256(
        "SetRecoveryCommitment(uint256 chainId,address registry,bytes32 accountId,uint64 epoch,uint64 nonce,bytes32 recoveryCommitment,uint64 deadline)"
    );
    bytes32 public constant REGISTER_HOMESERVER_TYPEHASH = keccak256(
        "RegisterHomeserver(uint256 chainId,address registry,bytes32 homeserverId,bytes32 genesisNonce,bytes32 signingKey,bytes32 endpointHash,uint64 deadline)"
    );
    bytes32 public constant SET_HOMESERVER_ENDPOINT_TYPEHASH = keccak256(
        "SetHomeserverEndpoint(uint256 chainId,address registry,bytes32 homeserverId,uint64 epoch,uint64 nonce,bytes32 endpointHash,uint64 deadline)"
    );
    bytes32 public constant ROTATE_HOMESERVER_KEY_TYPEHASH = keccak256(
        "RotateHomeserverKey(uint256 chainId,address registry,bytes32 homeserverId,uint64 epoch,uint64 nonce,bytes32 newSigningKey,uint64 deadline)"
    );

    struct Account {
        bytes32 homeserverId;
        bytes32 recoveryCommitment;
        uint64 epoch;
        uint64 nonce;
        uint8 activeDeviceCount;
        uint8 deviceThreshold;
        bool exists;
    }

    struct Approval {
        bytes32 deviceKey;
        bytes signature;
    }

    struct Device {
        uint64 addedAtEpoch;
        uint64 revokedAtEpoch;
        bool active;
    }

    struct Homeserver {
        bytes32 signingKey;
        uint64 epoch;
        uint64 nonce;
        bool active;
        string endpoint;
    }

    error AccountAlreadyExists(bytes32 accountId);
    error AccountNotFound(bytes32 accountId);
    error ActionExpired(uint64 deadline);
    error DeviceAlreadyActive(bytes32 deviceKey);
    error DeviceAlreadyKnown(bytes32 deviceKey);
    error DeviceLimitReached();
    error DeviceNotActive(bytes32 deviceKey);
    error DuplicateApproval(bytes32 deviceKey);
    error HomeserverAlreadyExists(bytes32 homeserverId);
    error HomeserverNotFound(bytes32 homeserverId);
    error InsufficientActiveDevices();
    error InvalidAccountId();
    error InvalidApprovalCount(uint256 supplied, uint256 required);
    error InvalidDeviceProof();
    error InvalidEndpoint();
    error InvalidEpoch(uint64 supplied, uint64 expected);
    error InvalidHomeserverId();
    error InvalidNonce(uint64 supplied, uint64 expected);
    error InvalidSignature(bytes32 publicKey);
    error InvalidSignatureLength();
    error InvalidThreshold(uint8 threshold);
    error ZeroValue();

    event AccountRegistered(
        bytes32 indexed accountId,
        bytes32 indexed genesisDeviceKey,
        bytes32 indexed homeserverId,
        bytes32 recoveryCommitment,
        uint64 epoch
    );
    event DeviceAdded(bytes32 indexed accountId, bytes32 indexed deviceKey, uint64 epoch);
    event DeviceRevoked(bytes32 indexed accountId, bytes32 indexed deviceKey, uint64 epoch);
    event DeviceThresholdChanged(bytes32 indexed accountId, uint8 threshold, uint64 epoch);
    event HomeserverChanged(
        bytes32 indexed accountId,
        bytes32 indexed oldHomeserverId,
        bytes32 indexed newHomeserverId,
        uint64 epoch
    );
    event HomeserverEndpointChanged(bytes32 indexed homeserverId, string endpoint, uint64 epoch);
    event HomeserverKeyRotated(
        bytes32 indexed homeserverId,
        bytes32 indexed oldSigningKey,
        bytes32 indexed newSigningKey,
        uint64 epoch
    );
    event HomeserverRegistered(
        bytes32 indexed homeserverId, bytes32 indexed signingKey, string endpoint, uint64 epoch
    );
    event RecoveryCommitmentChanged(
        bytes32 indexed accountId, bytes32 indexed recoveryCommitment, uint64 epoch
    );

    IEd25519Verifier public immutable ed25519Verifier;

    mapping(bytes32 accountId => Account account) private accounts;
    mapping(bytes32 accountId => mapping(bytes32 deviceKey => Device device)) private devices;
    mapping(bytes32 homeserverId => Homeserver homeserver) private homeservers;

    constructor(IEd25519Verifier verifier) {
        if (address(verifier) == address(0)) revert ZeroValue();
        ed25519Verifier = verifier;
    }

    function deriveAccountId(bytes32 genesisNonce, bytes32 genesisDeviceKey)
        public
        pure
        returns (bytes32)
    {
        if (genesisNonce == bytes32(0) || genesisDeviceKey == bytes32(0)) revert ZeroValue();
        return keccak256(abi.encode(ACCOUNT_ID_DOMAIN, genesisNonce, genesisDeviceKey));
    }

    function deriveHomeserverId(bytes32 genesisNonce, bytes32 signingKey)
        public
        pure
        returns (bytes32)
    {
        if (genesisNonce == bytes32(0) || signingKey == bytes32(0)) revert ZeroValue();
        return keccak256(abi.encode(HOMESERVER_ID_DOMAIN, genesisNonce, signingKey));
    }

    function getAccount(bytes32 accountId) external view returns (Account memory) {
        Account memory account = accounts[accountId];
        if (!account.exists) revert AccountNotFound(accountId);
        return account;
    }

    function getDevice(bytes32 accountId, bytes32 deviceKey)
        external
        view
        returns (Device memory)
    {
        if (!accounts[accountId].exists) revert AccountNotFound(accountId);
        return devices[accountId][deviceKey];
    }

    function getHomeserver(bytes32 homeserverId) external view returns (Homeserver memory) {
        Homeserver memory homeserver = homeservers[homeserverId];
        if (!homeserver.active) revert HomeserverNotFound(homeserverId);
        return homeserver;
    }

    function isDeviceActive(bytes32 accountId, bytes32 deviceKey) external view returns (bool) {
        return accounts[accountId].exists && devices[accountId][deviceKey].active;
    }

    function registerHomeserver(
        bytes32 homeserverId,
        bytes32 genesisNonce,
        bytes32 signingKey,
        string calldata endpoint,
        uint64 deadline,
        bytes calldata signature
    ) external {
        _requireLiveDeadline(deadline);
        if (deriveHomeserverId(genesisNonce, signingKey) != homeserverId) {
            revert InvalidHomeserverId();
        }
        if (homeservers[homeserverId].active) revert HomeserverAlreadyExists(homeserverId);
        _requireValidEndpoint(endpoint);

        bytes32 digest =
            registerHomeserverDigest(homeserverId, genesisNonce, signingKey, endpoint, deadline);
        _requireSignature(signingKey, digest, signature);

        homeservers[homeserverId] = Homeserver({
            signingKey: signingKey,
            epoch: 1,
            nonce: 0,
            active: true,
            endpoint: endpoint
        });
        emit HomeserverRegistered(homeserverId, signingKey, endpoint, 1);
    }

    function registerAccount(
        bytes32 accountId,
        bytes32 genesisNonce,
        bytes32 genesisDeviceKey,
        bytes32 homeserverId,
        bytes32 recoveryCommitment,
        uint64 deadline,
        bytes calldata signature
    ) external {
        _requireLiveDeadline(deadline);
        if (deriveAccountId(genesisNonce, genesisDeviceKey) != accountId) {
            revert InvalidAccountId();
        }
        if (accounts[accountId].exists) revert AccountAlreadyExists(accountId);
        if (!homeservers[homeserverId].active) revert HomeserverNotFound(homeserverId);

        bytes32 digest = registerAccountDigest(
            accountId, genesisNonce, genesisDeviceKey, homeserverId, recoveryCommitment, deadline
        );
        _requireSignature(genesisDeviceKey, digest, signature);

        accounts[accountId] = Account({
            homeserverId: homeserverId,
            recoveryCommitment: recoveryCommitment,
            epoch: 1,
            nonce: 0,
            activeDeviceCount: 1,
            deviceThreshold: 1,
            exists: true
        });
        devices[accountId][genesisDeviceKey] =
            Device({ addedAtEpoch: 1, revokedAtEpoch: 0, active: true });

        emit AccountRegistered(accountId, genesisDeviceKey, homeserverId, recoveryCommitment, 1);
        emit DeviceAdded(accountId, genesisDeviceKey, 1);
    }

    function addDevice(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 newDeviceKey,
        uint64 deadline,
        Approval[] calldata approvals,
        bytes calldata newDeviceProof
    ) external {
        Account storage account = _requireAccountState(accountId, epoch, nonce, deadline);
        if (newDeviceKey == bytes32(0)) revert ZeroValue();
        Device storage newDevice = devices[accountId][newDeviceKey];
        if (newDevice.active) revert DeviceAlreadyActive(newDeviceKey);
        if (newDevice.addedAtEpoch != 0) revert DeviceAlreadyKnown(newDeviceKey);
        if (account.activeDeviceCount >= MAX_ACTIVE_DEVICES) revert DeviceLimitReached();

        bytes32 digest = addDeviceDigest(accountId, epoch, nonce, newDeviceKey, deadline);
        _requireApprovals(accountId, account.deviceThreshold, digest, approvals);
        if (!_isValidSignature(newDeviceKey, digest, newDeviceProof)) revert InvalidDeviceProof();

        uint64 nextEpoch = _advance(account);
        account.activeDeviceCount += 1;
        newDevice.addedAtEpoch = nextEpoch;
        newDevice.active = true;
        emit DeviceAdded(accountId, newDeviceKey, nextEpoch);
    }

    function revokeDevice(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 deviceKey,
        uint64 deadline,
        Approval[] calldata approvals
    ) external {
        Account storage account = _requireAccountState(accountId, epoch, nonce, deadline);
        Device storage device = devices[accountId][deviceKey];
        if (!device.active) revert DeviceNotActive(deviceKey);
        if (account.activeDeviceCount - 1 < account.deviceThreshold) {
            revert InsufficientActiveDevices();
        }

        bytes32 digest = revokeDeviceDigest(accountId, epoch, nonce, deviceKey, deadline);
        _requireApprovals(accountId, account.deviceThreshold, digest, approvals);

        uint64 nextEpoch = _advance(account);
        account.activeDeviceCount -= 1;
        device.active = false;
        device.revokedAtEpoch = nextEpoch;
        emit DeviceRevoked(accountId, deviceKey, nextEpoch);
    }

    function setHomeserver(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 homeserverId,
        uint64 deadline,
        Approval[] calldata approvals
    ) external {
        Account storage account = _requireAccountState(accountId, epoch, nonce, deadline);
        if (!homeservers[homeserverId].active) revert HomeserverNotFound(homeserverId);

        bytes32 digest = setHomeserverDigest(accountId, epoch, nonce, homeserverId, deadline);
        _requireApprovals(accountId, account.deviceThreshold, digest, approvals);

        bytes32 previous = account.homeserverId;
        uint64 nextEpoch = _advance(account);
        account.homeserverId = homeserverId;
        emit HomeserverChanged(accountId, previous, homeserverId, nextEpoch);
    }

    function setDeviceThreshold(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        uint8 threshold,
        uint64 deadline,
        Approval[] calldata approvals
    ) external {
        Account storage account = _requireAccountState(accountId, epoch, nonce, deadline);
        if (threshold == 0 || threshold > account.activeDeviceCount) {
            revert InvalidThreshold(threshold);
        }

        bytes32 digest = setDeviceThresholdDigest(accountId, epoch, nonce, threshold, deadline);
        _requireApprovals(accountId, account.deviceThreshold, digest, approvals);

        uint64 nextEpoch = _advance(account);
        account.deviceThreshold = threshold;
        emit DeviceThresholdChanged(accountId, threshold, nextEpoch);
    }

    function setRecoveryCommitment(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 recoveryCommitment,
        uint64 deadline,
        Approval[] calldata approvals
    ) external {
        Account storage account = _requireAccountState(accountId, epoch, nonce, deadline);
        bytes32 digest =
            setRecoveryCommitmentDigest(accountId, epoch, nonce, recoveryCommitment, deadline);
        _requireApprovals(accountId, account.deviceThreshold, digest, approvals);

        uint64 nextEpoch = _advance(account);
        account.recoveryCommitment = recoveryCommitment;
        emit RecoveryCommitmentChanged(accountId, recoveryCommitment, nextEpoch);
    }

    function setHomeserverEndpoint(
        bytes32 homeserverId,
        uint64 epoch,
        uint64 nonce,
        string calldata endpoint,
        uint64 deadline,
        bytes calldata signature
    ) external {
        Homeserver storage homeserver =
            _requireHomeserverState(homeserverId, epoch, nonce, deadline);
        _requireValidEndpoint(endpoint);
        bytes32 digest = setHomeserverEndpointDigest(homeserverId, epoch, nonce, endpoint, deadline);
        _requireSignature(homeserver.signingKey, digest, signature);

        uint64 nextEpoch = _advance(homeserver);
        homeserver.endpoint = endpoint;
        emit HomeserverEndpointChanged(homeserverId, endpoint, nextEpoch);
    }

    function rotateHomeserverKey(
        bytes32 homeserverId,
        uint64 epoch,
        uint64 nonce,
        bytes32 newSigningKey,
        uint64 deadline,
        bytes calldata currentKeySignature,
        bytes calldata newKeyProof
    ) external {
        Homeserver storage homeserver =
            _requireHomeserverState(homeserverId, epoch, nonce, deadline);
        if (newSigningKey == bytes32(0)) revert ZeroValue();
        bytes32 digest =
            rotateHomeserverKeyDigest(homeserverId, epoch, nonce, newSigningKey, deadline);
        _requireSignature(homeserver.signingKey, digest, currentKeySignature);
        _requireSignature(newSigningKey, digest, newKeyProof);

        bytes32 previous = homeserver.signingKey;
        uint64 nextEpoch = _advance(homeserver);
        homeserver.signingKey = newSigningKey;
        emit HomeserverKeyRotated(homeserverId, previous, newSigningKey, nextEpoch);
    }

    function registerAccountDigest(
        bytes32 accountId,
        bytes32 genesisNonce,
        bytes32 genesisDeviceKey,
        bytes32 homeserverId,
        bytes32 recoveryCommitment,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                REGISTER_ACCOUNT_TYPEHASH,
                block.chainid,
                address(this),
                accountId,
                genesisNonce,
                genesisDeviceKey,
                homeserverId,
                recoveryCommitment,
                deadline
            )
        );
    }

    function addDeviceDigest(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 newDeviceKey,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                ADD_DEVICE_TYPEHASH,
                block.chainid,
                address(this),
                accountId,
                epoch,
                nonce,
                newDeviceKey,
                deadline
            )
        );
    }

    function revokeDeviceDigest(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 deviceKey,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                REVOKE_DEVICE_TYPEHASH,
                block.chainid,
                address(this),
                accountId,
                epoch,
                nonce,
                deviceKey,
                deadline
            )
        );
    }

    function setHomeserverDigest(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 homeserverId,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                SET_HOMESERVER_TYPEHASH,
                block.chainid,
                address(this),
                accountId,
                epoch,
                nonce,
                homeserverId,
                deadline
            )
        );
    }

    function setDeviceThresholdDigest(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        uint8 threshold,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                SET_DEVICE_THRESHOLD_TYPEHASH,
                block.chainid,
                address(this),
                accountId,
                epoch,
                nonce,
                threshold,
                deadline
            )
        );
    }

    function setRecoveryCommitmentDigest(
        bytes32 accountId,
        uint64 epoch,
        uint64 nonce,
        bytes32 recoveryCommitment,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                SET_RECOVERY_COMMITMENT_TYPEHASH,
                block.chainid,
                address(this),
                accountId,
                epoch,
                nonce,
                recoveryCommitment,
                deadline
            )
        );
    }

    function registerHomeserverDigest(
        bytes32 homeserverId,
        bytes32 genesisNonce,
        bytes32 signingKey,
        string calldata endpoint,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                REGISTER_HOMESERVER_TYPEHASH,
                block.chainid,
                address(this),
                homeserverId,
                genesisNonce,
                signingKey,
                keccak256(bytes(endpoint)),
                deadline
            )
        );
    }

    function setHomeserverEndpointDigest(
        bytes32 homeserverId,
        uint64 epoch,
        uint64 nonce,
        string calldata endpoint,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                SET_HOMESERVER_ENDPOINT_TYPEHASH,
                block.chainid,
                address(this),
                homeserverId,
                epoch,
                nonce,
                keccak256(bytes(endpoint)),
                deadline
            )
        );
    }

    function rotateHomeserverKeyDigest(
        bytes32 homeserverId,
        uint64 epoch,
        uint64 nonce,
        bytes32 newSigningKey,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                ROTATE_HOMESERVER_KEY_TYPEHASH,
                block.chainid,
                address(this),
                homeserverId,
                epoch,
                nonce,
                newSigningKey,
                deadline
            )
        );
    }

    function _advance(Account storage account) private returns (uint64 nextEpoch) {
        account.nonce += 1;
        account.epoch += 1;
        return account.epoch;
    }

    function _advance(Homeserver storage homeserver) private returns (uint64 nextEpoch) {
        homeserver.nonce += 1;
        homeserver.epoch += 1;
        return homeserver.epoch;
    }

    function _isValidSignature(bytes32 publicKey, bytes32 digest, bytes calldata signature)
        private
        view
        returns (bool)
    {
        if (signature.length != 64) return false;
        try ed25519Verifier.verify(publicKey, digest, signature) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }

    function _requireAccountState(bytes32 accountId, uint64 epoch, uint64 nonce, uint64 deadline)
        private
        view
        returns (Account storage account)
    {
        _requireLiveDeadline(deadline);
        account = accounts[accountId];
        if (!account.exists) revert AccountNotFound(accountId);
        if (epoch != account.epoch) revert InvalidEpoch(epoch, account.epoch);
        if (nonce != account.nonce) revert InvalidNonce(nonce, account.nonce);
    }

    function _requireApprovals(
        bytes32 accountId,
        uint8 threshold,
        bytes32 digest,
        Approval[] calldata approvals
    ) private view {
        if (approvals.length != threshold) {
            revert InvalidApprovalCount(approvals.length, threshold);
        }

        for (uint256 i = 0; i < approvals.length; i++) {
            bytes32 deviceKey = approvals[i].deviceKey;
            if (!devices[accountId][deviceKey].active) revert DeviceNotActive(deviceKey);
            for (uint256 j = 0; j < i; j++) {
                if (approvals[j].deviceKey == deviceKey) revert DuplicateApproval(deviceKey);
            }
            _requireSignature(deviceKey, digest, approvals[i].signature);
        }
    }

    function _requireHomeserverState(
        bytes32 homeserverId,
        uint64 epoch,
        uint64 nonce,
        uint64 deadline
    ) private view returns (Homeserver storage homeserver) {
        _requireLiveDeadline(deadline);
        homeserver = homeservers[homeserverId];
        if (!homeserver.active) revert HomeserverNotFound(homeserverId);
        if (epoch != homeserver.epoch) revert InvalidEpoch(epoch, homeserver.epoch);
        if (nonce != homeserver.nonce) revert InvalidNonce(nonce, homeserver.nonce);
    }

    function _requireLiveDeadline(uint64 deadline) private view {
        if (block.timestamp > deadline) revert ActionExpired(deadline);
    }

    function _requireSignature(bytes32 publicKey, bytes32 digest, bytes calldata signature)
        private
        view
    {
        if (signature.length != 64) revert InvalidSignatureLength();
        if (!_isValidSignature(publicKey, digest, signature)) revert InvalidSignature(publicKey);
    }

    function _requireValidEndpoint(string calldata endpoint) private pure {
        bytes calldata value = bytes(endpoint);
        if (value.length < 9 || value.length > 255) revert InvalidEndpoint();
        bytes8 prefix;
        assembly ("memory-safe") {
            prefix := calldataload(value.offset)
        }
        if (prefix != bytes8("https://")) revert InvalidEndpoint();
        if (value[8] == 0x2f) revert InvalidEndpoint();
        for (uint256 index = 8; index < value.length; index++) {
            bytes1 character = value[index];
            if (
                character == 0x3f || character == 0x23 || character == 0x40 || character == 0x5c
                    || uint8(character) <= 0x20 || uint8(character) >= 0x7f
                    || (character == 0x2f && index != value.length - 1)
            ) {
                revert InvalidEndpoint();
            }
        }
    }
}

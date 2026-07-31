// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { VexRegistry } from "../src/VexRegistry.sol";
import { DeterministicTestVerifier } from "./helpers/DeterministicTestVerifier.sol";

contract VexRegistryTest {
    uint64 private constant DEADLINE = type(uint64).max;

    DeterministicTestVerifier private verifier;
    VexRegistry private registry;

    bytes32 private serverKey = bytes32(uint256(101));
    bytes32 private serverNonce = bytes32(uint256(102));
    bytes32 private serverId;

    function setUp() public {
        verifier = new DeterministicTestVerifier();
        registry = new VexRegistry(verifier);
        serverId = registry.deriveHomeserverId(serverNonce, serverKey);
        bytes32 digest = registry.registerHomeserverDigest(
            serverId, serverNonce, serverKey, "https://one.example", DEADLINE
        );
        registry.registerHomeserver(
            serverId,
            serverNonce,
            serverKey,
            "https://one.example",
            DEADLINE,
            _signature(serverKey, digest)
        );
    }

    function testRegisterAccountAndAddDevice() public {
        (bytes32 accountId, bytes32 genesisNonce, bytes32 firstDevice) = _registerAccount();
        _assertEq(
            accountId, registry.deriveAccountId(genesisNonce, firstDevice), "derived account id"
        );

        VexRegistry.Account memory account = registry.getAccount(accountId);
        _assertEq(account.activeDeviceCount, 1, "initial device count");
        _assertEq(account.deviceThreshold, 1, "initial threshold");
        _assertTrue(registry.isDeviceActive(accountId, firstDevice), "first device active");

        bytes32 secondDevice = bytes32(uint256(203));
        bytes32 digest = registry.addDeviceDigest(
            accountId, account.epoch, account.nonce, secondDevice, DEADLINE
        );
        registry.addDevice(
            accountId,
            account.epoch,
            account.nonce,
            secondDevice,
            DEADLINE,
            _approvals(firstDevice, _signature(firstDevice, digest)),
            _signature(secondDevice, digest)
        );

        account = registry.getAccount(accountId);
        _assertEq(account.activeDeviceCount, 2, "device count after add");
        _assertEq(account.epoch, 2, "epoch after add");
        _assertEq(account.nonce, 1, "nonce after add");
        _assertTrue(registry.isDeviceActive(accountId, secondDevice), "second device active");
    }

    function testRejectsAccountIdNotBoundToGenesisDevice() public {
        bytes32 genesisNonce = bytes32(uint256(301));
        bytes32 firstDevice = bytes32(uint256(302));
        bytes32 wrongAccountId = bytes32(uint256(303));
        bytes32 digest = registry.registerAccountDigest(
            wrongAccountId, genesisNonce, firstDevice, serverId, bytes32(0), DEADLINE
        );
        (bool ok,) = address(registry).call(
            abi.encodeCall(
                VexRegistry.registerAccount,
                (
                    wrongAccountId,
                    genesisNonce,
                    firstDevice,
                    serverId,
                    bytes32(0),
                    DEADLINE,
                    _signature(firstDevice, digest)
                )
            )
        );
        _assertFalse(ok, "mismatched account id accepted");
    }

    function testRejectsAddDeviceReplay() public {
        (bytes32 accountId,, bytes32 firstDevice) = _registerAccount();
        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 secondDevice = bytes32(uint256(402));
        bytes32 digest = registry.addDeviceDigest(
            accountId, account.epoch, account.nonce, secondDevice, DEADLINE
        );
        VexRegistry.Approval[] memory approvals =
            _approvals(firstDevice, _signature(firstDevice, digest));
        bytes memory proof = _signature(secondDevice, digest);
        registry.addDevice(
            accountId, account.epoch, account.nonce, secondDevice, DEADLINE, approvals, proof
        );

        (bool ok,) = address(registry).call(
            abi.encodeCall(
                VexRegistry.addDevice,
                (
                    accountId,
                    account.epoch,
                    account.nonce,
                    bytes32(uint256(403)),
                    DEADLINE,
                    approvals,
                    proof
                )
            )
        );
        _assertFalse(ok, "replayed nonce accepted");
    }

    function testThresholdRequiresDistinctActiveDevices() public {
        (bytes32 accountId,, bytes32 firstDevice) = _registerAccount();
        bytes32 secondDevice = bytes32(uint256(502));
        _addDevice(accountId, firstDevice, secondDevice);

        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 thresholdDigest =
            registry.setDeviceThresholdDigest(accountId, account.epoch, account.nonce, 2, DEADLINE);
        registry.setDeviceThreshold(
            accountId,
            account.epoch,
            account.nonce,
            2,
            DEADLINE,
            _approvals(firstDevice, _signature(firstDevice, thresholdDigest))
        );

        account = registry.getAccount(accountId);
        bytes32 thirdDevice = bytes32(uint256(503));
        bytes32 addDigest =
            registry.addDeviceDigest(accountId, account.epoch, account.nonce, thirdDevice, DEADLINE);
        VexRegistry.Approval[] memory approvals = new VexRegistry.Approval[](2);
        approvals[0] = VexRegistry.Approval({
            deviceKey: firstDevice,
            signature: _signature(firstDevice, addDigest)
        });
        approvals[1] = VexRegistry.Approval({
            deviceKey: secondDevice,
            signature: _signature(secondDevice, addDigest)
        });
        registry.addDevice(
            accountId,
            account.epoch,
            account.nonce,
            thirdDevice,
            DEADLINE,
            approvals,
            _signature(thirdDevice, addDigest)
        );
        _assertTrue(registry.isDeviceActive(accountId, thirdDevice), "threshold add failed");
    }

    function testRevokedDeviceCannotAuthorize() public {
        (bytes32 accountId,, bytes32 firstDevice) = _registerAccount();
        bytes32 secondDevice = bytes32(uint256(602));
        _addDevice(accountId, firstDevice, secondDevice);

        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 revokeDigest = registry.revokeDeviceDigest(
            accountId, account.epoch, account.nonce, firstDevice, DEADLINE
        );
        registry.revokeDevice(
            accountId,
            account.epoch,
            account.nonce,
            firstDevice,
            DEADLINE,
            _approvals(secondDevice, _signature(secondDevice, revokeDigest))
        );
        _assertFalse(registry.isDeviceActive(accountId, firstDevice), "device remains active");

        account = registry.getAccount(accountId);
        bytes32 thirdDevice = bytes32(uint256(603));
        bytes32 addDigest =
            registry.addDeviceDigest(accountId, account.epoch, account.nonce, thirdDevice, DEADLINE);
        (bool ok,) = address(registry).call(
            abi.encodeCall(
                VexRegistry.addDevice,
                (
                    accountId,
                    account.epoch,
                    account.nonce,
                    thirdDevice,
                    DEADLINE,
                    _approvals(firstDevice, _signature(firstDevice, addDigest)),
                    _signature(thirdDevice, addDigest)
                )
            )
        );
        _assertFalse(ok, "revoked device authorized mutation");
    }

    function testRevokedDeviceKeyCannotBeReadded() public {
        (bytes32 accountId,, bytes32 firstDevice) = _registerAccount();
        bytes32 secondDevice = bytes32(uint256(652));
        _addDevice(accountId, firstDevice, secondDevice);

        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 revokeDigest = registry.revokeDeviceDigest(
            accountId, account.epoch, account.nonce, secondDevice, DEADLINE
        );
        registry.revokeDevice(
            accountId,
            account.epoch,
            account.nonce,
            secondDevice,
            DEADLINE,
            _approvals(firstDevice, _signature(firstDevice, revokeDigest))
        );

        account = registry.getAccount(accountId);
        bytes32 addDigest = registry.addDeviceDigest(
            accountId, account.epoch, account.nonce, secondDevice, DEADLINE
        );
        (bool ok,) = address(registry).call(
            abi.encodeCall(
                VexRegistry.addDevice,
                (
                    accountId,
                    account.epoch,
                    account.nonce,
                    secondDevice,
                    DEADLINE,
                    _approvals(firstDevice, _signature(firstDevice, addDigest)),
                    _signature(secondDevice, addDigest)
                )
            )
        );
        _assertFalse(ok, "revoked device key was re-added");
    }

    function testMigratesHomeserverWithDeviceApproval() public {
        (bytes32 accountId,, bytes32 firstDevice) = _registerAccount();
        bytes32 secondServerId;
        {
            bytes32 secondServerKey = bytes32(uint256(701));
            bytes32 secondServerNonce = bytes32(uint256(702));
            secondServerId = registry.deriveHomeserverId(secondServerNonce, secondServerKey);
            bytes32 registrationDigest = registry.registerHomeserverDigest(
                secondServerId, secondServerNonce, secondServerKey, "https://two.example", DEADLINE
            );
            registry.registerHomeserver(
                secondServerId,
                secondServerNonce,
                secondServerKey,
                "https://two.example",
                DEADLINE,
                _signature(secondServerKey, registrationDigest)
            );
        }

        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 digest = registry.setHomeserverDigest(
            accountId, account.epoch, account.nonce, secondServerId, DEADLINE
        );
        VexRegistry.Approval[] memory approvals =
            _approvals(firstDevice, _signature(firstDevice, digest));
        registry.setHomeserver(
            accountId, account.epoch, account.nonce, secondServerId, DEADLINE, approvals
        );
        _assertEq(
            registry.getAccount(accountId).homeserverId, secondServerId, "homeserver did not change"
        );
    }

    function testRejectsNonOriginHomeserverEndpoints() public {
        _assertFalse(
            _tryRegisterHomeserver("https:///", bytes32(uint256(709)), bytes32(uint256(710))),
            "empty authority accepted"
        );
        _assertFalse(
            _tryRegisterHomeserver(
                "https://user@example.com", bytes32(uint256(711)), bytes32(uint256(712))
            ),
            "userinfo endpoint accepted"
        );
        _assertFalse(
            _tryRegisterHomeserver(
                "https://two.example/federation", bytes32(uint256(713)), bytes32(uint256(714))
            ),
            "path endpoint accepted"
        );
        _assertFalse(
            _tryRegisterHomeserver(
                "https://two.example?key=value", bytes32(uint256(715)), bytes32(uint256(716))
            ),
            "query endpoint accepted"
        );
        _assertFalse(
            _tryRegisterHomeserver(
                "https://two.example#fragment", bytes32(uint256(717)), bytes32(uint256(718))
            ),
            "fragment endpoint accepted"
        );
        _assertFalse(
            _tryRegisterHomeserver(
                "https://two.example\n", bytes32(uint256(719)), bytes32(uint256(720))
            ),
            "whitespace endpoint accepted"
        );
        _assertFalse(
            _tryRegisterHomeserver(
                "https://two.example\\path", bytes32(uint256(723)), bytes32(uint256(724))
            ),
            "backslash endpoint accepted"
        );
        _assertTrue(
            _tryRegisterHomeserver(
                "https://two.example/", bytes32(uint256(721)), bytes32(uint256(722))
            ),
            "bare origin with trailing slash rejected"
        );
    }

    function testFuzzAccountIdChangesWithNonce(bytes32 nonceA, bytes32 nonceB) public view {
        if (nonceA == bytes32(0) || nonceB == bytes32(0) || nonceA == nonceB) return;
        bytes32 key = bytes32(uint256(801));
        bytes32 accountA = registry.deriveAccountId(nonceA, key);
        bytes32 accountB = registry.deriveAccountId(nonceB, key);
        _assertTrue(accountA != accountB, "nonce did not separate account ids");
    }

    function _addDevice(bytes32 accountId, bytes32 approver, bytes32 newDevice) private {
        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 digest =
            registry.addDeviceDigest(accountId, account.epoch, account.nonce, newDevice, DEADLINE);
        registry.addDevice(
            accountId,
            account.epoch,
            account.nonce,
            newDevice,
            DEADLINE,
            _approvals(approver, _signature(approver, digest)),
            _signature(newDevice, digest)
        );
    }

    function _approvals(bytes32 deviceKey, bytes memory signature)
        private
        pure
        returns (VexRegistry.Approval[] memory approvals)
    {
        approvals = new VexRegistry.Approval[](1);
        approvals[0] = VexRegistry.Approval({ deviceKey: deviceKey, signature: signature });
    }

    function _tryRegisterHomeserver(string memory endpoint, bytes32 key, bytes32 nonce)
        private
        returns (bool)
    {
        bytes32 id = registry.deriveHomeserverId(nonce, key);
        bytes32 digest = registry.registerHomeserverDigest(id, nonce, key, endpoint, DEADLINE);
        (bool ok,) = address(registry).call(
            abi.encodeCall(
                VexRegistry.registerHomeserver,
                (id, nonce, key, endpoint, DEADLINE, _signature(key, digest))
            )
        );
        return ok;
    }

    function _registerAccount()
        private
        returns (bytes32 accountId, bytes32 genesisNonce, bytes32 firstDevice)
    {
        genesisNonce = bytes32(uint256(201));
        firstDevice = bytes32(uint256(202));
        accountId = registry.deriveAccountId(genesisNonce, firstDevice);
        bytes32 digest = registry.registerAccountDigest(
            accountId, genesisNonce, firstDevice, serverId, bytes32(0), DEADLINE
        );
        registry.registerAccount(
            accountId,
            genesisNonce,
            firstDevice,
            serverId,
            bytes32(0),
            DEADLINE,
            _signature(firstDevice, digest)
        );
    }

    function _signature(bytes32 publicKey, bytes32 digest) private pure returns (bytes memory) {
        bytes32 proof = keccak256(abi.encode(publicKey, digest));
        return abi.encodePacked(proof, ~proof);
    }

    function _assertEq(bytes32 actual, bytes32 expected, string memory reason) private pure {
        require(actual == expected, reason);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory reason) private pure {
        require(actual == expected, reason);
    }

    function _assertFalse(bool value, string memory reason) private pure {
        require(!value, reason);
    }

    function _assertTrue(bool value, string memory reason) private pure {
        require(value, reason);
    }
}

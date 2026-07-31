// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2020-2026 Vex Heavy Industries LLC

pragma solidity 0.8.28;

import { IERC20 } from "../src/IERC20.sol";
import { VexNameRegistrar } from "../src/VexNameRegistrar.sol";
import { VexRegistry } from "../src/VexRegistry.sol";
import { DeterministicTestVerifier } from "./helpers/DeterministicTestVerifier.sol";

contract TestToken is IERC20 {
    mapping(address account => uint256 balance) public balanceOf;
    mapping(address owner => mapping(address spender => uint256 amount)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] < amount || balanceOf[from] < amount) return false;
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract VexNameRegistrarTest {
    uint64 private constant DEADLINE = type(uint64).max;
    uint256 private constant FEE = 20_000_000;

    bytes32 private accountId;
    bytes32 private deviceKey = bytes32(uint256(202));
    address private feeRecipient = address(0xfee);
    VexNameRegistrar private registrar;
    VexRegistry private registry;
    TestToken private token;

    function setUp() public {
        DeterministicTestVerifier verifier = new DeterministicTestVerifier();
        registry = new VexRegistry(verifier);
        token = new TestToken();
        registrar = new VexNameRegistrar(registry, token, feeRecipient, FEE, 0, 1 days);

        bytes32 serverKey = bytes32(uint256(101));
        bytes32 serverNonce = bytes32(uint256(102));
        bytes32 serverId = registry.deriveHomeserverId(serverNonce, serverKey);
        bytes32 serverDigest = registry.registerHomeserverDigest(
            serverId, serverNonce, serverKey, "https://one.example", DEADLINE
        );
        registry.registerHomeserver(
            serverId,
            serverNonce,
            serverKey,
            "https://one.example",
            DEADLINE,
            _signature(serverKey, serverDigest)
        );

        bytes32 accountNonce = bytes32(uint256(201));
        accountId = registry.deriveAccountId(accountNonce, deviceKey);
        bytes32 accountDigest = registry.registerAccountDigest(
            accountId, accountNonce, deviceKey, serverId, bytes32(0), DEADLINE
        );
        registry.registerAccount(
            accountId,
            accountNonce,
            deviceKey,
            serverId,
            bytes32(0),
            DEADLINE,
            _signature(deviceKey, accountDigest)
        );

        token.mint(address(this), FEE * 2);
        token.approve(address(registrar), type(uint256).max);
    }

    function testRegistersPaidNameWithDeviceApproval() public {
        _register("computer", bytes32(uint256(301)));

        bytes32 nameHash = registrar.hashName("computer");
        _assertEq(registrar.accountByNameHash(nameHash), accountId, "name resolution");
        _assertEq(registrar.nameByAccount(accountId), "computer", "reverse resolution");
        _assertEq(token.balanceOf(feeRecipient), FEE, "fee transfer");
        _assertEq(registrar.nonces(accountId), 1, "registrar nonce");
    }

    function testRejectsInvalidNames() public view {
        (bool uppercase,) =
            address(registrar).staticcall(abi.encodeCall(VexNameRegistrar.hashName, ("Computer")));
        (bool punctuation,) =
            address(registrar).staticcall(abi.encodeCall(VexNameRegistrar.hashName, ("comp.uter")));
        (bool tooShort,) =
            address(registrar).staticcall(abi.encodeCall(VexNameRegistrar.hashName, ("ab")));
        _assertFalse(uppercase, "uppercase name accepted");
        _assertFalse(punctuation, "punctuated name accepted");
        _assertFalse(tooShort, "short name accepted");
    }

    function testCommitmentIsBoundToPayer() public {
        bytes32 salt = bytes32(uint256(401));
        bytes32 nameHash = registrar.hashName("computer");
        registrar.commit(registrar.commitmentFor(accountId, nameHash, salt, address(this)));

        NameRegistrationCaller caller = new NameRegistrationCaller();
        (bool ok,) = address(caller).call(
            abi.encodeCall(
                NameRegistrationCaller.register,
                (registrar, "computer", accountId, salt, uint64(1), DEADLINE, _approvals(bytes("")))
            )
        );
        _assertFalse(ok, "another payer revealed the commitment");
    }

    function testRejectsReplayedNameApproval() public {
        _register("computer", bytes32(uint256(501)));

        bytes32 salt = bytes32(uint256(502));
        bytes32 nameHash = registrar.hashName("another");
        bytes32 commitment = registrar.commitmentFor(accountId, nameHash, salt, address(this));
        registrar.commit(commitment);
        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 staleDigest =
            registrar.registrationDigest(accountId, account.epoch, 0, nameHash, DEADLINE);
        (bool ok,) = address(registrar).call(
            abi.encodeCall(
                VexNameRegistrar.register,
                (
                    "another",
                    accountId,
                    salt,
                    account.epoch,
                    DEADLINE,
                    _approvals(_signature(deviceKey, staleDigest))
                )
            )
        );
        _assertFalse(ok, "account registered a second name with replayed nonce");
    }

    function _register(string memory username, bytes32 salt) private {
        bytes32 nameHash = registrar.hashName(username);
        bytes32 commitment = registrar.commitmentFor(accountId, nameHash, salt, address(this));
        registrar.commit(commitment);
        VexRegistry.Account memory account = registry.getAccount(accountId);
        bytes32 digest = registrar.registrationDigest(
            accountId, account.epoch, registrar.nonces(accountId), nameHash, DEADLINE
        );
        registrar.register(
            username,
            accountId,
            salt,
            account.epoch,
            DEADLINE,
            _approvals(_signature(deviceKey, digest))
        );
    }

    function _approvals(bytes memory signature)
        private
        view
        returns (VexRegistry.Approval[] memory approvals)
    {
        approvals = new VexRegistry.Approval[](1);
        approvals[0] = VexRegistry.Approval({ deviceKey: deviceKey, signature: signature });
    }

    function _signature(bytes32 publicKey, bytes32 digest) private pure returns (bytes memory) {
        bytes32 proof = keccak256(abi.encode(publicKey, digest));
        return abi.encodePacked(proof, ~proof);
    }

    function _assertEq(bytes32 actual, bytes32 expected, string memory reason) private pure {
        require(actual == expected, reason);
    }

    function _assertEq(string memory actual, string memory expected, string memory reason)
        private
        pure
    {
        require(keccak256(bytes(actual)) == keccak256(bytes(expected)), reason);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory reason) private pure {
        require(actual == expected, reason);
    }

    function _assertFalse(bool value, string memory reason) private pure {
        require(!value, reason);
    }
}

contract NameRegistrationCaller {
    function register(
        VexNameRegistrar registrar,
        string calldata username,
        bytes32 accountId,
        bytes32 salt,
        uint64 registryEpoch,
        uint64 deadline,
        VexRegistry.Approval[] calldata approvals
    ) external {
        registrar.register(username, accountId, salt, registryEpoch, deadline, approvals);
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {IInterchainSecurityModule} from "../../contracts/interfaces/IInterchainSecurityModule.sol";
import {OptimisticISM} from "../../contracts/isms/optimistic/OptimisticRoutingISM.sol";

import {TestIsm} from "./IsmTestUtils.sol";

contract OptimisticISMTest is Test {
    OptimisticISM ism;
    uint16 maxNumberOfFlags = 2;
    address watcher_1 = vm.addr(0x1);
    address watcher_2 = vm.addr(0x2);
    address submodule = address(0x123);
    bytes message = "optimistic";
    bytes metadata = "{key:value}";

    function setUp() public {
        ism = new OptimisticISM();
        ism.initialize(address(this), maxNumberOfFlags);
    }

    function deployTestIsm(bytes calldata requiredMetadata)
        internal
        returns (TestIsm)
    {
        return new TestIsm(abi.encode(requiredMetadata));
    }

    function testSubmodule() public {
        ism.setSubmodule(message, submodule);
        IInterchainSecurityModule submoduleContract = ism.submodule(message);
        assertEq(address(submoduleContract), submodule);
    }

    function testSetWatchers() public {
        ism.setWatchers(watcher_1);
        ism.setWatchers(watcher_2);
        assertEq(ism.watchers(watcher_1), true);
        assertEq(ism.watchers(watcher_2), true);
    }

    function testFail_TimeToMarkElapsed_MarkFraudulent() public {
        ism.setWatchers(watcher_1);
        ism.setWatchers(watcher_2);
        ism.setSubmodule(message, submodule);
        IInterchainSecurityModule submoduleContract = ism.submodule(message);
        vm.prank(watcher_1);
        ism.markFraudulent(address(submoduleContract));
        vm.prank(watcher_2);
        ism.markFraudulent(address(submoduleContract));
        vm.expectRevert("Time to mark fraudulent has elapsed");
    }

    function testMarkFraudulent() public {
        vm.roll(100);
        ism.setFraudulentTime(200);
        ism.setWatchers(watcher_1);
        ism.setWatchers(watcher_2);
        ism.setSubmodule(message, submodule);
        IInterchainSecurityModule submoduleContract = ism.submodule(message);
        vm.prank(watcher_1);
        ism.markFraudulent(address(submoduleContract));
        vm.prank(watcher_2);
        ism.markFraudulent(address(submoduleContract));
        assertEq(ism.fraudulentSubModules(address(submoduleContract)), 2);
    }

    function testPreVerify(bytes calldata _message) public {
        vm.roll(100);
        ism.setFraudulentTime(200);
        ism.setWatchers(watcher_1);
        ism.setWatchers(watcher_2);
        address testISM = address(deployTestIsm(_message));
        ism.setSubmodule(message, testISM);
        IInterchainSecurityModule submoduleContract = ism.submodule(message);
        vm.prank(watcher_1);
        ism.markFraudulent(address(submoduleContract));
        vm.prank(watcher_2);
        ism.markFraudulent(address(submoduleContract));
        ism.preVerify(metadata, message);
    }
}

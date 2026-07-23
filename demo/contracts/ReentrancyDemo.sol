// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReentrancyDemo
 * @dev Classic reentrancy vulnerability in withdraw.
 */
contract ReentrancyDemo {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No funds");

        // External call before state update - reentrancy possible
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "ETH transfer failed");

        balances[msg.sender] = 0; // State update AFTER external call
    }

    // Helper to check contract balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
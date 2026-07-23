// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MysteryLogic
 * @dev Intentionally complex contract with subtle fee calculation bug.
 * The fee calculation may lead to rounding errors and incorrect balances.
 */
contract MysteryLogic {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @dev Transfer with a fee: fee = (amount / 100) * 2
     * Problem: integer division truncates, leading to under-collection of fees.
     * Example: amount = 199 => amount/100 = 1, fee = 2, but actual 2% of 199 = 3.98 → should be 4.
     * Also, balances are updated with subtraction before checking sufficient funds.
     */
    function transferWithFee(address to, uint256 amount) public {
        require(amount > 0, "Amount must be >0");
        uint256 fee = (amount / 100) * 2; // floor division, not exact 2%
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        balances[to] += amount - fee;
        balances[address(this)] += fee; // fees accumulate in contract
    }

    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
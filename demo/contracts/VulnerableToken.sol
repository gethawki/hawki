// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableToken
 * @dev ERC20-like token with integer overflow/underflow and unchecked transfer.
 * Vulnerabilities:
 *   - Integer overflow in mint() (though Solidity 0.8+ has built-in checks, 
 *     we simulate by using unchecked block)
 *   - Unchecked return value in transfer (no require)
 */
contract VulnerableToken {
    mapping(address => uint256) public balanceOf;

    function mint(uint256 amount) public {
        // Unsafe addition - but in 0.8.x it would revert automatically.
        // To demonstrate overflow, we use unchecked.
        unchecked {
            balanceOf[msg.sender] += amount;
        }
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        // No check for underflow (balanceOf[msg.sender] < amount)
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
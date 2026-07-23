// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DelegateCallExample
 * @dev Uses delegatecall on an arbitrary address - dangerous.
 */
contract DelegateCallExample {
    address public target;
    uint256 public storedData;

    function execute(address _target, bytes memory data) public {
        target = _target;
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}
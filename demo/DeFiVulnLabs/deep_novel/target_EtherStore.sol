// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// EtherStore: a simple ether vault, reproduced from SunWeb3Sec/DeFiVulnLabs
// (a corpus of real, documented on-chain exploit patterns). withdrawFunds sends
// ether to the caller BEFORE decrementing their balance, so a reentrant caller
// can withdraw repeatedly. Authorized security-test target for the deep agent.
contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        (bool ok, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(ok, "send failed");
        if (balances[msg.sender] >= _weiToWithdraw) {
            balances[msg.sender] -= _weiToWithdraw;
        }
    }
}

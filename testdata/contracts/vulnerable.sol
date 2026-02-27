// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// This contract contains intentional vulnerabilities for testing solsec.
// DO NOT DEPLOY.
contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
        balances[msg.sender] = 1000000;
    }

    // VULNERABILITY 1: No access control on mint
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }

    // VULNERABILITY 2: Reentrancy — state change after external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // state change AFTER call
    }

    // VULNERABILITY 3: tx.origin authentication
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}
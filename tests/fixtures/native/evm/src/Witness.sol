// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Intentionally vulnerable toy fixture. NEVER deploy; not a bounty finding.
contract Witness {
    mapping(address => uint256) public credit;
    mapping(address => uint256) public protectedCredit;

    function issue(uint256 amount) external {
        credit[msg.sender] += amount;
        protectedCredit[msg.sender] += amount;
    }

    function unsafeClaim(uint256 amount) external {
        require(credit[msg.sender] >= amount, "not enough");
        // No decrement. This invariant is violated on replay.
    }

    function safeClaim(uint256 amount) external {
        require(protectedCredit[msg.sender] >= amount, "not enough");
        protectedCredit[msg.sender] -= amount;
    }
}

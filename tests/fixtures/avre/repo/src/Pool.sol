// Synthetic source fixture. The lexical signals below are not a vulnerable program claim.
pragma solidity ^0.8.20;

contract Pool {
    mapping(address => uint256) public shares;
    mapping(bytes32 => bool) public processed;
    uint256 public totalShares;
    uint256 public claimed;

    function deposit(uint256 amount) external {
        shares[msg.sender] += amount;
        totalShares += amount;
    }

    function withdraw(uint256 amount) external {
        shares[msg.sender] -= amount;
        totalShares -= amount;
    }

    function claim() external {
        uint256 snapshot = totalShares;
        claimed += snapshot;
    }

    function retry(bytes32 id) external {
        if (!processed[id]) {
            processed[id] = true;
        }
    }
}

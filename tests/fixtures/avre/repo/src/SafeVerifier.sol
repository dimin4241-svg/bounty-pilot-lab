// Negative lexical control: the relevant binding tokens are visible in the same source file.
pragma solidity ^0.8.20;

contract SafeVerifier {
    uint256 public nonce;

    function execute(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view returns (address) {
        bytes32 DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this)));
        require(nonce == 0, "consumed");
        require(digest == DOMAIN_SEPARATOR, "domain");
        address signer = ecrecover(digest, v, r, s);
        require(signer == msg.sender, "account");
        return signer;
    }
}

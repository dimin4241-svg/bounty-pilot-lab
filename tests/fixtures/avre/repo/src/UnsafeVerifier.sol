// Positive lexical lead fixture only; no claim that this is exploitable.
pragma solidity ^0.8.20;

contract UnsafeVerifier {
    function execute(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(digest, v, r, s);
    }
}

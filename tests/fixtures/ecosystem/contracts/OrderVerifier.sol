contract OrderVerifier {
    uint256 public treasury;
    function verifyOrder(bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        external pure returns (address)
    {
        return ecrecover(digest, v, r, s);
    }
}

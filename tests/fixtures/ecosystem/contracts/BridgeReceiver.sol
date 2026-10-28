contract BridgeReceiver {
    function relayMessage(bytes calldata payload) external {
        process(payload);
    }
}

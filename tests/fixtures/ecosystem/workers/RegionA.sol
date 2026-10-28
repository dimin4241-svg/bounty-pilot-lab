contract RegionA {
    mapping(bytes32 => bool) internal jobs;
    uint256 internal policyVersion;
    function authorizeJob(bytes32 id) external onlyRole(EXECUTOR_ROLE) {
        require(policyVersion >= 2);
        jobs[id] = true;
    }
}

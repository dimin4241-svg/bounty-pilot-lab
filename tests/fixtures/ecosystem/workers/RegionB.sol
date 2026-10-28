contract RegionB {
    mapping(bytes32 => bool) internal jobs;
    uint256 internal policyVersion;
    function authorizeJob(bytes32 id) external {
        jobs[id] = true;
    }
}

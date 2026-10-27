contract AccountLifecycle {
    mapping(bytes32 => address) internal tenantOwner;
    mapping(bytes32 => bool) internal deviceSessions;
    mapping(bytes32 => bool) internal jobs;
    mapping(bytes32 => bool) internal revokedAt;

    function createTenant(bytes32 id, address owner) external onlyAdmin {
        tenantOwner[id] = owner;
    }

    function restoreTenant(bytes32 id, address owner) external {
        tenantOwner[id] = owner;
    }

    function revokeDevice(bytes32 id) external onlyAdmin {
        deviceSessions[id] = false;
        revokedAt[id] = true;
    }

    function reconnectDevice(bytes32 id) external {
        deviceSessions[id] = true;
    }

    function deleteJob(bytes32 id) external onlyAdmin {
        jobs[id] = false;
    }

    function processJob(bytes32 id) external {
        jobs[id] = true;
    }
}

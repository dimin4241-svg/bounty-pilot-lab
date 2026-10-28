contract Admin {
    function configure() external onlyRole(DEFAULT_ADMIN_ROLE) {}
}

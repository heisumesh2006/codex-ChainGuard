// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IAgentRegistry {
    function rootAuthorizer() external view returns (address);
    function agentAddresses(bytes32 agentHash) external view returns (address);
    function agentRevoked(bytes32 agentHash) external view returns (bool);
    function getRevocationDetails(bytes32 agentHash) external view returns (
        string memory, string memory, string[] memory, bytes32, bytes32, uint64);
}

/// @notice Optional local-tested, grant-specific authority extension.
/// No existing public deployment is replaced or automatically upgraded.
contract GrantAuthority {
    struct Grant {
        bytes32 holder;
        bytes32 scope;
        bytes32 parent;
        uint64 issuedAt;
        uint64 expiresAt;
        uint64 revokedAt;
        bool exists;
    }
    IAgentRegistry public immutable registry;
    address public immutable rootAuthorizer;
    mapping(bytes32 => Grant) public grants;
    event GrantIssued(bytes32 indexed grantId, bytes32 indexed holder, bytes32 indexed scope, bytes32 parent, uint64 expiresAt);
    event GrantRevoked(bytes32 indexed grantId, uint64 revokedAt);

    modifier onlyRoot() { require(msg.sender == rootAuthorizer, "ROOT_ONLY"); _; }

    constructor(address registryAddress) {
        registry = IAgentRegistry(registryAddress);
        rootAuthorizer = registry.rootAuthorizer();
        require(msg.sender == rootAuthorizer, "ROOT_ONLY");
    }

    function issueGrant(bytes32 id, bytes32 holder, bytes32 scope, bytes32 parent, uint64 expiresAt) external onlyRoot {
        require(id != bytes32(0) && !grants[id].exists, "GRANT_EXISTS_OR_INVALID");
        require(scope != bytes32(0) && registry.agentAddresses(holder) != address(0), "INVALID_HOLDER_OR_SCOPE");
        require(!registry.agentRevoked(holder) && expiresAt > block.timestamp, "HOLDER_REVOKED_OR_EXPIRED");
        if (parent != bytes32(0)) {
            require(isValidNow(parent), "INVALID_PARENT");
            require(grants[parent].scope == scope && expiresAt <= grants[parent].expiresAt, "SCOPE_OR_EXPIRY_ESCALATION");
            bytes32 cursor = parent;
            for (uint256 depth; cursor != bytes32(0); depth++) {
                require(depth < 31, "MAX_DEPTH");
                require(grants[cursor].holder != holder, "SELF_OR_CYCLIC_DELEGATION");
                cursor = grants[cursor].parent;
            }
        }
        grants[id] = Grant(holder, scope, parent, uint64(block.timestamp), expiresAt, 0, true);
        emit GrantIssued(id, holder, scope, parent, expiresAt);
    }

    function revokeGrant(bytes32 id) external onlyRoot {
        require(grants[id].exists, "GRANT_NOT_FOUND");
        if (grants[id].revokedAt == 0) {
            grants[id].revokedAt = uint64(block.timestamp);
            emit GrantRevoked(id, uint64(block.timestamp));
        }
    }

    function isValidNow(bytes32 id) public view returns (bool) {
        return wasValidAt(id, uint64(block.timestamp));
    }

    function wasValidAt(bytes32 id, uint64 when) public view returns (bool) {
        if (id == bytes32(0)) return false;
        bytes32 cursor = id;
        for (uint256 depth; cursor != bytes32(0); depth++) {
            if (depth >= 32) return false;
            Grant storage grant = grants[cursor];
            if (!grant.exists || when < grant.issuedAt || when >= grant.expiresAt
                    || (grant.revokedAt != 0 && when >= grant.revokedAt)) return false;
            if (registry.agentRevoked(grant.holder)) {
                (,,,,, uint64 revokedAt) = registry.getRevocationDetails(grant.holder);
                if (when >= revokedAt) return false;
            }
            cursor = grant.parent;
        }
        return true;
    }
}

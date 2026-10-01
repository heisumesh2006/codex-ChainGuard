// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Compact commitments for agent identity, scoped credentials and audit events.
/// Full readable JSON remains off-chain. Record IDs are domain-separated
/// SHA-256 commitments to kind + content hash, allowing one decommission event
/// to be anchored as both a revocation and an action-log commitment.
contract AgentTrustRegistry {
    address public immutable rootAuthorizer;

    // 1 credential, 2 delegation, 3 revocation, 4 action hash.
    struct Commitment {
        bytes32 contentHash;
        uint8 kind;
        uint64 anchoredAt;
    }

    struct Credential {
        bytes32 agentHash;
        address agentAddress;
        address issuer;
        bytes32 permissionScope;
        bytes32 delegationScope;
        uint64 issuedAt;
        uint64 expiresAt;
        bool active;
        bytes32 contentHash;
    }

    // Full-agent revocation metadata is public so a cold verifier needs no
    // off-chain event JSON. revokedAt keeps the exact Module 1 ISO-8601 value.
    struct RevocationDetails {
        string revokedAt;
        string revokedBy;
        string[] permissions;
        bytes32 contentHash;
        bytes32 recordId;
        uint64 confirmedAt;
    }

    mapping(bytes32 => address) public agentAddresses;
    mapping(address => bytes32) public addressAgents;
    mapping(bytes32 => bool) public agentRevoked;
    mapping(bytes32 => RevocationDetails) private revocationDetails;
    mapping(bytes32 => Credential) public credentials;
    mapping(bytes32 => Commitment) public commitments;
    mapping(bytes32 => mapping(bytes32 => bytes32)) public scopeCredentials;
    mapping(bytes32 => bool) public delegationGrants;

    event AgentRegistered(bytes32 indexed agentHash, address indexed account);
    event CredentialIssued(bytes32 indexed recordId, bytes32 indexed agentHash, bytes32 contentHash);
    event DelegationAnchored(bytes32 indexed recordId, bytes32 indexed delegatorHash, bytes32 indexed delegateeHash, bytes32 contentHash);
    event RevocationAnchored(bytes32 indexed recordId, bytes32 indexed agentHash, bytes32 contentHash);
    event ActionHashAnchored(bytes32 indexed recordId, bytes32 contentHash);

    modifier onlyRoot() {
        require(msg.sender == rootAuthorizer, "ROOT_ONLY");
        _;
    }

    constructor() {
        rootAuthorizer = msg.sender;
    }

    function registerAgent(bytes32 agentHash, address account) external onlyRoot {
        require(agentHash != bytes32(0) && account != address(0), "INVALID_AGENT");
        require(agentAddresses[agentHash] == address(0), "AGENT_EXISTS");
        require(addressAgents[account] == bytes32(0), "ADDRESS_EXISTS");
        agentAddresses[agentHash] = account;
        addressAgents[account] = agentHash;
        emit AgentRegistered(agentHash, account);
    }

    function issueCredential(
        bytes32 recordId,
        bytes32 agentHash,
        address agentAddress,
        address issuer,
        bytes32 permissionScope,
        bytes32 delegationScope,
        uint64 issuedAt,
        uint64 expiresAt,
        bytes32 contentHash
    ) external onlyRoot {
        _newCommitment(recordId, contentHash, 1);
        require(agentAddresses[agentHash] == agentAddress && agentAddress != address(0), "AGENT_NOT_REGISTERED");
        require(!agentRevoked[agentHash], "AGENT_REVOKED");
        require(permissionScope != bytes32(0), "EMPTY_SCOPE");
        require(delegationScope == bytes32(0) || delegationScope == permissionScope, "BAD_DELEGATION_SCOPE");
        require(expiresAt > issuedAt && expiresAt > block.timestamp, "CREDENTIAL_EXPIRED");
        require(scopeCredentials[agentHash][permissionScope] == bytes32(0), "SCOPE_EXISTS");
        require(addressAgents[issuer] != bytes32(0), "ISSUER_NOT_REGISTERED");
        if (issuer != rootAuthorizer) {
            bytes32 grantKey = keccak256(abi.encode(addressAgents[issuer], agentHash, permissionScope));
            require(delegationGrants[grantKey], "DELEGATION_NOT_ANCHORED");
        }
        credentials[recordId] = Credential(
            agentHash, agentAddress, issuer, permissionScope, delegationScope,
            issuedAt, expiresAt, true, contentHash
        );
        scopeCredentials[agentHash][permissionScope] = recordId;
        emit CredentialIssued(recordId, agentHash, contentHash);
    }

    function anchorDelegation(
        bytes32 recordId,
        bytes32 delegatorHash,
        bytes32 delegateeHash,
        bytes32 permissionHash,
        bytes32 contentHash
    ) external onlyRoot {
        _newCommitment(recordId, contentHash, 2);
        require(agentAddresses[delegatorHash] != address(0), "DELEGATOR_NOT_REGISTERED");
        require(agentAddresses[delegateeHash] != address(0), "DELEGATEE_NOT_REGISTERED");
        require(!agentRevoked[delegatorHash] && !agentRevoked[delegateeHash], "AGENT_REVOKED");
        bytes32 credentialId = scopeCredentials[delegatorHash][permissionHash];
        Credential storage credential = credentials[credentialId];
        require(credential.active && credential.expiresAt > block.timestamp, "NO_ACTIVE_CREDENTIAL");
        require(credential.delegationScope == permissionHash, "DELEGATION_SCOPE_DENIED");
        bytes32 grantKey = keccak256(abi.encode(delegatorHash, delegateeHash, permissionHash));
        require(!delegationGrants[grantKey], "DELEGATION_EXISTS");
        delegationGrants[grantKey] = true;
        emit DelegationAnchored(recordId, delegatorHash, delegateeHash, contentHash);
    }

    function anchorRevocationDetailed(
        bytes32 recordId,
        bytes32 agentHash,
        bytes32[] calldata credentialIds,
        bytes32 contentHash,
        string calldata revokedAt,
        string calldata revokedBy,
        string[] calldata permissions
    ) external onlyRoot {
        require(bytes(revokedAt).length != 0, "EMPTY_REVOCATION_TIME");
        require(keccak256(bytes(revokedBy)) == keccak256(bytes("ROOT_AUTHORIZER")), "INVALID_REVOKER");
        _newCommitment(recordId, contentHash, 3);
        require(agentAddresses[agentHash] != address(0), "AGENT_NOT_REGISTERED");
        require(!agentRevoked[agentHash], "AGENT_REVOKED");
        agentRevoked[agentHash] = true;
        for (uint256 i = 0; i < credentialIds.length; i++) {
            Credential storage credential = credentials[credentialIds[i]];
            require(credential.agentHash == agentHash && credential.active, "INVALID_CREDENTIAL");
            credential.active = false;
        }
        RevocationDetails storage details = revocationDetails[agentHash];
        details.revokedAt = revokedAt;
        details.revokedBy = revokedBy;
        details.contentHash = contentHash;
        details.recordId = recordId;
        details.confirmedAt = uint64(block.timestamp);
        for (uint256 i = 0; i < permissions.length; i++) {
            details.permissions.push(permissions[i]);
        }
        emit RevocationAnchored(recordId, agentHash, contentHash);
    }

    function getRevocationDetails(bytes32 agentHash) external view returns (
        string memory revokedAt,
        string memory revokedBy,
        string[] memory permissions,
        bytes32 contentHash,
        bytes32 recordId,
        uint64 confirmedAt
    ) {
        require(agentRevoked[agentHash], "AGENT_NOT_REVOKED");
        RevocationDetails storage details = revocationDetails[agentHash];
        return (details.revokedAt, details.revokedBy, details.permissions,
                details.contentHash, details.recordId, details.confirmedAt);
    }

    function anchorActionHash(bytes32 recordId, bytes32 contentHash) external onlyRoot {
        _newCommitment(recordId, contentHash, 4);
        emit ActionHashAnchored(recordId, contentHash);
    }

    function _newCommitment(bytes32 recordId, bytes32 contentHash, uint8 kind) internal {
        require(
            recordId != bytes32(0) && recordId == sha256(abi.encodePacked(kind, contentHash)),
            "INVALID_RECORD_ID"
        );
        require(commitments[recordId].kind == 0, "RECORD_EXISTS");
        commitments[recordId] = Commitment(contentHash, kind, uint64(block.timestamp));
    }
}

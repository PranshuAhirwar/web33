// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/**
 * @title PixelProof Network
 * @dev A decentralized platform for digital asset verification and authenticity proof
 */
contract Project is AccessControl, ReentrancyGuard {
    using Counters for Counters.Counter;
    
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    
    Counters.Counter private _proofIds;
    Counters.Counter private _assetIds;

    struct Asset {
        uint256 assetId;
        string assetName;
        string assetType;
        address creator;
        uint256 creationTimestamp;
        string metadataURI;
        bool isVerified;
        bool exists;
    }

    struct ProofRecord {
        uint256 proofId;
        uint256 assetId;
        address verifier;
        uint256 timestamp;
        string proofHash;
        string verificationType;
        bool isValid;
    }

    struct OwnershipHistory {
        address owner;
        uint256 timestamp;
        string transferNote;
    }

    mapping(uint256 => Asset) private _assets;
    mapping(uint256 => ProofRecord[]) private _assetProofs;
    mapping(uint256 => OwnershipHistory[]) private _ownershipHistory;
    mapping(address => uint256[]) private _creatorAssets;
    mapping(bytes32 => bool) private _uniqueHashes;
    mapping(uint256 => address) private _currentOwner;

    event AssetRegistered(uint256 indexed assetId, address indexed creator, string assetName, uint256 timestamp);
    event AssetVerified(uint256 indexed assetId, uint256 indexed proofId, address indexed verifier, uint256 timestamp);
    event OwnershipTransferred(uint256 indexed assetId, address indexed from, address indexed to, uint256 timestamp);
    event ProofAdded(uint256 indexed proofId, uint256 indexed assetId, string verificationType);
    event VerifierAdded(address indexed verifier);
    event IssuerAdded(address indexed issuer);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
        _grantRole(ISSUER_ROLE, msg.sender);
    }

    /**
     * @dev Register a new digital asset
     * @param assetName Name of the asset
     * @param assetType Type/category of the asset
     * @param metadataURI URI pointing to asset metadata
     * @return assetId The ID of the registered asset
     */
    function registerAsset(
        string memory assetName,
        string memory assetType,
        string memory metadataURI
    ) public returns (uint256) {
        require(bytes(assetName).length > 0, "Asset name cannot be empty");
        require(bytes(metadataURI).length > 0, "Metadata URI cannot be empty");

        _assetIds.increment();
        uint256 newAssetId = _assetIds.current();

        _assets[newAssetId] = Asset({
            assetId: newAssetId,
            assetName: assetName,
            assetType: assetType,
            creator: msg.sender,
            creationTimestamp: block.timestamp,
            metadataURI: metadataURI,
            isVerified: false,
            exists: true
        });

        _currentOwner[newAssetId] = msg.sender;
        _creatorAssets[msg.sender].push(newAssetId);
        
        _ownershipHistory[newAssetId].push(OwnershipHistory({
            owner: msg.sender,
            timestamp: block.timestamp,
            transferNote: "Initial registration"
        }));

        emit AssetRegistered(newAssetId, msg.sender, assetName, block.timestamp);
        return newAssetId;
    }

    /**
     * @dev Add verification proof for an asset
     * @param assetId ID of the asset to verify
     * @param proofHash Cryptographic hash of the proof
     * @param verificationType Type of verification performed
     */
    function addVerificationProof(
        uint256 assetId,
        string memory proofHash,
        string memory verificationType
    ) public onlyRole(VERIFIER_ROLE) {
        require(_assets[assetId].exists, "Asset does not exist");
        require(bytes(proofHash).length > 0, "Proof hash cannot be empty");

        bytes32 hashBytes = keccak256(abi.encodePacked(proofHash));
        require(!_uniqueHashes[hashBytes], "Proof hash already used");

        _proofIds.increment();
        uint256 newProofId = _proofIds.current();

        ProofRecord memory newProof = ProofRecord({
            proofId: newProofId,
            assetId: assetId,
            verifier: msg.sender,
            timestamp: block.timestamp,
            proofHash: proofHash,
            verificationType: verificationType,
            isValid: true
        });

        _assetProofs[assetId].push(newProof);
        _uniqueHashes[hashBytes] = true;
        _assets[assetId].isVerified = true;

        emit ProofAdded(newProofId, assetId, verificationType);
        emit AssetVerified(assetId, newProofId, msg.sender, block.timestamp);
    }

    /**
     * @dev Transfer ownership of an asset
     * @param assetId ID of the asset to transfer
     * @param newOwner Address of the new owner
     * @param transferNote Note about the transfer
     */
    function transferOwnership(
        uint256 assetId,
        address newOwner,
        string memory transferNote
    ) public nonReentrant {
        require(_assets[assetId].exists, "Asset does not exist");
        require(_currentOwner[assetId] == msg.sender, "Only current owner can transfer");
        require(newOwner != address(0), "Invalid new owner address");
        require(newOwner != msg.sender, "Cannot transfer to yourself");

        address previousOwner = _currentOwner[assetId];
        _currentOwner[assetId] = newOwner;

        _ownershipHistory[assetId].push(OwnershipHistory({
            owner: newOwner,
            timestamp: block.timestamp,
            transferNote: transferNote
        }));

        emit OwnershipTransferred(assetId, previousOwner, newOwner, block.timestamp);
    }

    /**
     * @dev Verify the authenticity of an asset
     * @param assetId ID of the asset to check
     * @return isAuthentic Boolean indicating if asset is verified
     * @return proofCount Number of verification proofs
     */
    function verifyAssetAuthenticity(uint256 assetId) 
        public 
        view 
        returns (bool isAuthentic, uint256 proofCount) 
    {
        require(_assets[assetId].exists, "Asset does not exist");
        return (_assets[assetId].isVerified, _assetProofs[assetId].length);
    }

    /**
     * @dev Get asset details
     * @param assetId ID of the asset
     * @return Asset struct with all asset information
     */
    function getAsset(uint256 assetId) public view returns (Asset memory) {
        require(_assets[assetId].exists, "Asset does not exist");
        return _assets[assetId];
    }

    /**
     * @dev Get all verification proofs for an asset
     * @param assetId ID of the asset
     * @return Array of proof records
     */
    function getAssetProofs(uint256 assetId) public view returns (ProofRecord[] memory) {
        require(_assets[assetId].exists, "Asset does not exist");
        return _assetProofs[assetId];
    }

    /**
     * @dev Get complete ownership history for an asset
     * @param assetId ID of the asset
     * @return Array of ownership history records
     */
    function getOwnershipHistory(uint256 assetId) public view returns (OwnershipHistory[] memory) {
        require(_assets[assetId].exists, "Asset does not exist");
        return _ownershipHistory[assetId];
    }

    /**
     * @dev Get current owner of an asset
     * @param assetId ID of the asset
     * @return Address of current owner
     */
    function getCurrentOwner(uint256 assetId) public view returns (address) {
        require(_assets[assetId].exists, "Asset does not exist");
        return _currentOwner[assetId];
    }

    /**
     * @dev Get all assets created by a specific address
     * @param creator Address of the creator
     * @return Array of asset IDs
     */
    function getAssetsByCreator(address creator) public view returns (uint256[] memory) {
        return _creatorAssets[creator];
    }

    /**
     * @dev Check if a proof hash has been used
     * @param proofHash Hash to check
     * @return Boolean indicating if hash exists
     */
    function isProofHashUsed(string memory proofHash) public view returns (bool) {
        bytes32 hashBytes = keccak256(abi.encodePacked(proofHash));
        return _uniqueHashes[hashBytes];
    }

    /**
     * @dev Get provenance trail for an asset
     * @param assetId ID of the asset
     * @return creator Original creator
     * @return currentOwner Current owner
     * @return transferCount Number of ownership transfers
     * @return isVerified Verification status
     */
    function getProvenance(uint256 assetId) 
        public 
        view 
        returns (
            address creator,
            address currentOwner,
            uint256 transferCount,
            bool isVerified
        ) 
    {
        require(_assets[assetId].exists, "Asset does not exist");
        Asset memory asset = _assets[assetId];
        
        return (
            asset.creator,
            _currentOwner[assetId],
            _ownershipHistory[assetId].length,
            asset.isVerified
        );
    }

    /**
     * @dev Add a new verifier
     * @param verifier Address to grant verifier role
     */
    function addVerifier(address verifier) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(verifier != address(0), "Invalid verifier address");
        grantRole(VERIFIER_ROLE, verifier);
        emit VerifierAdded(verifier);
    }

    /**
     * @dev Add a new issuer
     * @param issuer Address to grant issuer role
     */
    function addIssuer(address issuer) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(issuer != address(0), "Invalid issuer address");
        grantRole(ISSUER_ROLE, issuer);
        emit IssuerAdded(issuer);
    }

    /**
     * @dev Remove a verifier
     * @param verifier Address to revoke verifier role from
     */
    function removeVerifier(address verifier) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(VERIFIER_ROLE, verifier);
    }

    /**
     * @dev Remove an issuer
     * @param issuer Address to revoke issuer role from
     */
    function removeIssuer(address issuer) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(ISSUER_ROLE, issuer);
    }

    /**
     * @dev Get total number of registered assets
     * @return Total asset count
     */
    function getTotalAssets() public view returns (uint256) {
        return _assetIds.current();
    }

    /**
     * @dev Get total number of verification proofs issued
     * @return Total proof count
     */
    function getTotalProofs() public view returns (uint256) {
        return _proofIds.current();
    }

    /**
     * @dev Check if an address has verifier role
     * @param account Address to check
     * @return Boolean indicating if address is verifier
     */
    function isVerifier(address account) public view returns (bool) {
        return hasRole(VERIFIER_ROLE, account);
    }

    /**
     * @dev Check if an address has issuer role
     * @param account Address to check
     * @return Boolean indicating if address is issuer
     */
    function isIssuer(address account) public view returns (bool) {
        return hasRole(ISSUER_ROLE, account);
    }
}
// 
Contract End
// 

// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

abstract contract ERC1155PermitSignatureExtension {
    /// @notice EIP-712 Ethereum typed structured data hashing and signing
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public immutable SETPERMITFORALL_TYPEHASH;

    /// @notice Nonces used for EIP-2612 sytle permits
    mapping(address => uint256) public approvalNonces;

    constructor(bytes memory name, bytes memory version) {
        bytes memory EIP712Domain =
            bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(keccak256(EIP712Domain), keccak256(name), keccak256(version), block.chainid, address(this))
        );
        SETPERMITFORALL_TYPEHASH =
            keccak256("SetPermitForAll(address owner,address operator,bool approved,uint256 nonce,uint256 deadline)");
    }

    function setPermitForAll(
        address owner,
        address operator,
        bool approved,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        external
    {
        require(_signaturesEnabled(), "Permit Signature Disabled");
        require(deadline >= block.timestamp);
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(SETPERMITFORALL_TYPEHASH, owner, operator, approved, approvalNonces[owner]++, deadline)
                )
            )
        );
        address recoveredAddress = ecrecover(digest, v, r, s);
        require(recoveredAddress != address(0) && recoveredAddress == owner);
        _setApprovalForAll(owner, operator, approved);
    }

    function _signaturesEnabled() internal virtual returns (bool);

    function _setApprovalForAll(address owner, address operator, bool approved) internal virtual;
}

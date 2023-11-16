// SPDX-License-Identifier: unlicensed
// Cowri Labs Inc.

pragma solidity 0.8.20;

/// @notice Implementing this allows a primitive to be called by the Ocean's
///  defi framework.
interface IOceanPrimitive {
    function computeOutputAmount(
        uint256 inputToken,
        uint256 outputToken,
        uint256 inputAmount,
        address userAddress,
        bytes32 metadata
    )
        external
        returns (uint256 outputAmount);

    function computeInputAmount(
        uint256 inputToken,
        uint256 outputToken,
        uint256 outputAmount,
        address userAddress,
        bytes32 metadata
    )
        external
        returns (uint256 inputAmount);

    function getTokenSupply(uint256 tokenId) external view returns (uint256 totalSupply);
}

// SPDX-License-Identifier: unlicensed
// Cowri Labs Inc.

pragma solidity 0.8.20;

/**
 * @title Interface for external contracts that issue tokens on the Ocean's
 *  public multitoken ledger
 * @dev Implemented by OceanERC1155.
 */
interface IOceanToken {
    function registerNewTokens(
        uint256 currentNumberOfTokens,
        uint256 numberOfAdditionalTokens
    )
        external
        returns (uint256[] memory);
}

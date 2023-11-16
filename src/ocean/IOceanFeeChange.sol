// SPDX-License-Identifier: unlicensed
// Cowri Labs Inc.

pragma solidity 0.8.20;

/// @notice to be implemented by a contract that is the Ocean.owner()
interface IOceanFeeChange {
    function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external;
}

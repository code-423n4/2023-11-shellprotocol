// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import { LiquidityPool } from "../proteus/LiquidityPool.sol";

contract ConstantSum is LiquidityPool {
    constructor(
        uint256 xToken_,
        uint256 yToken_,
        address ocean_,
        uint256 initialLpTokenSupply_
    )
        LiquidityPool(xToken_, yToken_, ocean_, initialLpTokenSupply_, address(0))
    { }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance
     */
    function swapGivenInputAmount(uint256, uint256 inputAmount) public pure override returns (uint256 outputAmount) {
        outputAmount = inputAmount;
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply to get the lpTokenSupply
     */
    function depositGivenInputAmount(
        uint256,
        uint256 depositAmount
    )
        public
        pure
        override
        returns (uint256 mintAmount)
    {
        mintAmount = depositAmount;
    }

    function withdrawGivenInputAmount(
        uint256,
        uint256 burnAmount
    )
        public
        pure
        override
        returns (uint256 withdrawnAmount)
    {
        withdrawnAmount = burnAmount;
    }

    function swapGivenOutputAmount(uint256, uint256 outputAmount) public pure override returns (uint256 inputAmount) {
        inputAmount = outputAmount;
    }

    function depositGivenOutputAmount(
        uint256,
        uint256 mintAmount
    )
        public
        pure
        override
        returns (uint256 depositAmount)
    {
        depositAmount = mintAmount;
    }

    function withdrawGivenOutputAmount(
        uint256,
        uint256 withdrawnAmount
    )
        public
        pure
        override
        returns (uint256 burnAmount)
    {
        burnAmount = withdrawnAmount;
    }
}

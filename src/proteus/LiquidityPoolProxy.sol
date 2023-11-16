// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import { LiquidityPool } from "./LiquidityPool.sol";
import { ILiquidityPoolImplementation, SpecifiedToken } from "./ILiquidityPoolImplementation.sol";

contract LiquidityPoolProxy is LiquidityPool, Ownable {
    //*********************************************************************//
    // --------------------------- custom errors ------------------------- //
    //*********************************************************************//
    error POOL_IS_FROZEN();

    ILiquidityPoolImplementation public implementation;
    bool public poolFrozen = false;

    event ImplementationChanged(address operator, address oldImplementation, address newImplementation);

    event PoolFrozen(address operator);

    modifier notFrozen() {
        if (poolFrozen) revert POOL_IS_FROZEN();
        _;
    }

    constructor(
        uint256 xToken_,
        uint256 yToken_,
        address ocean_,
        uint256 initialLpTokenSupply_
    )
        LiquidityPool(xToken_, yToken_, ocean_, initialLpTokenSupply_, address(0))
    {
        // External calls with enums rely on both contracts using the same
        // mapping between enum fields and uint8 values.
        assert(uint8(SpecifiedToken.X) == 0);
        assert(uint8(SpecifiedToken.Y) == 1);
    }

    function setImplementation(address _implementation) external onlyOwner {
        emit ImplementationChanged(msg.sender, address(implementation), _implementation);
        implementation = ILiquidityPoolImplementation(_implementation);
    }

    function freezePool(bool freeze) external onlyOwner {
        emit PoolFrozen(msg.sender);
        poolFrozen = freeze;
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance
     */
    function swapGivenInputAmount(
        uint256 inputToken,
        uint256 inputAmount
    )
        public
        view
        override
        notFrozen
        returns (uint256 outputAmount)
    {
        (uint256 xBalance, uint256 yBalance) = _getBalances();

        SpecifiedToken specifiedToken = _specifiedToken(inputToken);
        if (specifiedToken == SpecifiedToken.X) {
            xBalance -= inputAmount;
        } else {
            if (specifiedToken != SpecifiedToken.Y) revert INVALID_TOKEN_ID();
            yBalance -= inputAmount;
        }

        outputAmount = implementation.swapGivenInputAmount(xBalance, yBalance, inputAmount, specifiedToken);
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply to get the lpTokenSupply
     */
    function depositGivenInputAmount(
        uint256 depositToken,
        uint256 depositAmount
    )
        public
        view
        override
        notFrozen
        returns (uint256 mintAmount)
    {
        (uint256 xBalance, uint256 yBalance) = _getBalances();
        uint256 totalSupply = _getTotalSupply();

        SpecifiedToken specifiedToken = _specifiedToken(depositToken);
        if (specifiedToken == SpecifiedToken.X) {
            xBalance -= depositAmount;
        } else {
            if (specifiedToken != SpecifiedToken.Y) revert INVALID_TOKEN_ID();
            yBalance -= depositAmount;
        }

        mintAmount =
            implementation.depositGivenInputAmount(xBalance, yBalance, totalSupply, depositAmount, specifiedToken);
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply to get the lpTokenSupply
     */
    function withdrawGivenInputAmount(
        uint256 withdrawnToken,
        uint256 burnAmount
    )
        public
        view
        override
        notFrozen
        returns (uint256 withdrawnAmount)
    {
        (uint256 xBalance, uint256 yBalance) = _getBalances();
        uint256 totalSupply = _getTotalSupply();
        withdrawnAmount = implementation.withdrawGivenInputAmount(
            xBalance, yBalance, totalSupply, burnAmount, _specifiedToken(withdrawnToken)
        );
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance
     */
    function swapGivenOutputAmount(
        uint256 outputToken,
        uint256 outputAmount
    )
        public
        view
        override
        notFrozen
        returns (uint256 inputAmount)
    {
        (uint256 xBalance, uint256 yBalance) = _getBalances();

        SpecifiedToken specifiedToken = _specifiedToken(outputToken);
        if (specifiedToken == SpecifiedToken.X) {
            xBalance += outputAmount;
        } else {
            if (specifiedToken != SpecifiedToken.Y) revert INVALID_TOKEN_ID();
            yBalance += outputAmount;
        }

        inputAmount = implementation.swapGivenOutputAmount(xBalance, yBalance, outputAmount, specifiedToken);
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply() to get the lpTokenSupply
     */
    function depositGivenOutputAmount(
        uint256 depositToken,
        uint256 mintAmount
    )
        public
        view
        override
        notFrozen
        returns (uint256 depositAmount)
    {
        (uint256 xBalance, uint256 yBalance) = _getBalances();
        uint256 totalSupply = _getTotalSupply();
        depositAmount = implementation.depositGivenOutputAmount(
            xBalance, yBalance, totalSupply, mintAmount, _specifiedToken(depositToken)
        );
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply() to get the lpTokenSupply
     */
    function withdrawGivenOutputAmount(
        uint256 withdrawnToken,
        uint256 withdrawnAmount
    )
        public
        view
        override
        notFrozen
        returns (uint256 burnAmount)
    {
        (uint256 xBalance, uint256 yBalance) = _getBalances();
        uint256 totalSupply = _getTotalSupply();

        SpecifiedToken specifiedToken = _specifiedToken(withdrawnToken);
        if (specifiedToken == SpecifiedToken.X) {
            xBalance += withdrawnAmount;
        } else {
            if (specifiedToken != SpecifiedToken.Y) revert INVALID_TOKEN_ID();
            yBalance += withdrawnAmount;
        }

        burnAmount =
            implementation.withdrawGivenOutputAmount(xBalance, yBalance, totalSupply, withdrawnAmount, specifiedToken);
    }

    function _specifiedToken(uint256 tokenId) private view returns (SpecifiedToken) {
        if (tokenId == xToken) {
            return SpecifiedToken.X;
        } else {
            assert(tokenId == yToken);
            return SpecifiedToken.Y;
        }
    }
}

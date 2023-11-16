// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

enum SpecifiedToken {
    X,
    Y
}

interface ILiquidityPoolImplementation {
    function swapGivenInputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 inputAmount,
        SpecifiedToken inputToken
    )
        external
        view
        returns (uint256 outputAmount);

    function depositGivenInputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 depositedAmount,
        SpecifiedToken depositedToken
    )
        external
        view
        returns (uint256 mintedAmount);

    function withdrawGivenInputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 burnedAmount,
        SpecifiedToken withdrawnToken
    )
        external
        view
        returns (uint256 withdrawnAmount);

    function swapGivenOutputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 outputAmount,
        SpecifiedToken outputToken
    )
        external
        view
        returns (uint256 inputAmount);

    function depositGivenOutputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 mintedAmount,
        SpecifiedToken depositedToken
    )
        external
        view
        returns (uint256 depositedAmount);

    function withdrawGivenOutputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 withdrawnAmount,
        SpecifiedToken withdrawnToken
    )
        external
        view
        returns (uint256 burnedAmount);
}

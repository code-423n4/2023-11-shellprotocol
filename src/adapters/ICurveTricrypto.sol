// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

interface ICurveTricrypto {
    function exchange(uint256 i, uint256 j, uint256 dx, uint256 min_dy, bool use_eth) external payable;

    function add_liquidity(uint256[3] memory amounts, uint256 min_mint_amount) external;

    function remove_liquidity_one_coin(uint256 token_amount, uint256 i, uint256 min_amount) external;

    function coins(uint256 i) external view returns (address);

    function token() external view returns (address);
}

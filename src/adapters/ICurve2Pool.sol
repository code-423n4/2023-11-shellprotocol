// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

interface ICurve2Pool {
    function exchange(int128 i, int128 j, uint256 _dx, uint256 _min_dy) external returns (uint256);

    function add_liquidity(uint256[2] memory _amounts, uint256 _min_mint_amount) external returns (uint256);

    function remove_liquidity_one_coin(
        uint256 _burn_amount,
        int128 i,
        uint256 _min_received
    )
        external
        returns (uint256);

    function coins(uint256 i) external view returns (address);
}

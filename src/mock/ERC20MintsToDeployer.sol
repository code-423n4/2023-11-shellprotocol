// SPDX-License-Identifier: Unlicensed
// Cowri Labs, Inc.

pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ERC20MintsToDeployer is ERC20 {
    uint8 private _decimals;

    constructor(uint256 amount_, uint8 decimals_) ERC20("", "") {
        _mint(msg.sender, amount_);
        _decimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }
}

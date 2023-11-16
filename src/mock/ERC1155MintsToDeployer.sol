// SPDX-License-Identifier: Unlicensed

pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

contract ERC1155MintsToDeployer is ERC1155 {
    constructor(uint256[] memory ids, uint256[] memory amounts) ERC1155("") {
        for (uint256 i = 0; i < ids.length; ++i) {
            _mint(msg.sender, ids[i], amounts[i], "");
        }
    }
}

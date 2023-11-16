// SPDX-License-Identifier: Unlicensed

pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract ERC721MintsToDeployer is ERC721 {
    constructor(uint256[] memory ids) ERC721("", "") {
        for (uint256 i = 0; i < ids.length; ++i) {
            _safeMint(msg.sender, ids[i]);
        }
    }
}

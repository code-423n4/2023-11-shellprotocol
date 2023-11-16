// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract Interfaces {
    bytes4 public immutable i165;
    bytes4 public immutable i1155;
    bytes4 public immutable i1155m;
    bytes4 public immutable i1155r;

    constructor() {
        i165 = type(IERC165).interfaceId;
        i1155 = type(IERC1155).interfaceId;
        i1155m = type(IERC1155MetadataURI).interfaceId;
        i1155r = type(IERC1155Receiver).interfaceId;
    }
}

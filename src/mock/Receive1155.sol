// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract Receive1155 is IERC1155Receiver {
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165) returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }

    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata data
    )
        external
        pure
        override
        returns (bytes4)
    {
        if (data.length == 0) {
            return IERC1155Receiver.onERC1155Received.selector;
        } else if (uint8(data[0]) == 1) {
            revert("Code coverage");
        } else {
            return 0;
        }
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata data
    )
        external
        pure
        override
        returns (bytes4)
    {
        if (data.length == 0) {
            return IERC1155Receiver.onERC1155BatchReceived.selector;
        } else if (uint8(data[0]) == 1) {
            revert("Code coverage");
        } else {
            return 0;
        }
    }
}

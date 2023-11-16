// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "../ocean/Interactions.sol";
import "../ocean/IOceanPrimitive.sol";

contract MaliciousPrimitive is IOceanPrimitive {
    address public immutable ocean;

    constructor(address ocean_) {
        ocean = ocean_;
    }

    modifier onlyOcean() {
        require(msg.sender == ocean);
        _;
    }

    function computeOutputAmount(
        uint256 inputToken,
        uint256 outputToken,
        uint256 inputAmount,
        address userAddress,
        bytes32 metadata
    )
        external
        override
        onlyOcean
        returns (uint256 outputAmount)
    {
        // returning a low amount to be given to the user
        outputAmount = 1e12;
    }

    function computeInputAmount(
        uint256 inputToken,
        uint256 outputToken,
        uint256 outputAmount,
        address userAddress,
        bytes32 maximumInputAmount
    )
        external
        override
        onlyOcean
        returns (uint256 inputAmount)
    {
        // returning a high amount to be taken from the user
        inputAmount = 1e21;
    }

    /**
     * @dev Handles the receipt of a single ERC1155 token type. This function is
     * called at the end of a `safeTransferFrom` after the balance has been updated.
     * @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if transfer is allowed
     */
    function onERC1155Received(address, address, uint256, uint256, bytes memory) public pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    /**
     * @dev This callback is part of IERC1155Receiver, which we must implement
     *  to wrap ERC-1155 tokens.
     * @dev The Ocean never initiates ERC1155 Batch Transfers.
     * @dev We don't revert, prefering to let the external contract
     *  decide what it wants to do when safeTransfer is called on a contract
     *  that does not return the expected selector.
     */
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    )
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    function getTokenSupply(uint256 tokenId) external view override returns (uint256) {
        return 0;
    }
}

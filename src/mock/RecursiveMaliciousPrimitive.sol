// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "../ocean/Interactions.sol";
import "../ocean/IOceanPrimitive.sol";

contract RecursiveMaliciousPrimitive is IOceanPrimitive {
    uint256 constant RECURSIVE_CALL_LIMIT = 100;

    address public immutable ocean;

    uint256 callCounter = 0;

    constructor(address ocean_) {
        ocean = ocean_;
    }

    modifier onlyOcean() {
        require(msg.sender == ocean);
        _;
    }

    /**
     * used to fetch the Ocean interaction id
     */
    function _fetchInteractionId(address token, uint256 interactionType) internal pure returns (bytes32) {
        uint256 packedValue = uint256(uint160(token));
        packedValue |= interactionType << 248;
        return bytes32(abi.encode(packedValue));
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
        // recursion limit to keep in mind failures due to gas limit
        if (callCounter < RECURSIVE_CALL_LIMIT) {
            // attempt to trick the Ocean by passing a single interaction with a doMultipleInteractions call
            // doMultipleInteraction also has the same behaviour in test
            Interaction[] memory interactions = new Interaction[](1);
            interactions[0] = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(address(this), uint256(InteractionType.ComputeOutputAmount)),
                inputToken: inputToken,
                outputToken: outputToken,
                specifiedAmount: inputAmount,
                metadata: bytes32(0)
            });

            uint256[] memory ids = new uint[](2);
            ids[0] = inputToken;
            ids[1] = outputToken;

            callCounter += 1;
            IOceanInteractions(ocean).doMultipleInteractions(interactions, ids);
            callCounter = 0;
            outputAmount = 1e12;
        }
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
        // recursion limit to keep in mind failures due to gas limit
        if (callCounter < RECURSIVE_CALL_LIMIT) {
            // attempt to trick the Ocean by passing a single interaction with a doMultipleInteractions call
            // doMultipleInteraction also has the same behaviour in test
            Interaction[] memory interactions = new Interaction[](1);
            interactions[0] = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(address(this), uint256(InteractionType.ComputeInputAmount)),
                inputToken: inputToken,
                outputToken: outputToken,
                specifiedAmount: outputAmount,
                metadata: bytes32(0)
            });

            uint256[] memory ids = new uint[](2);
            ids[0] = inputToken;
            ids[1] = outputToken;

            callCounter += 1;
            IOceanInteractions(ocean).doMultipleInteractions(interactions, ids);

            callCounter = 0;
            inputAmount = 1e21;
        }
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

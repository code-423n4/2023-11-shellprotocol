// SPDX-License-Identifier: unlicensed
// Cowri Labs Inc.

pragma solidity 0.8.20;

/**
 * @param interactionTypeAndAddress the type of interaction and the external
 *  contract called during this interaction.
 * @param inputToken this field is ignored except when the interaction type
 *  begins with "Compute".  During a "Compute" interaction, this token is given
 *  to the external contract.
 * @param outputToken this field is ignored except when the interaction type
 *  begins with "Compute".  During a "Compute" interaction, this token is
 *  received from the external contract.
 * @param specifiedAmount This value is the amount of the specified token.
 *  See the comment above the declaration for InteractionType for information
 *  on specified tokens.  When this value is equal to type(uint256).max, it is
 *  a request by the user to use the intra-transaction delta of the specified
 *  token as the specified amount.  See LibBalanceDelta for more information
 *  about this.  When the Ocean executes an interaction, it resolves the
 *  specifiedAmount before calling the external contract.  During a "721"
 *  interaction, the resolved specifiedAmount must be identically "1".
 * @param metadata This value is used in two ways.  During "Compute"
 *  interactions, it is forwarded to the external contract.  The external
 *  contract can define whatever expectations it wants for these 32 bytes.  The
 *  caller is expected to be aware of the expectations of the external contract
 *  invoked during the interaction.  During 721/1155 and wraps and unwraps,
 *  these bytes are cast to uint256 and used as the external ledger's token ID
 *  for the interaction.
 */
struct Interaction {
    bytes32 interactionTypeAndAddress;
    uint256 inputToken;
    uint256 outputToken;
    uint256 specifiedAmount;
    bytes32 metadata;
}

/**
 * InteractionType determines how the properties of Interaction are interpreted
 *
 * The interface implemented by the external contract, the specified token
 *  for the interaction, and what sign (+/-) of delta can be used are
 *  determined by the InteractionType.
 *
 * @param WrapErc20
 *      type(externalContract).interfaceId == IERC20
 *      specifiedToken == calculateOceanId(externalContract, 0)
 *      negative delta can be used as specifiedAmount
 *
 * @param UnwrapErc20
 *      type(externalContract).interfaceId == IERC20
 *      specifiedToken == calculateOceanId(externalContract, 0)
 *      positive delta can be used as specifiedAmount
 *
 * @param WrapErc721
 *      type(externalContract).interfaceId == IERC721
 *      specifiedToken == calculateOceanId(externalContract, metadata)
 *      negative delta can be used as specifiedAmount
 *
 * @param UnwrapErc721
 *      type(externalContract).interfaceId == IERC721
 *      specifiedToken == calculateOceanId(externalContract, metadata)
 *      positive delta can be used as specifiedAmount
 *
 * @param WrapErc1155
 *      type(externalContract).interfaceId == IERC1155
 *      specifiedToken == calculateOceanId(externalContract, metadata)
 *      negative delta can be used as specifiedAmount
 *
 * @param WrapErc1155
 *      type(externalContract).interfaceId == IERC1155
 *      specifiedToken == calculateOceanId(externalContract, metadata)
 *      positive delta can be used as specifiedAmount
 *
 * @param ComputeInputAmount
 *      type(externalContract).interfaceId == IOceanexternalContract
 *      specifiedToken == outputToken
 *      negative delta can be used as specifiedAmount
 *
 * @param ComputeOutputAmount
 *      type(externalContract).interfaceId == IOceanexternalContract
 *      specifiedToken == inputToken
 *      positive delta can be used as specifiedAmount
 */
enum InteractionType {
    WrapErc20,
    UnwrapErc20,
    WrapErc721,
    UnwrapErc721,
    WrapErc1155,
    UnwrapErc1155,
    ComputeInputAmount,
    ComputeOutputAmount,
    UnwrapEther
}

interface IOceanInteractions {
    function unwrapFeeDivisor() external view returns(uint256);

    function doMultipleInteractions(
        Interaction[] calldata interactions,
        uint256[] calldata ids
    )
        external
        payable
        returns (
            uint256[] memory burnIds,
            uint256[] memory burnAmounts,
            uint256[] memory mintIds,
            uint256[] memory mintAmounts
        );

    function forwardedDoMultipleInteractions(
        Interaction[] calldata interactions,
        uint256[] calldata ids,
        address userAddress
    )
        external
        payable
        returns (
            uint256[] memory burnIds,
            uint256[] memory burnAmounts,
            uint256[] memory mintIds,
            uint256[] memory mintAmounts
        );

    function doInteraction(Interaction calldata interaction)
        external
        payable
        returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount);

    function forwardedDoInteraction(
        Interaction calldata interaction,
        address userAddress
    )
        external
        payable
        returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount);
}

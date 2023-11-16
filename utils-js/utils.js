const {
    COMPUTE_INPUT_AMOUNT,
    COMPUTE_OUTPUT_AMOUNT,
    ELEVEN_BYTES_OF_PADDING,
    ERC20_WRAP,
    ERC20_UNWRAP,
    ERC721_WRAP,
    ERC721_UNWRAP,
    ERC1155_WRAP,
    ERC1155_UNWRAP
} = require("./constants");

const calculateWrappedTokenId = ({ address, id }) => {
    return ethers.utils.solidityKeccak256(["address", "uint256"], [address, id]);
}

const idsFromInteractions = ({ interactions }) => {
    const interactionToIds = ({ interaction }) => {
        const interactionIds = [];
        const { interactionType, address } = unpackInteractionTypeAndAddress({
            interactionTypeAndAddress: interaction.interactionTypeAndAddress
        });
        if (interactionType === ERC20_WRAP || interactionType === ERC20_UNWRAP) {
            interactionIds.push(calculateWrappedTokenId({
                address: address,
                id: 0
            }))
        } else if (
            interactionType === ERC721_WRAP
            || interactionType === ERC721_UNWRAP
            || interactionType === ERC1155_WRAP
            || interactionType === ERC1155_UNWRAP
        ) {
            interactionIds.push(
                calculateWrappedTokenId({
                    address: address,
                    id: interaction.metadata
                })
            );
        } else if (
            interactionType === COMPUTE_INPUT_AMOUNT
            || interactionType == COMPUTE_OUTPUT_AMOUNT
        ) {
            interactionIds.push(interaction.inputToken);
            interactionIds.push(interaction.outputToken);
        } else {
            throw new Error("INVALID INTERACTION TYPE");
        }
        return interactionIds;
    }
    // for each interaction, determine the relevant unified ledger IDs
    const idsArrayNested = interactions.map((interaction) => interactionToIds({ interaction }));
    // flatten the nested arrays and take the set to find unique ids
    const idsSet = new Set(idsArrayNested.flat());
    // Set.values() returns an iterator, spread it into a list
    const idsList = [...idsSet.values()];
    // because of the 
    const ids = idsList.map((id) => ethers.BigNumber.from(id));
    return ids;
}

const packInteractionTypeAndAddress = ({ interactionType, address }) => {
    console.assert(ethers.utils.isAddress(address));
    return ethers.utils.hexConcat([interactionType, ELEVEN_BYTES_OF_PADDING, address]);
}

const numberWithFixedDecimals = ({ number, decimals }) => {
    const base = ethers.BigNumber.from("10");
    const mantissa = ethers.BigNumber.from(number);
    const exponent = ethers.BigNumber.from(decimals);
    return mantissa.mul(base.pow(exponent))
}

const unpackInteractionTypeAndAddress = ({ interactionTypeAndAddress }) => {
    const interactionType = ethers.utils.hexDataSlice(interactionTypeAndAddress, 0, 1);
    const address = ethers.utils.hexDataSlice(interactionTypeAndAddress, 12);
    console.assert(ethers.utils.isAddress(address));
    return { interactionType, address };
}

const useDelta = (interaction) => {
    return {
        ...interaction,
        specifiedAmount: ethers.constants.MaxUint256
    }
}

module.exports = {
    calculateWrappedTokenId,
    idsFromInteractions,
    numberWithFixedDecimals,
    packInteractionTypeAndAddress,
    unpackInteractionTypeAndAddress,
    useDelta
}
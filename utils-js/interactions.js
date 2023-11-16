const {
    COMPUTE_INPUT_AMOUNT,
    COMPUTE_OUTPUT_AMOUNT,
    ERC20_WRAP,
    ERC20_UNWRAP,
    ERC721_WRAP,
    ERC721_UNWRAP,
    ERC1155_WRAP,
    ERC1155_UNWRAP,
    THIRTY_TWO_BYTES_OF_ZERO,
    OCEAN_NORMALIZED_DECIMALS
} = require("./constants");

const {
    packInteractionTypeAndAddress,
    numberWithFixedDecimals
} = require("./utils");


const wrapERC20 = ({ address, amount }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC20_WRAP,
        address
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: amount,
        metadata: THIRTY_TWO_BYTES_OF_ZERO
    };
}

const unitWrapERC20 = ({ address, amount }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC20_WRAP,
        address
    });
    const unitAmount = numberWithFixedDecimals({
        number: amount,
        decimals: OCEAN_NORMALIZED_DECIMALS
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: unitAmount,
        metadata: THIRTY_TWO_BYTES_OF_ZERO
    };
}

const wrapERC721 = ({ address, id }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC721_WRAP,
        address
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: 1,
        metadata: ethers.utils.hexZeroPad(id, 32)
    };
}

const wrapERC1155 = ({ address, id, amount }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC1155_WRAP,
        address
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: amount,
        metadata: ethers.utils.hexZeroPad(id, 32)
    };
}

const unwrapERC20 = ({ address, amount }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC20_UNWRAP,
        address
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: amount,
        metadata: THIRTY_TWO_BYTES_OF_ZERO
    };
}

const unitUnwrapERC20 = ({ address, amount }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC20_UNWRAP,
        address
    });
    const unitAmount = numberWithFixedDecimals({
        number: amount,
        decimals: OCEAN_NORMALIZED_DECIMALS
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: unitAmount,
        metadata: THIRTY_TWO_BYTES_OF_ZERO
    };
}

const unwrapERC721 = ({ address, id }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC721_UNWRAP,
        address
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: 1,
        metadata: ethers.utils.hexZeroPad(id, 32)
    };
}

const unwrapERC1155 = ({ address, id, amount }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: ERC1155_UNWRAP, address
    });
    return {
        interactionTypeAndAddress: interactionTypeAndAddress,
        inputToken: 0,
        outputToken: 0,
        specifiedAmount: amount,
        metadata: ethers.utils.hexZeroPad(id, 32)
    };
}

const computeOutputAmount = ({ address, inputToken, outputToken, specifiedAmount, metadata }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: COMPUTE_OUTPUT_AMOUNT,
        address
    });
    return {
        interactionTypeAndAddress,
        inputToken,
        outputToken,
        specifiedAmount,
        metadata
    };
}

const computeInputAmount = ({ address, inputToken, outputToken, specifiedAmount, metadata }) => {
    const interactionTypeAndAddress = packInteractionTypeAndAddress({
        interactionType: COMPUTE_INPUT_AMOUNT,
        address
    });
    return {
        interactionTypeAndAddress,
        inputToken,
        outputToken,
        specifiedAmount,
        metadata
    };
}

module.exports = {
    computeInputAmount,
    computeOutputAmount,
    unitUnwrapERC20,
    unitWrapERC20,
    unwrapERC1155,
    unwrapERC20,
    unwrapERC721,
    wrapERC1155,
    wrapERC20,
    wrapERC721
}
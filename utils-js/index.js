const constants = require("./constants");
const interactions = require("./interactions");
const utils = require("./utils");

const executeInteractions = async ({ ocean, signer, interactions }) => {
    const ids = utils.idsFromInteractions({ interactions });
    return await ocean.connect(signer).doMultipleInteractions(interactions, ids);
}

const executeInteraction = async ({ ocean, signer, interaction }) => {
    return await ocean.connect(signer).doInteraction(interaction);
}

module.exports = {
    constants,
    executeInteractions,
    executeInteraction,
    interactions,
    utils
}
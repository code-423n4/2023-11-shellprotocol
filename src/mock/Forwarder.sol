// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import { IOceanInteractions, Interaction } from "../ocean/Interactions.sol";

contract Forwarder {
    function singlePassthrough(Interaction calldata interaction, address ocean) external returns (bool) {
        IOceanInteractions(ocean).forwardedDoInteraction(interaction, msg.sender);
        return true;
    }

    function multiplePassthrough(
        Interaction[] calldata interactions,
        uint256[] calldata ids,
        address ocean
    )
        external
        returns (bool)
    {
        IOceanInteractions(ocean).forwardedDoMultipleInteractions(interactions, ids, msg.sender);
        return true;
    }
}

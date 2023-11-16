// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "../ocean/Ocean.sol";
import "forge-std/Script.sol";

contract DeployOcean is Script {
    Ocean _ocean;

    function run() external {
        vm.startBroadcast();

        _ocean = new Ocean("");
        console.log(address(_ocean));
    }
}
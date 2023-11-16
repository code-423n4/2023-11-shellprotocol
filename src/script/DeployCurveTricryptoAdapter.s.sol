// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "../adapters/CurveTricryptoAdapter.sol";
import "forge-std/Script.sol";

contract DeployCurveTricryptoAdapter is Script {
    CurveTricryptoAdapter _curveAdapter;

    function run() external {
        vm.startBroadcast();

        _curveAdapter = new CurveTricryptoAdapter(address(23), address(25)); // using mock values
        console.log(address(_curveAdapter));
    }
}
// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "../adapters/Curve2PoolAdapter.sol";
import "forge-std/Script.sol";

contract DeployCurve2PoolAdapter is Script {
    Curve2PoolAdapter _curveAdapter;

    function run() external {
        vm.startBroadcast();

        _curveAdapter = new Curve2PoolAdapter(address(23), address(25)); // using mock values
        console.log(address(_curveAdapter));
    }
}
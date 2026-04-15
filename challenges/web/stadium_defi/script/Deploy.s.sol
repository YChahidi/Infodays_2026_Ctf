// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {StadiumBetting} from "../contracts/StadiumBetting.sol";
import {TrophyVault} from "../contracts/TrophyVault.sol";

contract Deploy is Script {
    function run() external {
        string memory flag = vm.envString("FLAG");
        uint256 seedWei = vm.envOr("TREASURY_SEED_WEI", uint256(10 ether));

        vm.startBroadcast();

        StadiumBetting betting = new StadiumBetting{value: seedWei}();
        TrophyVault vault = new TrophyVault(flag, address(betting));

        vm.stopBroadcast();

        string memory json = string.concat(
            '{"betting":"',
            vm.toString(address(betting)),
            '","vault":"',
            vm.toString(address(vault)),
            '","seedWei":"',
            vm.toString(seedWei),
            '"}'
        );
        vm.writeFile("/app/state/deployed.json", json);
    }
}

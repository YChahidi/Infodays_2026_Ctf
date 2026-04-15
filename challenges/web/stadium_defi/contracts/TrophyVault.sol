// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Trophy Vault
/// @notice Holds the Infodays 2026 tournament sealed flag. The flag is
///         released the moment the Stadium Betting treasury is fully
///         drained — at which point the tournament is considered "called".
contract TrophyVault {
    bool public claimed;
    string private _flag;
    address public immutable betting;

    event FlagClaimed(address indexed winner, string flag);

    constructor(string memory flag_, address betting_) {
        _flag = flag_;
        betting = betting_;
    }

    /// @notice Claim the sealed flag once the betting treasury hits zero.
    function claim() external {
        require(!claimed, "already claimed");
        require(betting.balance == 0, "treasury not drained");
        claimed = true;
        emit FlagClaimed(msg.sender, _flag);
    }

    /// @notice Read the flag after a successful claim.
    function flag() external view returns (string memory) {
        require(claimed, "not claimed yet");
        return _flag;
    }
}

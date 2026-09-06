// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Stadium Betting Pool
/// @notice Infodays 2026 tournament betting treasury. Users deposit ETH to
///         lock a position on match outcomes; the treasury holds the pool
///         until the final whistle.
contract StadiumBetting {
    mapping(address => uint256) public balance;
    uint256 public totalDeposited;

    bool private _locked;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    modifier nonReentrant() {
        require(!_locked, "reentrancy");
        _locked = true;
        _;
        _locked = false;
    }

    constructor() payable {
        // Treasury is seeded with house liquidity from the tournament
        // organisers at deploy time. This ETH backs early payouts.
    }

    function deposit() external payable {
        require(msg.value > 0, "no value");
        balance[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Standard withdraw. Protected against reentrancy.
    function withdraw(uint256 amount) external nonReentrant {
        require(balance[msg.sender] >= amount, "insufficient");
        balance[msg.sender] -= amount;
        totalDeposited -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Drain the caller's entire stake in a single call.
    /// @dev    Legacy helper used by the mobile app before the refactor.
    ///         TODO(ops): migrate callers to withdraw() and remove this.
    function emergencyWithdraw() external {
        uint256 amount = balance[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balance[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);
    }

    receive() external payable {
        // Accept raw ETH top-ups from the house.
    }
}

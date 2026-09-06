// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title Golden Boot Kernel — v2 (INSANE)
/// @notice Strictly-gated UUPS kernel that records who holds a Golden
///         Boot Pass.  Passes are bearer tokens signed off-chain by
///         Erling Haaland's signer key.  Upgrades require at least two
///         passes to the SAME caller, forcing attackers to forge
///         multiple sigs rather than just malleating one.
///
///         Three-bug design:
///           1. _recover() is permissive (no low-s check) — malleability
///              is possible but useless: (holder, nonce) replay dedup
///              blocks reusing either promo sig from a different holder.
///           2. The deploy broadcasts TWO canary signatures that share
///              an ECDSA nonce k — recover the signer's private key
///              from (r, s1, m1) + (r, s2, m2) and forge passes at will.
///           3. upgradeToAndCall's gate requires passCount[msg.sender]
///              >= 2, forcing the attacker to actually use the
///              recovered privkey to mint two passes under distinct
///              nonces.
contract GoldenBootKernel is Initializable, UUPSUpgradeable {
    // -------------------------------------------------------- storage

    address public signer;
    mapping(bytes32 => bool) public usedSigHash;        // legacy replay (malleable)
    mapping(bytes32 => bool) public usedHolderNonce;    // real replay (holder || nonce)
    mapping(address => uint256) public passCount;

    // -------------------------------------------------------- events

    event PassMinted(address indexed holder, uint256 nonce, bytes signature);
    event GoldenBootClaimed(address indexed winner);

    // -------------------------------------------------------- init

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    function initialize(address _signer) external initializer {
        __UUPSUpgradeable_init();
        signer = _signer;
    }

    // -------------------------------------------------------- pass

    /// @notice Canonical per-pass digest.  Bound to holder + nonce so
    ///         malleability is a dead end.
    function passDigest(address holder, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("HAALAND_GB_PASS_V2", holder, nonce));
    }

    /// @notice Submit a signed pass for `holder`.  nonce must be unused.
    function mintPass(address holder, uint256 nonce, bytes calldata sig) external {
        bytes32 sigHash = keccak256(sig);
        require(!usedSigHash[sigHash], "sig replay");
        bytes32 hnHash = keccak256(abi.encode(holder, nonce));
        require(!usedHolderNonce[hnHash], "holder/nonce replay");

        require(_recover(passDigest(holder, nonce), sig) == signer, "bad sig");

        usedSigHash[sigHash] = true;
        usedHolderNonce[hnHash] = true;
        passCount[holder] += 1;
        emit PassMinted(holder, nonce, sig);
    }

    // -------------------------------------------------------- upgrade

    function _authorizeUpgrade(address) internal view override {
        require(passCount[msg.sender] >= 2, "need 2 passes to upgrade");
    }

    // -------------------------------------------------------- crypto

    /// @dev Permissive recovery: accepts high-s values, so (r, s) and
    ///      (r, n-s) both recover the same signer.  Malleability is
    ///      useful in other contexts but this contract's replay check
    ///      on (holder, nonce) neutralises it.
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) { v += 27; }
        return ecrecover(digest, v, r, s);
    }

    // storage gap for upgrades (-1 bytes32 for `passCount`)
    uint256[46] private __gap;
}

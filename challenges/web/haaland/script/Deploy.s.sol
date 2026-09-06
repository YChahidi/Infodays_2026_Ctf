// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {GoldenBootKernel} from "../contracts/GoldenBootKernel.sol";

/// @notice Deploys the proxy + kernel and broadcasts the two canary
///         promo signatures (which share an ECDSA nonce — that's the
///         intended weakness).  Signatures are pre-computed off-chain
///         by `script/gen_promos.py` and passed in via env vars.
contract Deploy is Script {
    function run() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        uint256 signerPk   = vm.envUint("SIGNER_PK");
        uint256 promoPk1   = vm.envUint("PROMO_PK_1");
        uint256 promoPk2   = vm.envUint("PROMO_PK_2");
        bytes memory sig1  = vm.envBytes("PROMO_SIG_1");
        bytes memory sig2  = vm.envBytes("PROMO_SIG_2");

        address signer = vm.addr(signerPk);
        address promo1 = vm.addr(promoPk1);
        address promo2 = vm.addr(promoPk2);

        vm.startBroadcast(deployerPk);
        GoldenBootKernel impl = new GoldenBootKernel();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(GoldenBootKernel.initialize, (signer))
        );
        vm.stopBroadcast();

        GoldenBootKernel kernel = GoldenBootKernel(address(proxy));

        // Promo holder 1 redeems their pass.
        vm.startBroadcast(promoPk1);
        kernel.mintPass(promo1, 0, sig1);
        vm.stopBroadcast();

        // Promo holder 2 redeems their pass — same k, different msg.
        vm.startBroadcast(promoPk2);
        kernel.mintPass(promo2, 0, sig2);
        vm.stopBroadcast();

        console.log("proxy   ", address(proxy));
        console.log("impl    ", address(impl));
        console.log("signer  ", signer);
        console.log("promo1  ", promo1);
        console.log("promo2  ", promo2);

        string memory json = string.concat(
            '{"proxy":"',   vm.toString(address(proxy)),
            '","impl":"',   vm.toString(address(impl)),
            '","signer":"', vm.toString(signer),
            '","promos":["', vm.toString(promo1), '","', vm.toString(promo2), '"]',
            '}'
        );
        vm.writeFile("/app/state/deployed.json", json);
    }
}

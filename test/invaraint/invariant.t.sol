// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Test } from "forge-std/Test.sol";
import { Handler } from "./handler.t.sol";
import { L1Token } from "src/L1Token.sol";
import { L1BossBridge } from "src/L1BossBridge.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";

contract InvariantTest is StdInvariant, Test {
    Handler handler;
    L1Token token;
    L1BossBridge bridge;
    Account signer;
    address initialUser;
    uint256 initialLiquidity = 1000e18;

    function setUp() external {
        token = new L1Token();
        signer = makeAccount("signer");
        bridge = new L1BossBridge(IERC20(token));
        bridge.setSigner(signer.addr, true);
        handler = new Handler(address(bridge), signer.key);

        address initialUserL2 = makeAddr("initalUserL2");
        deal(address(token), address(this), initialLiquidity);

        token.approve(address(bridge), initialLiquidity);
        bridge.depositTokensToL2(address(this), initialUserL2, initialLiquidity);

        bytes4[] memory targetSelectors = new bytes4[](2);
        targetSelectors[0] = handler.depositToBridge.selector;
        targetSelectors[1] = handler.withdrawFromBridge.selector;

        targetSelector(FuzzSelector(address(handler), targetSelectors));
        targetContract(address(handler));
    }

    function invariantUserWithdrawlsLessThanDeposits() external {
        assertLe(handler.userWithdrawals(), handler.userDeposits(), "Withdrawan more than deposited");
    }
}

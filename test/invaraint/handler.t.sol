// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { L1BossBridge } from "src/L1BossBridge.sol";
import { L1Token } from "src/L1Token.sol";
import { L1Vault } from "src/L1Vault.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Handler is Test {
    L1BossBridge immutable i_bridge;
    L1Token immutable i_token;
    L1Vault immutable i_vault;
    uint256 private signerKey;
    // Track balances
    // Tracking Variables
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public userDeposits;
    uint256 public userWithdrawals;
    uint256 public vaultBalances; // Tracks expected vault balance per user

    address user = makeAddr("user");

    constructor(address bridge, uint256 key) {
        i_bridge = L1BossBridge(bridge);
        i_token = L1Token(address(i_bridge.token()));
        i_vault = i_bridge.vault();
        signerKey = key;
    }

    function depositToBridge(uint256 amount, address l2Recipient) external {
        uint256 vaultBalance = i_token.balanceOf(address(i_vault));
        amount = bound(amount, 0, i_bridge.DEPOSIT_LIMIT() - vaultBalance);

        deal(address(i_token), user, amount);
        vm.startPrank(user);
        i_token.approve(address(i_bridge), amount);
        i_bridge.depositTokensToL2(user, l2Recipient, amount);
        vm.stopPrank();

        userDeposits += amount;
        vaultBalances = vaultBalance + amount;
    }

    function withdrawFromBridge(uint256 amount) external {
        vm.assume(userDeposits > 0);
        uint256 vaultBalance = i_token.balanceOf(address(i_vault));

        amount = bound(amount, 0, userDeposits);
        vm.assume(i_token.balanceOf(address(i_vault)) >= amount);
        (uint8 v, bytes32 r, bytes32 s) = _createSignedWithdrawal(user, amount);
        vm.prank(user);
        i_bridge.withdrawTokensToL1(user, amount, v, r, s);

        userWithdrawals += amount;
        vaultBalances = vaultBalance - amount;
    }

    function _createSignedWithdrawal(
        address to,
        uint256 amount
    )
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        // Create the message payload
        bytes memory message = abi.encode(
            address(i_token),
            0, // value
            abi.encodeCall(IERC20.transferFrom, (address(i_vault), to, amount))
        );

        // Hash and sign the message
        bytes32 messageHash = keccak256(message);
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        (v, r, s) = vm.sign(signerKey, ethSignedHash);
    }
}

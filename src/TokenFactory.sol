// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/* 
* @title TokenFactory
* @dev Allows the owner to deploy new ERC20 contracts
* @dev This contract will be deployed on both an L1 & an L2
*/
contract TokenFactory is Ownable {
    mapping(string tokenSymbol => address tokenAddress) private s_tokenToAddress;

    event TokenDeployed(string symbol, address addr);

    constructor() Ownable(msg.sender) { }

    /*
     * @dev Deploys a new ERC20 contract
     * @param symbol The symbol of the new token
     * @param contractBytecode The bytecode of the new token
     */
    //@audit-high assembly code will never work because contracts cannot be deployed on EraVM using any kind of bytecode
    //@note https://docs.zksync.io/zksync-protocol/differences/evm-instructions
    //@note EraVM does not use bytecode for contract deployment. Instead, it refers to contracts using their bytecode
    // hashes. In order to deploy a contract, please use the `new` operator in Solidity instead of raw
    // 'create'/'create2' in assembly
    //@audit-low this can be masked as external rather public
    function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        //@audit-q are you sure you want this out of scope. There could be better ways to do this.
        assembly {
            addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }

    //@audit-low this can be masked as external rather public
    function getTokenAddressFromSymbol(string memory symbol) public view returns (address addr) {
        return s_tokenToAddress[symbol];
    }
}

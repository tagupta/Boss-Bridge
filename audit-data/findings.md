### [H-1] Use of create opcode in `TokenFactory::deployToken` causes token deployment to fail on zkSync Era (Unsupported Opcode → Token Creation Failure)

**Description:** The `TokenFactory::deployToken` function uses the low-level `create` opcode to deploy new token contracts. However, `zkSync Era` does not currently support the create opcode for contract deployment. Any transaction attempting to execute this function will revert, making it impossible to deploy tokens through this method.

```js
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr)
    {
        assembly {
@>           addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }
```

**Impact:** All attempts to deploy `TokenFactory` contract on `zksync era` will fail, preventing the intended functionality of dynamic token creation.

**Proof of Concept:**

1. Deploy the contract containing deployToken to zkSync Era.
2. Call deployToken("TEST", contractBytecode) with valid ERC20 bytecode.
3. Transaction fails with an "unsupported opcode" error due to the create opcode execution.

**Recommended Mitigation:**

> EraVM does not use bytecode for contract deployment. Instead, it refers to contracts using their bytecode
> hashes. In order to deploy a contract, please use the `new` operator in Solidity instead of raw **'create'/'create2'** in assembly.

Replace the low-level create opcode with a deployment method supported by zkSync Era, such as:

- Using CREATE2 (which zkSync Era supports), ensuring deterministic addresses.
- Using zkSync-specific factory patterns or system calls (SystemContracts API).
- Leveraging zkSync's ContractDeployer precompile for contract creation.

For more information, refer[this](https://docs.zksync.io/zksync-protocol/differences/evm-instructions) document from zksync.

### [G-1] Functions can be marked external instead of public to optimize gas

**Description:**

```js
function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        assembly {
            addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }
```

```js
function getTokenAddressFromSymbol(string memory symbol) public view returns (address addr) {
        return s_tokenToAddress[symbol];
    }
```

**Impact:** This is a minor gas optimization opportunity. Changing from public to external can reduce gas costs for each external call, improving efficiency in production deployments.

**Recommended Mitigation:**
Change the function visibility from public to external:

```diff
-   function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {}
+   function deployToken(string memory symbol, bytes memory contractBytecode) external onlyOwner returns (address addr) {}

-   function getTokenAddressFromSymbol(string memory symbol) public view returns (address addr) {}
+   function getTokenAddressFromSymbol(string memory symbol) external view returns (address addr) {}
```

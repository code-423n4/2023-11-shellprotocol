# Winning bot race submission
 This is the top-ranked automated findings report, from The_Madaladinator bot. All findings in this report will be considered known issues for the purposes of your C4 audit.
 
 Shell Protocol Bot Race Report - The_Madaladinator

 ## Summary

 | |Issue|Instances| Gas Savings
 |-|:-|:-:|:-:|
| [[M-01](#m-01)] | Centralization risk | 51| 0|
| [[M-02](#m-02)] | `approve` return value not checked | 4| 0|
| [[M-03](#m-03)] | Contracts are completely non-functional due to incompatible Solidity version with Arbitrum | 4| 0|
| [[L-01](#l-01)] | User facing functions should have `address(0)` checks | 20| 0|
| [[L-02](#l-02)] | Use `require` instead of `assert` | 4| 0|
| [[L-03](#l-03)] | Lack of two-step update for critical functions | 1| 0|
| [[L-04](#l-04)] | `decimals()` is not part of the ERC20 standard | 8| 0|
| [[L-05](#l-05)] | Some tokens may revert when zero value transfers are made | 1| 0|
| [[L-06](#l-06)] | Unused/empty `receive`/`fallback` function | 1| 0|
| [[L-07](#l-07)] | Some tokens do not consider `type(uint256).max` as an infinite approval | 4| 0|
| [[L-08](#l-08)] | Contracts use infinite approvals with no means to revoke | 6| 0|
| [[L-09](#l-09)] | Cap state variables at reasonable values | 57| 0|
| [[L-10](#l-10)] | Checks-Effects-Interactions pattern not followed | 12| 0|
| [[L-11](#l-11)] | Some tokens may revert on large approvals | 4| 0|
| [[L-12](#l-12)] | Some tokens may revert on large transfers | 1| 0|
| [[L-13](#l-13)] | Vulnerable package versions are being used | 1| 0|
| [[L-14](#l-14)] | Possible loss of precision | 4| 0|
| [[L-15](#l-15)] | Downcasting `uint` or `int` may result in overflow | 1| 0|
| [[L-16](#l-16)] | Use a low level call to send ether instead of `.send()` or `.transfer()` | 1| 0|
| [[G-01](#g-01)] | `abi.encodePacked` is more gas efficient than `abi.encode` | 1| 0|
| [[G-02](#g-02)] | Functions guaranteed to revert when called by normal users can be marked `payable` | 51| 42|
| [[G-03](#g-03)] | Use assembly to emit events | 22| 114|
| [[G-04](#g-04)] | Use assembly to calculate hashes | 1| 374|
| [[G-05](#g-05)] | Using assembly's `selfbalance()` is cheaper than `address(this).balance` | 1| 159|
| [[G-06](#g-06)] |  Use assembly to write storage values | 28| 300|
| [[G-07](#g-07)] | Use `require` instead of `assert` | 4| 0|
| [[G-08](#g-08)] | Assigning to structs can be more efficient | 42| 260|
| [[G-09](#g-09)] | Avoid zero transfer to save gas | 2| 100|
| [[G-10](#g-10)] | `address(this)` should be cached | 13| 0|
| [[G-11](#g-11)] | Cache multiple accesses of mapping/array values | 7| 42|
| [[G-12](#g-12)] | Function result should be cached | 50| 0|
| [[G-13](#g-13)] | Use `calldata` instead of `memory` for function arguments that are read only | 25| 0|
| [[G-14](#g-14)] | Divisions can be `unchecked` to save gas | 4| 40|
| [[G-15](#g-15)] | Same cast is done multiple times | 69| 0|
| [[G-16](#g-16)] | Stack variable cost less while used in emitting event | 1| 97|
| [[G-17](#g-17)] | Cache length outside of for loop | 1| 97|
| [[G-18](#g-18)] | Use `do while` loops intead of `for` loops | 2| 23|
| [[G-19](#g-19)] | Using `>=` is cheaper than `>` | 11| 6|
| [[G-20](#g-20)] | Inline `modifier`s that are only used once, to save gas | 3| 0|
| [[G-21](#g-21)] | Inline `internal` functions that are only called once | 5| 60|
| [[G-22](#g-22)] | Expressions for constant values such as a call to `keccak256` should use `immutable` rather than `constant` | 1| 100|
| [[G-23](#g-23)] | Using `storage` instead of `memory` for structs/arrays saves gas | 15| 0|
| [[G-24](#g-24)] | Refactor modifiers to call a local function | 1| 1000|
| [[G-25](#g-25)] | Combine multiple mappings with the same key type where appropriate | 4| 40084|
| [[G-26](#g-26)] | Nesting `if`-statements is cheaper than using `&&` | 12| 6|
| [[G-27](#g-27)] | Function names can be optimized to save gas | 74| 22|
| [[G-28](#g-28)] | Use `payable` for constructor | 4| 84|
| [[G-29](#g-29)] | Use more recent OpenZeppelin version for gas boost | 4| 0|
| [[G-30](#g-30)] | Not using the named return variable is confusing and can waste gas | 124| 0|
| [[G-31](#g-31)] | Use `solady` library where possible to save gas | 1| 0|
| [[G-32](#g-32)] | Assigning state variables directly with named struct constructors wastes gas | 14| 56|
| [[G-33](#g-33)] | Use `!= 0` instead of `> 0` for uints | 8| 6|
| [[G-34](#g-34)] | Usage of `uint` smaller than 32 bytes (256 bits) incurs overhead | 2| 12|
| [[G-35](#g-35)] | Use named return values | 4| 0|
| [[G-36](#g-36)] | Avoid updating storage when the value hasn't changed | 6| 800|
| [[G-37](#g-37)] | Use assembly for integer zero checks | 1| 6|
| [[G-38](#g-38)] | Use custom errors | 3| 24|
| [[G-39](#g-39)] | Use `via-ir` for deployment | 1| 0|
| [[N-01](#n-01)] | Not using the named return variable anywhere in the function is confusing | 75| 0|
| [[N-02](#n-02)] | Use modifiers for address checks | 1| 0|
| [[N-03](#n-03)] | Missing `address(0)` checks when assigning to `address` state variables | 2| 0|
| [[N-04](#n-04)] | Consider adding denylist | 1| 0|
| [[N-05](#n-05)] | Functions missing empty `bytes` check | 24| 0|
| [[N-06](#n-06)] | Comparisons should place constants on the left hand side | 7| 0|
| [[N-07](#n-07)] | Use enum values instead of constant array indexes | 5| 0|
| [[N-08](#n-08)] | `constructor` should emit an event | 4| 0|
| [[N-09](#n-09)] | Contracts should expose an `interface` | 2| 0|
| [[N-10](#n-10)] | Contract does not follow suggested layout ordering | 22| 0|
| [[N-11](#n-11)] | Control structures do not follow the Solidity style guide | 261| 0|
| [[N-12](#n-12)] | Take advantage of Custom Error's return value property | 11| 0|
| [[N-13](#n-13)] | Use custom errors rather than `require`/`revert` | 3| 0|
| [[N-14](#n-14)] | Complex casting | 3| 0|
| [[N-15](#n-15)] | Redundant `else` block | 42| 0|
| [[N-16](#n-16)] | Consider adding emergency-stop functionality | 2| 0|
| [[N-17](#n-17)] | Use `ERC1155Holder` over `ERC1155Receiver` | 1| 0|
| [[N-18](#n-18)] | Events may be emitted out of order due to reentrancy | 112| 0|
| [[N-19](#n-19)] | Event missing `msg.sender` parameter | 13| 0|
| [[N-20](#n-20)] | Use `indexed` for event parameters | 49| 0|
| [[N-21](#n-21)] | Function modifier order does not follow the Solidity Style Guide | 26| 0|
| [[N-22](#n-22)] | Function order doesn't follow Solidity style guide | 4| 0|
| [[N-23](#n-23)] | High Cyclomatic Complexity in Functions | 44| 0|
| [[N-24](#n-24)] | `address` parameters should be sanitized | 180| 0|
| [[N-25](#n-25)] | Use ternary expressions over `if`/`else` where possible | 27| 0|
| [[N-26](#n-26)] | Variable names for `immutable` variables should be in CONSTANT_CASE | 9| 0|
| [[N-27](#n-27)] | Visibility should be explicitly set rather than defaulting to `internal` | 13| 0|
| [[N-28](#n-28)] | Imports could be organized more systematically | 4| 0|
| [[N-29](#n-29)] | Place `interface` files into a dedicated folder | 1| 0|
| [[N-30](#n-30)] | Complex functions should include comments | 1| 0|
| [[N-31](#n-31)] | Lines too long | 8| 0|
| [[N-32](#n-32)] | Use constants rather than magic numbers | 5| 0|
| [[N-33](#n-33)] | Import specific identifiers rather than the whole file | 6| 0|
| [[N-34](#n-34)] | Multiple address/ID mappings can be combined into a single mapping of an address/ID to a struct, for readability | 4| 0|
| [[N-35](#n-35)] | Array inputs not sanitised | 30| 0|
| [[N-36](#n-36)] | Use named function calls | 4| 0|
| [[N-37](#n-37)] | Use named parameters for mappings | 5| 0|
| [[N-38](#n-38)] | Named return variables used before assignment | 1| 0|
| [[N-39](#n-39)] | Natspec: contract natspec missing | 1| 0|
| [[N-40](#n-40)] | Natspec: contract natspec missing `@author` tag | 4| 0|
| [[N-41](#n-41)] | Natspec: contract natspec missing `@dev` tag | 4| 0|
| [[N-42](#n-42)] | Natspec: contract natspec missing `@notice` tag | 2| 0|
| [[N-43](#n-43)] | Natspec: contract natspec missing `@title` tag | 4| 0|
| [[N-44](#n-44)] | Natspec: error natspec missing | 2| 0|
| [[N-45](#n-45)] | Natspec: error natspec missing `@dev` tag | 4| 0|
| [[N-46](#n-46)] | Natspec: error natspec missing `@notice` tag | 4| 0|
| [[N-47](#n-47)] | Natspec: error natspec missing `@param` tag | 2| 0|
| [[N-48](#n-48)] | Natspec: event natspec missing | 82| 0|
| [[N-49](#n-49)] | Natspec: event natspec missing `@dev` tag | 98| 0|
| [[N-50](#n-50)] | Natspec: event natspec missing `@notice` tag | 98| 0|
| [[N-51](#n-51)] | Natspec: event natspec missing `@param` tag | 98| 0|
| [[N-52](#n-52)] | Natspec: function natspec missing | 14| 0|
| [[N-53](#n-53)] | Natspec: modifier natspec missing `@dev` tag | 1| 0|
| [[N-54](#n-54)] | Natspec: modifier natspec missing `@notice` tag | 1| 0|
| [[N-55](#n-55)] | Non-external function names should begin with an underscore | 35| 0|
| [[N-56](#n-56)] | Non-external variable names should begin with an underscore | 6| 0|
| [[N-57](#n-57)] | `public` functions not called internally should be declared `external` | 1| 0|
| [[N-58](#n-58)] | Use descriptive reason strings for `require`/`revert` | 3| 0|
| [[N-59](#n-59)] | Use a `struct` instead of returning multiple values | 99| 0|
| [[N-60](#n-60)] | Make use of Solidiy's `using` keyword | 23| 0|
| [[N-61](#n-61)] | Use scientific notation/underscores for large values | 1| 0|
| [[N-62](#n-62)] | Setter does not check that value is changed | 6| 0|
| [[N-63](#n-63)] | Consider using a timelock for admin/governance functions | 1| 0|
| [[N-64](#n-64)] | Use single file for all system-wide constants | 5| 0|
| [[N-65](#n-65)] | Body of `if` statement should be placed on a new line | 8| 0|
| [[N-66](#n-66)] | State variable declaration should include comments | 3| 0|
| [[N-67](#n-67)] | Structs, enums, events and errors should be named using CapWords style | 4| 0|
| [[N-68](#n-68)] | Function returns unassigned variable | 34| 0|
| [[N-69](#n-69)] | Avoid using underscore at the end of a variable name | 9| 0|
| [[N-70](#n-70)] | Large numeric literals should use underscores | 1| 0|
| [[N-71](#n-71)] | Use inline comments for unnamed variables | 38| 0|
| [[N-72](#n-72)] | Remove unused imports | 2| 0|
| [[N-73](#n-73)] | Unused local variable | 1| 0|
| [[N-74](#n-74)] | Use `bytes.concat` over `abi.encodePacked` | 1| 0|
| [[N-75](#n-75)] | Use `delete` rather than assigning to `0` | 19| 0|
| [[N-76](#n-76)] | Use of `approve` is discouraged | 4| 0|
| [[N-77](#n-77)] | Use `@inheritdoc` for overridden functions | 122| 0|
| [[N-78](#n-78)] | Use named return values | 30| 0|
| [[N-79](#n-79)] | Use a `struct` to encapsulate multiple function parameters | 75| 0|
| [[N-80](#n-80)] | Use descriptive constant rather than `0` for function arguments | 20| 0|
| [[N-81](#n-81)] | No need to initialize variables to their default value | 2| 0|
| [[N-82](#n-82)] | Variable names should not end with an underscore | 7| 0|
| [[N-83](#n-83)] | Avoid extraneous whitespace | 4| 0|
| [[N-84](#n-84)] | Missing `address(0)` checks in constructor | 3| 0|
| [[N-85](#n-85)] | Missing zero check when assigning `int`/`uint` to state | 5| 0|
| [[N-86](#n-86)] | Top level declarations should be separated by two blank lines | 80| 0|
| [[N-87](#n-87)] | Large or complicated code bases should implement invariant tests | 1| 0|
| [[N-88](#n-88)] | Tests should have full coverage | 1| 0|
| [[N-89](#n-89)] | Codebase should go through formal verification | 1| 0|


 Shell Protocol Bot Race Report - The_Madaladinator ### Medium Risk Issues


### [M-01]<a name="m-01"></a> Centralization risk
Utilizing an externally owned account (EOA) as the owner of contracts poses significant dangers of centralization and represents a vulnerable single point of failure. A single private key is susceptible to theft during a hacking incident, or the sole possessor of the key may encounter difficulties in retrieving it when required. It is advisable to contemplate transitioning to a multi-signature arrangement or implementing a role-based authorization framework.

*There are 51 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

```


*GitHub* : [L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296)

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

```


*GitHub* : [L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92)
### [M-02]<a name="m-02"></a> `approve` return value not checked
Not all `IERC20` implementations `revert` when there's a failure in `approve`. The function signature has a `boolean` return value and they indicate errors that way instead. By not checking the return value, operations that should have marked as failed, may potentially go through without actually approving anything.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);

191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L190](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L190),[L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);

243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L242),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243)
### [M-03]<a name="m-03"></a> Contracts are completely non-functional due to incompatible Solidity version with Arbitrum
The Shell Protocol V2 is currently live on Arbitrum mainnet (see https://app.shellprotocol.io/). This audit is for V3 and uses version 0.8.20 of Solidity whereas V2 used version 0.8.10 (see [Shell github](https://github.com/Shell-Protocol/Shell-Protocol/blob/main/src/ocean/Ocean.sol)).  The compiler for Solidity 0.8.20 switches the default target EVM version to [Shanghai](https://blog.soliditylang.org/2023/05/10/solidity-0.8.20-release-announcement/#important-note), which includes the new PUSH0 op code. This op code may not yet be implemented on all L2s, so deployment on these chains will fail. See this relevant [issue](https://github.com/ethereum/solidity/issues/14254) on the official Solidity github for reference.  As the contract(s) are intended to be deployed on Arbitrum, this will cause them to be completely non-functional.  To work around this issue, use an earlier EVM version, such as 0.8.19.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

6: pragma solidity 0.8.20;

```


*GitHub* : [L6](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L6)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

4: pragma solidity 0.8.20;

```


*GitHub* : [L4](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L4)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

4: pragma solidity 0.8.20;

```


*GitHub* : [L4](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L4)

```solidity
File: src/adapters/OceanAdapter.sol

4: pragma solidity 0.8.20;

```


*GitHub* : [L4](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L4)### Low Risk Issues


### [L-01]<a name="l-01"></a> User facing functions should have `address(0)` checks
Parameters of type address in your functions should be checked to ensure that they are not assigned the null address (address(0x0)). Failure to validate these parameters can lead to transaction reverts, wasted gas, the need for transaction resubmission, and may even require redeployment of contracts within the protocol in certain situations. Implement checks for address(0x0) to avoid these potential issues.

*There are 20 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

```


*GitHub* : [L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242)
### [L-02]<a name="l-02"></a> Use `require` instead of `assert`
Prior to Solidity 0.8.0, pressing a confirm consumes the remainder of the process's available gas instead of returning it, as request()/revert() did.  assert() and ruqire(); The big difference between the two is that the assert()function when false, uses up all the remaining gas and reverts all the changes made. Meanwhile, a require() function when false, also reverts back all the changes made to the contract but does refund all the remaining gas fees we offered to pay. This is the most common Solidity function used by developers for debugging and error handling.  Assertion() should be avoided even after solidity version 0.8.0, because its documentation states "The Assert function generates an error of type Panic(uint256). Code that works properly should never Panic, even on invalid external input. If this happens, you need to fix it in your contract. there's a mistake".

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

667:             assert(interactionType == InteractionType.UnwrapEther && specifiedToken == WRAPPED_ETHER_ID);

721:             assert(interactionType == InteractionType.UnwrapEther);

1100:             assert(normalizedTruncatedAmount == 0);

1101:             assert(normalizedTransferAmount > amount);

```


*GitHub* : [L667](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L667),[L721](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L721),[L1100](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1100),[L1101](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1101)
### [L-03]<a name="l-03"></a> Lack of two-step update for critical functions
A copy-paste error or a typo may end up bricking protocol functionality, or sending tokens to an address with no known private key. Consider implementing a two-step procedure for critical functions, where the recipient is set as pending, and must "accept" the assignment by making an affirmative call. A straight forward way of doing this would be to have the target contracts implement [EIP-165](https://eips.ethereum.org/EIPS/eip-165), and to have the "set" functions ensure that the recipient is of the right interface type.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

```


*GitHub* : [L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196)
### [L-04]<a name="l-04"></a> `decimals()` is not part of the ERC20 standard
The `decimals()` function is not a part of the [ERC-20 standard](https://eips.ethereum.org/EIPS/eip-20), and was addedlater as an [optional extension](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/IERC20Metadata.sol). As such, some valid ERC20 tokens do not support this interface, so it is unsafe to blindly cast all tokens to this interface, and then call this function.

*There are 8 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

821:         try IERC20Metadata(tokenAddress).decimals() returns (uint8 decimals) {

865:         try IERC20Metadata(tokenAddress).decimals() returns (uint8 decimals) {

```


*GitHub* : [L821](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L821),[L865](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L865)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

81:         decimals[xToken] = IERC20Metadata(xTokenAddress).decimals();

88:         decimals[yToken] = IERC20Metadata(yTokenAddress).decimals();

93:         decimals[lpTokenId] = IERC20Metadata(primitive_).decimals();

```


*GitHub* : [L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L81),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L88),[L93](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L93)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

89:         decimals[xToken] = IERC20Metadata(xTokenAddress).decimals();

96:         decimals[yToken] = IERC20Metadata(yTokenAddress).decimals();

109:         decimals[lpTokenId] = IERC20Metadata(lpTokenAddress).decimals();

```


*GitHub* : [L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L89),[L96](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L96),[L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L109)
### [L-05]<a name="l-05"></a> Some tokens may revert when zero value transfers are made
In spite of the fact that EIP-20 [states](https://github.com/ethereum/EIPs/blob/46b9b698815abbfa628cd1097311deee77dd45c5/EIPS/eip-20.md?plain=1#L116) that zero-valued transfers must be accepted, some tokens, such as LEND will revert if this is attempted, which may cause transactions that involve other tokens (such as batch operations) to fully revert. Consider skipping the transfer if the amount is zero, which will also save gas.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

836:             SafeERC20.safeTransferFrom(IERC20(tokenAddress), userAddress, address(this), transferAmount);

```


*GitHub* : [L836](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L836)
### [L-06]<a name="l-06"></a> Unused/empty `receive`/`fallback` function
If the intention is for the ETH to be used, the function should call another function, otherwise it should revert (e.g. `require(msg.sender == address(weth))`).

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

291:     fallback() external payable { }

```


*GitHub* : [L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L291)
### [L-07]<a name="l-07"></a> Some tokens do not consider `type(uint256).max` as an infinite approval
Some tokens such as [COMP](https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/Governance/Comp.sol#L89-L91) downcast such approvals to uint96 and use that as a raw value rather than interpreting it as an infinite approval. Eventually these approvals will reach zero, at which point the calling contract will no longer function properly.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L190](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L190),[L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L242),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243)
### [L-08]<a name="l-08"></a> Contracts use infinite approvals with no means to revoke
Infinite approvals on external contracts can be dangerous if the target becomes compromised. See [here](https://revoke.cash/exploits) for a list of approval exploits.  The following contracts are vulnerable to such attacks since they have no functionality to revoke the approval (call `approve` with amount `0`). Consider enabling the contract to revoke approval in emergency situations.

*There are 6 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

20: contract Curve2PoolAdapter is OceanAdapter {

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20),[L190](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L190),[L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

25: contract CurveTricryptoAdapter is OceanAdapter {

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L242),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243)
### [L-09]<a name="l-09"></a> Cap state variables at reasonable values
Consider adding maximum value checks to ensure that state variables cannot be set to values that may excessively harm users.

*There are 57 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

200:         unwrapFeeDivisor = nextUnwrapFeeDivisor;

464:             balanceDeltas[i] = BalanceDelta(ids[i], 0);

609:             inputToken = specifiedToken;
610:             inputAmount = specifiedAmount;

617:             outputToken = specifiedToken;
618:             outputAmount = specifiedAmount;

625:             outputToken = specifiedToken;
626:             outputAmount = specifiedAmount;

629:             inputToken = specifiedToken;
630:             inputAmount = specifiedAmount;

643:             outputToken = specifiedToken;
644:             outputAmount = specifiedAmount;

649:             inputToken = specifiedToken;
650:             inputAmount = specifiedAmount;

657:             outputToken = specifiedToken;
658:             outputAmount = specifiedAmount;

661:             inputToken = specifiedToken;
662:             inputAmount = specifiedAmount;

668:             inputToken = specifiedToken;
669:             inputAmount = specifiedAmount;

759:         outputAmount =
760:             IOceanPrimitive(primitive).computeOutputAmount(inputToken, outputToken, inputAmount, userAddress, metadata);

800:         inputAmount =
801:             IOceanPrimitive(primitive).computeInputAmount(inputToken, outputToken, outputAmount, userAddress, metadata);

1102:             dust = normalizedTransferAmount - amount;

1134:             convertedAmount = amountToConvert;

1139:             convertedAmount = amountToConvert * shift;

1144:             convertedAmount = amountToConvert / shift;
1145:             truncatedAmount = amountToConvert % shift;

1159:         feeCharged = unwrapAmount / unwrapFeeDivisor;

```


*GitHub* : [L200](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L200),[L464](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L464),[L609](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L609),[L610](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L610),[L617](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L617),[L618](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L618),[L625](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L625),[L626](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L626),[L629](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L629),[L630](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L630),[L643](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L643),[L644](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L644),[L649](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L649),[L650](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L650),[L657](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L657),[L658](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L658),[L661](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L661),[L662](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L662),[L668](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L668),[L669](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L669),[L759](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L759),[L760](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L760),[L800](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L800),[L801](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L801),[L1102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1102),[L1134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1134),[L1139](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1139),[L1144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1144),[L1145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1145),[L1159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1159)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

173:         outputAmount = _convertDecimals(decimals[outputToken], NORMALIZED_DECIMALS, rawOutputAmount);

```


*GitHub* : [L173](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L173)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

131:             interaction = Interaction({
132:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.WrapErc20)),
133:                 inputToken: 0,
134:                 outputToken: 0,
135:                 specifiedAmount: amount,
136:                 metadata: bytes32(0)
137:             });

151:             interaction = Interaction({
152:                 interactionTypeAndAddress: _fetchInteractionId(address(0), uint256(InteractionType.UnwrapEther)),
153:                 inputToken: 0,
154:                 outputToken: 0,
155:                 specifiedAmount: amount,
156:                 metadata: bytes32(0)
157:             });

159:             interaction = Interaction({
160:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.UnwrapErc20)),
161:                 inputToken: 0,
162:                 outputToken: 0,
163:                 specifiedAmount: amount,
164:                 metadata: bytes32(0)
165:             });

225:         outputAmount = _convertDecimals(decimals[outputToken], NORMALIZED_DECIMALS, rawOutputAmount);

```


*GitHub* : [L131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L131),[L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L132),[L133](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L133),[L134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L134),[L135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L135),[L136](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L136),[L137](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L137),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L151),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L152),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L153),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L154),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L155),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L156),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L157),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L159),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L160),[L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L161),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L162),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L164),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L165),[L225](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L225)

```solidity
File: src/adapters/OceanAdapter.sol

73:         outputAmount = primitiveOutputAmount(inputToken, outputToken, unwrappedAmount, metadata);

149:             convertedAmount = amountToConvert;

153:             convertedAmount = amountToConvert * shift;

157:             convertedAmount = amountToConvert / shift;

```


*GitHub* : [L73](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L73),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L149),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L153),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L157)
### [L-10]<a name="l-10"></a> Checks-Effects-Interactions pattern not followed
The [Checks-Effects-Interactions](https://fravoll.github.io/solidity-patterns/checks_effects_interactions.html) pattern (CEI) is a best practice that reduces the attack surface for reentrancy attacks.  To adhere to this pattern, place state variable updates before external calls within functions.

*There are 12 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

889:     function _erc721Wrap(address tokenAddress, uint256 tokenId, address userAddress, uint256 oceanId) private {

892:         _ERC721InteractionStatus = NOT_INTERACTION;

920:     function _erc1155Wrap(
921:         address tokenAddress,
922:         uint256 tokenId,
923:         uint256 amount,
924:         address userAddress,
925:         uint256 oceanId
926:     )
927:         private
928:     {

932:         _ERC1155InteractionStatus = NOT_INTERACTION;

```


*GitHub* : [L920](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L920),[L889](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L889),[L892](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L892),[L921](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L921),[L922](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L922),[L923](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L923),[L924](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L924),[L925](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L925),[L926](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L926),[L927](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L927),[L928](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L928),[L932](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L932)
### [L-11]<a name="l-11"></a> Some tokens may revert on large approvals
Tokens such as [COMP](https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/Governance/Comp.sol#L78-L98) or [UNI](https://github.com/Uniswap/governance/blob/master/contracts/Uni.sol#L141-L161) will revert on approval if the `amount` exceeds `type(uint96).max`. Ensure that the calls below can be broken up into smaller batches if necessary.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L190](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L190),[L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L242),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243)
### [L-12]<a name="l-12"></a> Some tokens may revert on large transfers
Tokens such as [COMP](https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/Governance/Comp.sol#L109-L142) or [UNI](https://github.com/Uniswap/governance/blob/master/contracts/Uni.sol#L203-L236) will revert on `transfer`/`transferFrom` when an address' balance reaches `type(uint96).max`. Ensure that the calls below can be broken up into smaller batches if necessary.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

836:             SafeERC20.safeTransferFrom(IERC20(tokenAddress), userAddress, address(this), transferAmount);

```


*GitHub* : [L836](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L836)
### [L-13]<a name="l-13"></a> Vulnerable package versions are being used
This project's used OpenZeppelin version (4.8.1) is vulnerable to one or more of the specific CVEs listed below. Consider switching to a more recent version that doesn't have these vulnerabilities.  <details> <summary>Vulnerabilities</summary>  [CVE-2023-26488](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26488): The ERC721Consecutive contract designed for minting NFTs in batches does not update balances when a batch has size 1 and consists of a single token. Subsequent transfers from the receiver of that token may overflow the balance as reported by `balanceOf`. The issue exclusively presents with batches of size 1. The issue has been patched in 4.8.2 (@openzeppelin/contracts >=4.8.0 <4.8.2).  [CVE-2023-30541](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30541): A function in the implementation contract may be inaccessible if its selector clashes with one of the proxy's own selectors. Specifically, if the clashing function has a different signature with incompatible ABI encoding, the proxy could revert while attempting to decode the arguments from calldata. The probability of an accidental clash is negligible, but one could be caused deliberately and could cause a reduction in availability. The issue has been fixed in version 4.8.3. As a workaround if a function appears to be inaccessible for this reason, it may be possible to craft the calldata such that ABI decoding does not fail at the proxy and the function is properly proxied through (@openzeppelin/contracts >=3.2.0 <4.8.3).  [CVE-2023-30542](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30542): The proposal creation entrypoint (`propose`) in `GovernorCompatibilityBravo` allows the creation of proposals with a `signatures` array shorter than the `calldatas` array. This causes the additional elements of the latter to be ignored, and if the proposal succeeds the corresponding actions would eventually execute without any calldata. The `ProposalCreated` event correctly represents what will eventually execute, but the proposal parameters as queried through `getActions` appear to respect the original intended calldata. This issue has been patched in 4.8.3. As a workaround, ensure that all proposals that pass through governance have equal length `signatures` and `calldatas` parameters (@openzeppelin/contracts >=4.3.0 <4.8.3).  [CVE-2023-34234](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-5h3x-9wvq-w4m2): By frontrunning the creation of a proposal, an attacker can become the proposer and gain the ability to cancel it. The attacker can do this repeatedly to try to prevent a proposal from being proposed at all. This impacts the Governor contract in v4.9.0 only, and the GovernorCompatibilityBravo contract since v4.3.0.  [CVE-2023-34459](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-wprv-93r4-jj2p) When the verifyMultiProof, verifyMultiProofCalldata, processMultiProof, or processMultiProofCalldata functions are in use, it is possible to construct merkle trees that allow forging a valid multiproof for an arbitrary set of leaves. A contract may be vulnerable if it uses multiproofs for verification and the merkle tree that is processed includes a node with value 0 at depth 1(just under the root). This could happen inadvertently for balanced trees with 3 leaves or less, if the leaves are not hashed.This could happen deliberately if a malicious tree builder includes such a node in the tree. A contract is not vulnerable if it uses single- leaf proving (verify, verifyCalldata, processProof, or processProofCalldata), or if it uses multiproofs with a known tree that has hashed leaves.Standard merkle trees produced or validated with the @openzeppelin/merkle-tree library are safe (@openzeppelin/contracts >=4.7.0 <4.9.2).  </details>

*There are 1 instance(s) of this issue:*

```solidity
File: All in-scope files
```

*GitHub* : https://github.com/code-423n4/2023-11-shellprotocol
### [L-14]<a name="l-14"></a> Possible loss of precision
Division by large numbers may result in precision loss due to rounding down, or even the result being erroneously equal to zero. Consider adding checks on the numerator to ensure precision loss is handled appropriately.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

1144:             convertedAmount = amountToConvert / shift;

1159:         feeCharged = unwrapAmount / unwrapFeeDivisor;

```


*GitHub* : [L1144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1144),[L1159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1159)

```solidity
File: src/adapters/OceanAdapter.sol

70:         uint256 unwrapFee = inputAmount / IOceanInteractions(ocean).unwrapFeeDivisor();

157:             convertedAmount = amountToConvert / shift;

```


*GitHub* : [L70](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L70),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L157)
### [L-15]<a name="l-15"></a> Downcasting `uint` or `int` may result in overflow
Consider using OpenZeppelin's `SafeCast` library to prevent unexpected overflows.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

689:         externalContract = address(uint160(uint256(interactionTypeAndAddress)));

```


*GitHub* : [L689](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L689)
### [L-16]<a name="l-16"></a> Use a low level call to send ether instead of `.send()` or `.transfer()`
The `.send()` function intends to transfer an ETH amount with a fixed amount of 2300 gas. This function is not equipped to handle changes in the underlying `.send()` and `.transfer()` functions which may supply different amounts of gas in the future. Additionally, if the recipient implements a fallback function containing some sort of logic, this may inevitably revert, meaning the vault and owner of the contract will never be able to call certain sensitive functions.  Consider using `.call()` instead with the checks-effects-interactions pattern implemented correctly. Careful consideration needs to be made to prevent reentrancy.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

982:         payable(userAddress).transfer(transferAmount);

```


*GitHub* : [L982](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L982)### Gas Risk Issues


### [G-01]<a name="g-01"></a> `abi.encodePacked` is more gas efficient than `abi.encode`
`abi.encode` pads all elementary types to 32 bytes, whereas `abi.encodePacked` will only use the minimal required memory to encode the data. See [here](https://docs.soliditylang.org/en/v0.8.11/abi-spec.html?highlight=encodepacked#non-standard-packed-mode) for more info.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

102:         return bytes32(abi.encode(packedValue));

```


*GitHub* : [L102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L102)
### [G-02]<a name="g-02"></a> Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as payable will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.  The extra opcodes avoided are `CALLVALUE`(2), `DUP1`(3), `ISZERO`(3), `PUSH2`(3), `JUMPI`(10), `PUSH1`(3), `DUP1`(3), `REVERT`(0), `JUMPDEST`(1), `POP`(2), which costs an average of about 21 gas per call to the function, in addition to the extra deployment cost (2400 per instance).

*There are 51 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

```


*GitHub* : [L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295)

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

```


*GitHub* : [L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92)
### [G-03]<a name="g-03"></a> Use assembly to emit events
For example `emit ExampleEvent(amount)` (amount is `uint256`) can be re-written as ```solidity assembly {     let memptr := mload(0x40)     mstore(0x00, calldataload(0x44))     mstore(0x20, calldataload(0xa4))     mstore(0x40, amount)     log1(         0x00,         0x60,         // keccak256("ExampleEvent(uint256)")         0x12210f92675543a3eee7d9f6cc64eaca8eb1431502f685da3f48e7593e2b7f1e     )     mstore(0x40, memptr) } ```

*There are 22 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

199:         emit ChangeUnwrapFee(unwrapFeeDivisor, nextUnwrapFeeDivisor, msg.sender);

216:         emit OceanTransaction(msg.sender, 1);

243:         emit OceanTransaction(msg.sender, interactions.length);

266:         emit ForwardedOceanTransaction(msg.sender, userAddress, 1);

297:         emit ForwardedOceanTransaction(msg.sender, userAddress, interactions.length);

396:             emit EtherWrap(msg.value, userAddress);

479:             emit EtherWrap(msg.value, userAddress);

764:         emit ComputeOutputAmount(primitive, inputToken, outputToken, inputAmount, outputAmount, userAddress);

805:         emit ComputeInputAmount(primitive, inputToken, outputToken, inputAmount, outputAmount, userAddress);

838:             emit Erc20Wrap(tokenAddress, transferAmount, amount, dust, userAddress, outputToken);

876:             emit Erc20Unwrap(tokenAddress, transferAmount, amount, feeCharged, userAddress, inputToken);

893:         emit Erc721Wrap(tokenAddress, tokenId, userAddress, oceanId);

905:         emit Erc721Unwrap(tokenAddress, tokenId, userAddress, oceanId);

933:         emit Erc1155Wrap(tokenAddress, tokenId, amount, userAddress, oceanId);

969:         emit Erc1155Unwrap(tokenAddress, tokenId, amount, feeCharged, userAddress, oceanId);

983:         emit EtherUnwrap(transferAmount, feeCharged, userAddress);

```


*GitHub* : [L199](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L199),[L805](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L805),[L838](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L838),[L876](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L876),[L893](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L893),[L905](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L905),[L933](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L933),[L969](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L969),[L983](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L983),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L216),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L243),[L266](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L266),[L297](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L297),[L396](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L396),[L479](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L479),[L764](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L764)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

178:             emit Swap(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

180:             emit Deposit(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

182:             emit Withdraw(outputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

```


*GitHub* : [L180](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L180),[L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L182),[L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L178)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

230:             emit Swap(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

232:             emit Deposit(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

234:             emit Withdraw(outputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

```


*GitHub* : [L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L234),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L230),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L232)
### [G-04]<a name="g-04"></a> Use assembly to calculate hashes
Saves 5000 deployment gas per instance and 374 runtime gas per instance.  ### Unoptimized ```solidity function solidityHash(uint256 a, uint256 b) public view { 	//unoptimized 	keccak256(abi.encodePacked(a, b)); } ```  ### Optimized ```solidity function assemblyHash(uint256 a, uint256 b) public view { 	//optimized 	assembly { 		mstore(0x00, a) 		mstore(0x20, b) 		let hashedVal := keccak256(0x00, 0x40) 	} } ```

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

109:         return uint256(keccak256(abi.encodePacked(tokenAddress, tokenId)));

```


*GitHub* : [L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L109)
### [G-05]<a name="g-05"></a> Using assembly's `selfbalance()` is cheaper than `address(this).balance`
Saves 159 gas per instance.  ```solidity assembly {  	mstore(0x00, selfbalance())  	return(0x00, 0x20) } ```

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

251:             return address(this).balance;

```


*GitHub* : [L251](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L251)
### [G-06]<a name="g-06"></a>  Use assembly to write storage values
``` // unoptimized owner = _newOwner  // optimized assembly { sstore(owner.slot, _newOwner) } ```

*There are 28 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

170:         unwrapFeeDivisor = type(uint256).max;
171:         _ERC1155InteractionStatus = NOT_INTERACTION;
172:         _ERC721InteractionStatus = NOT_INTERACTION;
173:         WRAPPED_ETHER_ID = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))

200:         unwrapFeeDivisor = nextUnwrapFeeDivisor;

890:         _ERC721InteractionStatus = INTERACTION;

892:         _ERC721InteractionStatus = NOT_INTERACTION;

930:         _ERC1155InteractionStatus = INTERACTION;

932:         _ERC1155InteractionStatus = NOT_INTERACTION;

```


*GitHub* : [L892](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L892),[L932](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L932),[L170](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L170),[L171](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L171),[L172](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L172),[L173](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L173),[L200](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L200),[L890](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L890),[L930](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L930)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

79:         xToken = _calculateOceanId(xTokenAddress, 0);

81:         decimals[xToken] = IERC20Metadata(xTokenAddress).decimals();

85:         yToken = _calculateOceanId(yTokenAddress, 0);
86:         indexOf[yToken] = int128(1);

88:         decimals[yToken] = IERC20Metadata(yTokenAddress).decimals();

91:         lpTokenId = _calculateOceanId(primitive_, 0);

93:         decimals[lpTokenId] = IERC20Metadata(primitive_).decimals();

```


*GitHub* : [L93](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L93),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L91),[L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L79),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L81),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L86),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L88)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

87:         xToken = _calculateOceanId(xTokenAddress, 0);

89:         decimals[xToken] = IERC20Metadata(xTokenAddress).decimals();

93:         yToken = _calculateOceanId(yTokenAddress, 0);
94:         indexOf[yToken] = 1;

96:         decimals[yToken] = IERC20Metadata(yTokenAddress).decimals();

100:         zToken = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))
101:         indexOf[zToken] = 2;

103:         decimals[zToken] = NORMALIZED_DECIMALS;

107:         lpTokenId = _calculateOceanId(lpTokenAddress, 0);

109:         decimals[lpTokenId] = IERC20Metadata(lpTokenAddress).decimals();

```


*GitHub* : [L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L87),[L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L109),[L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L107),[L103](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L103),[L101](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L101),[L100](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L100),[L96](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L96),[L94](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L94),[L93](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L93),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L89)

```solidity
File: src/adapters/OceanAdapter.sol

33:         ocean = ocean_;
34:         primitive = primitive_;

```


*GitHub* : [L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L34),[L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L33)
### [G-07]<a name="g-07"></a> Use `require` instead of `assert`
Prior to solc 0.8.0, `assert` used the invalid opcode which used up all the remaining gas while `require` used the revert opcode which refunded the gas and therefore the importance of using `require` instead of `assert` was greater.  However, after 0.8.0, `assert` uses revert opcode just like `require` but creates a `Panic(uint256)` error instead of `Error(string)` created by `require`.  Solidity documentation states: 'The `assert` function generates an error of type `Panic(uint256)`. Code that works properly should never Panic, even on invalid external input. If this happens, you need to fix it in your contract. there's a mistake'.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

667:             assert(interactionType == InteractionType.UnwrapEther && specifiedToken == WRAPPED_ETHER_ID);

721:             assert(interactionType == InteractionType.UnwrapEther);

1100:             assert(normalizedTruncatedAmount == 0);

1101:             assert(normalizedTransferAmount > amount);

```


*GitHub* : [L1101](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1101),[L721](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L721),[L1100](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1100),[L667](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L667)
### [G-08]<a name="g-08"></a> Assigning to structs can be more efficient
By changing the pattern of assigning value to the structure, gas savings of ~130 per instance are achieved. In addition, this use will provide significant savings in distribution costs.  Instead of   ```solidity     MyStruct memory myStruct = MyStruct(_a, _b, _c); ```  write  ```solidity     MyStruct memory myStruct;     myStruct.a = _a;     myStruct.b = _b;     myStruct.c = _c; ```

*There are 42 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

105:         Interaction memory interaction = Interaction({
106:             interactionTypeAndAddress: _fetchInteractionId(tokenAddress, uint256(InteractionType.WrapErc20)),
107:             inputToken: 0,
108:             outputToken: 0,
109:             specifiedAmount: amount,
110:             metadata: bytes32(0)
111:         });

124:         Interaction memory interaction = Interaction({
125:             interactionTypeAndAddress: _fetchInteractionId(tokenAddress, uint256(InteractionType.UnwrapErc20)),
126:             inputToken: 0,
127:             outputToken: 0,
128:             specifiedAmount: amount,
129:             metadata: bytes32(0)
130:         });

```


*GitHub* : [L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L107),[L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L108),[L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L109),[L110](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L110),[L105](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L105),[L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L111),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L124),[L130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L130),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L129),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L128),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L127),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L126),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L125),[L106](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L106)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

122:             interaction = Interaction({
123:                 interactionTypeAndAddress: 0,
124:                 inputToken: 0,
125:                 outputToken: 0,
126:                 specifiedAmount: 0,
127:                 metadata: bytes32(0)
128:             });

131:             interaction = Interaction({
132:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.WrapErc20)),
133:                 inputToken: 0,
134:                 outputToken: 0,
135:                 specifiedAmount: amount,
136:                 metadata: bytes32(0)
137:             });

151:             interaction = Interaction({
152:                 interactionTypeAndAddress: _fetchInteractionId(address(0), uint256(InteractionType.UnwrapEther)),
153:                 inputToken: 0,
154:                 outputToken: 0,
155:                 specifiedAmount: amount,
156:                 metadata: bytes32(0)
157:             });

159:             interaction = Interaction({
160:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.UnwrapErc20)),
161:                 inputToken: 0,
162:                 outputToken: 0,
163:                 specifiedAmount: amount,
164:                 metadata: bytes32(0)
165:             });

```


*GitHub* : [L131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L131),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L128),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L127),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L126),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L125),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L124),[L123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L123),[L122](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L122),[L134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L134),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L165),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L164),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L163),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L162),[L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L161),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L160),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L159),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L157),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L156),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L155),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L154),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L153),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L152),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L151),[L137](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L137),[L136](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L136),[L135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L135),[L133](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L133),[L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L132)
### [G-09]<a name="g-09"></a> Avoid zero transfer to save gas
In Solidity, unnecessary operations can waste gas. For example, a transfer function without a zero amount check uses gas even if called with a zero amount, since the contract state remains unchanged. Implementing a zero amount check avoids these unnecessary function calls, saving gas and improving efficiency.

*There are 2 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

836:             SafeERC20.safeTransferFrom(IERC20(tokenAddress), userAddress, address(this), transferAmount);

875:             SafeERC20.safeTransfer(IERC20(tokenAddress), userAddress, transferAmount);

```


*GitHub* : [L836](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L836),[L875](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L875)
### [G-10]<a name="g-10"></a> `address(this)` should be cached
Cacheing saves gas when compared to repeating the calculation at each point it is used in the contract.

*There are 13 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

836:             SafeERC20.safeTransferFrom(IERC20(tokenAddress), userAddress, address(this), transferAmount);

891:         IERC721(tokenAddress).safeTransferFrom(userAddress, address(this), tokenId);

904:         IERC721(tokenAddress).safeTransferFrom(address(this), userAddress, tokenId);

929:         if (tokenAddress == address(this)) revert NO_RECURSIVE_WRAPS();

931:         IERC1155(tokenAddress).safeTransferFrom(userAddress, address(this), tokenId, amount, "");

964:         if (tokenAddress == address(this)) revert NO_RECURSIVE_UNWRAPS();

968:         IERC1155(tokenAddress).safeTransferFrom(address(this), userAddress, tokenId, amountRemaining, "");

```


*GitHub* : [L891](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L891),[L904](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L904),[L929](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L929),[L931](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L931),[L968](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L968),[L964](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L964),[L836](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L836)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

213:                 uint256 wethBalance = IERC20Metadata(underlying[zToken]).balanceOf(address(this));

215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

251:             return address(this).balance;

253:             return IERC20Metadata(tokenAddress).balanceOf(address(this));

```


*GitHub* : [L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L213),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L251](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L251),[L253](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L253)
### [G-11]<a name="g-11"></a> Cache multiple accesses of mapping/array values
Caching a mapping's value in a local `storage` or `calldata` variable when the value is accessed multiple times, saves ~42 gas per access due to not having to recalculate the key's keccak256 hash (Gkeccak256 - 30 gas) and that calculation's associated stack operations. Caching an array's struct avoids recalculating the array offsets into memory/calldata.

*There are 7 instance(s) of this issue:*

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

208:             if (inputToken == zToken) IWETH(underlying[zToken]).deposit{ value: rawInputAmount }();

213:                 uint256 wethBalance = IERC20Metadata(underlying[zToken]).balanceOf(address(this));

215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

192:         uint256 _balanceBefore = _getBalance(underlying[outputToken]);

223:         uint256 rawOutputAmount = _getBalance(underlying[outputToken]) - _balanceBefore;

```


*GitHub* : [L208](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L208),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L213),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217),[L192](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L192),[L223](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L223)
### [G-12]<a name="g-12"></a> Function result should be cached
The instances below show multiple calls to a single function within the same function.

*There are 50 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

142:     function primitiveOutputAmount(
143:         uint256 inputToken,
144:         uint256 outputToken,
145:         uint256 inputAmount,
146:         bytes32 minimumOutputAmount
147:     )
148:         internal
149:         override
150:         returns (uint256 outputAmount)
151:     {

163:             rawOutputAmount =
164:                 ICurve2Pool(primitive).exchange(indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0);

168:             rawOutputAmount = ICurve2Pool(primitive).add_liquidity(inputAmounts, 0);

170:             rawOutputAmount = ICurve2Pool(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

189:     function _approveToken(address tokenAddress) private {
190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L146),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L145),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L151),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L164),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L168),[L170](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L170),[L189](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L189),[L190](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L190),[L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

118:     function wrapToken(uint256 tokenId, uint256 amount) internal override {

129:             IOceanInteractions(ocean).doInteraction{ value: amount }(interaction);

138:             IOceanInteractions(ocean).doInteraction(interaction);

178:     function primitiveOutputAmount(
179:         uint256 inputToken,
180:         uint256 outputToken,
181:         uint256 inputAmount,
182:         bytes32 minimumOutputAmount
183:     )
184:         internal
185:         override
186:         returns (uint256 outputAmount)
187:     {

201:             ICurveTricrypto(primitive).exchange{ value: inputToken == zToken ? rawInputAmount : 0 }(
202:                 indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0, useEth
203:             );

210:             ICurveTricrypto(primitive).add_liquidity(inputAmounts, 0);

214:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

208:             if (inputToken == zToken) IWETH(underlying[zToken]).deposit{ value: rawInputAmount }();

215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

213:                 uint256 wethBalance = IERC20Metadata(underlying[zToken]).balanceOf(address(this));

215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

219:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);
219:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

192:         uint256 _balanceBefore = _getBalance(underlying[outputToken]);

223:         uint256 rawOutputAmount = _getBalance(underlying[outputToken]) - _balanceBefore;

241:     function _approveToken(address tokenAddress) private {
242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L242),[L118](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L118),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L129),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L138),[L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L178),[L179](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L179),[L180](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L180),[L181](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L181),[L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L182),[L183](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L183),[L184](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L184),[L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L185),[L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L186),[L187](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L187),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L201),[L202](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L202),[L203](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L203),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L210),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L214),[L208](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L208),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L213),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217),[L219](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L219),[L219](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L219),[L192](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L192),[L223](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L223),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L241)
### [G-13]<a name="g-13"></a> Use `calldata` instead of `memory` for function arguments that are read only
When a function with a `memory` array is called externally, the `abi.decode()` step has to use a for-loop to copy each index of the `calldata` to the `memory` index. Each iteration of this for-loop costs at least 60 gas (i.e. 60 * `<mem_array>.length`). Using calldata directly, obliviates the need for such a loop in the contract code and runtime execution.  If the array is passed to an `internal` function which passes the array to another `internal` function where the array is modified and therefore `memory` is used in the `external` call, it's still more gas-efficient to use `calldata` when the external function uses modifiers, since the modifiers may prevent the `internal` functions from being called. `Structs` have the same overhead as an array of length one

*There are 25 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

597:     function _executeInteraction(
598:         Interaction memory interaction,
599:         InteractionType interactionType,
600:         address externalContract,
601:         uint256 specifiedToken,
602:         uint256 specifiedAmount,
603:         address userAddress
604:     )
605:         internal
606:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
607:     {

682:     function _unpackInteractionTypeAndAddress(Interaction memory interaction)
683:         internal
684:         pure
685:         returns (InteractionType interactionType, address externalContract)
686:     {

700:     function _getSpecifiedToken(
701:         InteractionType interactionType,
702:         address externalContract,
703:         Interaction memory interaction
704:     )
705:         internal
706:         view
707:         returns (uint256 specifiedToken)
708:     {

```


*GitHub* : [L605](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L605),[L597](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L597),[L598](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L598),[L599](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L599),[L600](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L600),[L601](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L601),[L602](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L602),[L603](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L603),[L604](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L604),[L606](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L606),[L607](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L607),[L682](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L682),[L683](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L683),[L684](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L684),[L685](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L685),[L686](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L686),[L700](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L700),[L701](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L701),[L702](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L702),[L703](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L703),[L704](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L704),[L705](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L705),[L706](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L706),[L707](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L707),[L708](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L708)
### [G-14]<a name="g-14"></a> Divisions can be `unchecked` to save gas
The expression `type(int).min/(-1)` is the only case where division causes an overflow. Therefore, uncheck can be used to save gas in scenarios where it is certain that such an overflow will not occur.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

1144:             convertedAmount = amountToConvert / shift;

1159:         feeCharged = unwrapAmount / unwrapFeeDivisor;

```


*GitHub* : [L1144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1144),[L1159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1159)

```solidity
File: src/adapters/OceanAdapter.sol

70:         uint256 unwrapFee = inputAmount / IOceanInteractions(ocean).unwrapFeeDivisor();

157:             convertedAmount = amountToConvert / shift;

```


*GitHub* : [L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L157),[L70](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L70)
### [G-15]<a name="g-15"></a> Same cast is done multiple times
It's cheaper to do it once, and store the result to a variable.

*There are 69 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

645:             _erc721Wrap(externalContract, uint256(interaction.metadata), userAddress, outputToken);

653:             _erc721Unwrap(externalContract, uint256(interaction.metadata), userAddress, inputToken);

659:             _erc1155Wrap(externalContract, uint256(interaction.metadata), outputAmount, userAddress, outputToken);

665:             _erc1155Unwrap(externalContract, uint256(interaction.metadata), inputAmount, userAddress, inputToken);

929:         if (tokenAddress == address(this)) revert NO_RECURSIVE_WRAPS();

931:         IERC1155(tokenAddress).safeTransferFrom(userAddress, address(this), tokenId, amount, "");

964:         if (tokenAddress == address(this)) revert NO_RECURSIVE_UNWRAPS();

968:         IERC1155(tokenAddress).safeTransferFrom(address(this), userAddress, tokenId, amountRemaining, "");

```


*GitHub* : [L665](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L665),[L929](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L929),[L931](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L931),[L968](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L968),[L964](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L964),[L645](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L645),[L653](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L653),[L659](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L659)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

163:             rawOutputAmount =
164:                 ICurve2Pool(primitive).exchange(indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0);

168:             rawOutputAmount = ICurve2Pool(primitive).add_liquidity(inputAmounts, 0);

170:             rawOutputAmount = ICurve2Pool(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);
191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L164),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L168),[L170](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L170),[L190](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L190),[L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

122:             interaction = Interaction({
123:                 interactionTypeAndAddress: 0,
124:                 inputToken: 0,
125:                 outputToken: 0,
126:                 specifiedAmount: 0,
127:                 metadata: bytes32(0)
128:             });

131:             interaction = Interaction({
132:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.WrapErc20)),
133:                 inputToken: 0,
134:                 outputToken: 0,
135:                 specifiedAmount: amount,
136:                 metadata: bytes32(0)
137:             });

129:             IOceanInteractions(ocean).doInteraction{ value: amount }(interaction);

138:             IOceanInteractions(ocean).doInteraction(interaction);

151:             interaction = Interaction({
152:                 interactionTypeAndAddress: _fetchInteractionId(address(0), uint256(InteractionType.UnwrapEther)),
153:                 inputToken: 0,
154:                 outputToken: 0,
155:                 specifiedAmount: amount,
156:                 metadata: bytes32(0)
157:             });

159:             interaction = Interaction({
160:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.UnwrapErc20)),
161:                 inputToken: 0,
162:                 outputToken: 0,
163:                 specifiedAmount: amount,
164:                 metadata: bytes32(0)
165:             });

201:             ICurveTricrypto(primitive).exchange{ value: inputToken == zToken ? rawInputAmount : 0 }(
202:                 indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0, useEth
203:             );

210:             ICurveTricrypto(primitive).add_liquidity(inputAmounts, 0);

214:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

208:             if (inputToken == zToken) IWETH(underlying[zToken]).deposit{ value: rawInputAmount }();

215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

213:                 uint256 wethBalance = IERC20Metadata(underlying[zToken]).balanceOf(address(this));

215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

219:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

192:         uint256 _balanceBefore = _getBalance(underlying[outputToken]);

223:         uint256 rawOutputAmount = _getBalance(underlying[outputToken]) - _balanceBefore;

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);
243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

251:             return address(this).balance;

253:             return IERC20Metadata(tokenAddress).balanceOf(address(this));

```


*GitHub* : [L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L132),[L122](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L122),[L123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L123),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L124),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L125),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L126),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L127),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L128),[L131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L131),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L129),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L138),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L151),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L152),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L153),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L154),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L155),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L156),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L157),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L159),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L160),[L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L161),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L162),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L164),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L165),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L201),[L202](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L202),[L203](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L203),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L210),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L214),[L208](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L208),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L213),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217),[L219](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L219),[L192](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L192),[L223](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L223),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L242),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243),[L251](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L251),[L253](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L253),[L133](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L133),[L134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L134),[L135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L135),[L136](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L136),[L137](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L137)
### [G-16]<a name="g-16"></a> Stack variable cost less while used in emitting event
Use the `function`/`modifier`s local copy of the state variable, rather than incurring an extra `Gwarmaccess` (**100 gas**). In the unlikely event that the state variable hasn't already been used by the `function`/`modifier`, consider whether it is really necessary to include it in the event, given the fact that it incurs a `Gcoldsload` (**2100 gas**), or whether it can be passed in to or back out of the functions that _do_ use it.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

199:         emit ChangeUnwrapFee(unwrapFeeDivisor, nextUnwrapFeeDivisor, msg.sender);

```


*GitHub* : [L199](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L199)
### [G-17]<a name="g-17"></a> Cache length outside of for loop
Currently, the solidity compiler will always read the length of the array during each iteration.  That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

501:             for (uint256 i = 0; i < interactions.length;) {

```


*GitHub* : [L501](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L501)
### [G-18]<a name="g-18"></a> Use `do while` loops intead of `for` loops
A `do while` loop will cost less gas since the condition is not being checked for the first iteration.

*There are 2 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

463:         for (uint256 i = 0; i < _idLength;) {

501:             for (uint256 i = 0; i < interactions.length;) {

```


*GitHub* : [L501](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L501),[L463](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L463)
### [G-19]<a name="g-19"></a> Using `>=` is cheaper than `>`
The compiler uses opcodes GT and ISZERO for solidity code that uses `>`, but only requires LT for `>=`, which [saves 3 gas](https://gist.github.com/IllIllI000/3dc79d25acccfa16dee4e83ffdc6ffde). It should be converted to the <=/>= equivalent when comparing against integer literals.

*There are 11 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

419:         if (inputAmount > 0) {

426:         if (outputAmount > 0) {

527:                 if (inputAmount > 0) {

533:                 if (outputAmount > 0) {

558:             } else if (mintIds.length > 1) {

568:             } else if (burnIds.length > 1) {

1009:         if (_isNotTokenOfPrimitive(inputToken, primitive) && (inputAmount > 0)) {

1043:         if (_isNotTokenOfPrimitive(outputToken, primitive) && (outputAmount > 0)) {

1084:         if (truncated > 0) {

1167:         if (amount > 0) {

```


*GitHub* : [L1009](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1009),[L568](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L568),[L533](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L533),[L1167](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1167),[L1084](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1084),[L1043](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1043),[L558](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L558),[L419](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L419),[L426](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L426),[L527](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L527)

```solidity
File: src/adapters/OceanAdapter.sol

101:         packedValue |= interactionType << 248;

```


*GitHub* : [L101](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L101)
### [G-20]<a name="g-20"></a> Inline `modifier`s that are only used once, to save gas
Inline `modifier`s that are only used once, to save gas.

*There are 3 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

305:     function supportsInterface(bytes4 interfaceId) public view virtual override(OceanERC1155, IERC165) returns (bool) {
305:     function supportsInterface(bytes4 interfaceId) public view virtual override(OceanERC1155, IERC165) returns (bool) {

```


*GitHub* : [L305](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L305),[L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196),[L305](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L305)
### [G-21]<a name="g-21"></a> Inline `internal` functions that are only called once
Saves 20-40 gas per instance. See https://blog.soliditylang.org/2021/03/02/saving-gas-with-simple-inliner/ for more details.

*There are 5 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

612:             outputAmount = _computeOutputAmount(

619:             inputAmount = _computeInputAmount(

```


*GitHub* : [L619](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L619),[L612](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L612)

```solidity
File: src/adapters/OceanAdapter.sol

67:         unwrapToken(inputToken, inputAmount);

73:         outputAmount = primitiveOutputAmount(inputToken, outputToken, unwrappedAmount, metadata);

75:         wrapToken(outputToken, outputAmount);

```


*GitHub* : [L67](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L67),[L75](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L75),[L73](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L73)
### [G-22]<a name="g-22"></a> Expressions for constant values such as a call to `keccak256` should use `immutable` rather than `constant`
When left as `constant`, the value is re-calculated each time it is used instead of being converted to a constant at compile time. This costs an extra ~100 gas for each access.  Using `immutable` only incurs the gas costs for the computation at deploy time.  See [here](https://github.com/ethereum/solidity/issues/9232) for a detailed description of the issue.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

102:     uint256 constant GET_BALANCE_DELTA = type(uint256).max;

```


*GitHub* : [L102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L102)
### [G-23]<a name="g-23"></a> Using `storage` instead of `memory` for structs/arrays saves gas
When fetching data from a storage location, assigning the data to a `memory` variable causes all fields of the struct/array to be read from storage, which incurs a Gcoldsload (2100 gas) for each field of the struct/array. If the fields are read from the new memory variable, they incur an additional `MLOAD` rather than a cheap stack read.  Instead of declaring the variable with the `memory` keyword, declaring the variable with the `storage` keyword and caching any fields that need to be re-read in stack variables, will be much cheaper, only incuring the Gcoldsload for the fields actually read. The only time it makes sense to read the whole struct/array into a `memory` variable, is if the full struct/array is being returned by the function, is being passed to a function that requires `memory`, or if the array/struct is being read from another `memory` array/struct.

*There are 15 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

460:         BalanceDelta[] memory balanceDeltas = new BalanceDelta[](ids.length);

```


*GitHub* : [L460](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L460)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

105:         Interaction memory interaction = Interaction({
106:             interactionTypeAndAddress: _fetchInteractionId(tokenAddress, uint256(InteractionType.WrapErc20)),
107:             inputToken: 0,
108:             outputToken: 0,
109:             specifiedAmount: amount,
110:             metadata: bytes32(0)
111:         });

124:         Interaction memory interaction = Interaction({
125:             interactionTypeAndAddress: _fetchInteractionId(tokenAddress, uint256(InteractionType.UnwrapErc20)),
126:             inputToken: 0,
127:             outputToken: 0,
128:             specifiedAmount: amount,
129:             metadata: bytes32(0)
130:         });

```


*GitHub* : [L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L111),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L124),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L125),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L126),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L127),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L128),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L129),[L130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L130),[L105](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L105),[L106](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L106),[L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L107),[L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L108),[L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L109),[L110](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L110)
### [G-24]<a name="g-24"></a> Refactor modifiers to call a local function
Modifiers code is copied in all instances where it's used, increasing bytecode size. By doing a refractor to the internal function, one can reduce bytecode size significantly at the cost of one JUMP.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

38:     modifier onlyOcean() {

```


*GitHub* : [L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L38)
### [G-25]<a name="g-25"></a> Combine multiple mappings with the same key type where appropriate
Saves a storage slot for the mapping. Depending on the circumstances and sizes of types, can avoid a Gsset (20000 gas) per mapping combined. Reads and subsequent writes can also be cheaper when a function requires both values and they both fit in the same storage slot. Finally, if both fields are accessed in the same function, can save ~42 gas per access due to [not having to recalculate the key's keccak256 hash](https://gist.github.com/IllIllI000/ec23a57daa30a8f8ca8b9681c8ccefb0) (Gkeccak256 - 30 gas) and that calculation's associated stack operations.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

65:     mapping(uint256 => int128) indexOf;

68:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L68](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L68),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L65)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

73:     mapping(uint256 => uint256) indexOf;

76:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L73](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L73),[L76](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L76)
### [G-26]<a name="g-26"></a> Nesting `if`-statements is cheaper than using `&&`
Nesting `if`-statements avoids the stack operations of setting up and using an extra `jumpdest`, and saves **6 [gas](https://gist.github.com/IllIllI000/7f3b818abecfadbef93b894481ae7d19)**. Note that if an `else` statement is present, then nesting would use **more** gas, not less.

*There are 12 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

1009:         if (_isNotTokenOfPrimitive(inputToken, primitive) && (inputAmount > 0)) {
1010:             // Since the primitive consented to receiving this token by not
1011:             // reverting when it was called, we mint the token without
1012:             // doing a safe transfer acceptance check. This breaks the
1013:             // ERC1155 specification but in a way we hope is inconsequential, since
1014:             // all primitives are developed by people who must be
1015:             // aware of how the ocean works.
1016:             _mintWithoutSafeTransferAcceptanceCheck(primitive, inputToken, inputAmount);
1017:         }

1043:         if (_isNotTokenOfPrimitive(outputToken, primitive) && (outputAmount > 0)) {
1044:             _burn(primitive, outputToken, outputAmount);
1045:         }

```


*GitHub* : [L1009](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1009),[L1010](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1010),[L1011](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1011),[L1012](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1012),[L1013](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1013),[L1014](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1014),[L1015](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1015),[L1016](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1016),[L1017](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1017),[L1043](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1043),[L1044](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1044),[L1045](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1045)
### [G-27]<a name="g-27"></a> Function names can be optimized to save gas
`public`/`external` function names and `public` member variable names can be optimized to save gas. Below are the interfaces/abstract contracts that can be optimized so that the most frequently-called functions use the least amount of gas possible during method lookup. Method IDs that have two leading zero bytes can save 128 gas each during deployment, and renaming functions to have lower method IDs will save 22 gas per call, [per sorted position shifted](https://medium.com/joyso/solidity-how-does-function-name-affect-gas-consumption-in-smart-contract-47d270d8ac92).

*There are 74 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

305:     function supportsInterface(bytes4 interfaceId) public view virtual override(OceanERC1155, IERC165) returns (bool) {

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

326:     function onERC1155Received(
327:         address,
328:         address,
329:         uint256,
330:         uint256,
331:         bytes calldata
332:     )
333:         external
334:         view
335:         override
336:         returns (bytes4)
337:     {

353:     function onERC1155BatchReceived(
354:         address,
355:         address,
356:         uint256[] calldata,
357:         uint256[] calldata,
358:         bytes calldata
359:     )
360:         external
361:         pure
362:         override
363:         returns (bytes4)
364:     {

```


*GitHub* : [L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L305](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L305),[L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309),[L326](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L326),[L327](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L327),[L328](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L328),[L329](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L329),[L330](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L330),[L331](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L331),[L332](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L332),[L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79),[L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L357](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L357),[L358](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L358),[L359](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L359),[L360](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L360),[L361](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L361),[L362](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L362),[L363](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L363),[L364](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L364),[L333](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L333),[L334](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L334),[L335](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L335),[L336](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L336),[L337](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L337),[L353](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L353),[L354](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L354),[L355](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L355),[L356](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L356)
### [G-28]<a name="g-28"></a> Use `payable` for constructor
Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided. A constructor can safely be marked as payable, since only the deployer would be able to pass funds, and the project itself would not pass any funds.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

169:     constructor(string memory uri_) OceanERC1155(uri_) {

```


*GitHub* : [L169](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L169)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

77:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L77)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

85:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L85)

```solidity
File: src/adapters/OceanAdapter.sol

32:     constructor(address ocean_, address primitive_) {

```


*GitHub* : [L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L32)
### [G-29]<a name="g-29"></a> Use more recent OpenZeppelin version for gas boost
OpenZeppelin version 4.9.0+ provides many small gas optimizations, see [here](https://github.com/OpenZeppelin/openzeppelin-contracts/releases/tag/v4.9.0) for more info.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

1: // SPDX-License-Identifier: MIT

```


*GitHub* : [L1](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

1: // SPDX-License-Identifier: MIT

```


*GitHub* : [L1](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L1)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

1: // SPDX-License-Identifier: MIT

```


*GitHub* : [L1](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L1)

```solidity
File: src/adapters/OceanAdapter.sol

1: // SPDX-License-Identifier: MIT

```


*GitHub* : [L1](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L1)
### [G-30]<a name="g-30"></a> Not using the named return variable is confusing and can waste gas
Consider changing the variable to be an unnamed one, since the variable is never assigned, nor is it returned by name. If the optimizer is not turned on, leaving the code as it is will also waste gas for the stack variable.

*There are 124 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

682:     function _unpackInteractionTypeAndAddress(Interaction memory interaction)
683:         internal
684:         pure
685:         returns (InteractionType interactionType, address externalContract)
686:     {

700:     function _getSpecifiedToken(
701:         InteractionType interactionType,
702:         address externalContract,
703:         Interaction memory interaction
704:     )
705:         internal
706:         view
707:         returns (uint256 specifiedToken)
708:     {

1068:     function _determineTransferAmount(
1069:         uint256 amount,
1070:         uint8 decimals
1071:     )
1072:         private
1073:         pure
1074:         returns (uint256 transferAmount, uint256 dust)
1075:     {

1123:     function _convertDecimals(
1124:         uint8 decimalsFrom,
1125:         uint8 decimalsTo,
1126:         uint256 amountToConvert
1127:     )
1128:         internal
1129:         pure
1130:         returns (uint256 convertedAmount, uint256 truncatedAmount)
1131:     {

1158:     function _calculateUnwrapFee(uint256 unwrapAmount) private view returns (uint256 feeCharged) {

```


*GitHub* : [L1073](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1073),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L682](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L682),[L683](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L683),[L684](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L684),[L685](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L685),[L686](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L686),[L700](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L700),[L701](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L701),[L702](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L702),[L703](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L703),[L704](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L704),[L705](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L705),[L706](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L706),[L707](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L707),[L708](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L708),[L1068](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1068),[L1069](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1069),[L1070](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1070),[L1071](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1071),[L1072](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1072),[L1074](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1074),[L1075](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1075),[L1123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1123),[L1124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1124),[L1125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1125),[L1126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1126),[L1127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1127),[L1128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1128),[L1129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1129),[L1130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1130),[L1131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1131),[L1158](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1158)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

201:     function _determineComputeType(
202:         uint256 inputToken,
203:         uint256 outputToken
204:     )
205:         private
206:         view
207:         returns (ComputeType computeType)
208:     {

```


*GitHub* : [L207](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L207),[L206](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L206),[L205](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L205),[L204](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L204),[L203](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L203),[L202](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L202),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L201),[L208](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L208)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

264:     function _determineComputeType(
265:         uint256 inputToken,
266:         uint256 outputToken
267:     )
268:         private
269:         view
270:         returns (ComputeType computeType)
271:     {

```


*GitHub* : [L268](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L268),[L267](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L267),[L266](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L266),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L265),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L264),[L270](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L270),[L271](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L271),[L269](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L269)

```solidity
File: src/adapters/OceanAdapter.sol

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

138:     function _convertDecimals(
139:         uint8 decimalsFrom,
140:         uint8 decimalsTo,
141:         uint256 amountToConvert
142:     )
143:         internal
144:         pure
145:         returns (uint256 convertedAmount)
146:     {

161:     function primitiveOutputAmount(
162:         uint256 inputToken,
163:         uint256 outputToken,
164:         uint256 inputAmount,
165:         bytes32 metadata
166:     )
167:         internal
168:         virtual
169:         returns (uint256 outputAmount);

```


*GitHub* : [L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L138),[L139](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L139),[L140](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L140),[L141](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L141),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L146),[L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L161),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L162),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L164),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L165),[L166](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L166),[L167](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L167),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L168),[L169](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L169),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82)
### [G-31]<a name="g-31"></a> Use `solady` library where possible to save gas
[Solady](https://github.com/Vectorized/solady) is a Solidity library inspired by [Solmate](https://github.com/rari-capital/solmate), optimized heavily for gas optimizations and battle tested by [hundreds of developers](https://www.alchemy.com/dapps/solady). Consider implementing solady contracts where possible to reduce runtime gas fees.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

```


*GitHub* : [L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79)
### [G-32]<a name="g-32"></a> Assigning state variables directly with named struct constructors wastes gas
Using named arguments for struct means that the compiler needs to organize the fields in memory before doing the assignment, which wastes gas. Set each field directly in storage (use dot-notation), or use the unnamed version of the constructor.

*There are 14 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

105:         Interaction memory interaction = Interaction({
106:             interactionTypeAndAddress: _fetchInteractionId(tokenAddress, uint256(InteractionType.WrapErc20)),
107:             inputToken: 0,
108:             outputToken: 0,
109:             specifiedAmount: amount,
110:             metadata: bytes32(0)
111:         });

```


*GitHub* : [L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L108),[L105](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L105),[L106](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L106),[L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L107),[L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L109),[L110](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L110),[L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L111)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

122:             interaction = Interaction({
123:                 interactionTypeAndAddress: 0,
124:                 inputToken: 0,
125:                 outputToken: 0,
126:                 specifiedAmount: 0,
127:                 metadata: bytes32(0)
128:             });

```


*GitHub* : [L122](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L122),[L123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L123),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L124),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L127),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L126),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L125),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L128)
### [G-33]<a name="g-33"></a> Use `!= 0` instead of `> 0` for uints
Use `!= 0` instead of `> 0` for uints.

*There are 8 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

419:         if (inputAmount > 0) {

426:         if (outputAmount > 0) {

527:                 if (inputAmount > 0) {

533:                 if (outputAmount > 0) {

1009:         if (_isNotTokenOfPrimitive(inputToken, primitive) && (inputAmount > 0)) {

1043:         if (_isNotTokenOfPrimitive(outputToken, primitive) && (outputAmount > 0)) {

1084:         if (truncated > 0) {

1167:         if (amount > 0) {

```


*GitHub* : [L1084](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1084),[L527](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L527),[L419](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L419),[L533](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L533),[L1009](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1009),[L1043](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1043),[L1167](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1167),[L426](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L426)
### [G-34]<a name="g-34"></a> Usage of `uint` smaller than 32 bytes (256 bits) incurs overhead
When using elements that are smaller than 32 bytes, your contract's gas usage may be higher. This is because the EVM operates on 32 bytes at a time. Therefore, if the element is smaller than that, the EVM must use more operations in order to reduce the size of the element from 32 bytes to the desired size.  Consider using a larger size then downcasting where needed.  https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html

*There are 2 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

68:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L68](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L68)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

76:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L76](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L76)
### [G-35]<a name="g-35"></a> Use named return values
Using named return values instead of explicitly calling `return` saves ~13 execution gas per call and >1000 deployment gas per instance.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

305:     function supportsInterface(bytes4 interfaceId) public view virtual override(OceanERC1155, IERC165) returns (bool) {

```


*GitHub* : [L305](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L305)

```solidity
File: src/adapters/OceanAdapter.sol

99:     function _fetchInteractionId(address token, uint256 interactionType) internal pure returns (bytes32) {

108:     function _calculateOceanId(address tokenAddress, uint256 tokenId) internal pure returns (uint256) {

117:     function onERC1155Received(address, address, uint256, uint256, bytes memory) public pure returns (bytes4) {

```


*GitHub* : [L99](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L99),[L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L108),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L117)
### [G-36]<a name="g-36"></a> Avoid updating storage when the value hasn't changed
If the old value is equal to the new value, not re-storing the value will avoid a Gsreset (2900 gas), potentially at the expense of a Gcoldsload (2100 gas) or a Gwarmaccess (100 gas).

*There are 6 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {
197:         /// @notice as the divisor gets smaller, the fee charged gets larger
198:         if (MIN_UNWRAP_FEE_DIVISOR > nextUnwrapFeeDivisor) revert();
199:         emit ChangeUnwrapFee(unwrapFeeDivisor, nextUnwrapFeeDivisor, msg.sender);
200:         unwrapFeeDivisor = nextUnwrapFeeDivisor;
201:     }

```


*GitHub* : [L198](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L198),[L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196),[L197](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L197),[L199](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L199),[L200](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L200),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L201)
### [G-37]<a name="g-37"></a> Use assembly for integer zero checks
Using assembly to check for zero can save gas by allowing more direct access to the evm and reducing some of the overhead associated with high-level operations in solidity.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

1100:             assert(normalizedTruncatedAmount == 0);

```


*GitHub* : [L1100](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1100)
### [G-38]<a name="g-38"></a> Use custom errors
Use of custom errors reduces both deployment and runtime gas costs, and allows passing of dynamic information.

*There are 3 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

198:         if (MIN_UNWRAP_FEE_DIVISOR > nextUnwrapFeeDivisor) revert();

```


*GitHub* : [L198](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L198)

```solidity
File: src/adapters/OceanAdapter.sol

39:         require(msg.sender == ocean);

93:         revert();

```


*GitHub* : [L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L39),[L93](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L93)
### [G-39]<a name="g-39"></a> Use `via-ir` for deployment
Enable on the command line using `--via-ir` or with the option `{"viaIR": true}` for more powerful optimization passes that span across functions. See [here](https://docs.soliditylang.org/en/v0.8.17/ir-breaking-changes.html) for more info.

*There are 1 instance(s) of this issue:*

```solidity
File: All in-scope files
```

*GitHub* : https://github.com/code-423n4/2023-11-shellprotocol### NonCritical Risk Issues


### [N-01]<a name="n-01"></a> Not using the named return variable anywhere in the function is confusing
Consider changing the variable to be unnamed, or return it using its name.

*There are 75 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

```


*GitHub* : [L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

201:     function _determineComputeType(
202:         uint256 inputToken,
203:         uint256 outputToken
204:     )
205:         private
206:         view
207:         returns (ComputeType computeType)
208:     {

```


*GitHub* : [L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L201),[L202](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L202),[L203](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L203),[L204](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L204),[L205](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L205),[L206](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L206),[L207](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L207),[L208](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L208)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

264:     function _determineComputeType(
265:         uint256 inputToken,
266:         uint256 outputToken
267:     )
268:         private
269:         view
270:         returns (ComputeType computeType)
271:     {

```


*GitHub* : [L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L265),[L266](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L266),[L267](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L267),[L268](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L268),[L269](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L269),[L270](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L270),[L271](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L271)

```solidity
File: src/adapters/OceanAdapter.sol

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

173:     function unwrapToken(uint256 tokenId, uint256 amount) internal virtual;

```


*GitHub* : [L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92),[L173](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L173)
### [N-02]<a name="n-02"></a> Use modifiers for address checks
Modifiers in Solidity can improve code readability and modularity by encapsulating repetitive checks, such as address validity checks, into a reusable construct. For example, an `onlyOwner` modifier can be used to replace repetitive `require(msg.sender == owner)` checks across several functions, reducing code redundancy and enhancing maintainability.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

39:         require(msg.sender == ocean);

```


*GitHub* : [L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L39)
### [N-03]<a name="n-03"></a> Missing `address(0)` checks when assigning to `address` state variables
Missing `address(0)` checks when assigning to `address` state variables.

*There are 2 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

33:         ocean = ocean_;
34:         primitive = primitive_;

```


*GitHub* : [L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L33),[L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L34)
### [N-04]<a name="n-04"></a> Consider adding denylist
A denylist helps to prevent malicious users from spending stolen ERC20 or ERC721 tokens in the protocol.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

```


*GitHub* : [L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309)
### [N-05]<a name="n-05"></a> Functions missing empty `bytes` check
Passing empty bytes to a function can cause unexpected behavior, such as certain operations failing, producing incorrect results, or wasting gas. It is recommended to check that all `bytes` parameters are not empty.

*There are 24 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

```


*GitHub* : [L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92)
### [N-06]<a name="n-06"></a> Comparisons should place constants on the left hand side
This practise avoids [typo errors](https://www.moserware.com/2008/01/constants-on-left-are-better-but-this.html).

*There are 7 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

391:         if (msg.value != 0) {

474:         if (msg.value != 0) {

554:             if (mintIds.length == 1) {

564:             if (burnIds.length == 1) {

640:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

648:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

1100:             assert(normalizedTruncatedAmount == 0);

```


*GitHub* : [L391](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L391),[L474](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L474),[L554](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L554),[L564](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L564),[L640](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L640),[L648](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L648),[L1100](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1100)
### [N-07]<a name="n-07"></a> Use enum values instead of constant array indexes
Create a commented enum value to use instead of constant array indexes to make the code more readable and reduce margin for error.

*There are 5 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

557:                 _mint(userAddress, mintIds[0], mintAmounts[0]);

567:                 _burn(userAddress, burnIds[0], burnAmounts[0]);

688:         interactionType = InteractionType(uint8(interactionTypeAndAddress[0]));

```


*GitHub* : [L557](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L557),[L567](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L567),[L688](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L688)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

166:             uint256[2] memory inputAmounts;

```


*GitHub* : [L166](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L166)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

205:             uint256[3] memory inputAmounts;

```


*GitHub* : [L205](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L205)
### [N-08]<a name="n-08"></a> `constructor` should emit an event
Use events to signal significant changes to off-chain monitoring tools.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

169:     constructor(string memory uri_) OceanERC1155(uri_) {

```


*GitHub* : [L169](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L169)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

77:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L77)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

85:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L85)

```solidity
File: src/adapters/OceanAdapter.sol

32:     constructor(address ocean_, address primitive_) {

```


*GitHub* : [L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L32)
### [N-09]<a name="n-09"></a> Contracts should expose an `interface`
The contracts should expose an `interface` so that other projects can more easily integrate with it, without having to develop their own non-standard variants.

*There are 2 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

20: contract Curve2PoolAdapter is OceanAdapter {

```


*GitHub* : [L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

25: contract CurveTricryptoAdapter is OceanAdapter {

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25)
### [N-10]<a name="n-10"></a> Contract does not follow suggested layout ordering
Within a contract, the ordering should be: 1. Type declarations 2. State variables 3. Events 4. Modifiers 5. Functions See the  [Solidity style guide](https://docs.soliditylang.org/en/v0.8.16/style-guide.html#order-of-layout) for more info.

*There are 22 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

185:     modifier onlyApprovedForwarder(address userAddress) {

```


*GitHub* : [L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79),[L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L185)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

20: contract Curve2PoolAdapter is OceanAdapter {

30:     event Swap(
31:         uint256 inputToken,
32:         uint256 inputAmount,
33:         uint256 outputAmount,
34:         bytes32 slippageProtection,
35:         address user,
36:         bool computeOutput
37:     );

```


*GitHub* : [L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20),[L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L30),[L31](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L31),[L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L32),[L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L33),[L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L34),[L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L37)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

25: contract CurveTricryptoAdapter is OceanAdapter {

35:     event Swap(
36:         uint256 inputToken,
37:         uint256 inputAmount,
38:         uint256 outputAmount,
39:         bytes32 slippageProtection,
40:         address user,
41:         bool computeOutput
42:     );

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25),[L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L40),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L42),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L41)

```solidity
File: src/adapters/OceanAdapter.sol

14: abstract contract OceanAdapter is IOceanPrimitive {

38:     modifier onlyOcean() {

```


*GitHub* : [L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L14),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L38)
### [N-11]<a name="n-11"></a> Control structures do not follow the Solidity style guide
According to the [Solidity style guide](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures), braces should open on the same line as the declaration, close on their own line and the opening brace should be preceded by a single space.

*There are 261 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

186:         if (!isApprovedForAll(userAddress, msg.sender)) revert FORWARDER_NOT_APPROVED();

198:         if (MIN_UNWRAP_FEE_DIVISOR > nextUnwrapFeeDivisor) revert();

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

326:     function onERC1155Received(
327:         address,
328:         address,
329:         uint256,
330:         uint256,
331:         bytes calldata
332:     )
333:         external
334:         view
335:         override
336:         returns (bytes4)
337:     {

353:     function onERC1155BatchReceived(
354:         address,
355:         address,
356:         uint256[] calldata,
357:         uint256[] calldata,
358:         bytes calldata
359:     )
360:         external
361:         pure
362:         override
363:         returns (bytes4)
364:     {

380:     function _doInteraction(
381:         Interaction calldata interaction,
382:         address userAddress
383:     )
384:         internal
385:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
386:     {

445:     function _doMultipleInteractions(
446:         Interaction[] calldata interactions,
447:         uint256[] calldata ids,
448:         address userAddress
449:     )
450:         internal
451:         returns (
452:             uint256[] memory burnIds,
453:             uint256[] memory burnAmounts,
454:             uint256[] memory mintIds,
455:             uint256[] memory mintAmounts
456:         )
457:     {

597:     function _executeInteraction(
598:         Interaction memory interaction,
599:         InteractionType interactionType,
600:         address externalContract,
601:         uint256 specifiedToken,
602:         uint256 specifiedAmount,
603:         address userAddress
604:     )
605:         internal
606:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
607:     {

640:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

648:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

682:     function _unpackInteractionTypeAndAddress(Interaction memory interaction)
683:         internal
684:         pure
685:         returns (InteractionType interactionType, address externalContract)
686:     {

700:     function _getSpecifiedToken(
701:         InteractionType interactionType,
702:         address externalContract,
703:         Interaction memory interaction
704:     )
705:         internal
706:         view
707:         returns (uint256 specifiedToken)
708:     {

745:     function _computeOutputAmount(
746:         address primitive,
747:         uint256 inputToken,
748:         uint256 outputToken,
749:         uint256 inputAmount,
750:         address userAddress,
751:         bytes32 metadata
752:     )
753:         internal
754:         returns (uint256 outputAmount)
755:     {

786:     function _computeInputAmount(
787:         address primitive,
788:         uint256 inputToken,
789:         uint256 outputToken,
790:         uint256 outputAmount,
791:         address userAddress,
792:         bytes32 metadata
793:     )
794:         internal
795:         returns (uint256 inputAmount)
796:     {

920:     function _erc1155Wrap(
921:         address tokenAddress,
922:         uint256 tokenId,
923:         uint256 amount,
924:         address userAddress,
925:         uint256 oceanId
926:     )
927:         private
928:     {
929:         if (tokenAddress == address(this)) revert NO_RECURSIVE_WRAPS();

955:     function _erc1155Unwrap(
956:         address tokenAddress,
957:         uint256 tokenId,
958:         uint256 amount,
959:         address userAddress,
960:         uint256 oceanId
961:     )
962:         private
963:     {
964:         if (tokenAddress == address(this)) revert NO_RECURSIVE_UNWRAPS();

1068:     function _determineTransferAmount(
1069:         uint256 amount,
1070:         uint8 decimals
1071:     )
1072:         private
1073:         pure
1074:         returns (uint256 transferAmount, uint256 dust)
1075:     {

1123:     function _convertDecimals(
1124:         uint8 decimalsFrom,
1125:         uint8 decimalsTo,
1126:         uint256 amountToConvert
1127:     )
1128:         internal
1129:         pure
1130:         returns (uint256 convertedAmount, uint256 truncatedAmount)
1131:     {

```


*GitHub* : [L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L186),[L198](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L198),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L326](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L326),[L327](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L327),[L328](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L328),[L329](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L329),[L330](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L330),[L331](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L331),[L332](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L332),[L333](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L333),[L334](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L334),[L335](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L335),[L336](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L336),[L337](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L337),[L353](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L353),[L354](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L354),[L355](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L355),[L356](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L356),[L357](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L357),[L358](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L358),[L359](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L359),[L360](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L360),[L361](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L361),[L362](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L362),[L363](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L363),[L364](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L364),[L380](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L380),[L381](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L381),[L382](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L382),[L383](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L383),[L384](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L384),[L385](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L385),[L386](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L386),[L445](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L445),[L446](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L446),[L447](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L447),[L448](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L448),[L449](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L449),[L450](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L450),[L451](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L451),[L452](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L452),[L453](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L453),[L454](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L454),[L455](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L455),[L456](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L456),[L457](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L457),[L597](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L597),[L598](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L598),[L599](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L599),[L600](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L600),[L601](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L601),[L602](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L602),[L603](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L603),[L604](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L604),[L605](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L605),[L606](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L606),[L607](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L607),[L640](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L640),[L648](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L648),[L682](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L682),[L683](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L683),[L684](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L684),[L685](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L685),[L686](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L686),[L700](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L700),[L701](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L701),[L702](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L702),[L703](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L703),[L704](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L704),[L705](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L705),[L706](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L706),[L707](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L707),[L708](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L708),[L745](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L745),[L746](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L746),[L747](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L747),[L748](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L748),[L749](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L749),[L750](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L750),[L751](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L751),[L752](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L752),[L753](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L753),[L754](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L754),[L755](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L755),[L786](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L786),[L787](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L787),[L788](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L788),[L789](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L789),[L790](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L790),[L791](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L791),[L792](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L792),[L793](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L793),[L794](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L794),[L795](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L795),[L796](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L796),[L920](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L920),[L921](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L921),[L922](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L922),[L923](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L923),[L924](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L924),[L925](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L925),[L926](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L926),[L927](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L927),[L928](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L928),[L929](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L929),[L955](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L955),[L956](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L956),[L957](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L957),[L958](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L958),[L959](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L959),[L960](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L960),[L961](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L961),[L962](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L962),[L963](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L963),[L964](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L964),[L1068](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1068),[L1069](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1069),[L1070](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1070),[L1071](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1071),[L1072](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1072),[L1073](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1073),[L1074](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1074),[L1075](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1075),[L1123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1123),[L1124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1124),[L1125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1125),[L1126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1126),[L1127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1127),[L1128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1128),[L1129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1129),[L1130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1130),[L1131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1131)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

142:     function primitiveOutputAmount(
143:         uint256 inputToken,
144:         uint256 outputToken,
145:         uint256 inputAmount,
146:         bytes32 minimumOutputAmount
147:     )
148:         internal
149:         override
150:         returns (uint256 outputAmount)
151:     {

175:         if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();

201:     function _determineComputeType(
202:         uint256 inputToken,
203:         uint256 outputToken
204:     )
205:         private
206:         view
207:         returns (ComputeType computeType)
208:     {
209:         if (((inputToken == xToken) && (outputToken == yToken)) || ((inputToken == yToken) && (outputToken == xToken)))
210:         {

209:         if (((inputToken == xToken) && (outputToken == yToken)) || ((inputToken == yToken) && (outputToken == xToken)))
210:         {

```


*GitHub* : [L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L151),[L175](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L175),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L201),[L202](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L202),[L203](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L203),[L204](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L204),[L205](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L205),[L206](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L206),[L207](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L207),[L208](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L208),[L209](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L209),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L210),[L209](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L209),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L210)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

178:     function primitiveOutputAmount(
179:         uint256 inputToken,
180:         uint256 outputToken,
181:         uint256 inputAmount,
182:         bytes32 minimumOutputAmount
183:     )
184:         internal
185:         override
186:         returns (uint256 outputAmount)
187:     {

201:             ICurveTricrypto(primitive).exchange{ value: inputToken == zToken ? rawInputAmount : 0 }(
202:                 indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0, useEth
203:             );

227:         if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();

264:     function _determineComputeType(
265:         uint256 inputToken,
266:         uint256 outputToken
267:     )
268:         private
269:         view
270:         returns (ComputeType computeType)
271:     {
272:         if (
273:             ((inputToken == xToken && outputToken == yToken) || (inputToken == yToken && outputToken == xToken))
274:                 || ((inputToken == xToken && outputToken == zToken) || (inputToken == zToken && outputToken == xToken))
275:                 || ((inputToken == yToken && outputToken == zToken) || (inputToken == zToken && outputToken == yToken))
276:         ) {

```


*GitHub* : [L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L178),[L179](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L179),[L180](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L180),[L181](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L181),[L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L182),[L183](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L183),[L184](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L184),[L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L185),[L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L186),[L187](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L187),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L201),[L202](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L202),[L203](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L203),[L227](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L227),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L265),[L266](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L266),[L267](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L267),[L268](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L268),[L269](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L269),[L270](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L270),[L271](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L271),[L272](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L272),[L273](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L273),[L274](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L274),[L275](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L275),[L276](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L276)

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

138:     function _convertDecimals(
139:         uint8 decimalsFrom,
140:         uint8 decimalsTo,
141:         uint256 amountToConvert
142:     )
143:         internal
144:         pure
145:         returns (uint256 convertedAmount)
146:     {

```


*GitHub* : [L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L138),[L139](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L139),[L140](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L140),[L141](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L141),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L146)
### [N-12]<a name="n-12"></a> Take advantage of Custom Error's return value property
An important feature of Custom Error is that values such as address, tokenID, msg.value can be written inside the () sign, this kind of approach provides a serious advantage in debugging and examining the revert details of dapps such as tenderly.

*There are 11 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

186:         if (!isApprovedForAll(userAddress, msg.sender)) revert FORWARDER_NOT_APPROVED();

640:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

648:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

840:             revert NO_DECIMAL_METHOD();

878:             revert NO_DECIMAL_METHOD();

929:         if (tokenAddress == address(this)) revert NO_RECURSIVE_WRAPS();

964:         if (tokenAddress == address(this)) revert NO_RECURSIVE_UNWRAPS();

```


*GitHub* : [L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L186),[L640](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L640),[L648](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L648),[L840](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L840),[L878](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L878),[L929](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L929),[L964](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L964)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

175:         if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();

217:             revert INVALID_COMPUTE_TYPE();

```


*GitHub* : [L175](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L175),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L217)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

227:         if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();

287:             revert INVALID_COMPUTE_TYPE();

```


*GitHub* : [L227](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L227),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L287)
### [N-13]<a name="n-13"></a> Use custom errors rather than `require`/`revert`
Custom errors are available from solidity version 0.8.4. Custom errors are more easily processed in try-catch blocks, and are easier to re-use and maintain.

*There are 3 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

198:         if (MIN_UNWRAP_FEE_DIVISOR > nextUnwrapFeeDivisor) revert();

```


*GitHub* : [L198](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L198)

```solidity
File: src/adapters/OceanAdapter.sol

39:         require(msg.sender == ocean);

93:         revert();

```


*GitHub* : [L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L39),[L93](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L93)
### [N-14]<a name="n-14"></a> Complex casting
Complex casting should be avoided in Solidity contracts where possible to prevent unintended consequences and ensure accurate data representation. Performing multiple type casts in succession can lead to unexpected truncation, rounding errors, or loss of precision, potentially compromising the contract's functionality and reliability. Consider adding comments to explain in detail why the casts are necessary, and any implicit reasons why the cast does not introduce an overflow.

*There are 3 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

689:         externalContract = address(uint160(uint256(interactionTypeAndAddress)));

```


*GitHub* : [L689](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L689)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

167:             inputAmounts[uint256(int256(indexOfInputAmount))] = rawInputAmount;

```


*GitHub* : [L167](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L167)

```solidity
File: src/adapters/OceanAdapter.sol

100:         uint256 packedValue = uint256(uint160(token));

```


*GitHub* : [L100](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L100)
### [N-15]<a name="n-15"></a> Redundant `else` block
One level of nesting can be removed by not having an else block when the if-block returns.

*There are 42 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

310:         if (_ERC721InteractionStatus == INTERACTION) {
311:             return IERC721Receiver.onERC721Received.selector;
312:         } else {
313:             return 0;
314:         }

338:         if (_ERC1155InteractionStatus == INTERACTION) {
339:             return IERC1155Receiver.onERC1155Received.selector;
340:         } else {
341:             return 0;
342:         }

```


*GitHub* : [L310](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L310),[L311](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L311),[L312](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L312),[L313](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L313),[L314](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L314),[L338](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L338),[L339](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L339),[L340](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L340),[L341](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L341),[L342](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L342)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

209:         if (((inputToken == xToken) && (outputToken == yToken)) || ((inputToken == yToken) && (outputToken == xToken)))
210:         {
211:             return ComputeType.Swap;
212:         } else if (((inputToken == xToken) || (inputToken == yToken)) && (outputToken == lpTokenId)) {
213:             return ComputeType.Deposit;
214:         } else if ((inputToken == lpTokenId) && ((outputToken == xToken) || (outputToken == yToken))) {
215:             return ComputeType.Withdraw;
216:         } else {
217:             revert INVALID_COMPUTE_TYPE();
218:         }

```


*GitHub* : [L209](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L209),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L215),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L217),[L218](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L218)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

250:         if (tokenAddress == underlying[zToken]) {
251:             return address(this).balance;
252:         } else {
253:             return IERC20Metadata(tokenAddress).balanceOf(address(this));
254:         }

272:         if (
273:             ((inputToken == xToken && outputToken == yToken) || (inputToken == yToken && outputToken == xToken))
274:                 || ((inputToken == xToken && outputToken == zToken) || (inputToken == zToken && outputToken == xToken))
275:                 || ((inputToken == yToken && outputToken == zToken) || (inputToken == zToken && outputToken == yToken))
276:         ) {
277:             return ComputeType.Swap;
278:         } else if (
279:             ((inputToken == xToken) || (inputToken == yToken) || (inputToken == zToken)) && (outputToken == lpTokenId)
280:         ) {
281:             return ComputeType.Deposit;
282:         } else if (
283:             (inputToken == lpTokenId) && ((outputToken == xToken) || (outputToken == yToken) || (outputToken == zToken))
284:         ) {
285:             return ComputeType.Withdraw;
286:         } else {
287:             revert INVALID_COMPUTE_TYPE();
288:         }

```


*GitHub* : [L250](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L250),[L251](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L251),[L252](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L252),[L253](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L253),[L254](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L254),[L272](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L272),[L273](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L273),[L274](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L274),[L275](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L275),[L276](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L276),[L277](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L277),[L278](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L278),[L279](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L279),[L280](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L280),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L288)
### [N-16]<a name="n-16"></a> Consider adding emergency-stop functionality
Adding a way to quickly halt protocol functionality in an emergency, rather than having to pause individual contracts one-by-one, will make in-progress hack mitigation faster and much less stressful.

*There are 2 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

```


*GitHub* : [L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

25: contract CurveTricryptoAdapter is OceanAdapter {

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25)
### [N-17]<a name="n-17"></a> Use `ERC1155Holder` over `ERC1155Receiver`
View OpenZeppelin's v5.0 release candidate changes [here](https://github.com/OpenZeppelin/openzeppelin-contracts/releases/tag/v5.0.0-rc.0).

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

14: import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

```


*GitHub* : [L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L14)
### [N-18]<a name="n-18"></a> Events may be emitted out of order due to reentrancy
To strictly conform to the Checks Effects Interactions pattern, it is recommended to emit events before any external interactions.

*There are 112 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

445:     function _doMultipleInteractions(
446:         Interaction[] calldata interactions,
447:         uint256[] calldata ids,
448:         address userAddress
449:     )
450:         internal
451:         returns (
452:             uint256[] memory burnIds,
453:             uint256[] memory burnAmounts,
454:             uint256[] memory mintIds,
455:             uint256[] memory mintAmounts
456:         )
457:     {

478:             balanceDeltas.increaseBalanceDelta(WRAPPED_ETHER_ID, msg.value);
479:             emit EtherWrap(msg.value, userAddress);

745:     function _computeOutputAmount(
746:         address primitive,
747:         uint256 inputToken,
748:         uint256 outputToken,
749:         uint256 inputAmount,
750:         address userAddress,
751:         bytes32 metadata
752:     )
753:         internal
754:         returns (uint256 outputAmount)
755:     {

759:         outputAmount =
760:             IOceanPrimitive(primitive).computeOutputAmount(inputToken, outputToken, inputAmount, userAddress, metadata);

764:         emit ComputeOutputAmount(primitive, inputToken, outputToken, inputAmount, outputAmount, userAddress);

786:     function _computeInputAmount(
787:         address primitive,
788:         uint256 inputToken,
789:         uint256 outputToken,
790:         uint256 outputAmount,
791:         address userAddress,
792:         bytes32 metadata
793:     )
794:         internal
795:         returns (uint256 inputAmount)
796:     {

800:         inputAmount =
801:             IOceanPrimitive(primitive).computeInputAmount(inputToken, outputToken, outputAmount, userAddress, metadata);

805:         emit ComputeInputAmount(primitive, inputToken, outputToken, inputAmount, outputAmount, userAddress);

820:     function _erc20Wrap(address tokenAddress, uint256 amount, address userAddress, uint256 outputToken) private {

836:             SafeERC20.safeTransferFrom(IERC20(tokenAddress), userAddress, address(this), transferAmount);

838:             emit Erc20Wrap(tokenAddress, transferAmount, amount, dust, userAddress, outputToken);

864:     function _erc20Unwrap(address tokenAddress, uint256 amount, address userAddress, uint256 inputToken) private {

875:             SafeERC20.safeTransfer(IERC20(tokenAddress), userAddress, transferAmount);
876:             emit Erc20Unwrap(tokenAddress, transferAmount, amount, feeCharged, userAddress, inputToken);

889:     function _erc721Wrap(address tokenAddress, uint256 tokenId, address userAddress, uint256 oceanId) private {

891:         IERC721(tokenAddress).safeTransferFrom(userAddress, address(this), tokenId);

893:         emit Erc721Wrap(tokenAddress, tokenId, userAddress, oceanId);

903:     function _erc721Unwrap(address tokenAddress, uint256 tokenId, address userAddress, uint256 oceanId) private {
904:         IERC721(tokenAddress).safeTransferFrom(address(this), userAddress, tokenId);
905:         emit Erc721Unwrap(tokenAddress, tokenId, userAddress, oceanId);

920:     function _erc1155Wrap(
921:         address tokenAddress,
922:         uint256 tokenId,
923:         uint256 amount,
924:         address userAddress,
925:         uint256 oceanId
926:     )
927:         private
928:     {

931:         IERC1155(tokenAddress).safeTransferFrom(userAddress, address(this), tokenId, amount, "");

933:         emit Erc1155Wrap(tokenAddress, tokenId, amount, userAddress, oceanId);

955:     function _erc1155Unwrap(
956:         address tokenAddress,
957:         uint256 tokenId,
958:         uint256 amount,
959:         address userAddress,
960:         uint256 oceanId
961:     )
962:         private
963:     {

968:         IERC1155(tokenAddress).safeTransferFrom(address(this), userAddress, tokenId, amountRemaining, "");
969:         emit Erc1155Unwrap(tokenAddress, tokenId, amount, feeCharged, userAddress, oceanId);

978:     function _etherUnwrap(uint256 amount, address userAddress) private {

982:         payable(userAddress).transfer(transferAmount);
983:         emit EtherUnwrap(transferAmount, feeCharged, userAddress);

```


*GitHub* : [L903](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L903),[L445](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L445),[L446](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L446),[L447](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L447),[L448](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L448),[L449](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L449),[L450](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L450),[L451](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L451),[L452](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L452),[L453](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L453),[L454](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L454),[L455](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L455),[L456](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L456),[L457](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L457),[L478](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L478),[L479](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L479),[L745](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L745),[L746](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L746),[L747](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L747),[L748](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L748),[L749](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L749),[L750](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L750),[L751](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L751),[L752](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L752),[L753](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L753),[L754](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L754),[L755](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L755),[L759](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L759),[L760](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L760),[L764](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L764),[L786](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L786),[L787](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L787),[L788](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L788),[L789](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L789),[L790](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L790),[L791](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L791),[L792](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L792),[L793](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L793),[L794](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L794),[L795](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L795),[L796](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L796),[L800](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L800),[L801](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L801),[L805](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L805),[L820](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L820),[L836](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L836),[L838](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L838),[L864](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L864),[L875](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L875),[L876](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L876),[L889](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L889),[L891](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L891),[L893](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L893),[L904](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L904),[L905](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L905),[L920](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L920),[L921](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L921),[L922](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L922),[L923](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L923),[L924](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L924),[L925](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L925),[L926](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L926),[L927](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L927),[L928](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L928),[L931](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L931),[L933](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L933),[L955](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L955),[L956](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L956),[L957](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L957),[L958](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L958),[L959](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L959),[L960](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L960),[L961](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L961),[L962](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L962),[L963](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L963),[L968](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L968),[L969](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L969),[L978](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L978),[L982](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L982),[L983](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L983)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

142:     function primitiveOutputAmount(
143:         uint256 inputToken,
144:         uint256 outputToken,
145:         uint256 inputAmount,
146:         bytes32 minimumOutputAmount
147:     )
148:         internal
149:         override
150:         returns (uint256 outputAmount)
151:     {

163:             rawOutputAmount =
164:                 ICurve2Pool(primitive).exchange(indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0);

168:             rawOutputAmount = ICurve2Pool(primitive).add_liquidity(inputAmounts, 0);

170:             rawOutputAmount = ICurve2Pool(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

178:             emit Swap(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

```


*GitHub* : [L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L163),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L151),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L150),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L149),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L148),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L147),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L146),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L145),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L142),[L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L178),[L170](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L170),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L168),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L164)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

178:     function primitiveOutputAmount(
179:         uint256 inputToken,
180:         uint256 outputToken,
181:         uint256 inputAmount,
182:         bytes32 minimumOutputAmount
183:     )
184:         internal
185:         override
186:         returns (uint256 outputAmount)
187:     {

210:             ICurveTricrypto(primitive).add_liquidity(inputAmounts, 0);

214:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);
215:                 IWETH(underlying[zToken]).withdraw(
216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
217:                 );

219:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

230:             emit Swap(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

```


*GitHub* : [L219](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L219),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L215),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L230),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L214),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L210),[L187](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L187),[L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L186),[L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L185),[L184](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L184),[L183](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L183),[L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L182),[L181](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L181),[L180](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L180),[L179](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L179),[L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L178),[L216](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L216),[L217](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L217)
### [N-19]<a name="n-19"></a> Event missing `msg.sender` parameter
When an action is triggered based on a user's action, not being able to filter based on who triggered the action makes event processing a lot more cumbersome. Including the `msg.sender` the events of these types of action will make events much more useful to end users, especially when `msg.sender` is not `tx.origin`.

*There are 13 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

396:             emit EtherWrap(msg.value, userAddress);

479:             emit EtherWrap(msg.value, userAddress);

764:         emit ComputeOutputAmount(primitive, inputToken, outputToken, inputAmount, outputAmount, userAddress);

805:         emit ComputeInputAmount(primitive, inputToken, outputToken, inputAmount, outputAmount, userAddress);

838:             emit Erc20Wrap(tokenAddress, transferAmount, amount, dust, userAddress, outputToken);

876:             emit Erc20Unwrap(tokenAddress, transferAmount, amount, feeCharged, userAddress, inputToken);

893:         emit Erc721Wrap(tokenAddress, tokenId, userAddress, oceanId);

905:         emit Erc721Unwrap(tokenAddress, tokenId, userAddress, oceanId);

933:         emit Erc1155Wrap(tokenAddress, tokenId, amount, userAddress, oceanId);

969:         emit Erc1155Unwrap(tokenAddress, tokenId, amount, feeCharged, userAddress, oceanId);

983:         emit EtherUnwrap(transferAmount, feeCharged, userAddress);

```


*GitHub* : [L838](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L838),[L983](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L983),[L969](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L969),[L933](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L933),[L905](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L905),[L893](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L893),[L876](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L876),[L805](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L805),[L764](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L764),[L479](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L479),[L396](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L396)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

182:             emit Withdraw(outputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

```


*GitHub* : [L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L182)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

234:             emit Withdraw(outputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);

```


*GitHub* : [L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L234)
### [N-20]<a name="n-20"></a> Use `indexed` for event parameters
Index event fields make the field more quickly accessible to  [off-chain tools](https://ethereum.stackexchange.com/questions/40396/can-somebody-please-explain-the-concept-of-event-indexing) that parse events. This is especially useful when it comes to filtering based on an address. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields).  Where applicable, each event should use three `indexed` fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three applicable fields, all of the applicable fields should be indexed.

*There are 49 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

111:     event ChangeUnwrapFee(uint256 oldFee, uint256 newFee, address sender);

```


*GitHub* : [L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L111)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

30:     event Swap(
31:         uint256 inputToken,
32:         uint256 inputAmount,
33:         uint256 outputAmount,
34:         bytes32 slippageProtection,
35:         address user,
36:         bool computeOutput
37:     );
38:     event Deposit(
39:         uint256 inputToken,
40:         uint256 inputAmount,
41:         uint256 outputAmount,
42:         bytes32 slippageProtection,
43:         address user,
44:         bool computeOutput
45:     );
46:     event Withdraw(
47:         uint256 outputToken,
48:         uint256 inputAmount,
49:         uint256 outputAmount,
50:         bytes32 slippageProtection,
51:         address user,
52:         bool computeOutput
53:     );

```


*GitHub* : [L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L35),[L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L34),[L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L33),[L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L32),[L31](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L31),[L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L30),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L53),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L52),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L48),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L47),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L46),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L45),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L44),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L43),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L42),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L41),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L40),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L39),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L37),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L36)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

35:     event Swap(
36:         uint256 inputToken,
37:         uint256 inputAmount,
38:         uint256 outputAmount,
39:         bytes32 slippageProtection,
40:         address user,
41:         bool computeOutput
42:     );
43:     event Deposit(
44:         uint256 inputToken,
45:         uint256 inputAmount,
46:         uint256 outputAmount,
47:         bytes32 slippageProtection,
48:         address user,
49:         bool computeOutput
50:     );
51:     event Withdraw(
52:         uint256 outputToken,
53:         uint256 inputAmount,
54:         uint256 outputAmount,
55:         bytes32 slippageProtection,
56:         address user,
57:         bool computeOutput
58:     );

```


*GitHub* : [L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L40),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L58),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L57),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L56),[L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L55),[L54](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L54),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L53),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L52),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L51),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L50),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L49),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L48),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L47),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L46),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L45),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L44),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L43),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L42),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L41),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L39),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L38),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L37),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L36),[L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L35)
### [N-21]<a name="n-21"></a> Function modifier order does not follow the Solidity Style Guide
The [Solidity Style Guide](https://docs.soliditylang.org/en/v0.8.19/style-guide.html#function-declaration) states that the modifier order for a function should be:  1. Visibility 2. Mutability 3. Virtual 4. Override 5. Custom modifiers  The following functions do not adhere to this ordering.

*There are 26 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

```


*GitHub* : [L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295)
### [N-22]<a name="n-22"></a> Function order doesn't follow Solidity style guide
The [Solidity style guide](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#order-of-functions) states that functions should be laid out in the following order: `constructor`, `receive`, `fallback`, `external`, `public`, `internal`, `private`. For brevity, only the first function that violates this rule is shown in the following contracts.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

```


*GitHub* : [L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79),[L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

25: contract CurveTricryptoAdapter is OceanAdapter {

249:     function _getBalance(address tokenAddress) internal view returns (uint256 balance) {

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25),[L249](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L249)
### [N-23]<a name="n-23"></a> High Cyclomatic Complexity in Functions
Functions with high cyclomatic complexity are harder to understand, test, and maintain. Consider breaking down these blocks into more manageable units, by splitting things into utility functions, by reducing nesting, and by using early returns.  See [here](https://en.wikipedia.org/wiki/Cyclomatic_complexity) for more information on cyclomatic complexity.

*There are 44 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

445:     function _doMultipleInteractions(
446:         Interaction[] calldata interactions,
447:         uint256[] calldata ids,
448:         address userAddress
449:     )
450:         internal
451:         returns (
452:             uint256[] memory burnIds,
453:             uint256[] memory burnAmounts,
454:             uint256[] memory mintIds,
455:             uint256[] memory mintAmounts
456:         )
457:     {

597:     function _executeInteraction(
598:         Interaction memory interaction,
599:         InteractionType interactionType,
600:         address externalContract,
601:         uint256 specifiedToken,
602:         uint256 specifiedAmount,
603:         address userAddress
604:     )
605:         internal
606:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
607:     {

```


*GitHub* : [L446](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L446),[L607](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L607),[L606](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L606),[L605](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L605),[L604](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L604),[L603](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L603),[L602](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L602),[L601](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L601),[L600](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L600),[L599](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L599),[L598](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L598),[L597](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L597),[L457](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L457),[L456](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L456),[L455](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L455),[L454](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L454),[L453](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L453),[L452](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L452),[L451](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L451),[L450](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L450),[L449](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L449),[L448](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L448),[L447](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L447),[L445](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L445)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

142:     function primitiveOutputAmount(
143:         uint256 inputToken,
144:         uint256 outputToken,
145:         uint256 inputAmount,
146:         bytes32 minimumOutputAmount
147:     )
148:         internal
149:         override
150:         returns (uint256 outputAmount)
151:     {

```


*GitHub* : [L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L151),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L143),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L142),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L149)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

178:     function primitiveOutputAmount(
179:         uint256 inputToken,
180:         uint256 outputToken,
181:         uint256 inputAmount,
182:         bytes32 minimumOutputAmount
183:     )
184:         internal
185:         override
186:         returns (uint256 outputAmount)
187:     {

```


*GitHub* : [L183](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L183),[L187](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L187),[L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L186),[L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L185),[L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L178),[L179](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L179),[L180](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L180),[L181](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L181),[L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L182),[L184](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L184)
### [N-24]<a name="n-24"></a> `address` parameters should be sanitized
Implement a zero address check in functions with `address` parameters to prevent unexpected behaviour.

*There are 180 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

305:     function supportsInterface(bytes4 interfaceId) public view virtual override(OceanERC1155, IERC165) returns (bool) {

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

326:     function onERC1155Received(
327:         address,
328:         address,
329:         uint256,
330:         uint256,
331:         bytes calldata
332:     )
333:         external
334:         view
335:         override
336:         returns (bytes4)
337:     {

353:     function onERC1155BatchReceived(
354:         address,
355:         address,
356:         uint256[] calldata,
357:         uint256[] calldata,
358:         bytes calldata
359:     )
360:         external
361:         pure
362:         override
363:         returns (bytes4)
364:     {

380:     function _doInteraction(
381:         Interaction calldata interaction,
382:         address userAddress
383:     )
384:         internal
385:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
386:     {

445:     function _doMultipleInteractions(
446:         Interaction[] calldata interactions,
447:         uint256[] calldata ids,
448:         address userAddress
449:     )
450:         internal
451:         returns (
452:             uint256[] memory burnIds,
453:             uint256[] memory burnAmounts,
454:             uint256[] memory mintIds,
455:             uint256[] memory mintAmounts
456:         )
457:     {

597:     function _executeInteraction(
598:         Interaction memory interaction,
599:         InteractionType interactionType,
600:         address externalContract,
601:         uint256 specifiedToken,
602:         uint256 specifiedAmount,
603:         address userAddress
604:     )
605:         internal
606:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
607:     {

682:     function _unpackInteractionTypeAndAddress(Interaction memory interaction)
683:         internal
684:         pure
685:         returns (InteractionType interactionType, address externalContract)
686:     {

700:     function _getSpecifiedToken(
701:         InteractionType interactionType,
702:         address externalContract,
703:         Interaction memory interaction
704:     )
705:         internal
706:         view
707:         returns (uint256 specifiedToken)
708:     {

745:     function _computeOutputAmount(
746:         address primitive,
747:         uint256 inputToken,
748:         uint256 outputToken,
749:         uint256 inputAmount,
750:         address userAddress,
751:         bytes32 metadata
752:     )
753:         internal
754:         returns (uint256 outputAmount)
755:     {

786:     function _computeInputAmount(
787:         address primitive,
788:         uint256 inputToken,
789:         uint256 outputToken,
790:         uint256 outputAmount,
791:         address userAddress,
792:         bytes32 metadata
793:     )
794:         internal
795:         returns (uint256 inputAmount)
796:     {

820:     function _erc20Wrap(address tokenAddress, uint256 amount, address userAddress, uint256 outputToken) private {

864:     function _erc20Unwrap(address tokenAddress, uint256 amount, address userAddress, uint256 inputToken) private {

889:     function _erc721Wrap(address tokenAddress, uint256 tokenId, address userAddress, uint256 oceanId) private {

903:     function _erc721Unwrap(address tokenAddress, uint256 tokenId, address userAddress, uint256 oceanId) private {

920:     function _erc1155Wrap(
921:         address tokenAddress,
922:         uint256 tokenId,
923:         uint256 amount,
924:         address userAddress,
925:         uint256 oceanId
926:     )
927:         private
928:     {

955:     function _erc1155Unwrap(
956:         address tokenAddress,
957:         uint256 tokenId,
958:         uint256 amount,
959:         address userAddress,
960:         uint256 oceanId
961:     )
962:         private
963:     {

978:     function _etherUnwrap(uint256 amount, address userAddress) private {

1004:     function _increaseBalanceOfPrimitive(address primitive, uint256 inputToken, uint256 inputAmount) internal {

1038:     function _decreaseBalanceOfPrimitive(address primitive, uint256 outputToken, uint256 outputAmount) internal {

```


*GitHub* : [L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L305](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L305),[L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309),[L326](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L326),[L327](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L327),[L328](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L328),[L329](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L329),[L330](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L330),[L331](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L331),[L332](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L332),[L333](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L333),[L334](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L334),[L335](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L335),[L336](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L336),[L337](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L337),[L353](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L353),[L354](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L354),[L355](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L355),[L356](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L356),[L357](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L357),[L358](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L358),[L359](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L359),[L360](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L360),[L361](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L361),[L362](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L362),[L363](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L363),[L364](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L364),[L380](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L380),[L381](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L381),[L382](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L382),[L383](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L383),[L384](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L384),[L385](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L385),[L386](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L386),[L445](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L445),[L446](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L446),[L447](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L447),[L448](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L448),[L449](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L449),[L450](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L450),[L451](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L451),[L452](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L452),[L453](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L453),[L454](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L454),[L455](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L455),[L456](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L456),[L457](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L457),[L597](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L597),[L598](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L598),[L599](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L599),[L600](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L600),[L601](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L601),[L602](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L602),[L603](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L603),[L604](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L604),[L605](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L605),[L606](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L606),[L607](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L607),[L682](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L682),[L683](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L683),[L684](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L684),[L685](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L685),[L686](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L686),[L700](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L700),[L701](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L701),[L702](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L702),[L703](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L703),[L704](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L704),[L705](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L705),[L706](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L706),[L707](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L707),[L708](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L708),[L745](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L745),[L746](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L746),[L747](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L747),[L748](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L748),[L749](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L749),[L750](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L750),[L751](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L751),[L752](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L752),[L753](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L753),[L754](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L754),[L755](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L755),[L786](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L786),[L787](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L787),[L788](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L788),[L789](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L789),[L790](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L790),[L791](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L791),[L792](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L792),[L793](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L793),[L794](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L794),[L795](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L795),[L796](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L796),[L820](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L820),[L864](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L864),[L889](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L889),[L903](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L903),[L920](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L920),[L921](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L921),[L922](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L922),[L923](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L923),[L924](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L924),[L925](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L925),[L926](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L926),[L927](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L927),[L928](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L928),[L955](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L955),[L956](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L956),[L957](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L957),[L958](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L958),[L959](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L959),[L960](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L960),[L961](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L961),[L962](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L962),[L963](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L963),[L978](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L978),[L1004](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1004),[L1038](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1038)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

189:     function _approveToken(address tokenAddress) private {

```


*GitHub* : [L189](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L189)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

241:     function _approveToken(address tokenAddress) private {

249:     function _getBalance(address tokenAddress) internal view returns (uint256 balance) {

```


*GitHub* : [L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L241),[L249](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L249)

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

99:     function _fetchInteractionId(address token, uint256 interactionType) internal pure returns (bytes32) {

108:     function _calculateOceanId(address tokenAddress, uint256 tokenId) internal pure returns (uint256) {

117:     function onERC1155Received(address, address, uint256, uint256, bytes memory) public pure returns (bytes4) {

```


*GitHub* : [L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92),[L99](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L99),[L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L108),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L117)
### [N-25]<a name="n-25"></a> Use ternary expressions over `if`/`else` where possible
Using ternary operators instead of `if`/`else` statements improves readability and reduces the number of lines of code.

*There are 27 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

338:         if (_ERC1155InteractionStatus == INTERACTION) {
339:             return IERC1155Receiver.onERC1155Received.selector;
340:         } else {
341:             return 0;
342:         }

```


*GitHub* : [L338](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L338),[L339](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L339),[L340](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L340),[L341](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L341),[L342](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L342)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

150:         if (tokenId == zToken) {
151:             interaction = Interaction({
152:                 interactionTypeAndAddress: _fetchInteractionId(address(0), uint256(InteractionType.UnwrapEther)),
153:                 inputToken: 0,
154:                 outputToken: 0,
155:                 specifiedAmount: amount,
156:                 metadata: bytes32(0)
157:             });
158:         } else {
159:             interaction = Interaction({
160:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.UnwrapErc20)),
161:                 inputToken: 0,
162:                 outputToken: 0,
163:                 specifiedAmount: amount,
164:                 metadata: bytes32(0)
165:             });
166:         }

250:         if (tokenAddress == underlying[zToken]) {
251:             return address(this).balance;
252:         } else {
253:             return IERC20Metadata(tokenAddress).balanceOf(address(this));
254:         }

```


*GitHub* : [L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L151),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L152),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L153),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L154),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L155),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L156),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L157),[L158](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L158),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L159),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L160),[L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L161),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L162),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L164),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L165),[L166](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L166),[L250](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L250),[L251](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L251),[L252](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L252),[L253](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L253),[L254](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L254)
### [N-26]<a name="n-26"></a> Variable names for `immutable` variables should be in CONSTANT_CASE
Names should consist of all capital letters, with underscores separating words.

*There are 9 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

56:     uint256 public immutable xToken;

59:     uint256 public immutable yToken;

62:     uint256 public immutable lpTokenId;

```


*GitHub* : [L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L56),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L59),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L62)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

61:     uint256 public immutable xToken;

64:     uint256 public immutable yToken;

67:     uint256 public immutable zToken;

70:     uint256 public immutable lpTokenId;

```


*GitHub* : [L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L61),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L64),[L67](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L67),[L70](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L70)

```solidity
File: src/adapters/OceanAdapter.sol

19:     address public immutable ocean;

22:     address public immutable primitive;

```


*GitHub* : [L19](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L19),[L22](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L22)
### [N-27]<a name="n-27"></a> Visibility should be explicitly set rather than defaulting to `internal`
The default visibility for mappings and state variables is `internal`. Explicitly defining visibility improves readability and reduces margin for error during development, testing and auditing.

*There are 13 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

95:     uint256 constant MIN_UNWRAP_FEE_DIVISOR = 2000;

99:     uint8 constant NORMALIZED_DECIMALS = 18;

102:     uint256 constant GET_BALANCE_DELTA = type(uint256).max;

106:     uint256 constant NOT_INTERACTION = 1;
107:     uint256 constant INTERACTION = 2;
108:     uint256 _ERC1155InteractionStatus;
109:     uint256 _ERC721InteractionStatus;

```


*GitHub* : [L95](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L95),[L99](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L99),[L102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L102),[L106](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L106),[L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L107),[L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L108),[L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L109)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

65:     mapping(uint256 => int128) indexOf;

68:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L65),[L68](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L68)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

73:     mapping(uint256 => uint256) indexOf;

76:     mapping(uint256 => uint8) decimals;

291:     fallback() external payable { }

```


*GitHub* : [L73](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L73),[L76](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L76),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L291)

```solidity
File: src/adapters/OceanAdapter.sol

16:     uint8 constant NORMALIZED_DECIMALS = 18;

```


*GitHub* : [L16](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L16)
### [N-28]<a name="n-28"></a> Imports could be organized more systematically
The contract's interface should be imported first, followed by each of the interfaces it uses, followed by all other files. The contracts below do not follow this layout.

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

```


*GitHub* : [L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

20: contract Curve2PoolAdapter is OceanAdapter {

```


*GitHub* : [L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

25: contract CurveTricryptoAdapter is OceanAdapter {

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25)

```solidity
File: src/adapters/OceanAdapter.sol

14: abstract contract OceanAdapter is IOceanPrimitive {

```


*GitHub* : [L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L14)
### [N-29]<a name="n-29"></a> Place `interface` files into a dedicated folder
Using a separate folder for interfaces keeps the codebase organised and helps to facilitate security audits as well as future development.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

10: interface IWETH {

```


*GitHub* : [L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L10)
### [N-30]<a name="n-30"></a> Complex functions should include comments
Large and/or complex functions should include comments to make them easier to understand and reduce margin for error.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

864:     function _erc20Unwrap(address tokenAddress, uint256 amount, address userAddress, uint256 inputToken) private {

```


*GitHub* : [L864](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L864)
### [N-31]<a name="n-31"></a> Lines too long
[Solidity's style guide](https://docs.soliditylang.org/en/latest/style-guide.html#maximum-line-length) states that the maximum suggested line length is 120 characters.   Also, if lines exceed 164 characters then a horizontal scroll bar will be required when viewing the file on Github.  Extensions such as prettier are a simple solution.

*There are 8 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

399:             (InteractionType interactionType, address externalContract) = _unpackInteractionTypeAndAddress(interaction);

413:                 interaction, interactionType, externalContract, specifiedToken, interaction.specifiedAmount, userAddress

760:             IOceanPrimitive(primitive).computeOutputAmount(inputToken, outputToken, inputAmount, userAddress, metadata);

801:             IOceanPrimitive(primitive).computeInputAmount(inputToken, outputToken, outputAmount, userAddress, metadata);

```


*GitHub* : [L399](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L399),[L413](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L413),[L760](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L760),[L801](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L801)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

23:  *   curve tricrypto adapter contract enabling swapping, adding liquidity & removing liquidity for the curve usdt-wbtc-eth pool

132:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.WrapErc20)),

160:                 interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.UnwrapErc20)),

283:             (inputToken == lpTokenId) && ((outputToken == xToken) || (outputToken == yToken) || (outputToken == zToken))

```


*GitHub* : [L23](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L23),[L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L132),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L160),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L283)
### [N-32]<a name="n-32"></a> Use constants rather than magic numbers
Improves code readability and reduces margin for error.

*There are 5 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

1138:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

1143:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

```


*GitHub* : [L1138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1138),[L1143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1143)

```solidity
File: src/adapters/OceanAdapter.sol

101:         packedValue |= interactionType << 248;

152:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

156:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

```


*GitHub* : [L101](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L101),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L152),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L156)
### [N-33]<a name="n-33"></a> Import specific identifiers rather than the whole file
Prefer import declarations that specify the symbol(s) using the form `import {SYMBOL} from "SomeContract.sol"` rather than importing the whole file.  This improves readability, makes flattened files smaller, and speeds up compilation.

*There are 6 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

7: import "./ICurve2Pool.sol";

8: import "./OceanAdapter.sol";

```


*GitHub* : [L7](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L7),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L8)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

7: import "./ICurveTricrypto.sol";

8: import "./OceanAdapter.sol";

```


*GitHub* : [L7](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L7),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L8)

```solidity
File: src/adapters/OceanAdapter.sol

7: import "../ocean/IOceanPrimitive.sol";

8: import "../ocean/Interactions.sol";

```


*GitHub* : [L7](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L7),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L8)
### [N-34]<a name="n-34"></a> Multiple address/ID mappings can be combined into a single mapping of an address/ID to a struct, for readability
Multiple address/ID mappings can be combined into a single mapping of an address/ID to a struct, for readability.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

65:     mapping(uint256 => int128) indexOf;

68:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L65),[L68](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L68)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

73:     mapping(uint256 => uint256) indexOf;

76:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L73](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L73),[L76](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L76)
### [N-35]<a name="n-35"></a> Array inputs not sanitised
If the length of the arrays are not required to be of the same length, user operations may not be fully executed due to a mismatch in the number of items iterated over, versus the number of items provided in the second array.

*There are 30 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

```


*GitHub* : [L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296)
### [N-36]<a name="n-36"></a> Use named function calls
When calling a function, use named parameters to improve readability and reduce the chance of making mistakes. For example: `_mint({account: msg.sender, amount: _amount})`

*There are 4 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

306:         return interfaceId == type(IERC1155Receiver).interfaceId || super.supportsInterface(interfaceId);

516:                     specifiedAmount = balanceDeltas.getBalanceDelta(interactionType, specifiedToken);

529:                     balanceDeltas.decreaseBalanceDelta(inputToken, inputAmount);

535:                     balanceDeltas.increaseBalanceDelta(outputToken, outputAmount);

```


*GitHub* : [L306](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L306),[L516](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L516),[L529](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L529),[L535](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L535)
### [N-37]<a name="n-37"></a> Use named parameters for mappings
Consider using named parameters in mappings (e.g. `mapping(address account => uint256 balance)`) to improve readability. This feature is present since Solidity 0.8.18.

*There are 5 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

65:     mapping(uint256 => int128) indexOf;

68:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L65),[L68](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L68)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

73:     mapping(uint256 => uint256) indexOf;

76:     mapping(uint256 => uint8) decimals;

```


*GitHub* : [L73](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L73),[L76](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L76)

```solidity
File: src/adapters/OceanAdapter.sol

25:     mapping(uint256 => address) public underlying;

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L25)
### [N-38]<a name="n-38"></a> Named return variables used before assignment
As no value is written to the variable, the default value is always read. This is usually due to a bug in the code logic that causes an invalid value to be used.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

251:             return address(this).balance;

```


*GitHub* : [L251](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L251)
### [N-39]<a name="n-39"></a> Natspec: contract natspec missing
Natspec: contract natspec missing.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

10: interface IWETH {

```


*GitHub* : [L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L10)
### [N-40]<a name="n-40"></a> Natspec: contract natspec missing `@author` tag
Natspec: contract natspec missing `@author` tag.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

20: contract Curve2PoolAdapter is OceanAdapter {

```


*GitHub* : [L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

10: interface IWETH {

25: contract CurveTricryptoAdapter is OceanAdapter {

```


*GitHub* : [L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L10),[L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25)

```solidity
File: src/adapters/OceanAdapter.sol

14: abstract contract OceanAdapter is IOceanPrimitive {

```


*GitHub* : [L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L14)
### [N-41]<a name="n-41"></a> Natspec: contract natspec missing `@dev` tag
Natspec: contract natspec missing `@dev` tag.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

20: contract Curve2PoolAdapter is OceanAdapter {

```


*GitHub* : [L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

10: interface IWETH {

25: contract CurveTricryptoAdapter is OceanAdapter {

```


*GitHub* : [L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L10),[L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25)

```solidity
File: src/adapters/OceanAdapter.sol

14: abstract contract OceanAdapter is IOceanPrimitive {

```


*GitHub* : [L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L14)
### [N-42]<a name="n-42"></a> Natspec: contract natspec missing `@notice` tag
Natspec: contract natspec missing `@notice` tag.

*There are 2 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

```


*GitHub* : [L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

10: interface IWETH {

```


*GitHub* : [L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L10)
### [N-43]<a name="n-43"></a> Natspec: contract natspec missing `@title` tag
Natspec: contract natspec missing `@title` tag.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

20: contract Curve2PoolAdapter is OceanAdapter {

```


*GitHub* : [L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

10: interface IWETH {

25: contract CurveTricryptoAdapter is OceanAdapter {

```


*GitHub* : [L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L10),[L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L25)

```solidity
File: src/adapters/OceanAdapter.sol

14: abstract contract OceanAdapter is IOceanPrimitive {

```


*GitHub* : [L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L14)
### [N-44]<a name="n-44"></a> Natspec: error natspec missing
Natspec: error natspec missing.

*There are 2 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

25:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L25)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

30:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L30)
### [N-45]<a name="n-45"></a> Natspec: error natspec missing `@dev` tag
Natspec: error natspec missing `@dev` tag.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

24:     error INVALID_COMPUTE_TYPE();
25:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L24](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L24),[L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L25)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

29:     error INVALID_COMPUTE_TYPE();
30:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L29](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L29),[L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L30)
### [N-46]<a name="n-46"></a> Natspec: error natspec missing `@notice` tag
Natspec: error natspec missing `@notice` tag.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

24:     error INVALID_COMPUTE_TYPE();
25:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L24](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L24),[L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L25)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

29:     error INVALID_COMPUTE_TYPE();
30:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L29](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L29),[L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L30)
### [N-47]<a name="n-47"></a> Natspec: error natspec missing `@param` tag
Natspec: error natspec missing `@param` tag.

*There are 2 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

25:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L25)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

30:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L30)
### [N-48]<a name="n-48"></a> Natspec: event natspec missing
Natspec: event natspec missing.

*There are 82 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

111:     event ChangeUnwrapFee(uint256 oldFee, uint256 newFee, address sender);
112:     event Erc20Wrap(
113:         address indexed erc20Token,
114:         uint256 transferredAmount,
115:         uint256 wrappedAmount,
116:         uint256 dust,
117:         address indexed user,
118:         uint256 indexed oceanId
119:     );
120:     event Erc20Unwrap(
121:         address indexed erc20Token,
122:         uint256 transferredAmount,
123:         uint256 unwrappedAmount,
124:         uint256 feeCharged,
125:         address indexed user,
126:         uint256 indexed oceanId
127:     );
128:     event Erc721Wrap(address indexed erc721Token, uint256 erc721id, address indexed user, uint256 indexed oceanId);
129:     event Erc721Unwrap(address indexed erc721Token, uint256 erc721Id, address indexed user, uint256 indexed oceanId);
130:     event Erc1155Wrap(
131:         address indexed erc1155Token, uint256 erc1155Id, uint256 amount, address indexed user, uint256 indexed oceanId
132:     );
133:     event Erc1155Unwrap(
134:         address indexed erc1155Token,
135:         uint256 erc1155Id,
136:         uint256 amount,
137:         uint256 feeCharged,
138:         address indexed user,
139:         uint256 indexed oceanId
140:     );
141:     event EtherWrap(uint256 amount, address indexed user);
142:     event EtherUnwrap(uint256 amount, uint256 feeCharged, address indexed user);
143:     event ComputeOutputAmount(
144:         address indexed primitive,
145:         uint256 inputToken,
146:         uint256 outputToken,
147:         uint256 inputAmount,
148:         uint256 outputAmount,
149:         address indexed user
150:     );
151:     event ComputeInputAmount(
152:         address indexed primitive,
153:         uint256 inputToken,
154:         uint256 outputToken,
155:         uint256 inputAmount,
156:         uint256 outputAmount,
157:         address indexed user
158:     );
159:     event OceanTransaction(address indexed user, uint256 numberOfInteractions);
160:     event ForwardedOceanTransaction(address indexed forwarder, address indexed user, uint256 numberOfInteractions);

```


*GitHub* : [L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L111),[L112](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L112),[L113](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L113),[L114](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L114),[L115](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L115),[L116](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L116),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L117),[L118](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L118),[L119](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L119),[L120](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L120),[L121](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L121),[L122](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L122),[L123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L123),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L124),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L125),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L126),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L127),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L128),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L129),[L130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L130),[L131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L131),[L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L132),[L133](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L133),[L134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L134),[L135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L135),[L136](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L136),[L137](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L137),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L138),[L139](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L139),[L140](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L140),[L141](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L141),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L151),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L152),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L153),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L154),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L155),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L156),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L157),[L158](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L158),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L159),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L160)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

38:     event Deposit(
39:         uint256 inputToken,
40:         uint256 inputAmount,
41:         uint256 outputAmount,
42:         bytes32 slippageProtection,
43:         address user,
44:         bool computeOutput
45:     );
46:     event Withdraw(
47:         uint256 outputToken,
48:         uint256 inputAmount,
49:         uint256 outputAmount,
50:         bytes32 slippageProtection,
51:         address user,
52:         bool computeOutput
53:     );

```


*GitHub* : [L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L53)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

43:     event Deposit(
44:         uint256 inputToken,
45:         uint256 inputAmount,
46:         uint256 outputAmount,
47:         bytes32 slippageProtection,
48:         address user,
49:         bool computeOutput
50:     );
51:     event Withdraw(
52:         uint256 outputToken,
53:         uint256 inputAmount,
54:         uint256 outputAmount,
55:         bytes32 slippageProtection,
56:         address user,
57:         bool computeOutput
58:     );

```


*GitHub* : [L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L53),[L54](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L54),[L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L58)
### [N-49]<a name="n-49"></a> Natspec: event natspec missing `@dev` tag
Natspec: event natspec missing `@dev` tag.

*There are 98 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

111:     event ChangeUnwrapFee(uint256 oldFee, uint256 newFee, address sender);
112:     event Erc20Wrap(
113:         address indexed erc20Token,
114:         uint256 transferredAmount,
115:         uint256 wrappedAmount,
116:         uint256 dust,
117:         address indexed user,
118:         uint256 indexed oceanId
119:     );
120:     event Erc20Unwrap(
121:         address indexed erc20Token,
122:         uint256 transferredAmount,
123:         uint256 unwrappedAmount,
124:         uint256 feeCharged,
125:         address indexed user,
126:         uint256 indexed oceanId
127:     );
128:     event Erc721Wrap(address indexed erc721Token, uint256 erc721id, address indexed user, uint256 indexed oceanId);
129:     event Erc721Unwrap(address indexed erc721Token, uint256 erc721Id, address indexed user, uint256 indexed oceanId);
130:     event Erc1155Wrap(
131:         address indexed erc1155Token, uint256 erc1155Id, uint256 amount, address indexed user, uint256 indexed oceanId
132:     );
133:     event Erc1155Unwrap(
134:         address indexed erc1155Token,
135:         uint256 erc1155Id,
136:         uint256 amount,
137:         uint256 feeCharged,
138:         address indexed user,
139:         uint256 indexed oceanId
140:     );
141:     event EtherWrap(uint256 amount, address indexed user);
142:     event EtherUnwrap(uint256 amount, uint256 feeCharged, address indexed user);
143:     event ComputeOutputAmount(
144:         address indexed primitive,
145:         uint256 inputToken,
146:         uint256 outputToken,
147:         uint256 inputAmount,
148:         uint256 outputAmount,
149:         address indexed user
150:     );
151:     event ComputeInputAmount(
152:         address indexed primitive,
153:         uint256 inputToken,
154:         uint256 outputToken,
155:         uint256 inputAmount,
156:         uint256 outputAmount,
157:         address indexed user
158:     );
159:     event OceanTransaction(address indexed user, uint256 numberOfInteractions);
160:     event ForwardedOceanTransaction(address indexed forwarder, address indexed user, uint256 numberOfInteractions);

```


*GitHub* : [L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L111),[L112](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L112),[L113](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L113),[L114](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L114),[L115](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L115),[L116](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L116),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L117),[L118](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L118),[L119](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L119),[L120](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L120),[L121](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L121),[L122](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L122),[L123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L123),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L124),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L125),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L126),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L127),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L128),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L129),[L130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L130),[L131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L131),[L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L132),[L133](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L133),[L134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L134),[L135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L135),[L136](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L136),[L137](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L137),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L138),[L139](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L139),[L140](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L140),[L141](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L141),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L151),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L152),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L153),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L154),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L155),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L156),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L157),[L158](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L158),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L159),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L160)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

30:     event Swap(
31:         uint256 inputToken,
32:         uint256 inputAmount,
33:         uint256 outputAmount,
34:         bytes32 slippageProtection,
35:         address user,
36:         bool computeOutput
37:     );
38:     event Deposit(
39:         uint256 inputToken,
40:         uint256 inputAmount,
41:         uint256 outputAmount,
42:         bytes32 slippageProtection,
43:         address user,
44:         bool computeOutput
45:     );
46:     event Withdraw(
47:         uint256 outputToken,
48:         uint256 inputAmount,
49:         uint256 outputAmount,
50:         bytes32 slippageProtection,
51:         address user,
52:         bool computeOutput
53:     );

```


*GitHub* : [L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L30),[L31](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L31),[L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L32),[L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L33),[L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L34),[L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L53)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

35:     event Swap(
36:         uint256 inputToken,
37:         uint256 inputAmount,
38:         uint256 outputAmount,
39:         bytes32 slippageProtection,
40:         address user,
41:         bool computeOutput
42:     );
43:     event Deposit(
44:         uint256 inputToken,
45:         uint256 inputAmount,
46:         uint256 outputAmount,
47:         bytes32 slippageProtection,
48:         address user,
49:         bool computeOutput
50:     );
51:     event Withdraw(
52:         uint256 outputToken,
53:         uint256 inputAmount,
54:         uint256 outputAmount,
55:         bytes32 slippageProtection,
56:         address user,
57:         bool computeOutput
58:     );

```


*GitHub* : [L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L53),[L54](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L54),[L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L58)
### [N-50]<a name="n-50"></a> Natspec: event natspec missing `@notice` tag
Natspec: event natspec missing `@notice` tag.

*There are 98 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

111:     event ChangeUnwrapFee(uint256 oldFee, uint256 newFee, address sender);
112:     event Erc20Wrap(
113:         address indexed erc20Token,
114:         uint256 transferredAmount,
115:         uint256 wrappedAmount,
116:         uint256 dust,
117:         address indexed user,
118:         uint256 indexed oceanId
119:     );
120:     event Erc20Unwrap(
121:         address indexed erc20Token,
122:         uint256 transferredAmount,
123:         uint256 unwrappedAmount,
124:         uint256 feeCharged,
125:         address indexed user,
126:         uint256 indexed oceanId
127:     );
128:     event Erc721Wrap(address indexed erc721Token, uint256 erc721id, address indexed user, uint256 indexed oceanId);
129:     event Erc721Unwrap(address indexed erc721Token, uint256 erc721Id, address indexed user, uint256 indexed oceanId);
130:     event Erc1155Wrap(
131:         address indexed erc1155Token, uint256 erc1155Id, uint256 amount, address indexed user, uint256 indexed oceanId
132:     );
133:     event Erc1155Unwrap(
134:         address indexed erc1155Token,
135:         uint256 erc1155Id,
136:         uint256 amount,
137:         uint256 feeCharged,
138:         address indexed user,
139:         uint256 indexed oceanId
140:     );
141:     event EtherWrap(uint256 amount, address indexed user);
142:     event EtherUnwrap(uint256 amount, uint256 feeCharged, address indexed user);
143:     event ComputeOutputAmount(
144:         address indexed primitive,
145:         uint256 inputToken,
146:         uint256 outputToken,
147:         uint256 inputAmount,
148:         uint256 outputAmount,
149:         address indexed user
150:     );
151:     event ComputeInputAmount(
152:         address indexed primitive,
153:         uint256 inputToken,
154:         uint256 outputToken,
155:         uint256 inputAmount,
156:         uint256 outputAmount,
157:         address indexed user
158:     );
159:     event OceanTransaction(address indexed user, uint256 numberOfInteractions);
160:     event ForwardedOceanTransaction(address indexed forwarder, address indexed user, uint256 numberOfInteractions);

```


*GitHub* : [L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L111),[L112](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L112),[L113](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L113),[L114](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L114),[L115](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L115),[L116](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L116),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L117),[L118](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L118),[L119](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L119),[L120](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L120),[L121](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L121),[L122](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L122),[L123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L123),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L124),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L125),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L126),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L127),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L128),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L129),[L130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L130),[L131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L131),[L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L132),[L133](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L133),[L134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L134),[L135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L135),[L136](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L136),[L137](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L137),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L138),[L139](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L139),[L140](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L140),[L141](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L141),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L151),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L152),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L153),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L154),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L155),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L156),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L157),[L158](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L158),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L159),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L160)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

30:     event Swap(
31:         uint256 inputToken,
32:         uint256 inputAmount,
33:         uint256 outputAmount,
34:         bytes32 slippageProtection,
35:         address user,
36:         bool computeOutput
37:     );
38:     event Deposit(
39:         uint256 inputToken,
40:         uint256 inputAmount,
41:         uint256 outputAmount,
42:         bytes32 slippageProtection,
43:         address user,
44:         bool computeOutput
45:     );
46:     event Withdraw(
47:         uint256 outputToken,
48:         uint256 inputAmount,
49:         uint256 outputAmount,
50:         bytes32 slippageProtection,
51:         address user,
52:         bool computeOutput
53:     );

```


*GitHub* : [L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L30),[L31](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L31),[L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L32),[L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L33),[L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L34),[L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L53)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

35:     event Swap(
36:         uint256 inputToken,
37:         uint256 inputAmount,
38:         uint256 outputAmount,
39:         bytes32 slippageProtection,
40:         address user,
41:         bool computeOutput
42:     );
43:     event Deposit(
44:         uint256 inputToken,
45:         uint256 inputAmount,
46:         uint256 outputAmount,
47:         bytes32 slippageProtection,
48:         address user,
49:         bool computeOutput
50:     );
51:     event Withdraw(
52:         uint256 outputToken,
53:         uint256 inputAmount,
54:         uint256 outputAmount,
55:         bytes32 slippageProtection,
56:         address user,
57:         bool computeOutput
58:     );

```


*GitHub* : [L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L53),[L54](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L54),[L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L58)
### [N-51]<a name="n-51"></a> Natspec: event natspec missing `@param` tag
Natspec: event natspec missing `@param` tag.

*There are 98 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

111:     event ChangeUnwrapFee(uint256 oldFee, uint256 newFee, address sender);
112:     event Erc20Wrap(
113:         address indexed erc20Token,
114:         uint256 transferredAmount,
115:         uint256 wrappedAmount,
116:         uint256 dust,
117:         address indexed user,
118:         uint256 indexed oceanId
119:     );
120:     event Erc20Unwrap(
121:         address indexed erc20Token,
122:         uint256 transferredAmount,
123:         uint256 unwrappedAmount,
124:         uint256 feeCharged,
125:         address indexed user,
126:         uint256 indexed oceanId
127:     );
128:     event Erc721Wrap(address indexed erc721Token, uint256 erc721id, address indexed user, uint256 indexed oceanId);
129:     event Erc721Unwrap(address indexed erc721Token, uint256 erc721Id, address indexed user, uint256 indexed oceanId);
130:     event Erc1155Wrap(
131:         address indexed erc1155Token, uint256 erc1155Id, uint256 amount, address indexed user, uint256 indexed oceanId
132:     );
133:     event Erc1155Unwrap(
134:         address indexed erc1155Token,
135:         uint256 erc1155Id,
136:         uint256 amount,
137:         uint256 feeCharged,
138:         address indexed user,
139:         uint256 indexed oceanId
140:     );
141:     event EtherWrap(uint256 amount, address indexed user);
142:     event EtherUnwrap(uint256 amount, uint256 feeCharged, address indexed user);
143:     event ComputeOutputAmount(
144:         address indexed primitive,
145:         uint256 inputToken,
146:         uint256 outputToken,
147:         uint256 inputAmount,
148:         uint256 outputAmount,
149:         address indexed user
150:     );
151:     event ComputeInputAmount(
152:         address indexed primitive,
153:         uint256 inputToken,
154:         uint256 outputToken,
155:         uint256 inputAmount,
156:         uint256 outputAmount,
157:         address indexed user
158:     );
159:     event OceanTransaction(address indexed user, uint256 numberOfInteractions);
160:     event ForwardedOceanTransaction(address indexed forwarder, address indexed user, uint256 numberOfInteractions);

```


*GitHub* : [L111](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L111),[L112](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L112),[L113](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L113),[L114](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L114),[L115](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L115),[L116](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L116),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L117),[L118](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L118),[L119](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L119),[L120](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L120),[L121](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L121),[L122](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L122),[L123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L123),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L124),[L125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L125),[L126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L126),[L127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L127),[L128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L128),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L129),[L130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L130),[L131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L131),[L132](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L132),[L133](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L133),[L134](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L134),[L135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L135),[L136](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L136),[L137](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L137),[L138](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L138),[L139](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L139),[L140](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L140),[L141](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L141),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L151),[L152](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L152),[L153](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L153),[L154](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L154),[L155](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L155),[L156](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L156),[L157](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L157),[L158](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L158),[L159](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L159),[L160](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L160)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

30:     event Swap(
31:         uint256 inputToken,
32:         uint256 inputAmount,
33:         uint256 outputAmount,
34:         bytes32 slippageProtection,
35:         address user,
36:         bool computeOutput
37:     );
38:     event Deposit(
39:         uint256 inputToken,
40:         uint256 inputAmount,
41:         uint256 outputAmount,
42:         bytes32 slippageProtection,
43:         address user,
44:         bool computeOutput
45:     );
46:     event Withdraw(
47:         uint256 outputToken,
48:         uint256 inputAmount,
49:         uint256 outputAmount,
50:         bytes32 slippageProtection,
51:         address user,
52:         bool computeOutput
53:     );

```


*GitHub* : [L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L30),[L31](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L31),[L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L32),[L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L33),[L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L34),[L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L53)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

35:     event Swap(
36:         uint256 inputToken,
37:         uint256 inputAmount,
38:         uint256 outputAmount,
39:         bytes32 slippageProtection,
40:         address user,
41:         bool computeOutput
42:     );
43:     event Deposit(
44:         uint256 inputToken,
45:         uint256 inputAmount,
46:         uint256 outputAmount,
47:         bytes32 slippageProtection,
48:         address user,
49:         bool computeOutput
50:     );
51:     event Withdraw(
52:         uint256 outputToken,
53:         uint256 inputAmount,
54:         uint256 outputAmount,
55:         bytes32 slippageProtection,
56:         address user,
57:         bool computeOutput
58:     );

```


*GitHub* : [L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L38),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L52),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L53),[L54](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L54),[L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L58)
### [N-52]<a name="n-52"></a> Natspec: function natspec missing
Natspec: function natspec missing.

*There are 14 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

```


*GitHub* : [L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

11:     function deposit() external payable;
12:     function withdraw(uint256 amount) external payable;

```


*GitHub* : [L11](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L11),[L12](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L12)

```solidity
File: src/adapters/OceanAdapter.sol

161:     function primitiveOutputAmount(
162:         uint256 inputToken,
163:         uint256 outputToken,
164:         uint256 inputAmount,
165:         bytes32 metadata
166:     )
167:         internal
168:         virtual
169:         returns (uint256 outputAmount);

171:     function wrapToken(uint256 tokenId, uint256 amount) internal virtual;

173:     function unwrapToken(uint256 tokenId, uint256 amount) internal virtual;

```


*GitHub* : [L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L161),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L162),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L164),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L165),[L166](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L166),[L167](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L167),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L168),[L169](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L169),[L171](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L171),[L173](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L173)
### [N-53]<a name="n-53"></a> Natspec: modifier natspec missing `@dev` tag
Natspec: modifier natspec missing `@dev` tag.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

38:     modifier onlyOcean() {

```


*GitHub* : [L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L38)
### [N-54]<a name="n-54"></a> Natspec: modifier natspec missing `@notice` tag
Natspec: modifier natspec missing `@notice` tag.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

185:     modifier onlyApprovedForwarder(address userAddress) {

```


*GitHub* : [L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L185)
### [N-55]<a name="n-55"></a> Non-external function names should begin with an underscore
According to the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html#underscore-prefix-for-non-external-functions-and-variables), non-external function names should begin with an underscore.

*There are 35 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

102:     function wrapToken(uint256 tokenId, uint256 amount) internal override {

121:     function unwrapToken(uint256 tokenId, uint256 amount) internal override {

142:     function primitiveOutputAmount(
143:         uint256 inputToken,
144:         uint256 outputToken,
145:         uint256 inputAmount,
146:         bytes32 minimumOutputAmount
147:     )
148:         internal
149:         override
150:         returns (uint256 outputAmount)
151:     {

```


*GitHub* : [L102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L102),[L121](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L121),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L151)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

118:     function wrapToken(uint256 tokenId, uint256 amount) internal override {

147:     function unwrapToken(uint256 tokenId, uint256 amount) internal override {

178:     function primitiveOutputAmount(
179:         uint256 inputToken,
180:         uint256 outputToken,
181:         uint256 inputAmount,
182:         bytes32 minimumOutputAmount
183:     )
184:         internal
185:         override
186:         returns (uint256 outputAmount)
187:     {

```


*GitHub* : [L118](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L118),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L147),[L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L178),[L179](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L179),[L180](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L180),[L181](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L181),[L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L182),[L183](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L183),[L184](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L184),[L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L185),[L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L186),[L187](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L187)

```solidity
File: src/adapters/OceanAdapter.sol

161:     function primitiveOutputAmount(
162:         uint256 inputToken,
163:         uint256 outputToken,
164:         uint256 inputAmount,
165:         bytes32 metadata
166:     )
167:         internal
168:         virtual
169:         returns (uint256 outputAmount);

171:     function wrapToken(uint256 tokenId, uint256 amount) internal virtual;

173:     function unwrapToken(uint256 tokenId, uint256 amount) internal virtual;

```


*GitHub* : [L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L161),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L162),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L164),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L165),[L166](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L166),[L167](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L167),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L168),[L169](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L169),[L171](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L171),[L173](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L173)
### [N-56]<a name="n-56"></a> Non-external variable names should begin with an underscore
According to the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html#underscore-prefix-for-non-external-functions-and-variables), non-external variable names should begin with an underscore.

*There are 6 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

95:     uint256 constant MIN_UNWRAP_FEE_DIVISOR = 2000;

99:     uint8 constant NORMALIZED_DECIMALS = 18;

102:     uint256 constant GET_BALANCE_DELTA = type(uint256).max;

106:     uint256 constant NOT_INTERACTION = 1;

107:     uint256 constant INTERACTION = 2;

```


*GitHub* : [L95](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L95),[L99](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L99),[L102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L102),[L106](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L106),[L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L107)

```solidity
File: src/adapters/OceanAdapter.sol

16:     uint8 constant NORMALIZED_DECIMALS = 18;

```


*GitHub* : [L16](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L16)
### [N-57]<a name="n-57"></a> `public` functions not called internally should be declared `external`
Contracts [are allowed](https://docs.soliditylang.org/en/latest/contracts.html#function-overriding) to override their parents' functions and change the visibility from external to public.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

117:     function onERC1155Received(address, address, uint256, uint256, bytes memory) public pure returns (bytes4) {

```


*GitHub* : [L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L117)
### [N-58]<a name="n-58"></a> Use descriptive reason strings for `require`/`revert`
Providing descriptive error strings is important to help user understand why their transaction might have reverted, and also aids debugging.

*There are 3 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

198:         if (MIN_UNWRAP_FEE_DIVISOR > nextUnwrapFeeDivisor) revert();

```


*GitHub* : [L198](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L198)

```solidity
File: src/adapters/OceanAdapter.sol

39:         require(msg.sender == ocean);

93:         revert();

```


*GitHub* : [L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L39),[L93](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L93)
### [N-59]<a name="n-59"></a> Use a `struct` instead of returning multiple values
Functions that return many variables can become difficult to read and maintain. Using a struct to encapsulate these return values can improve code readability, increase reusability, and reduce the likelihood of errors. Consider refactoring functions that return more than three variables to use a struct instead.

*There are 99 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

380:     function _doInteraction(
381:         Interaction calldata interaction,
382:         address userAddress
383:     )
384:         internal
385:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
386:     {

445:     function _doMultipleInteractions(
446:         Interaction[] calldata interactions,
447:         uint256[] calldata ids,
448:         address userAddress
449:     )
450:         internal
451:         returns (
452:             uint256[] memory burnIds,
453:             uint256[] memory burnAmounts,
454:             uint256[] memory mintIds,
455:             uint256[] memory mintAmounts
456:         )
457:     {

597:     function _executeInteraction(
598:         Interaction memory interaction,
599:         InteractionType interactionType,
600:         address externalContract,
601:         uint256 specifiedToken,
602:         uint256 specifiedAmount,
603:         address userAddress
604:     )
605:         internal
606:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
607:     {

682:     function _unpackInteractionTypeAndAddress(Interaction memory interaction)
683:         internal
684:         pure
685:         returns (InteractionType interactionType, address externalContract)
686:     {

1068:     function _determineTransferAmount(
1069:         uint256 amount,
1070:         uint8 decimals
1071:     )
1072:         private
1073:         pure
1074:         returns (uint256 transferAmount, uint256 dust)
1075:     {

1123:     function _convertDecimals(
1124:         uint8 decimalsFrom,
1125:         uint8 decimalsTo,
1126:         uint256 amountToConvert
1127:     )
1128:         internal
1129:         pure
1130:         returns (uint256 convertedAmount, uint256 truncatedAmount)
1131:     {

```


*GitHub* : [L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L380](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L380),[L381](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L381),[L382](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L382),[L383](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L383),[L384](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L384),[L385](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L385),[L386](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L386),[L445](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L445),[L446](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L446),[L447](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L447),[L448](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L448),[L449](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L449),[L450](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L450),[L451](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L451),[L452](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L452),[L453](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L453),[L454](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L454),[L455](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L455),[L456](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L456),[L457](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L457),[L597](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L597),[L598](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L598),[L599](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L599),[L600](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L600),[L601](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L601),[L602](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L602),[L603](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L603),[L604](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L604),[L605](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L605),[L606](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L606),[L607](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L607),[L682](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L682),[L683](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L683),[L684](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L684),[L685](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L685),[L686](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L686),[L1068](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1068),[L1069](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1069),[L1070](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1070),[L1071](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1071),[L1072](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1072),[L1073](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1073),[L1074](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1074),[L1075](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1075),[L1123](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1123),[L1124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1124),[L1125](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1125),[L1126](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1126),[L1127](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1127),[L1128](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1128),[L1129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1129),[L1130](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1130),[L1131](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1131)
### [N-60]<a name="n-60"></a> Make use of Solidiy's `using` keyword
The directive `using A for B` can be used to attach functions (`A`) as operators to user-defined value types or as member functions to any type (`B`). The member functions receive the object they are called on as their first parameter (like the `self` variable in Python). The operator functions receive operands as parameters.  Doing so improves readability, makes debugging easier, and promotes modularity and reusability in the code.

*There are 23 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

18: import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

836:             SafeERC20.safeTransferFrom(IERC20(tokenAddress), userAddress, address(this), transferAmount);

875:             SafeERC20.safeTransfer(IERC20(tokenAddress), userAddress, transferAmount);

1048:     /**
1049:      * @dev This function determines the correct argument to pass to
1050:      *  the external token contract
1051:      * @dev Say the in-Ocean unwrap amount (in 18-decimal) is 0.123456789012345678
1052:      *      If the external token uses decimals == 6:
1053:      *          transferAmount == 123456
1054:      *          dust == 789012345678
1055:      *      If the external token uses decimals == 18:
1056:      *          transferAmount == 123456789012345678
1057:      *          dust == 0
1058:      *      If the external token uses decimals == 21:
1059:      *          transferAmount == 123456789012345678000
1060:      *          dust == 0
1061:      * @param amount the amount of in-Ocean tokens being unwrapped
1062:      * @param decimals returned by IERC20(token).decimals()
1063:      * @return transferAmount the amount passed to SafeERC20.safeTransfer()
1064:      * @return dust The amount of in-Ocean token that are not unwrapped
1065:      *  due to the mismatch between the external token's decimal basis and the
1066:      *  Ocean's NORMALIZED_DECIMALS basis.
1067:      */

```


*GitHub* : [L18](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L18),[L836](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L836),[L875](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L875),[L1048](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1048),[L1049](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1049),[L1050](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1050),[L1051](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1051),[L1052](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1052),[L1053](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1053),[L1054](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1054),[L1055](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1055),[L1056](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1056),[L1057](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1057),[L1058](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1058),[L1059](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1059),[L1060](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1060),[L1061](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1061),[L1062](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1062),[L1063](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1063),[L1064](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1064),[L1065](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1065),[L1066](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1066),[L1067](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1067)
### [N-61]<a name="n-61"></a> Use scientific notation/underscores for large values
e.g. `1e6` or `1_000_000` instead of `1000000`.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

95:     uint256 constant MIN_UNWRAP_FEE_DIVISOR = 2000;

```


*GitHub* : [L95](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L95)
### [N-62]<a name="n-62"></a> Setter does not check that value is changed
In setter functions, consider adding a check for whether the new value is equal to the old value.

*There are 6 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {
197:         /// @notice as the divisor gets smaller, the fee charged gets larger
198:         if (MIN_UNWRAP_FEE_DIVISOR > nextUnwrapFeeDivisor) revert();
199:         emit ChangeUnwrapFee(unwrapFeeDivisor, nextUnwrapFeeDivisor, msg.sender);
200:         unwrapFeeDivisor = nextUnwrapFeeDivisor;
201:     }

```


*GitHub* : [L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196),[L197](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L197),[L198](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L198),[L199](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L199),[L200](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L200),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L201)
### [N-63]<a name="n-63"></a> Consider using a timelock for admin/governance functions
Admin functions that change state should consider adding timelocks so that users and other privileged roles can be notified of and react to upcoming changes. Also, this protects users against a compromised/malicious admin account.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

```


*GitHub* : [L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196)
### [N-64]<a name="n-64"></a> Use single file for all system-wide constants
Use single file for all system-wide constants.

*There are 5 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

95:     uint256 constant MIN_UNWRAP_FEE_DIVISOR = 2000;

99:     uint8 constant NORMALIZED_DECIMALS = 18;

102:     uint256 constant GET_BALANCE_DELTA = type(uint256).max;

106:     uint256 constant NOT_INTERACTION = 1;

107:     uint256 constant INTERACTION = 2;

```


*GitHub* : [L95](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L95),[L99](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L99),[L102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L102),[L106](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L106),[L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L107)
### [N-65]<a name="n-65"></a> Body of `if` statement should be placed on a new line
According to the [Solidity style guide](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures), `if` statements whose body contains a single line should look like this:  ```solidity if (x < 10)     x += 1; ```

*There are 8 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

186:         if (!isApprovedForAll(userAddress, msg.sender)) revert FORWARDER_NOT_APPROVED();

198:         if (MIN_UNWRAP_FEE_DIVISOR > nextUnwrapFeeDivisor) revert();

640:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

648:             if (specifiedAmount != 1) revert INVALID_ERC721_AMOUNT();

929:         if (tokenAddress == address(this)) revert NO_RECURSIVE_WRAPS();

964:         if (tokenAddress == address(this)) revert NO_RECURSIVE_UNWRAPS();

```


*GitHub* : [L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L186),[L198](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L198),[L640](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L640),[L648](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L648),[L929](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L929),[L964](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L964)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

175:         if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L175](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L175)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

227:         if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L227](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L227)
### [N-66]<a name="n-66"></a> State variable declaration should include comments
Comments describing the purpose of each state variable help to make code more readable.

*There are 3 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

107:     uint256 constant INTERACTION = 2;

108:     uint256 _ERC1155InteractionStatus;

109:     uint256 _ERC721InteractionStatus;

```


*GitHub* : [L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L107),[L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L108),[L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L109)
### [N-67]<a name="n-67"></a> Structs, enums, events and errors should be named using CapWords style
See the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html#struct-names) for more info.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

24:     error INVALID_COMPUTE_TYPE();
25:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L24](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L24),[L25](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L25)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

29:     error INVALID_COMPUTE_TYPE();
30:     error SLIPPAGE_LIMIT_EXCEEDED();

```


*GitHub* : [L29](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L29),[L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L30)
### [N-68]<a name="n-68"></a> Function returns unassigned variable
Make sure that functions with a return value always return a valid and assigned value. Even if the default value is as expected, it should be assigned with the default value for code clarity and to reduce confusion.

*There are 34 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

445:     function _doMultipleInteractions(
446:         Interaction[] calldata interactions,
447:         uint256[] calldata ids,
448:         address userAddress
449:     )
450:         internal
451:         returns (
452:             uint256[] memory burnIds,
453:             uint256[] memory burnAmounts,
454:             uint256[] memory mintIds,
455:             uint256[] memory mintAmounts
456:         )
457:     {

```


*GitHub* : [L445](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L445),[L446](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L446),[L447](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L447),[L448](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L448),[L449](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L449),[L450](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L450),[L451](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L451),[L452](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L452),[L453](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L453),[L454](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L454),[L455](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L455),[L456](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L456),[L457](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L457)

```solidity
File: src/adapters/OceanAdapter.sol

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

161:     function primitiveOutputAmount(
162:         uint256 inputToken,
163:         uint256 outputToken,
164:         uint256 inputAmount,
165:         bytes32 metadata
166:     )
167:         internal
168:         virtual
169:         returns (uint256 outputAmount);

```


*GitHub* : [L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92),[L161](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L161),[L162](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L162),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L164),[L165](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L165),[L166](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L166),[L167](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L167),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L168),[L169](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L169)
### [N-69]<a name="n-69"></a> Avoid using underscore at the end of a variable name
The use of the underscore at the end of the variable name is unusual, consider refactoring it.

*There are 9 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

163:      * @dev Creates custom ERC-1155 with passed uri_, sets DAO address, and

169:     constructor(string memory uri_) OceanERC1155(uri_) {

499:             address userAddress_ = userAddress;

```


*GitHub* : [L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L163),[L169](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L169),[L499](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L499)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

77:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

77:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L77),[L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L77)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

85:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

85:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L85),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L85)

```solidity
File: src/adapters/OceanAdapter.sol

32:     constructor(address ocean_, address primitive_) {

32:     constructor(address ocean_, address primitive_) {

```


*GitHub* : [L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L32),[L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L32)
### [N-70]<a name="n-70"></a> Large numeric literals should use underscores
Large numeric literals should use underscores.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

95:     uint256 constant MIN_UNWRAP_FEE_DIVISOR = 2000;

```


*GitHub* : [L95](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L95)
### [N-71]<a name="n-71"></a> Use inline comments for unnamed variables
For example, write `function foo(uint256 x, uint256 /* y */)` instead of `function foo(uint256 x, uint256)`.

*There are 38 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

326:     function onERC1155Received(
327:         address,
328:         address,
329:         uint256,
330:         uint256,
331:         bytes calldata
332:     )
333:         external
334:         view
335:         override
336:         returns (bytes4)
337:     {

353:     function onERC1155BatchReceived(
354:         address,
355:         address,
356:         uint256[] calldata,
357:         uint256[] calldata,
358:         bytes calldata
359:     )
360:         external
361:         pure
362:         override
363:         returns (bytes4)
364:     {

```


*GitHub* : [L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309),[L326](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L326),[L327](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L327),[L328](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L328),[L329](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L329),[L330](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L330),[L331](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L331),[L332](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L332),[L333](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L333),[L334](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L334),[L335](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L335),[L336](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L336),[L337](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L337),[L353](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L353),[L354](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L354),[L355](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L355),[L356](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L356),[L357](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L357),[L358](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L358),[L359](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L359),[L360](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L360),[L361](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L361),[L362](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L362),[L363](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L363),[L364](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L364)

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

117:     function onERC1155Received(address, address, uint256, uint256, bytes memory) public pure returns (bytes4) {

```


*GitHub* : [L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L117)
### [N-72]<a name="n-72"></a> Remove unused imports
Unused imports should be removed to improve readability and reduce contract bytecode size. Note that contracts referenced in comments/NatSpec but not utilised by the contract need not be imported.

*There are 2 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

6: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

8: import "../ocean/Interactions.sol";

```


*GitHub* : [L6](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L6),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L8)
### [N-73]<a name="n-73"></a> Unused local variable
Unused local variable.

*There are 1 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

306:         return interfaceId == type(IERC1155Receiver).interfaceId || super.supportsInterface(interfaceId);

```


*GitHub* : [L306](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L306)
### [N-74]<a name="n-74"></a> Use `bytes.concat` over `abi.encodePacked`
Starting with version 0.8.4, Solidity has the bytes.concat() function, which allows one to concatenate a list of bytes/strings, without extra padding. Using this function rather than abi.encodePacked() makes the intended operation more clear, leading to less reviewer confusion.

*There are 1 instance(s) of this issue:*

```solidity
File: src/adapters/OceanAdapter.sol

109:         return uint256(keccak256(abi.encodePacked(tokenAddress, tokenId)));

```


*GitHub* : [L109](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L109)
### [N-75]<a name="n-75"></a> Use `delete` rather than assigning to `0`
Using `delete` more closely aligns with the intention of the action, and draws more attention towards the changing of state, which may lead to a more thorough audit of its associated logic"

*There are 19 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

392:             inputToken = 0;

393:             inputAmount = 0;

623:             inputToken = 0;

624:             inputAmount = 0;

631:             outputToken = 0;

632:             outputAmount = 0;

641:             inputToken = 0;

642:             inputAmount = 0;

651:             outputToken = 0;

652:             outputAmount = 0;

655:             inputToken = 0;

656:             inputAmount = 0;

663:             outputToken = 0;

664:             outputAmount = 0;

670:             outputToken = 0;

671:             outputAmount = 0;

1107:             dust = 0;

1135:             truncatedAmount = 0;

1140:             truncatedAmount = 0;

```


*GitHub* : [L392](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L392),[L393](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L393),[L623](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L623),[L624](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L624),[L631](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L631),[L632](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L632),[L641](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L641),[L642](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L642),[L651](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L651),[L652](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L652),[L655](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L655),[L656](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L656),[L663](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L663),[L664](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L664),[L670](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L670),[L671](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L671),[L1107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1107),[L1135](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1135),[L1140](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L1140)
### [N-76]<a name="n-76"></a> Use of `approve` is discouraged
OpenZeppelin recommends using `increaseAllowance` and `decreaseAllowance` instead of `approve` to mitigate against the problem described [here](https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729).  Source: [OpenZeppelin docs](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20-increaseAllowance-address-uint256-), OpenZeppelin [ERC20.sol](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol#L170-L216).

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L190](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L190),[L191](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L191)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


*GitHub* : [L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L242),[L243](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L243)
### [N-77]<a name="n-77"></a> Use `@inheritdoc` for overridden functions
See the [Solidity docs](https://docs.soliditylang.org/en/latest/natspec-format.html#tags) for more info.

*There are 122 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

210:     function doInteraction(Interaction calldata interaction)
211:         external
212:         payable
213:         override
214:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
215:     {

229:     function doMultipleInteractions(
230:         Interaction[] calldata interactions,
231:         uint256[] calldata ids
232:     )
233:         external
234:         payable
235:         override
236:         returns (
237:             uint256[] memory burnIds,
238:             uint256[] memory burnAmounts,
239:             uint256[] memory mintIds,
240:             uint256[] memory mintAmounts
241:         )
242:     {

256:     function forwardedDoInteraction(
257:         Interaction calldata interaction,
258:         address userAddress
259:     )
260:         external
261:         payable
262:         override
263:         onlyApprovedForwarder(userAddress)
264:         returns (uint256 burnId, uint256 burnAmount, uint256 mintId, uint256 mintAmount)
265:     {

281:     function forwardedDoMultipleInteractions(
282:         Interaction[] calldata interactions,
283:         uint256[] calldata ids,
284:         address userAddress
285:     )
286:         external
287:         payable
288:         override
289:         onlyApprovedForwarder(userAddress)
290:         returns (
291:             uint256[] memory burnIds,
292:             uint256[] memory burnAmounts,
293:             uint256[] memory mintIds,
294:             uint256[] memory mintAmounts
295:         )
296:     {

305:     function supportsInterface(bytes4 interfaceId) public view virtual override(OceanERC1155, IERC165) returns (bool) {

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

326:     function onERC1155Received(
327:         address,
328:         address,
329:         uint256,
330:         uint256,
331:         bytes calldata
332:     )
333:         external
334:         view
335:         override
336:         returns (bytes4)
337:     {

353:     function onERC1155BatchReceived(
354:         address,
355:         address,
356:         uint256[] calldata,
357:         uint256[] calldata,
358:         bytes calldata
359:     )
360:         external
361:         pure
362:         override
363:         returns (bytes4)
364:     {

```


*GitHub* : [L196](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L196),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L210),[L211](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L211),[L212](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L212),[L213](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L213),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L214),[L215](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L215),[L229](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L229),[L230](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L230),[L231](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L231),[L232](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L232),[L233](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L233),[L234](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L234),[L235](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L235),[L236](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L236),[L237](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L237),[L238](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L238),[L239](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L239),[L240](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L240),[L241](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L241),[L242](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L242),[L256](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L256),[L257](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L257),[L258](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L258),[L259](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L259),[L260](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L260),[L261](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L261),[L262](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L262),[L263](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L263),[L264](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L264),[L265](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L265),[L281](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L281),[L282](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L282),[L283](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L283),[L284](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L284),[L285](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L285),[L286](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L286),[L287](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L287),[L288](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L288),[L289](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L289),[L290](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L290),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L291),[L292](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L292),[L293](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L293),[L294](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L294),[L295](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L295),[L296](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L296),[L305](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L305),[L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309),[L326](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L326),[L327](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L327),[L328](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L328),[L329](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L329),[L330](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L330),[L331](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L331),[L332](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L332),[L333](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L333),[L334](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L334),[L335](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L335),[L336](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L336),[L337](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L337),[L353](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L353),[L354](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L354),[L355](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L355),[L356](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L356),[L357](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L357),[L358](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L358),[L359](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L359),[L360](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L360),[L361](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L361),[L362](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L362),[L363](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L363),[L364](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L364)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

102:     function wrapToken(uint256 tokenId, uint256 amount) internal override {

121:     function unwrapToken(uint256 tokenId, uint256 amount) internal override {

142:     function primitiveOutputAmount(
143:         uint256 inputToken,
144:         uint256 outputToken,
145:         uint256 inputAmount,
146:         bytes32 minimumOutputAmount
147:     )
148:         internal
149:         override
150:         returns (uint256 outputAmount)
151:     {

```


*GitHub* : [L102](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L102),[L121](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L121),[L142](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L142),[L143](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L143),[L144](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L144),[L145](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L145),[L146](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L146),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L147),[L148](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L148),[L149](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L149),[L150](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L150),[L151](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L151)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

118:     function wrapToken(uint256 tokenId, uint256 amount) internal override {

147:     function unwrapToken(uint256 tokenId, uint256 amount) internal override {

178:     function primitiveOutputAmount(
179:         uint256 inputToken,
180:         uint256 outputToken,
181:         uint256 inputAmount,
182:         bytes32 minimumOutputAmount
183:     )
184:         internal
185:         override
186:         returns (uint256 outputAmount)
187:     {

```


*GitHub* : [L118](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L118),[L147](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L147),[L178](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L178),[L179](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L179),[L180](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L180),[L181](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L181),[L182](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L182),[L183](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L183),[L184](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L184),[L185](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L185),[L186](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L186),[L187](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L187)

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

124:     function getTokenSupply(uint256 tokenId) external view override returns (uint256) {

```


*GitHub* : [L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L124)
### [N-78]<a name="n-78"></a> Use named return values
Using named return values instead of explicitly calling `return` improves the readability of the code.

*There are 30 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

305:     function supportsInterface(bytes4 interfaceId) public view virtual override(OceanERC1155, IERC165) returns (bool) {

309:     function onERC721Received(address, address, uint256, bytes calldata) external view override returns (bytes4) {

326:     function onERC1155Received(
327:         address,
328:         address,
329:         uint256,
330:         uint256,
331:         bytes calldata
332:     )
333:         external
334:         view
335:         override
336:         returns (bytes4)
337:     {

353:     function onERC1155BatchReceived(
354:         address,
355:         address,
356:         uint256[] calldata,
357:         uint256[] calldata,
358:         bytes calldata
359:     )
360:         external
361:         pure
362:         override
363:         returns (bytes4)
364:     {

```


*GitHub* : [L305](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L305),[L309](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L309),[L326](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L326),[L327](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L327),[L328](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L328),[L329](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L329),[L330](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L330),[L331](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L331),[L332](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L332),[L333](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L333),[L334](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L334),[L335](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L335),[L336](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L336),[L337](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L337),[L353](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L353),[L354](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L354),[L355](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L355),[L356](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L356),[L357](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L357),[L358](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L358),[L359](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L359),[L360](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L360),[L361](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L361),[L362](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L362),[L363](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L363),[L364](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L364)

```solidity
File: src/adapters/OceanAdapter.sol

99:     function _fetchInteractionId(address token, uint256 interactionType) internal pure returns (bytes32) {

108:     function _calculateOceanId(address tokenAddress, uint256 tokenId) internal pure returns (uint256) {

117:     function onERC1155Received(address, address, uint256, uint256, bytes memory) public pure returns (bytes4) {

124:     function getTokenSupply(uint256 tokenId) external view override returns (uint256) {

```


*GitHub* : [L99](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L99),[L108](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L108),[L117](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L117),[L124](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L124)
### [N-79]<a name="n-79"></a> Use a `struct` to encapsulate multiple function parameters
If a function has too many parameters, replacing them with a struct can improve code readability and maintainability, increase reusability, and reduce the likelihood of errors when passing the parameters.

*There are 75 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

597:     function _executeInteraction(
598:         Interaction memory interaction,
599:         InteractionType interactionType,
600:         address externalContract,
601:         uint256 specifiedToken,
602:         uint256 specifiedAmount,
603:         address userAddress
604:     )
605:         internal
606:         returns (uint256 inputToken, uint256 inputAmount, uint256 outputToken, uint256 outputAmount)
607:     {

745:     function _computeOutputAmount(
746:         address primitive,
747:         uint256 inputToken,
748:         uint256 outputToken,
749:         uint256 inputAmount,
750:         address userAddress,
751:         bytes32 metadata
752:     )
753:         internal
754:         returns (uint256 outputAmount)
755:     {

786:     function _computeInputAmount(
787:         address primitive,
788:         uint256 inputToken,
789:         uint256 outputToken,
790:         uint256 outputAmount,
791:         address userAddress,
792:         bytes32 metadata
793:     )
794:         internal
795:         returns (uint256 inputAmount)
796:     {

920:     function _erc1155Wrap(
921:         address tokenAddress,
922:         uint256 tokenId,
923:         uint256 amount,
924:         address userAddress,
925:         uint256 oceanId
926:     )
927:         private
928:     {

955:     function _erc1155Unwrap(
956:         address tokenAddress,
957:         uint256 tokenId,
958:         uint256 amount,
959:         address userAddress,
960:         uint256 oceanId
961:     )
962:         private
963:     {

```


*GitHub* : [L597](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L597),[L598](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L598),[L599](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L599),[L600](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L600),[L601](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L601),[L602](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L602),[L603](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L603),[L604](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L604),[L605](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L605),[L606](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L606),[L607](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L607),[L745](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L745),[L746](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L746),[L747](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L747),[L748](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L748),[L749](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L749),[L750](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L750),[L751](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L751),[L752](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L752),[L753](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L753),[L754](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L754),[L755](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L755),[L786](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L786),[L787](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L787),[L788](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L788),[L789](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L789),[L790](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L790),[L791](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L791),[L792](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L792),[L793](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L793),[L794](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L794),[L795](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L795),[L796](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L796),[L920](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L920),[L921](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L921),[L922](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L922),[L923](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L923),[L924](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L924),[L925](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L925),[L926](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L926),[L927](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L927),[L928](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L928),[L955](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L955),[L956](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L956),[L957](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L957),[L958](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L958),[L959](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L959),[L960](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L960),[L961](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L961),[L962](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L962),[L963](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L963)

```solidity
File: src/adapters/OceanAdapter.sol

55:     function computeOutputAmount(
56:         uint256 inputToken,
57:         uint256 outputToken,
58:         uint256 inputAmount,
59:         address,
60:         bytes32 metadata
61:     )
62:         external
63:         override
64:         onlyOcean
65:         returns (uint256 outputAmount)
66:     {

81:     function computeInputAmount(
82:         uint256 inputToken,
83:         uint256 outputToken,
84:         uint256 outputAmount,
85:         address userAddress,
86:         bytes32 maximumInputAmount
87:     )
88:         external
89:         override
90:         onlyOcean
91:         returns (uint256 inputAmount)
92:     {

```


*GitHub* : [L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L66),[L81](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L81),[L82](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L82),[L83](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L83),[L84](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L84),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L85),[L86](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L86),[L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L87),[L88](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L88),[L89](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L89),[L90](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L90),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L91),[L92](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L92)
### [N-80]<a name="n-80"></a> Use descriptive constant rather than `0` for function arguments
Passing zero as a function argument can sometimes result in a security issue (e.g. passing zero as the slippage parameter). Consider using a `constant` variable with a descriptive name, so it's clear that the argument is intentionally being used, and for the right reasons.

*There are 20 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

173:         WRAPPED_ETHER_ID = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))

464:             balanceDeltas[i] = BalanceDelta(ids[i], 0);

710:             specifiedToken = _calculateOceanId(externalContract, 0);

```


*GitHub* : [L173](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L173),[L464](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L464),[L710](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L710)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

79:         xToken = _calculateOceanId(xTokenAddress, 0);

85:         yToken = _calculateOceanId(yTokenAddress, 0);

91:         lpTokenId = _calculateOceanId(primitive_, 0);

163:             rawOutputAmount =
164:                 ICurve2Pool(primitive).exchange(indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0);

168:             rawOutputAmount = ICurve2Pool(primitive).add_liquidity(inputAmounts, 0);

170:             rawOutputAmount = ICurve2Pool(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

```


*GitHub* : [L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L79),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L85),[L91](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L91),[L163](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L163),[L164](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L164),[L168](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L168),[L170](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L170)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

87:         xToken = _calculateOceanId(xTokenAddress, 0);

93:         yToken = _calculateOceanId(yTokenAddress, 0);

100:         zToken = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))

107:         lpTokenId = _calculateOceanId(lpTokenAddress, 0);

201:             ICurveTricrypto(primitive).exchange{ value: inputToken == zToken ? rawInputAmount : 0 }(
202:                 indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0, useEth
203:             );

210:             ICurveTricrypto(primitive).add_liquidity(inputAmounts, 0);

214:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

219:                 ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);

```


*GitHub* : [L87](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L87),[L93](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L93),[L100](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L100),[L107](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L107),[L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L201),[L202](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L202),[L203](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L203),[L210](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L210),[L214](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L214),[L219](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L219)
### [N-81]<a name="n-81"></a> No need to initialize variables to their default value
Since the variables are automatically set to 0 when created, it is redundant to initialize it with 0 again.

*There are 2 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

463:         for (uint256 i = 0; i < _idLength;) {

501:             for (uint256 i = 0; i < interactions.length;) {

```


*GitHub* : [L463](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L463),[L501](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L501)
### [N-82]<a name="n-82"></a> Variable names should not end with an underscore
The use of underscore at the end of the variable name is uncommon and also suggests that the variable name was not completely changed.  Consider refactoring `variableName_` to `variableName`.

*There are 7 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

499:             address userAddress_ = userAddress;

```


*GitHub* : [L499](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L499)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

77:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {
77:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L77),[L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L77)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

85:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {
85:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L85),[L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L85)

```solidity
File: src/adapters/OceanAdapter.sol

32:     constructor(address ocean_, address primitive_) {
32:     constructor(address ocean_, address primitive_) {

```


*GitHub* : [L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L32),[L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L32)
### [N-83]<a name="n-83"></a> Avoid extraneous whitespace
See the [Solidity style guide](https://docs.soliditylang.org/en/v0.8.16/style-guide.html#whitespace-in-expressions) for more details.

*There are 4 instance(s) of this issue:*

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

129:             IOceanInteractions(ocean).doInteraction{ value: amount }(interaction);

201:             ICurveTricrypto(primitive).exchange{ value: inputToken == zToken ? rawInputAmount : 0 }(

208:             if (inputToken == zToken) IWETH(underlying[zToken]).deposit{ value: rawInputAmount }();

291:     fallback() external payable { }

```


*GitHub* : [L201](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L201),[L129](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L129),[L208](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L208),[L291](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L291)
### [N-84]<a name="n-84"></a> Missing `address(0)` checks in constructor
Failing to check for invalid parameters on deployment may result in an erroneous input and require an expensive redeployment.

*There are 3 instance(s) of this issue:*

```solidity
File: src/adapters/Curve2PoolAdapter.sol

77:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L77)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

85:     constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {

```


*GitHub* : [L85](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L85)

```solidity
File: src/adapters/OceanAdapter.sol

32:     constructor(address ocean_, address primitive_) {

```


*GitHub* : [L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L32)
### [N-85]<a name="n-85"></a> Missing zero check when assigning `int`/`uint` to state
There are some missing checks in these functions, and this could lead to unexpected scenarios. Consider always adding a sanity check for state variables.

*There are 5 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

200:         unwrapFeeDivisor = nextUnwrapFeeDivisor;

890:         _ERC721InteractionStatus = INTERACTION;

892:         _ERC721InteractionStatus = NOT_INTERACTION;

930:         _ERC1155InteractionStatus = INTERACTION;

932:         _ERC1155InteractionStatus = NOT_INTERACTION;

```


*GitHub* : [L200](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L200),[L892](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L892),[L890](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L890),[L930](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L930),[L932](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L932)
### [N-86]<a name="n-86"></a> Top level declarations should be separated by two blank lines
See the [Solidity style guide](https://docs.soliditylang.org/en/v0.8.16/style-guide.html#blank-lines) for more details.

*There are 80 instance(s) of this issue:*

```solidity
File: src/ocean/Ocean.sol

6: pragma solidity 0.8.20;

8: // OpenZeppelin ERC Interfaces
9: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

27: import { OceanERC1155 } from "./OceanERC1155.sol";

29: /**
30:  * @title A public multitoken ledger for defi
31:  * @author Cowri Labs Team
32:  * @dev The ocean is designed to interact with contracts that implement IERC20,
33:  *  IERC721, IERC-1155, or IOceanPrimitive.
34:  * @dev The ocean is three things.
35:  *  1. At the highest level, it is a defi framework[0]. Users provide a list
36:  *   of interactions, and the ocean executes those interactions. Each
37:  *   interaction involves a call to an external contract. These calls result
38:  *   in updates to the ocean's accounting system.
39:  *  2. Suporting this defi framework is an accounting system that can transfer,
40:  *   mint, or burn tokens. Each token in the accounting system is identified by
41:  *   its oceanId. Every oceanId is uniquely derived from an external contract
42:  *   address. This external contract is the only contract able to cause mints
43:  *   or burns of this token[1].
44:  *  3. Supporting this accounting system is an ERC-1155 ledger with all the
45:  *   standard ERC-1155 features. Users and primitives can interact with their
46:  *   tokens using both the defi framework and the ERC-1155 functions.
47:  *
48:  * [0] We call it a framework because the ocean calls predefined functions on
49:  *  external contracts at certain points in its exection. The lifecycle is
50:  *  managed by the ocean, while the business logic is managed by external
51:  *  contracts.  Conceptually this is quite similar to a typical web framework.
52:  * [1] For example, when a user wraps an ERC-20 token into the ocean, the
53:  *   framework calls the ERC-20 transfer function, and upon success, mints the
54:  *   wrapped token to the user. In another case, when a user deposits a base
55:  *   token into a liquidity pool to recieve liquidity provider tokens, the
56:  *   framework calls the liquidity pool, tells it how much of the base token it
57:  *   will receive, and asks it how much of the liquidity provider token it
58:  *   would like to mint. When the pool responds, the framework mints this
59:  *   amount to the user.
60:  *
61:  * @dev Getting started tips:
62:  *  1. Check out Interactions.sol
63:  *  2. Read through the implementation of Ocean.doInteraction(), glossing over
64:  *   the function call to _executeInteraction().
65:  *  3. Read through the imlementation of Ocean.doMultipleInteractions(), again
66:  *   glossing over the function call to _executeInteraction(). When you
67:  *   encounter calls to LibBalanceDelta, check out their implementations.
68:  *  4. Read through _executeInteraction() and all the functions it calls.
69:  *   Understand how this is the line separating the accounting for the external
70:  *   contracts and the accounting for the current user.
71:  *   You can read the implementations of the specific interactions in any
72:  *   order, but it might be good to go through them in order of increasing
73:  *   complexity. The called functions, in order of increasing complexity, are:
74:  *   wrapErc721, unwrapErc721, wrapErc1155, unwrapErc1155, computeOutputAmount,
75:  *   computeInputAmount, unwrapErc20, and wrapErc20.  When you get to
76:  *   computeOutputAmount, check out IOceanPrimitive, IOceanToken, and the
77:  *   function registerNewTokens() in OceanERC1155.
78:  */
79: contract Ocean is IOceanInteractions, IOceanFeeChange, OceanERC1155, IERC721Receiver, IERC1155Receiver {

```


*GitHub* : [L32](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L32),[L33](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L33),[L34](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L34),[L35](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L35),[L36](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L36),[L37](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L37),[L38](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L38),[L6](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L6),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L8),[L9](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L9),[L27](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L27),[L29](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L29),[L30](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L30),[L31](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L31),[L53](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L53),[L54](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L54),[L55](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L55),[L56](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L56),[L57](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L57),[L58](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L58),[L59](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L59),[L60](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L60),[L61](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L61),[L62](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L62),[L63](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L63),[L64](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L64),[L65](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L65),[L66](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L66),[L67](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L67),[L68](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L68),[L69](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L69),[L70](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L70),[L71](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L71),[L72](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L72),[L73](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L73),[L74](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L74),[L75](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L75),[L76](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L76),[L77](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L77),[L78](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L78),[L79](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L79),[L39](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L39),[L40](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L40),[L41](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L41),[L42](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L42),[L43](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L43),[L44](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L44),[L45](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L45),[L46](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L46),[L47](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L47),[L48](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L48),[L49](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L49),[L50](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L50),[L51](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L51),[L52](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/ocean/Ocean.sol#L52)

```solidity
File: src/adapters/Curve2PoolAdapter.sol

4: pragma solidity 0.8.20;

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

8: import "./OceanAdapter.sol";

10: enum ComputeType {
11:     Deposit,
12:     Swap,
13:     Withdraw
14: }

16: /**
17:  * @notice
18:  *   curve2pool adapter contract enabling swapping, adding liquidity & removing liquidity for the curve usdc-usdt pool
19:  */
20: contract Curve2PoolAdapter is OceanAdapter {

```


*GitHub* : [L4](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L4),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L8),[L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L10),[L11](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L11),[L12](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L12),[L13](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L13),[L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L14),[L16](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L16),[L20](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L20),[L18](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L18),[L19](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L19),[L17](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L17),[L6](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/Curve2PoolAdapter.sol#L6)

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

4: pragma solidity 0.8.20;

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

8: import "./OceanAdapter.sol";

10: interface IWETH {

```


*GitHub* : [L4](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L4),[L6](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L6),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L8),[L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/CurveTricryptoAdapter.sol#L10)

```solidity
File: src/adapters/OceanAdapter.sol

4: pragma solidity 0.8.20;

6: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

8: import "../ocean/Interactions.sol";

10: /**
11:  * @notice
12:  *   Helper contract for shell adapters
13:  */
14: abstract contract OceanAdapter is IOceanPrimitive {

```


*GitHub* : [L13](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L13),[L4](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L4),[L6](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L6),[L8](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L8),[L10](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L10),[L11](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L11),[L12](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L12),[L14](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/src/adapters/OceanAdapter.sol#L14)
### [N-87]<a name="n-87"></a> Large or complicated code bases should implement invariant tests
Large code bases, or code with lots of inline-assembly, complicated math, or complicated interactions between multiple contracts, should implement [invariant fuzzing tests](https://medium.com/coinmonks/smart-contract-fuzzing-d9b88e0b0a05). Invariant fuzzers such as Echidna require the test writer to come up with invariants which should not be violated under any circumstances, and the fuzzer tests various inputs and function calls to ensure that the invariants always hold. Even code with 100% code coverage can still have bugs due to the order of the operations a user performs, and invariant fuzzers, with properly and extensively-written invariants, can close this testing gap significantly.

*There are 1 instance(s) of this issue:*

```solidity
File: All in-scope files
```

*GitHub* : https://github.com/code-423n4/2023-11-shellprotocol
### [N-88]<a name="n-88"></a> Tests should have full coverage
While 100% code coverage does not guarantee that there are no bugs, it often will catch easy-to-find bugs, and will ensure that there are fewer regressions when the code invariably has to be modified. Furthermore, in order to get full coverage, code authors will often have to re-organize their code so that it is more modular, so that each component can be tested separately, which reduces interdependencies between modules and layers, and makes for code that is easier to reason about and audit.

*There are 1 instance(s) of this issue:*

```solidity
File: All in-scope files
```

*GitHub* : https://github.com/code-423n4/2023-11-shellprotocol
### [N-89]<a name="n-89"></a> Codebase should go through formal verification
Formal verification is the act of proving or disproving the correctness of intended algorithms underlying a system with respect to a certain formal specification/property/invariant, using formal methods of mathematics.  Some tools that are currently available to perform these tests on smart contracts are [SMTChecker](https://docs.soliditylang.org/en/latest/smtchecker.html) and [Certora Prover](https://www.certora.com/).

*There are 1 instance(s) of this issue:*

```solidity
File: All in-scope files
```

*GitHub* : https://github.com/code-423n4/2023-11-shellprotocol 
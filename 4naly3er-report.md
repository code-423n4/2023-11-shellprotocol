# Report


## Gas Optimizations


| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | Cache array length outside of loop | 1 |
| [GAS-2](#GAS-2) | For Operations that will not overflow, you could use unchecked | 100 |
| [GAS-3](#GAS-3) | Don't initialize variables with default value | 2 |
| [GAS-4](#GAS-4) | Functions guaranteed to revert when called by normal users can be marked `payable` | 1 |
| [GAS-5](#GAS-5) | Use != 0 instead of > 0 for unsigned integer comparison | 8 |
### <a name="GAS-1"></a>[GAS-1] Cache array length outside of loop
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*Instances (1)*:
```solidity
File: src/ocean/Ocean.sol

501:             for (uint256 i = 0; i < interactions.length;) {

```

### <a name="GAS-2"></a>[GAS-2] For Operations that will not overflow, you could use unchecked

*Instances (100)*:
```solidity
File: src/adapters/Curve2PoolAdapter.sol

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

7: import "./ICurve2Pool.sol";

8: import "./OceanAdapter.sol";

```

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

6: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

7: import "./ICurveTricrypto.sol";

8: import "./OceanAdapter.sol";

100:         zToken = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))

100:         zToken = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))

216:                     IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance

223:         uint256 rawOutputAmount = _getBalance(underlying[outputToken]) - _balanceBefore;

```

```solidity
File: src/adapters/OceanAdapter.sol

6: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

6: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

6: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

6: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

7: import "../ocean/IOceanPrimitive.sol";

7: import "../ocean/IOceanPrimitive.sol";

8: import "../ocean/Interactions.sol";

8: import "../ocean/Interactions.sol";

70:         uint256 unwrapFee = inputAmount / IOceanInteractions(ocean).unwrapFeeDivisor();

71:         uint256 unwrappedAmount = inputAmount - unwrapFee;

152:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

152:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

152:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

153:             convertedAmount = amountToConvert * shift;

156:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

156:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

156:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

157:             convertedAmount = amountToConvert / shift;

```

```solidity
File: src/ocean/Ocean.sol

9: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

9: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

9: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

9: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

9: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

10: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

10: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

10: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

10: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

11: import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

11: import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

11: import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

11: import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

12: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

12: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

12: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

12: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

13: import { IERC1155 } from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

13: import { IERC1155 } from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

13: import { IERC1155 } from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

13: import { IERC1155 } from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

14: import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

14: import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

14: import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

14: import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

15: import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

15: import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

15: import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

15: import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

18: import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

18: import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

18: import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

18: import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

18: import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

21: import { IOceanInteractions, Interaction, InteractionType } from "./Interactions.sol";

22: import { IOceanFeeChange } from "./IOceanFeeChange.sol";

23: import { IOceanPrimitive } from "./IOceanPrimitive.sol";

24: import { BalanceDelta, LibBalanceDelta } from "./BalanceDelta.sol";

27: import { OceanERC1155 } from "./OceanERC1155.sol";

173:         WRAPPED_ETHER_ID = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))

173:         WRAPPED_ETHER_ID = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))

466:                 ++i;

466:                 ++i;

538:                     ++i;

538:                     ++i;

561:             } // if there are none, we do nothing

561:             } // if there are none, we do nothing

571:             } // if there are none, we do nothing

571:             } // if there are none, we do nothing

867:             uint256 amountRemaining = amount - feeCharged;

871:             feeCharged += truncated;

966:         uint256 amountRemaining = amount - feeCharged;

981:         uint256 transferAmount = amount - feeCharged;

1092:             transferAmount += 1;

1102:             dust = normalizedTransferAmount - amount;

1138:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

1138:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

1138:             uint256 shift = 10 ** (uint256(decimalsTo - decimalsFrom));

1139:             convertedAmount = amountToConvert * shift;

1143:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

1143:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

1143:             uint256 shift = 10 ** (uint256(decimalsFrom - decimalsTo));

1144:             convertedAmount = amountToConvert / shift;

1159:         feeCharged = unwrapAmount / unwrapFeeDivisor;

```

### <a name="GAS-3"></a>[GAS-3] Don't initialize variables with default value

*Instances (2)*:
```solidity
File: src/ocean/Ocean.sol

463:         for (uint256 i = 0; i < _idLength;) {

501:             for (uint256 i = 0; i < interactions.length;) {

```

### <a name="GAS-4"></a>[GAS-4] Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (1)*:
```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

```

### <a name="GAS-5"></a>[GAS-5] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (8)*:
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


## Non Critical Issues


| |Issue|Instances|
|-|:-|:-:|
| [NC-1](#NC-1) | Return values of `approve()` not checked | 4 |
### <a name="NC-1"></a>[NC-1] Return values of `approve()` not checked
Not all IERC20 implementations `revert()` when there's a failure in `approve()`. The function signature has a boolean return value and they indicate errors that way instead. By not checking the return value, operations that should have marked as failed, may potentially go through without actually approving anything

*Instances (4)*:
```solidity
File: src/adapters/Curve2PoolAdapter.sol

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);

191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);

243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```


## Low Issues


| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) |  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()` | 1 |
| [L-2](#L-2) | Empty Function Body - Consider commenting why | 1 |
| [L-3](#L-3) | Unsafe ERC20 operation(s) | 5 |
### <a name="L-1"></a>[L-1]  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`
Use `abi.encode()` instead which will pad items to 32 bytes, which will [prevent hash collisions](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode) (e.g. `abi.encodePacked(0x123,0x456)` => `0x123456` => `abi.encodePacked(0x1,0x23456)`, but `abi.encode(0x123,0x456)` => `0x0...1230...456`). "Unless there is a compelling reason, `abi.encode` should be preferred". If there is only one argument to `abi.encodePacked()` it can often be cast to `bytes()` or `bytes32()` [instead](https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739).
If all arguments are strings and or bytes, `bytes.concat()` should be used instead

*Instances (1)*:
```solidity
File: src/adapters/OceanAdapter.sol

109:         return uint256(keccak256(abi.encodePacked(tokenAddress, tokenId)));

```

### <a name="L-2"></a>[L-2] Empty Function Body - Consider commenting why

*Instances (1)*:
```solidity
File: src/adapters/CurveTricryptoAdapter.sol

291:     fallback() external payable { }

```

### <a name="L-3"></a>[L-3] Unsafe ERC20 operation(s)

*Instances (5)*:
```solidity
File: src/adapters/Curve2PoolAdapter.sol

190:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);

191:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```

```solidity
File: src/adapters/CurveTricryptoAdapter.sol

242:         IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);

243:         IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);

```

```solidity
File: src/ocean/Ocean.sol

982:         payable(userAddress).transfer(transferAmount);

```


## Medium Issues


| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 1 |
### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact:
Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (1)*:
```solidity
File: src/ocean/Ocean.sol

196:     function changeUnwrapFee(uint256 nextUnwrapFeeDivisor) external override onlyOwner {

```


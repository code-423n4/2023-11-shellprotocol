// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "./ICurve2Pool.sol";
import "./OceanAdapter.sol";

enum ComputeType {
    Deposit,
    Swap,
    Withdraw
}

/**
 * @notice
 *   curve2pool adapter contract enabling swapping, adding liquidity & removing liquidity for the curve usdc-usdt pool
 */
contract Curve2PoolAdapter is OceanAdapter {
    /////////////////////////////////////////////////////////////////////
    //                             Errors                              //
    /////////////////////////////////////////////////////////////////////
    error INVALID_COMPUTE_TYPE();
    error SLIPPAGE_LIMIT_EXCEEDED();

    /////////////////////////////////////////////////////////////////////
    //                             Events                              //
    /////////////////////////////////////////////////////////////////////
    event Swap(
        uint256 inputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        bytes32 slippageProtection,
        address user,
        bool computeOutput
    );
    event Deposit(
        uint256 inputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        bytes32 slippageProtection,
        address user,
        bool computeOutput
    );
    event Withdraw(
        uint256 outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        bytes32 slippageProtection,
        address user,
        bool computeOutput
    );

    /// @notice x token Ocean ID.
    uint256 public immutable xToken;

    /// @notice y token Ocean ID.
    uint256 public immutable yToken;

    /// @notice lp token Ocean ID.
    uint256 public immutable lpTokenId;

    /// @notice map token Ocean IDs to corresponding Curve pool indices
    mapping(uint256 => int128) indexOf;

    /// @notice The underlying token decimals wrt to the Ocean ID
    mapping(uint256 => uint8) decimals;

    //*********************************************************************//
    // ---------------------------- constructor -------------------------- //
    //*********************************************************************//

    /**
     * @notice only initializing the immutables, mappings & approves tokens
     */
    constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {
        address xTokenAddress = ICurve2Pool(primitive).coins(0);
        xToken = _calculateOceanId(xTokenAddress, 0);
        underlying[xToken] = xTokenAddress;
        decimals[xToken] = IERC20Metadata(xTokenAddress).decimals();
        _approveToken(xTokenAddress);

        address yTokenAddress = ICurve2Pool(primitive).coins(1);
        yToken = _calculateOceanId(yTokenAddress, 0);
        indexOf[yToken] = int128(1);
        underlying[yToken] = yTokenAddress;
        decimals[yToken] = IERC20Metadata(yTokenAddress).decimals();
        _approveToken(yTokenAddress);

        lpTokenId = _calculateOceanId(primitive_, 0);
        underlying[lpTokenId] = primitive_;
        decimals[lpTokenId] = IERC20Metadata(primitive_).decimals();
        _approveToken(primitive_);
    }

    /**
     * @dev wraps the underlying token into the Ocean
     * @param tokenId Ocean ID of token to wrap
     * @param amount wrap amount
     */
    function wrapToken(uint256 tokenId, uint256 amount) internal override {
        address tokenAddress = underlying[tokenId];

        Interaction memory interaction = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(tokenAddress, uint256(InteractionType.WrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: amount,
            metadata: bytes32(0)
        });

        IOceanInteractions(ocean).doInteraction(interaction);
    }

    /**
     * @dev unwraps the underlying token from the Ocean
     * @param tokenId Ocean ID of token to unwrap
     * @param amount unwrap amount
     */
    function unwrapToken(uint256 tokenId, uint256 amount) internal override {
        address tokenAddress = underlying[tokenId];

        Interaction memory interaction = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(tokenAddress, uint256(InteractionType.UnwrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: amount,
            metadata: bytes32(0)
        });

        IOceanInteractions(ocean).doInteraction(interaction);
    }

    /**
     * @dev swaps/add liquidity/remove liquidity from Curve 2pool
     * @param inputToken The user is giving this token to the pool
     * @param outputToken The pool is giving this token to the user
     * @param inputAmount The amount of the inputToken the user is giving to the pool
     * @param minimumOutputAmount The minimum amount of tokens expected back after the exchange
     */
    function primitiveOutputAmount(
        uint256 inputToken,
        uint256 outputToken,
        uint256 inputAmount,
        bytes32 minimumOutputAmount
    )
        internal
        override
        returns (uint256 outputAmount)
    {
        uint256 rawInputAmount = _convertDecimals(NORMALIZED_DECIMALS, decimals[inputToken], inputAmount);

        ComputeType action = _determineComputeType(inputToken, outputToken);

        uint256 rawOutputAmount;

        // avoid multiple SLOADS
        int128 indexOfInputAmount = indexOf[inputToken];
        int128 indexOfOutputAmount = indexOf[outputToken];

        if (action == ComputeType.Swap) {
            rawOutputAmount =
                ICurve2Pool(primitive).exchange(indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0);
        } else if (action == ComputeType.Deposit) {
            uint256[2] memory inputAmounts;
            inputAmounts[uint256(int256(indexOfInputAmount))] = rawInputAmount;
            rawOutputAmount = ICurve2Pool(primitive).add_liquidity(inputAmounts, 0);
        } else {
            rawOutputAmount = ICurve2Pool(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);
        }

        outputAmount = _convertDecimals(decimals[outputToken], NORMALIZED_DECIMALS, rawOutputAmount);

        if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();

        if (action == ComputeType.Swap) {
            emit Swap(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);
        } else if (action == ComputeType.Deposit) {
            emit Deposit(inputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);
        } else {
            emit Withdraw(outputToken, inputAmount, outputAmount, minimumOutputAmount, primitive, true);
        }
    }

    /**
     * @dev Approves token to be spent by the Ocean and the Curve pool
     */
    function _approveToken(address tokenAddress) private {
        IERC20Metadata(tokenAddress).approve(ocean, type(uint256).max);
        IERC20Metadata(tokenAddress).approve(primitive, type(uint256).max);
    }

    /**
     * @dev Uses the inputToken and outputToken to determine the ComputeType
     *  (input: xToken, output: yToken) | (input: yToken, output: xToken) => SWAP
     *  base := xToken | yToken
     *  (input: base, output: lpToken) => DEPOSIT
     *  (input: lpToken, output: base) => WITHDRAW
     */
    function _determineComputeType(
        uint256 inputToken,
        uint256 outputToken
    )
        private
        view
        returns (ComputeType computeType)
    {
        if (((inputToken == xToken) && (outputToken == yToken)) || ((inputToken == yToken) && (outputToken == xToken)))
        {
            return ComputeType.Swap;
        } else if (((inputToken == xToken) || (inputToken == yToken)) && (outputToken == lpTokenId)) {
            return ComputeType.Deposit;
        } else if ((inputToken == lpTokenId) && ((outputToken == xToken) || (outputToken == yToken))) {
            return ComputeType.Withdraw;
        } else {
            revert INVALID_COMPUTE_TYPE();
        }
    }
}

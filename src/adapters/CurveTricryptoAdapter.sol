// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "./ICurveTricrypto.sol";
import "./OceanAdapter.sol";

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256 amount) external payable;
}

enum ComputeType {
    Deposit,
    Swap,
    Withdraw
}

/**
 * @notice
 *   curve tricrypto adapter contract enabling swapping, adding liquidity & removing liquidity for the curve usdt-wbtc-eth pool
 */
contract CurveTricryptoAdapter is OceanAdapter {
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

    /// @notice x token Ocean ID
    uint256 public immutable xToken;

    /// @notice y token Ocean ID
    uint256 public immutable yToken;

    /// @notice z token Ocean ID
    uint256 public immutable zToken;

    /// @notice lp token Ocean ID
    uint256 public immutable lpTokenId;

    /// @notice map token Ocean IDs to corresponding Curve pool indices
    mapping(uint256 => uint256) indexOf;

    /// @notice The underlying token decimals wrt to the Ocean ID
    mapping(uint256 => uint8) decimals;

    //*********************************************************************//
    // ---------------------------- constructor -------------------------- //
    //*********************************************************************//

    /**
     * @notice only initializing the immutables, mappings & approves tokens
     */
    constructor(address ocean_, address primitive_) OceanAdapter(ocean_, primitive_) {
        address xTokenAddress = ICurveTricrypto(primitive).coins(0);
        xToken = _calculateOceanId(xTokenAddress, 0);
        underlying[xToken] = xTokenAddress;
        decimals[xToken] = IERC20Metadata(xTokenAddress).decimals();
        _approveToken(xTokenAddress);

        address yTokenAddress = ICurveTricrypto(primitive).coins(1);
        yToken = _calculateOceanId(yTokenAddress, 0);
        indexOf[yToken] = 1;
        underlying[yToken] = yTokenAddress;
        decimals[yToken] = IERC20Metadata(yTokenAddress).decimals();
        _approveToken(yTokenAddress);

        address wethAddress = ICurveTricrypto(primitive).coins(2);
        zToken = _calculateOceanId(address(0x4574686572), 0); // hexadecimal(ascii("Ether"))
        indexOf[zToken] = 2;
        underlying[zToken] = wethAddress;
        decimals[zToken] = NORMALIZED_DECIMALS;
        _approveToken(wethAddress);

        address lpTokenAddress = ICurveTricrypto(primitive).token();
        lpTokenId = _calculateOceanId(lpTokenAddress, 0);
        underlying[lpTokenId] = lpTokenAddress;
        decimals[lpTokenId] = IERC20Metadata(lpTokenAddress).decimals();
        _approveToken(lpTokenAddress);
    }

    /**
     * @dev wraps the underlying token into the Ocean
     * @param tokenId Ocean ID of token to wrap
     * @param amount wrap amount
     */
    function wrapToken(uint256 tokenId, uint256 amount) internal override {
        Interaction memory interaction;

        if (tokenId == zToken) {
            interaction = Interaction({
                interactionTypeAndAddress: 0,
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: 0,
                metadata: bytes32(0)
            });
            IOceanInteractions(ocean).doInteraction{ value: amount }(interaction);
        } else {
            interaction = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.WrapErc20)),
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: amount,
                metadata: bytes32(0)
            });
            IOceanInteractions(ocean).doInteraction(interaction);
        }
    }

    /**
     * @dev unwraps the underlying token from the Ocean
     * @param tokenId Ocean ID of token to unwrap
     * @param amount unwrap amount
     */
    function unwrapToken(uint256 tokenId, uint256 amount) internal override {
        Interaction memory interaction;

        if (tokenId == zToken) {
            interaction = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(address(0), uint256(InteractionType.UnwrapEther)),
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: amount,
                metadata: bytes32(0)
            });
        } else {
            interaction = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(underlying[tokenId], uint256(InteractionType.UnwrapErc20)),
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: amount,
                metadata: bytes32(0)
            });
        }

        IOceanInteractions(ocean).doInteraction(interaction);
    }

    /**
     * @dev swaps/add liquidity/remove liquidity from Curve Tricrypto Pool
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

        uint256 _balanceBefore = _getBalance(underlying[outputToken]);

        // avoid multiple SLOADS
        uint256 indexOfInputAmount = indexOf[inputToken];
        uint256 indexOfOutputAmount = indexOf[outputToken];

        if (action == ComputeType.Swap) {
            bool useEth = inputToken == zToken || outputToken == zToken;

            ICurveTricrypto(primitive).exchange{ value: inputToken == zToken ? rawInputAmount : 0 }(
                indexOfInputAmount, indexOfOutputAmount, rawInputAmount, 0, useEth
            );
        } else if (action == ComputeType.Deposit) {
            uint256[3] memory inputAmounts;
            inputAmounts[indexOfInputAmount] = rawInputAmount;

            if (inputToken == zToken) IWETH(underlying[zToken]).deposit{ value: rawInputAmount }();

            ICurveTricrypto(primitive).add_liquidity(inputAmounts, 0);
        } else {
            if (outputToken == zToken) {
                uint256 wethBalance = IERC20Metadata(underlying[zToken]).balanceOf(address(this));
                ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);
                IWETH(underlying[zToken]).withdraw(
                    IERC20Metadata(underlying[zToken]).balanceOf(address(this)) - wethBalance
                );
            } else {
                ICurveTricrypto(primitive).remove_liquidity_one_coin(rawInputAmount, indexOfOutputAmount, 0);
            }
        }

        uint256 rawOutputAmount = _getBalance(underlying[outputToken]) - _balanceBefore;

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
     * @dev fetches underlying token balances
     */
    function _getBalance(address tokenAddress) internal view returns (uint256 balance) {
        if (tokenAddress == underlying[zToken]) {
            return address(this).balance;
        } else {
            return IERC20Metadata(tokenAddress).balanceOf(address(this));
        }
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
        if (
            ((inputToken == xToken && outputToken == yToken) || (inputToken == yToken && outputToken == xToken))
                || ((inputToken == xToken && outputToken == zToken) || (inputToken == zToken && outputToken == xToken))
                || ((inputToken == yToken && outputToken == zToken) || (inputToken == zToken && outputToken == yToken))
        ) {
            return ComputeType.Swap;
        } else if (
            ((inputToken == xToken) || (inputToken == yToken) || (inputToken == zToken)) && (outputToken == lpTokenId)
        ) {
            return ComputeType.Deposit;
        } else if (
            (inputToken == lpTokenId) && ((outputToken == xToken) || (outputToken == yToken) || (outputToken == zToken))
        ) {
            return ComputeType.Withdraw;
        } else {
            revert INVALID_COMPUTE_TYPE();
        }
    }

    fallback() external payable { }
}

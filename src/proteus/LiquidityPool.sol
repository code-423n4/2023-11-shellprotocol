// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "../ocean/IOceanPrimitive.sol";
import "../ocean/IOceanToken.sol";

interface IERC1155 {
    function balanceOfBatch(
        address[] calldata accounts,
        uint256[] calldata ids
    )
        external
        view
        returns (uint256[] memory);
}

enum ComputeType {
    Deposit,
    Swap,
    Withdraw
}

abstract contract LiquidityPool is IOceanPrimitive {
    //*********************************************************************//
    // --------------------------- custom errors ------------------------- //
    //*********************************************************************//
    error INVALID_COMPUTE_TYPE();
    error INVALID_TOKEN_ID();
    error SLIPPAGE_LIMIT_EXCEEDED();

    /// @notice The primitive delegates its state management and accounting to
    ///  this external contract.
    address public immutable ocean;
    /// @notice The oceanId of the first token in the base pair
    uint256 public immutable xToken;
    /// @notice The oceanId of the second token in the base pair
    uint256 public immutable yToken;
    /// @notice The oceanId of the Liquidity Provider token for this pool.  This
    ///  value is given to the primitive by the ocean in the constructor.
    uint256 public immutable lpTokenId;

    /// @notice Only this address can provide the initial liquidity.
    ///  Claiming initial liquidity is done by calling computeOutputAmount
    ///  twice, once with the xToken as the input and the lpTokenId as the output,
    ///  and once with the yToken as the input and the lpTokenId as the output.
    address private immutable claimerOrDeployer;
    /// @notice The first call to computeOutputAmount while claiming inital liquidity
    ///  returns (initialLpTokenSupply / 2) as the output amount.  The second call
    ///  does the same.
    uint256 private immutable initialLpTokenSupply;
    /// @dev default state for initialSupplyClaimed
    uint256 private constant UNCLAIMED = 2;
    /// @dev State the pool is in when only xToken or yToken has been provided
    uint256 private constant HALF_CLAIMED = 1;
    /// @dev State the pool is in when both tokens have been provided.
    uint256 private constant CLAIMED = 0;
    /// @dev State variable that ensures liquidity is provided correctly before
    ///  enabling full pool functionality.
    uint256 private initialSupplyClaimed = UNCLAIMED;

    /// @notice the total supply of the LP token.  The ocean keeps track of
    ///  who owns the LP token and how many tokens they have.  However, the
    ///  ocean uses an ERC-1155 ledger to do so, which does not track token
    ///  supply.  Wrapped tokens on the ocean do not require a total supply.
    ///  Some registered tokens will need a total supply, and others won't.
    ///  The primitive registering the token knows whether total supply must be
    ///  tracked, and so it is most economical for the primitive to privately
    ///  track the total supply of the token.
    uint256 private lpTokenSupply = 0;

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
    event InitialLiquidity(uint256 inputToken, uint256 inputAmount, uint256 outputAmount, address user, bool active);

    /**
     * @notice Sets up the immtuable variables.  Makes one external call to the
     *  provided ocean to register its Liquidity Provider token Id.  This allows
     *  the pool to mint its token on the ocean when users deposit, and burn
     *  its token on the ocean when users withdraw.
     * @param xToken_ one of the two tokens that make up the base pair
     * @param yToken_ the other of the two tokens that make up the base pair
     * @param ocean_ the address of the contract that handles the pool's
     *  accounting and order routing.  The pool must only change its internal
     *  state when it is called by the ocean.  All other public functions must
     *  have no side effects.
     * @param initialLpTokenSupply_ the initial supply of the Liquidity Provider
     *  token.  The process of seeding the pool with initial liquidity results
     *  in this many LP tokens being minted.  It should be an even number.
     * @param claimer This is an optional argument.  If address(0) is passed,
     *  the claimerOrDeployer state variable is set to the deployer
     *  (msg.sender). If any other value is passed, the claimerOrDeployer is
     *  set to the passed value.  The immutable state variable claimerOrDeployer
     *  guards the initial liquidity seeding.  Without this, anyone could claim
     *  the initial liquidity using any amount of xToken or yToken.
     */
    constructor(uint256 xToken_, uint256 yToken_, address ocean_, uint256 initialLpTokenSupply_, address claimer) {
        claimerOrDeployer = claimer == address(0) ? msg.sender : claimer;
        initialLpTokenSupply = initialLpTokenSupply_;
        ocean = ocean_;
        xToken = xToken_;
        yToken = yToken_;
        uint256[] memory registeredToken = IOceanToken(ocean_).registerNewTokens(0, 1);
        lpTokenId = registeredToken[0];
    }

    /// @dev this MUST be applied to every PUBLIC or EXTERNAL function that is
    ///  not PURE or VIEW.
    modifier onlyOcean() {
        require(msg.sender == ocean);
        _;
    }

    /// @dev this MUST be applied to every PUBLIC or EXTERNAL function that is
    ///  not PURE or VIEW, except for computeOutputAmount.  computeOutputAmount
    ///  has its own guard for this condition.
    modifier onlyClaimed() {
        require(initialSupplyClaimed == CLAIMED);
        _;
    }

    /**
     * @dev The ocean must always know the input and output tokens in order to
     *  do the accounting.  One of the token amounts is chosen by the user, and
     *  the other amount is chosen by the pool.  When computeOutputAmount is
     *  called, the user provides the inputAmount, and the pool uses this to
     *  compute the outputAmount
     * @dev This function delegates to a handler when the initalSupply has yet been
     *  claimed.  It MUST have the modifier onlyOcean.
     * @param inputToken The user is giving this token to the pool
     * @param outputToken The pool is giving this token to the user
     * @param inputAmount The amount of the inputToken the user is giving to the pool
     * @param userAddress The address of the user, passed from the accounting system.
     *  The userAddress is used in this case to determine if the user is allowed to
     *  claim the initial mint.
     * @dev the unusued param is a bytes32 field called metadata, which the user
     *  provides the ocean, and the ocean passes directly to the primitive.
     */
    function computeOutputAmount(
        uint256 inputToken,
        uint256 outputToken,
        uint256 inputAmount,
        address userAddress,
        bytes32 minimumOutputAmount
    )
        external
        override
        onlyOcean
        returns (uint256 outputAmount)
    {
        ComputeType action = _determineComputeType(inputToken, outputToken);

        if (initialSupplyClaimed != CLAIMED) {
            outputAmount = _handleInitialMints(inputToken, inputAmount, userAddress, action);
            lpTokenSupply += outputAmount;

            emit InitialLiquidity(inputToken, inputAmount, outputAmount, userAddress, (initialSupplyClaimed == CLAIMED));
        } else if (action == ComputeType.Swap) {
            // Swap action + computeOutput context => swapGivenInputAmount()
            outputAmount = swapGivenInputAmount(inputToken, inputAmount);

            emit Swap(inputToken, inputAmount, outputAmount, minimumOutputAmount, userAddress, true);
        } else if (action == ComputeType.Deposit) {
            // Deposit action + computeOutput context => depositGivenInputAmount()
            outputAmount = depositGivenInputAmount(inputToken, inputAmount);
            // Deposit, therefore outputToken is the LP token.  This means the
            // ocean is going to mint the outputAmount to the user.  We
            // need to increase the totalSupply by the mint (output) amount.
            lpTokenSupply += outputAmount;

            emit Deposit(inputToken, inputAmount, outputAmount, minimumOutputAmount, userAddress, true);
        } else {
            // Because the enum only has three values, if the third branch
            // is not a withdraw, the code must be wrong, so we use an assert.
            assert(action == ComputeType.Withdraw);
            // Withdraw action + computeOutput context => withdrawGivenInputAmount()
            outputAmount = withdrawGivenInputAmount(outputToken, inputAmount);
            // Withdraw, therefore inputToken is the LP token.  This means the
            // ocean is going to burn the inputAmount from the user.  We
            // need to decrease the totalSupply by the burn (input) amount.
            lpTokenSupply -= inputAmount;

            emit Withdraw(outputToken, inputAmount, outputAmount, minimumOutputAmount, userAddress, true);
        }

        if (uint256(minimumOutputAmount) > outputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();
    }

    /**
     * @dev The ocean must always know the input and output tokens in order to
     *  do the accounting.  One of the token amounts is chosen by the user, and
     *  the other amount is chosen by the pool.  When computeInputAmount is
     *  called, the user provides the outputAmount, and the pool uses this to
     *  compute the inputAmount necessary to receive the provided outputAmount.
     * @dev this function MUST have the modifiers onlyOcean and onlyClaimed
     * @param inputToken The user is giving this token to the pool
     * @param outputToken The pool is giving this token to the user
     * @param outputAmount The amount of the outputToken the pool will give to the user
     * @dev The first unusued param is the address of the user, passed from the
     *  accounting system.
     * @dev The second unusued param is a bytes32 field called metadata, which the
     *  user provides the ocean, and the ocean passes directly to the primitive.
     */
    function computeInputAmount(
        uint256 inputToken,
        uint256 outputToken,
        uint256 outputAmount,
        address userAddress,
        bytes32 maximumInputAmount
    )
        external
        override
        onlyOcean
        onlyClaimed
        returns (uint256 inputAmount)
    {
        ComputeType action = _determineComputeType(inputToken, outputToken);

        if (action == ComputeType.Swap) {
            // Swap action + computeInput context => swapGivenOutputAmount()
            inputAmount = swapGivenOutputAmount(outputToken, outputAmount);

            emit Swap(inputToken, inputAmount, outputAmount, maximumInputAmount, userAddress, false);
        } else if (action == ComputeType.Deposit) {
            // Deposit action + computeInput context => depositGivenOutputAmount()
            inputAmount = depositGivenOutputAmount(inputToken, outputAmount);
            // Deposit, therefore outputToken is the LP token.  This means the
            // ocean is going to mint the outputAmount to the user.  We
            // need to increase the totalSupply by the mint (output) amount.
            lpTokenSupply += outputAmount;

            emit Deposit(inputToken, inputAmount, outputAmount, maximumInputAmount, userAddress, false);
        } else {
            // Because the enum only has three values, if the third branch
            // is not a withdraw, the code must be wrong, so we use an assert.
            assert(action == ComputeType.Withdraw);
            // Withdraw action + computeInput context => withdrawGivenOutputAmount()
            inputAmount = withdrawGivenOutputAmount(outputToken, outputAmount);
            // Withdraw, therefore inputToken is the LP token.  This means the
            // ocean is going to burn the inputAmount from the user.  We
            // need to decrease the totalSupply by the burn (input) amount.
            lpTokenSupply -= inputAmount;

            emit Withdraw(outputToken, inputAmount, outputAmount, maximumInputAmount, userAddress, false);
        }

        if (uint256(maximumInputAmount) > 0) {
            if (uint256(maximumInputAmount) < inputAmount) revert SLIPPAGE_LIMIT_EXCEEDED();
        }
    }

    /// @notice part of the IOceanPrimitive interface, a standard way for
    ///  primitives to expose the total supply of their registered tokens
    ///  if they chose to.
    function getTokenSupply(uint256 tokenId) external view override returns (uint256 totalSupply) {
        if (tokenId != lpTokenId) revert INVALID_TOKEN_ID();
        totalSupply = lpTokenSupply;
    }

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance
     */
    function swapGivenInputAmount(
        uint256 inputToken,
        uint256 inputAmount
    )
        public
        view
        virtual
        returns (uint256 outputAmount);

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply to get the lpTokenSupply
     */
    function depositGivenInputAmount(
        uint256 depositToken,
        uint256 depositAmount
    )
        public
        view
        virtual
        returns (uint256 mintAmount);

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply to get the lpTokenSupply
     */
    function withdrawGivenInputAmount(
        uint256 withdrawnToken,
        uint256 burnAmount
    )
        public
        view
        virtual
        returns (uint256 withdrawnAmount);

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance
     */
    function swapGivenOutputAmount(
        uint256 outputToken,
        uint256 outputAmount
    )
        public
        view
        virtual
        returns (uint256 inputAmount);

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply() to get the lpTokenSupply
     */
    function depositGivenOutputAmount(
        uint256 depositToken,
        uint256 mintAmount
    )
        public
        view
        virtual
        returns (uint256 depositAmount);

    /**
     * @dev this function should begin by calling _getBalances() to get the
     *  xBalance and yBalance and _getTotalSupply() to get the lpTokenSupply
     */
    function withdrawGivenOutputAmount(
        uint256 withdrawnToken,
        uint256 withdrawnAmount
    )
        public
        view
        virtual
        returns (uint256 burnAmount);

    /// @dev Gets the pool's current balance of the xToken and the yToken from
    ///  the ocean.
    function _getBalances() internal view returns (uint256 xBalance, uint256 yBalance) {
        address[] memory accounts = new address[](2);
        uint256[] memory ids = new uint256[](2);

        accounts[0] = accounts[1] = address(this);
        ids[0] = xToken;
        ids[1] = yToken;

        uint256[] memory result = IERC1155(ocean).balanceOfBatch(accounts, ids);
        (xBalance, yBalance) = (result[0], result[1]);
    }

    /// @dev Provides a read only view of the current supply of the LP token
    /// @dev this is needed because the lpTokenSupply variable is private, since
    ///  contracts that inherit from this abstract contract should not modify the
    ///  lpTokenSupply directly.
    function _getTotalSupply() internal view returns (uint256 totalSupply) {
        totalSupply = lpTokenSupply;
    }

    /// @dev Manages the state transitions between UNCLAIMED, HALF_CLAIMED, and CLAIMED
    /// @dev Only accessible through computeOutputAmount.  The ComputeType MUST BE a
    ///  Deposit.
    /// @dev Only the claimerOrDeployer can perform the initial mints
    function _handleInitialMints(
        uint256 inputToken,
        uint256 inputAmount,
        address userAddress,
        ComputeType action
    )
        private
        returns (uint256 outputAmount)
    {
        require(userAddress == claimerOrDeployer);
        require(action == ComputeType.Deposit);
        require(inputAmount >= 10 ** 12);
        assert(initialSupplyClaimed != CLAIMED);
        (uint256 xBalance, uint256 yBalance) = _getBalances();

        if (inputToken == xToken) {
            xBalance -= inputAmount;
        } else {
            if (inputToken != yToken) revert INVALID_TOKEN_ID();
            yBalance -= inputAmount;
        }

        if (initialSupplyClaimed == UNCLAIMED) {
            assert(_getTotalSupply() == 0);
            assert((xBalance == 0) && (yBalance == 0));

            outputAmount = initialLpTokenSupply / 2;

            initialSupplyClaimed = HALF_CLAIMED;
        } else if ((initialSupplyClaimed == HALF_CLAIMED) && (xBalance == 0)) {
            assert(_getTotalSupply() == initialLpTokenSupply / 2);
            assert(yBalance > 0);
            require(inputToken == xToken);

            outputAmount = initialLpTokenSupply / 2;

            initialSupplyClaimed = CLAIMED;
        } else {
            assert(
                (initialSupplyClaimed == HALF_CLAIMED) && (yBalance == 0)
                    && (_getTotalSupply() == initialLpTokenSupply / 2)
            );
            require(inputToken == yToken);

            outputAmount = initialLpTokenSupply / 2;

            initialSupplyClaimed = CLAIMED;
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

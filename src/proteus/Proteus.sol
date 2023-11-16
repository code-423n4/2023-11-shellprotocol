// SPDX-License-Identifier: MIT
// Cowri Labs Inc.

pragma solidity 0.8.20;

import "abdk-libraries-solidity/ABDKMath64x64.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import { ILiquidityPoolImplementation, SpecifiedToken } from "./ILiquidityPoolImplementation.sol";
import { Slices } from "./Slices.sol";

contract Proteus is ILiquidityPoolImplementation, Slices {
    using ABDKMath64x64 for int128;
    using ABDKMath64x64 for int256;

    uint256 private constant INT_MAX = uint256(type(int256).max);
    int128 private constant ABDK_ONE = int128(int256(1 << 64));
    int128 private constant ABDK_TWO = int128(int256(2 << 64));
    // When a token has 18 decimals, this is one microtoken
    int256 private constant MIN_BALANCE = 10 ** 12;
    // The maximum slope (balance of y reserve) / (balance of x reserve)
    // This limits the pool to having at most 10**8 y for each x.
    int128 private constant MAX_M = 0x5f5e1000000000000000000;
    // The minimum slope (balance of y reserve) / (balance of x reserve)
    // This limits the pool to having at most 10**8 x for each y.
    int128 private constant MIN_M = 0x00000000000002af31dc461;
    // This limits the pool to inputting or outputting
    uint256 private constant MAX_BALANCE_AMOUNT_RATIO = 10 ** 11;
    // Equivalent to roughly twenty-five basis points since fee is applied twice.
    uint256 public constant BASE_FEE = 800;
    // When a token has 18 decimals, this is 1 nanotoken
    uint256 private constant FIXED_FEE = 10 ** 9;
    bool private constant FEE_UP = true;
    bool private constant FEE_DOWN = false;

    error BoundaryError();
    error AmountError();
    error CurveError();
    error BalanceError();

    constructor(
        int128[] memory ms,
        int128[] memory _as,
        int128[] memory bs,
        int128[] memory ks
    )
        Slices(ms, _as, bs, ks)
    {
        // External calls with enums rely on both contracts using the same
        // mapping between enum fields and uint8 values.
        assert(uint8(SpecifiedToken.X) == 0);
        assert(uint8(SpecifiedToken.Y) == 1);
    }

    /**
     * @dev Given an input amount of a reserve token, we compute an output
     *  amount of the other reserve token, keeping utility invariant.
     * @dev We use FEE_DOWN because we want to decrease the perceived
     *  input amount and decrease the observed output amount.
     */
    function swapGivenInputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 inputAmount,
        SpecifiedToken inputToken
    )
        external
        view
        returns (uint256 outputAmount)
    {
        require(inputAmount < INT_MAX && xBalance < INT_MAX && yBalance < INT_MAX);
        _checkAmountWithBalance(inputToken == SpecifiedToken.X ? xBalance : yBalance, inputAmount);
        int256 result = _swap(FEE_DOWN, int256(inputAmount), int256(xBalance), int256(yBalance), inputToken);
        require(result < 0);
        outputAmount = uint256(-result);
        _checkAmountWithBalance(inputToken == SpecifiedToken.X ? yBalance : xBalance, outputAmount);
    }

    /**
     * @dev Given an output amount of a reserve token, we compute an input
     *  amount of the other reserve token, keeping utility invariant.
     * @dev We use FEE_UP because we want to increase the perceived output
     *  amount and increase the observed input amount.
     */
    function swapGivenOutputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 outputAmount,
        SpecifiedToken outputToken
    )
        external
        view
        returns (uint256 inputAmount)
    {
        require(outputAmount < INT_MAX && xBalance < INT_MAX && yBalance < INT_MAX);
        _checkAmountWithBalance(outputToken == SpecifiedToken.X ? xBalance : yBalance, outputAmount);
        int256 result = _swap(FEE_UP, -int256(outputAmount), int256(xBalance), int256(yBalance), outputToken);
        require(result > 0);
        inputAmount = uint256(result);
        _checkAmountWithBalance(outputToken == SpecifiedToken.X ? yBalance : xBalance, inputAmount);
    }

    /**
     * @dev Given an input amount of a reserve token, we compute an output
     *  amount of LP tokens, scaling the total supply of the LP tokens with the
     *  utility of the pool.
     * @dev We use FEE_DOWN because we want to decrease the perceived amount
     *  deposited and decrease the amount of LP tokens minted.
     */
    function depositGivenInputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 depositedAmount,
        SpecifiedToken depositedToken
    )
        external
        view
        returns (uint256 mintedAmount)
    {
        require(depositedAmount < INT_MAX && xBalance < INT_MAX && yBalance < INT_MAX && totalSupply < INT_MAX);
        int256 result = _reserveTokenSpecified(
            depositedToken, int256(depositedAmount), FEE_DOWN, int256(totalSupply), int256(xBalance), int256(yBalance)
        );
        require(result > 0);
        mintedAmount = uint256(result);
    }

    /**
     * @dev Given an output amount of the LP token, we compute an amount of
     *  a reserve token that must be deposited to scale the utility of the pool
     *  in proportion to the change in total supply of the LP token.
     * @dev We use FEE_UP because we want to increase the perceived change in
     *  total supply and increase the observed amount deposited.
     */
    function depositGivenOutputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 mintedAmount,
        SpecifiedToken depositedToken
    )
        external
        view
        returns (uint256 depositedAmount)
    {
        require(mintedAmount < INT_MAX && xBalance < INT_MAX && yBalance < INT_MAX && totalSupply < INT_MAX);
        int256 result = _lpTokenSpecified(
            depositedToken, int256(mintedAmount), FEE_UP, int256(totalSupply), int256(xBalance), int256(yBalance)
        );
        require(result > 0);
        depositedAmount = uint256(result);
    }

    /**
     * @dev Given an output amount of a reserve token, we compute an amount of
     *  LP tokens that must be burned in order to decrease the total supply in
     *  proportion to the decrease in utility.
     * @dev We use FEE_UP because we want to increase the perceived amount
     *  withdrawn from the pool and increase the observed decrease in total
     *  supply.
     */
    function withdrawGivenOutputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 withdrawnAmount,
        SpecifiedToken withdrawnToken
    )
        external
        view
        returns (uint256 burnedAmount)
    {
        require(withdrawnAmount < INT_MAX && xBalance < INT_MAX && yBalance < INT_MAX && totalSupply < INT_MAX);
        int256 result = _reserveTokenSpecified(
            withdrawnToken, -int256(withdrawnAmount), FEE_UP, int256(totalSupply), int256(xBalance), int256(yBalance)
        );
        require(result < 0);
        burnedAmount = uint256(-result);
    }

    /**
     * @dev Given an input amount of the LP token, we compute an amount of
     *  a reserve token that must be output to decrease the pool's utility in
     *  proportion to the pool's decrease in total supply of the LP token.
     * @dev We use FEE_UP because we want to increase the perceived amount of
     *  reserve tokens leaving the pool and to increase the observed amount of
     *  LP tokens being burned.
     */
    function withdrawGivenInputAmount(
        uint256 xBalance,
        uint256 yBalance,
        uint256 totalSupply,
        uint256 burnedAmount,
        SpecifiedToken withdrawnToken
    )
        external
        view
        returns (uint256 withdrawnAmount)
    {
        require(burnedAmount < INT_MAX && xBalance < INT_MAX && yBalance < INT_MAX && totalSupply < INT_MAX);
        int256 result = _lpTokenSpecified(
            withdrawnToken, -int256(burnedAmount), FEE_DOWN, int256(totalSupply), int256(xBalance), int256(yBalance)
        );
        require(result < 0);
        withdrawnAmount = uint256(-result);
    }

    /**
     * @dev From a starting point (xi, yi), we can begin a swap in four ways:
     *  [+x, -x, +y, -y]. This function abstracts over those four ways using
     *  the specifiedToken parameter and the sign of the specifiedAmount
     *  integer.
     * @dev A starting coordinate can be combined with the specified amount
     *  to find a known final coordinate. A final coordinate and a final
     *  utility can be used to determine the final point.
     * @dev Using the final point and the initial point, we can find how much
     *  of the non-specified token must enter or leave the pool in order to
     *  keep utility invariant.
     * @dev see notes above _findFinalPoint for information on direction
     *  and other variables declared in this scope.
     */
    function _swap(
        bool feeDirection,
        int256 specifiedAmount,
        int256 xi,
        int256 yi,
        SpecifiedToken specifiedToken
    )
        internal
        view
        returns (int256 computedAmount)
    {
        int256 roundedSpecifiedAmount;
        {
            roundedSpecifiedAmount = _applyFeeByRounding(specifiedAmount, feeDirection);
        }

        int256 xf;
        int256 yf;
        {
            int128[] memory slopes = getSlopes();
            uint256 i = _findSlice(slopes, xi, yi);

            int128[] memory _as = getAs();
            int128[] memory bs = getBs();
            int128[] memory ks = getKs();
            int256 utility = _getUtility(xi, yi, _as[i], bs[i], ks[i]);

            if (specifiedToken == SpecifiedToken.X) {
                int256 fixedPoint = xi + roundedSpecifiedAmount;
                int256 direction = (roundedSpecifiedAmount < 0) ? int256(1) : int256(-1);
                (xf, yf) =
                    _findFinalPoint(fixedPoint, direction, utility, i, _getPointGivenXandUtility, slopes, _as, bs, ks);
            } else {
                int256 fixedPoint = yi + roundedSpecifiedAmount;
                int256 direction = (roundedSpecifiedAmount < 0) ? int256(-1) : int256(1);
                (xf, yf) =
                    _findFinalPoint(fixedPoint, direction, utility, i, _getPointGivenYandUtility, slopes, _as, bs, ks);
            }
        }

        if (specifiedToken == SpecifiedToken.X) {
            computedAmount = _applyFeeByRounding(yf - yi, feeDirection);
            _checkBalances(xi + specifiedAmount, yi + computedAmount);
        } else {
            computedAmount = _applyFeeByRounding(xf - xi, feeDirection);
            _checkBalances(xi + computedAmount, yi + specifiedAmount);
        }
    }

    /**
     * @dev When performing a deposit given an input amount or a withdraw
     *  given an output amount, we know the initial point and final point,
     *  which allows us to find the initial utility and final utility.
     * @dev With the initial utility and final utility, we need to change
     *  the total supply in proportion to the change in utility.
     */
    function _reserveTokenSpecified(
        SpecifiedToken specifiedToken,
        int256 specifiedAmount,
        bool feeDirection,
        int256 si,
        int256 xi,
        int256 yi
    )
        internal
        view
        returns (int256 computedAmount)
    {
        int256 xf;
        int256 yf;
        int256 ui;
        int256 uf;
        {
            if (specifiedToken == SpecifiedToken.X) {
                xf = xi + _applyFeeByRounding(specifiedAmount, feeDirection);
                yf = yi;
            } else {
                yf = yi + _applyFeeByRounding(specifiedAmount, feeDirection);
                xf = xi;
            }
        }
        {
            int128[] memory slopes = getSlopes();
            int128[] memory _as = getAs();
            int128[] memory bs = getBs();
            int128[] memory ks = getKs();
            {
                uint256 i = _findSlice(slopes, xi, yi);
                ui = _getUtility(xi, yi, _as[i], bs[i], ks[i]);
            }
            {
                uint256 j = _findSlice(slopes, xf, yf);
                uf = _getUtility(xf, yf, _as[j], bs[j], ks[j]);
            }
        }

        uint256 result = Math.mulDiv(uint256(uf), uint256(si), uint256(ui));
        require(result < INT_MAX);
        int256 sf = int256(result);
        computedAmount = _applyFeeByRounding(sf - si, feeDirection);
    }

    /**
     * @dev When performing a deposit given an output amount or a withdraw
     *  given an input amount, we know the initial total supply and the final
     *  total supply.
     * @dev Given the change in total supply, we need to find how much of a
     *  reserve token we need to take in or give out in order to change the
     *  pool's utility in proportion to the pool's change in total supply.
     * @dev see notes above _findFinalPoint for information on direction
     *  and other variables declared in this scope.
     */
    function _lpTokenSpecified(
        SpecifiedToken specifiedToken,
        int256 specifiedAmount,
        bool feeDirection,
        int256 si,
        int256 xi,
        int256 yi
    )
        internal
        view
        returns (int256 computedAmount)
    {
        int128[] memory slopes = getSlopes();
        int128[] memory _as = getAs();
        int128[] memory bs = getBs();
        int128[] memory ks = getKs();

        (int256 uf, uint256 i) =
            _getUtilityFinalLp(si, si + _applyFeeByRounding(specifiedAmount, feeDirection), xi, yi, slopes, _as, bs, ks);

        int256 xf;
        int256 yf;
        if (specifiedToken == SpecifiedToken.X) {
            int256 direction = (specifiedAmount < 0) ? int256(1) : int256(-1);
            (xf, yf) = _findFinalPoint(yi, direction, uf, i, _getPointGivenYandUtility, slopes, _as, bs, ks);
        } else {
            int256 direction = (specifiedAmount < 0) ? int256(-1) : int256(1);
            (xf, yf) = _findFinalPoint(xi, direction, uf, i, _getPointGivenXandUtility, slopes, _as, bs, ks);
        }

        if (specifiedToken == SpecifiedToken.X) {
            computedAmount = _applyFeeByRounding(xf - xi, feeDirection);
            _checkBalances(xi + computedAmount, yf);
        } else {
            computedAmount = _applyFeeByRounding(yf - yi, feeDirection);
            _checkBalances(xf, yi + computedAmount);
        }
    }

    /// @dev extracted to avoid stack-too-deep errors
    function _getUtilityFinalLp(
        int256 si,
        int256 sf,
        int256 xi,
        int256 yi,
        int128[] memory slopes,
        int128[] memory _as,
        int128[] memory bs,
        int128[] memory ks
    )
        internal
        pure
        returns (int256 uf, uint256 i)
    {
        require(sf >= MIN_BALANCE);
        i = _findSlice(slopes, xi, yi);
        int256 ui = _getUtility(xi, yi, _as[i], bs[i], ks[i]);
        uint256 result = Math.mulDiv(uint256(ui), uint256(sf), uint256(si));
        require(result < INT_MAX);
        uf = int256(result);
    }

    /**
     * @dev This function leverages several properties of proteus to find
     *  the final state of the balances after an action. These properties are:
     *   1. There is always a known coordinate. We always know at least one of
     *      xf or yf. In swaps we know the specified token (ti + amount == tf).
     *      In deposits or withdrawals, we know the non-specified token
     *      (ti == tf).
     *   2. There is always a known utility. During swaps utility is invariant
     *      (ui == uf).  During deposits or withdrawals, utility varies linearly
     *      with the known change in total supply of the LP token.
     *   3. There is only one slice (with parameters a, b, k and boundary
     *      slopes mLeft, mRight) of the piecewise curve where recovering the
     *      unknown coordinate from the known coordinate and know utility will
     *      result in a pair of coordinates that lie within the slice.
     *   4. Given initial slice i, the final slice
     *   5. We search to the left when the amount of y is increasing or the
     *      amount of x is decreasing.  We search to the right when the amount
     *      of x is increasing or the amount of y is decreasing. The slice
     *      parameters are stored starting with the slice along the x-axis
     *      and ending with the slice along the y-axis. To search to the left,
     *      we increment i.  To search to the right, we decrement i.
     * @param fixedCoordinate Known coordinate
     * @param direction Search direction. Either -1 (right) or +1 (left)
     * @param utility Known utility
     * @param i Initially the starting slice. Maintains search state.
     * @param getPoint Function that uses the known coordinate and the known
     *  utility to compute the unknown coordinate. Returns a point (x, y).
     * @param slopes y/x slopes that bound the slices of the piecewise curve
     * @param _as Horizontal shifts (x + a) of the piecewise curve
     * @param bs Vertical shifts (y + b) of the piecewise curve
     * @param ks Relative liquidity of the slice in comparison to the 0th slice
     */
    function _findFinalPoint(
        int256 fixedCoordinate,
        int256 direction,
        int256 utility,
        uint256 i,
        function(int256, int256, int128, int128, int128)
            pure
            returns (int256, int256) getPoint,
        int128[] memory slopes,
        int128[] memory _as,
        int128[] memory bs,
        int128[] memory ks
    )
        internal
        pure
        returns (int256 xf, int256 yf)
    {
        (xf, yf) = getPoint(fixedCoordinate, utility, _as[i], bs[i], ks[i]);
        while (_pointIsNotInSlice(slopes, i, xf, yf)) {
            i = _next(i, direction);
            (xf, yf) = getPoint(fixedCoordinate, utility, _as[i], bs[i], ks[i]);
        }
    }

    /**
     * @dev Utility is the pool's internal measure of how much value it holds
     * @dev The pool values the x reserve and y reserve based on how much of
     *  one it holds compared to the other. The higher ratio of y to x, the
     *  less it values y compared to x.
     * @dev Proteus uses piecewise hyperbolas that are scaled by utility u, and
     *  relative liquidity k, and translated horizontally by a and vertically
     *  by b.
     * @dev the equation for a curve in a slice is:
     *  k(ab - 1)u**2 + (ay + bx)u + xy/k = 0
     *  where y/x determines what slice we are in, utility is comparable
     *  between slices, and the combination of a, b, and k determine the prices
     *  at both edges of the slice, which determines rate of change of price
     *  within the slice, which changes the magnitude of price impact for a
     *  trade of a given size within the slice.
     * @dev isolate u in the equation using the quadratic formula above gives us two solutions.
     *  We always want the larger solution
     */
    function _getUtility(int256 x, int256 y, int128 a, int128 b, int128 k) internal pure returns (int256 utility) {
        int256 aQuad = k.mul(a.mul(b).sub(ABDK_ONE)).muli(1e18);
        int256 bQuad = a.muli(y) + b.muli(x);
        int256 cQuad = (x * y) / k.muli(1e18);

        int256 disc = int256(Math.sqrt(uint256((bQuad ** 2) - (aQuad * cQuad * 4))));
        int256 r0 = ((-bQuad + disc) * 1e18) / (2 * aQuad);
        int256 r1 = ((-bQuad - disc) * 1e18) / (2 * aQuad);

        if (a < 0 && b < 0) {
            utility = (r0 > r1) ? r1 : r0;
        } else {
            utility = (r0 > r1) ? r0 : r1;
        }

        if (utility < 0) {
            revert CurveError();
        }
    }

    /**
     * @dev Given a utility and a bonding curve (a, b, k) and one coordinate
     *  of a point on that curve, we can find the other coordinate of the
     *  point.
     * @dev the equation for a curve in a slice is:
     *  ((x / (ku)) + a) ((y / (ku)) + b) = 1 (see _getUtility notes)
     * @dev Isolating y in the equation above gives us the equation:
     *  y = (k^2 u^2)/(a k u + x) - b k u
     * @dev This function returns x as xf because we want to be able to call
     *  getPointGivenX and getPointGivenY and handle the returned values
     *  without caring about which particular function is was called.
     */
    function _getPointGivenXandUtility(
        int256 x,
        int256 utility,
        int128 a,
        int128 b,
        int128 k
    )
        internal
        pure
        returns (int256 xf, int256 yf)
    {
        xf = x;
        int256 ku = k.muli(utility);
        // ((x / (ku)) + a) ((y / (ku)) + b) = 1
        //
        yf = ((ku ** 2) / (a.muli(ku) + xf)) - b.muli(ku);
        if (yf < 0) {
            revert CurveError();
        }
    }

    /**
     * @dev Given a utility and a bonding curve (a, b, k) and one coordinate
     *  of a point on that curve, we can find the other coordinate of the
     *  point.
     * @dev the equation for a curve in a slice is:
     *  ((x / (ku)) + a) ((y / (ku)) + b) = 1 (see _getUtility notes)
     * @dev Isolating y in the equation above gives us the equation:
     *  x = (k^2 u^2)/(b k u + y) - a k u
     * @dev This function returns y as yf because we want to be able to call
     *  getPointGivenX and getPointGivenY and handle the returned values
     *  without caring about which particular function is was called.
     */
    function _getPointGivenYandUtility(
        int256 y,
        int256 utility,
        int128 a,
        int128 b,
        int128 k
    )
        internal
        pure
        returns (int256 xf, int256 yf)
    {
        yf = y;
        int256 ku = k.muli(utility);
        xf = ((ku ** 2) / (b.muli(ku) + yf)) - a.muli(ku);
        if (xf < 0) {
            revert CurveError();
        }
    }

    /**
     * @dev A point is in slice n if it is on or below the nth radial line that
     *  marks a slice boundary. If the slice is above the final radial line, it
     *  is in the final slice.
     * @dev the 0th slice is next to the x-axis, and the final slice is next to
     *  the y-axis.
     * @dev Points must be within a hexangle bounded by the lines:
     *   x = MIN_BALANCE
     *   y = MIN_BALANCE
     *   x = 2^255 - 1
     *   y = 2^255 - 1
     *   y = MAX_M * x
     *   y = MIN_M * x
     *  When balances are too close to the origin or the x and y axes, we
     *  can encounter problems with utility stability.
     */
    function _findSlice(int128[] memory slopes, int256 x, int256 y) internal pure returns (uint256 index) {
        if (x < MIN_BALANCE || y < MIN_BALANCE) {
            revert BalanceError();
        }

        int128 m = y.divi(x);
        if (m <= MIN_M) {
            revert BoundaryError();
        }

        for (uint256 i = 0; i < slopes.length; ++i) {
            if (m <= slopes[i]) {
                return i;
            }
        }
        if (m <= MAX_M) {
            return NUMBER_OF_SLOPES;
        }
        // MAX_M < m
        revert BoundaryError();
    }

    /**
     * @dev A point is not in a slice if it is above the slice's lefthand
     *  radial line, or if it is on or below the slice's righthand radial
     *  line.
     *      in slice: (mRight, mLeft]
     *      not in slice: [0, mRight] U (mLeft, type(int128).max]
     */
    function _pointIsNotInSlice(
        int128[] memory slopes,
        uint256 currentSlice,
        int256 x,
        int256 y
    )
        internal
        pure
        returns (bool inSlice)
    {
        (int128 mLeft, int128 mRight) = _getSliceBoundaries(slopes, currentSlice);
        int128 m = y.divi(x);
        inSlice = bool(m <= mRight || mLeft < m);
    }

    /**
     * @dev We number slices counterclockwise starting at the origin, so the
     *  lefthand slope is always greater than the righthand slope.
     * @dev The lefthand boundary is the n-th slope and the righthand boundary
     *  is the n-1-th slope.
     * @dev In the 0th slice, the righthand slope is MIN_M. This constant is
     *  slightly above the x-axis.
     * @dev In the final slice, the lefthand slope is MAX_M. This constant is
     *  slightly to the right of the y-axis.
     */
    function _getSliceBoundaries(
        int128[] memory slopes,
        uint256 index
    )
        internal
        pure
        returns (int128 mLeft, int128 mRight)
    {
        if (NUMBER_OF_SLOPES < index) {
            revert BoundaryError();
        }

        if (index == 0) {
            mLeft = slopes[0];
            mRight = MIN_M;
        } else if (index == NUMBER_OF_SLOPES) {
            mLeft = MAX_M;
            mRight = slopes[index - 1];
        } else {
            mLeft = slopes[index];
            mRight = slopes[index - 1];
        }
    }

    /**
     * @dev Next uses the parameter direction to abstract over traversing
     *  through the slices
     * @param currentSlice The slice we are leaving
     * @param direction This value is -1 when we are traversing to the right
     *  and +1 when we are traversing to the left.
     * @return nextSlice We add direction to the currentSlice to get the next
     *  slice. If the next slice is out of bounds, we throw an error.
     */
    function _next(uint256 currentSlice, int256 direction) internal pure returns (uint256 nextSlice) {
        assert(direction == -1 || direction == 1);
        int256 potentialSlice = int256(currentSlice) + direction;

        // Short circuit behavior means the unsigned cast is safe
        if (potentialSlice < 0 || NUMBER_OF_SLICES <= uint256(potentialSlice)) {
            revert BoundaryError();
        }
        // potentialSlice must be non-negative if we did not revert, so this
        // is a safe cast.
        nextSlice = uint256(potentialSlice);
        assert(nextSlice < NUMBER_OF_SLICES);
    }

    /**
     * @dev this limits the ratio between a starting balance and an input
     *  or output amount.
     * @dev when we swap very small amounts against a very large pool,
     *  precision errors can cause the pool to lose a small amount of value.
     */
    function _checkAmountWithBalance(uint256 balance, uint256 amount) private pure {
        if (balance / amount >= MAX_BALANCE_AMOUNT_RATIO) {
            revert AmountError();
        }
    }

    /**
     * @dev The pool's balances of the x reserve and y reserve tokens must be
     *  greater than the MIN_BALANCE
     * @dev The pool's ratio of y to x must be within the interval
     *  [MIN_M, MAX_M)
     */
    function _checkBalances(int256 x, int256 y) private pure {
        if (x < MIN_BALANCE || y < MIN_BALANCE) {
            revert BalanceError();
        }
        int128 finalBalanceRatio = y.divi(x);
        if (finalBalanceRatio < MIN_M) {
            revert BoundaryError();
        } else if (MAX_M <= finalBalanceRatio) {
            revert BoundaryError();
        }
    }

    /**
     * @dev Rounding and fees are equivalent concepts
     * @dev We charge fees by rounding values in directions that are beneficial
     *  to the pool.
     * @dev the BASE_FEE and FIXED_FEE values were chosen such that round
     *  enough to cover numerical stability issues that arise from using a
     *  fixed precision math library and piecewise bonding curves.
     */
    function _applyFeeByRounding(int256 amount, bool feeUp) private pure returns (int256 roundedAmount) {
        bool negative = amount < 0 ? true : false;
        uint256 absoluteValue = negative ? uint256(-amount) : uint256(amount);
        // FIXED_FEE * 2 because we will possibly deduct the FIXED_FEE from
        // this amount, and we don't want the final amount to be less than
        // the FIXED_FEE.
        if (absoluteValue < FIXED_FEE * 2) revert AmountError();

        uint256 roundedAbsoluteAmount;
        if (feeUp) {
            roundedAbsoluteAmount = absoluteValue + (absoluteValue / BASE_FEE) + FIXED_FEE;
            require(roundedAbsoluteAmount < INT_MAX);
        } else {
            roundedAbsoluteAmount = absoluteValue - (absoluteValue / BASE_FEE) - FIXED_FEE;
        }

        roundedAmount = negative ? -int256(roundedAbsoluteAmount) : int256(roundedAbsoluteAmount);
    }
}

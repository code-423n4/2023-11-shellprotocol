pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../../ocean/Interactions.sol";
import "../../ocean/Ocean.sol";
import "../../adapters/CurveTricryptoAdapter.sol";

contract TestCurveTricryptoAdapter is Test {
    Ocean ocean;
    address wallet = 0x1Bb89c2e0E3989826B4B1f05c9C23dc73CbCBA4F; // WBTC/USDT whale
    address lpWallet = 0x54be362171c527DeD44F0B78642064c435443417; // Tricrypto LP whale
    CurveTricryptoAdapter adapter;
    address usdtAddress = 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9;
    address wbtcAddress = 0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f;

    function setUp() public {
        vm.createSelectFork("https://arb1.arbitrum.io/rpc"); // Will start on latest block by default
        vm.prank(wallet);
        ocean = new Ocean("");
        adapter = new CurveTricryptoAdapter(address(ocean), 0x960ea3e3C7FB317332d990873d354E18d7645590); // Tricrypto
            // address
    }

    function testSwap(bool toggle, uint256 amount, uint256 unwrapFee) public {
        vm.startPrank(wallet);
        unwrapFee = bound(unwrapFee, 2000, type(uint256).max);
        ocean.changeUnwrapFee(unwrapFee);

        address inputAddress;
        address outputAddress;

        if (toggle) {
            inputAddress = wbtcAddress;
            outputAddress = usdtAddress;
            amount = bound(amount, 1e17, IERC20(inputAddress).balanceOf(wallet) * 1e9);
        } else {
            inputAddress = usdtAddress;
            outputAddress = wbtcAddress;
            amount = bound(amount, 1e17, IERC20(inputAddress).balanceOf(wallet) * 1e11);
        }

        IERC20(inputAddress).approve(address(ocean), amount);

        uint256 prevInputBalance = IERC20(inputAddress).balanceOf(wallet);
        uint256 prevOutputBalance = IERC20(outputAddress).balanceOf(wallet);

        Interaction[] memory interactions = new Interaction[](3);

        interactions[0] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(inputAddress, uint256(InteractionType.WrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: amount,
            metadata: bytes32(0)
        });

        interactions[1] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(address(adapter), uint256(InteractionType.ComputeOutputAmount)),
            inputToken: _calculateOceanId(inputAddress),
            outputToken: _calculateOceanId(outputAddress),
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        interactions[2] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(outputAddress, uint256(InteractionType.UnwrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        // erc1155 token id's for balance delta
        uint256[] memory ids = new uint256[](2);
        ids[0] = _calculateOceanId(inputAddress);
        ids[1] = _calculateOceanId(outputAddress);

        ocean.doMultipleInteractions(interactions, ids);

        uint256 newInputBalance = IERC20(inputAddress).balanceOf(wallet);
        uint256 newOutputBalance = IERC20(outputAddress).balanceOf(wallet);

        assertLt(newInputBalance, prevInputBalance);
        assertGt(newOutputBalance, prevOutputBalance);

        vm.stopPrank();
    }

    function testSwapEth(bool toggle, bool isInput, uint256 amount, uint256 unwrapFee) public {
        vm.startPrank(wallet);
        unwrapFee = bound(unwrapFee, 2000, type(uint256).max);
        ocean.changeUnwrapFee(unwrapFee);

        address inputAddress;
        address outputAddress;

        if (toggle) {
            inputAddress = isInput ? address(0) : usdtAddress;
            outputAddress = isInput ? wbtcAddress : address(0);
            amount = bound(amount, 1e17, isInput ? wallet.balance / 2 : IERC20(inputAddress).balanceOf(wallet) * 1e11);
        } else {
            inputAddress = isInput ? address(0) : wbtcAddress;
            outputAddress = isInput ? usdtAddress : address(0);
            amount = bound(amount, 1e17, isInput ? wallet.balance / 2 : IERC20(inputAddress).balanceOf(wallet) * 1e9);
        }

        if (inputAddress != address(0)) {
            IERC20(inputAddress).approve(address(ocean), amount);
        }

        uint256 prevInputBalance = isInput ? wallet.balance : IERC20(inputAddress).balanceOf(wallet);
        uint256 prevOutputBalance = isInput ? IERC20(outputAddress).balanceOf(wallet) : wallet.balance;

        Interaction[] memory interactions;
        uint256[] memory ids = new uint256[](2);

        uint256 wrappedEtherId = adapter.zToken();

        if (isInput) {
            interactions = new Interaction[](2);

            interactions[0] = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(
                    address(adapter), uint256(InteractionType.ComputeOutputAmount)
                    ),
                inputToken: wrappedEtherId,
                outputToken: _calculateOceanId(outputAddress),
                specifiedAmount: type(uint256).max,
                metadata: bytes32(0)
            });

            interactions[1] = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(outputAddress, uint256(InteractionType.UnwrapErc20)),
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: type(uint256).max,
                metadata: bytes32(0)
            });

            ids[0] = wrappedEtherId;
            ids[1] = _calculateOceanId(outputAddress);

            ocean.doMultipleInteractions{ value: amount }(interactions, ids);
        } else {
            interactions = new Interaction[](3);

            interactions[0] = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(inputAddress, uint256(InteractionType.WrapErc20)),
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: amount,
                metadata: bytes32(0)
            });

            interactions[1] = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(
                    address(adapter), uint256(InteractionType.ComputeOutputAmount)
                    ),
                inputToken: _calculateOceanId(inputAddress),
                outputToken: wrappedEtherId,
                specifiedAmount: type(uint256).max,
                metadata: bytes32(0)
            });

            interactions[2] = Interaction({
                interactionTypeAndAddress: _fetchInteractionId(outputAddress, uint256(InteractionType.UnwrapEther)),
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: type(uint256).max,
                metadata: bytes32(0)
            });

            ids[0] = _calculateOceanId(inputAddress);
            ids[1] = wrappedEtherId;

            ocean.doMultipleInteractions(interactions, ids);
        }

        uint256 newInputBalance = isInput ? wallet.balance : IERC20(inputAddress).balanceOf(wallet);
        uint256 newOutputBalance = isInput ? IERC20(outputAddress).balanceOf(wallet) : wallet.balance;

        assertLt(newInputBalance, prevInputBalance);
        assertGt(newOutputBalance, prevOutputBalance);

        vm.stopPrank();
    }

    function testDeposit(bool toggle, uint256 amount, uint256 unwrapFee) public {
        vm.startPrank(wallet);
        unwrapFee = bound(unwrapFee, 2000, type(uint256).max);
        ocean.changeUnwrapFee(unwrapFee);

        address inputAddress;

        if (toggle) {
            inputAddress = usdtAddress;
            amount = bound(amount, 1e17, IERC20(inputAddress).balanceOf(wallet) * 1e11);
        } else {
            inputAddress = wbtcAddress;
            amount = bound(amount, 1e17, IERC20(inputAddress).balanceOf(wallet) * 1e9);
        }

        address outputAddress = adapter.underlying(adapter.lpTokenId());

        IERC20(inputAddress).approve(address(ocean), amount);

        uint256 prevInputBalance = IERC20(inputAddress).balanceOf(wallet);
        uint256 prevOutputBalance = IERC20(outputAddress).balanceOf(wallet);

        Interaction[] memory interactions = new Interaction[](3);

        interactions[0] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(inputAddress, uint256(InteractionType.WrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: amount,
            metadata: bytes32(0)
        });

        interactions[1] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(address(adapter), uint256(InteractionType.ComputeOutputAmount)),
            inputToken: _calculateOceanId(inputAddress),
            outputToken: _calculateOceanId(outputAddress),
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        interactions[2] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(outputAddress, uint256(InteractionType.UnwrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        // erc1155 token id's for balance delta
        uint256[] memory ids = new uint256[](2);
        ids[0] = _calculateOceanId(inputAddress);
        ids[1] = _calculateOceanId(outputAddress);

        ocean.doMultipleInteractions(interactions, ids);

        uint256 newInputBalance = IERC20(inputAddress).balanceOf(wallet);
        uint256 newOutputBalance = IERC20(outputAddress).balanceOf(wallet);

        assertLt(newInputBalance, prevInputBalance);
        assertGt(newOutputBalance, prevOutputBalance);

        vm.stopPrank();
    }

    function testDepositEth(uint256 amount, uint256 unwrapFee) public {
        vm.startPrank(wallet);
        unwrapFee = bound(unwrapFee, 2000, type(uint256).max);
        ocean.changeUnwrapFee(unwrapFee);

        amount = bound(amount, 1e17, wallet.balance / 2);

        address outputAddress = adapter.underlying(adapter.lpTokenId());

        uint256 prevInputBalance = wallet.balance;
        uint256 prevOutputBalance = IERC20(outputAddress).balanceOf(wallet);

        uint256 wrappedEtherId = adapter.zToken();

        Interaction[] memory interactions = new Interaction[](2);

        interactions[0] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(address(adapter), uint256(InteractionType.ComputeOutputAmount)),
            inputToken: wrappedEtherId,
            outputToken: _calculateOceanId(outputAddress),
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        interactions[1] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(outputAddress, uint256(InteractionType.UnwrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        uint256[] memory ids = new uint256[](2);
        ids[0] = wrappedEtherId;
        ids[1] = _calculateOceanId(outputAddress);

        ocean.doMultipleInteractions{ value: amount }(interactions, ids);

        uint256 newInputBalance = wallet.balance;
        uint256 newOutputBalance = IERC20(outputAddress).balanceOf(wallet);

        assertLt(newInputBalance, prevInputBalance);
        assertGt(newOutputBalance, prevOutputBalance);

        vm.stopPrank();
    }

    function testWithdraw(bool toggle, uint256 amount, uint256 unwrapFee) public {
        unwrapFee = bound(unwrapFee, 2000, type(uint256).max);
        vm.prank(wallet);
        ocean.changeUnwrapFee(unwrapFee);

        address outputAddress;

        if (toggle) {
            outputAddress = usdtAddress;
        } else {
            outputAddress = wbtcAddress;
        }

        address inputAddress = adapter.underlying(adapter.lpTokenId());

        amount = bound(amount, 1e17, IERC20(inputAddress).balanceOf(lpWallet));

        vm.prank(lpWallet);
        IERC20(inputAddress).approve(address(ocean), amount);

        uint256 prevInputBalance = IERC20(inputAddress).balanceOf(lpWallet);
        uint256 prevOutputBalance = IERC20(outputAddress).balanceOf(lpWallet);

        Interaction[] memory interactions = new Interaction[](3);

        interactions[0] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(inputAddress, uint256(InteractionType.WrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: amount,
            metadata: bytes32(0)
        });

        interactions[1] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(address(adapter), uint256(InteractionType.ComputeOutputAmount)),
            inputToken: _calculateOceanId(inputAddress),
            outputToken: _calculateOceanId(outputAddress),
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        interactions[2] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(outputAddress, uint256(InteractionType.UnwrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        // erc1155 token id's for balance delta
        uint256[] memory ids = new uint256[](2);
        ids[0] = _calculateOceanId(inputAddress);
        ids[1] = _calculateOceanId(outputAddress);

        vm.prank(lpWallet);
        ocean.doMultipleInteractions(interactions, ids);

        uint256 newInputBalance = IERC20(inputAddress).balanceOf(lpWallet);
        uint256 newOutputBalance = IERC20(outputAddress).balanceOf(lpWallet);

        assertLt(newInputBalance, prevInputBalance);
        assertGt(newOutputBalance, prevOutputBalance);
    }

    function testWithdrawEth(uint256 amount, uint256 unwrapFee) public {
        unwrapFee = bound(unwrapFee, 2000, type(uint256).max);
        vm.prank(wallet);
        ocean.changeUnwrapFee(unwrapFee);

        address outputAddress = address(0);
        address inputAddress = adapter.underlying(adapter.lpTokenId());

        amount = bound(amount, 1e17, IERC20(inputAddress).balanceOf(lpWallet));

        vm.prank(lpWallet);
        IERC20(inputAddress).approve(address(ocean), amount);

        uint256 prevInputBalance = IERC20(inputAddress).balanceOf(lpWallet);
        uint256 prevOutputBalance = lpWallet.balance;

        uint256 wrappedEtherId = adapter.zToken();

        Interaction[] memory interactions = new Interaction[](3);

        interactions[0] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(inputAddress, uint256(InteractionType.WrapErc20)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: amount,
            metadata: bytes32(0)
        });

        interactions[1] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(address(adapter), uint256(InteractionType.ComputeOutputAmount)),
            inputToken: _calculateOceanId(inputAddress),
            outputToken: wrappedEtherId,
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        interactions[2] = Interaction({
            interactionTypeAndAddress: _fetchInteractionId(outputAddress, uint256(InteractionType.UnwrapEther)),
            inputToken: 0,
            outputToken: 0,
            specifiedAmount: type(uint256).max,
            metadata: bytes32(0)
        });

        // erc1155 token id's for balance delta
        uint256[] memory ids = new uint256[](2);
        ids[0] = _calculateOceanId(inputAddress);
        ids[1] = wrappedEtherId;

        vm.prank(lpWallet);
        ocean.doMultipleInteractions(interactions, ids);

        uint256 newInputBalance = IERC20(inputAddress).balanceOf(lpWallet);
        uint256 newOutputBalance = lpWallet.balance;

        assertLt(newInputBalance, prevInputBalance);
        assertGt(newOutputBalance, prevOutputBalance);
    }

    function _calculateOceanId(address tokenAddress) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(tokenAddress, uint256(0))));
    }

    function _fetchInteractionId(address token, uint256 interactionType) internal pure returns (bytes32) {
        uint256 packedValue = uint256(uint160(token));
        packedValue |= interactionType << 248;
        return bytes32(abi.encode(packedValue));
    }
}

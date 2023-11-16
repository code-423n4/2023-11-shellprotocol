const { ethers } = require("hardhat")
const { expect } = require("chai")
const shellv2 = require("../../utils-js");

const decimals = "18"
const mintAmount = shellv2.utils.numberWithFixedDecimals({ number: "1000000", decimals })

describe("Malicious Primitive Integration Test When Mock Primitive calls another primitive", () => {
    let mockPrimitive
    let maliciousPrimitive
    let deployer
    let alice
    let ocean
    const tokens = []
    const oceanIds = []

    before("Deploy Malicious Primitive", async () => {

        [deployer, alice] = await ethers.getSigners()
        const oceanContract = await ethers.getContractFactory("Ocean", deployer)
        ocean = await oceanContract.deploy("")

        const erc20Contract = await ethers.getContractFactory("ERC20MintsToDeployer")
        tokens[0] = await erc20Contract.deploy(mintAmount, decimals)
        oceanIds[0] = shellv2.utils.calculateWrappedTokenId({ address: tokens[0].address, id: 0 })
        tokens[1] = await erc20Contract.deploy(mintAmount, decimals)
        oceanIds[1] = shellv2.utils.calculateWrappedTokenId({ address: tokens[1].address, id: 0 })

        const wraps = [
            shellv2.interactions.unitWrapERC20({
                address: tokens[0].address,
                amount: "1000000"
            }),
            shellv2.interactions.unitWrapERC20({
                address: tokens[1].address,
                amount: "1000000"
            })
        ]

        await tokens[0].connect(deployer).approve(ocean.address, mintAmount);
        await tokens[1].connect(deployer).approve(ocean.address, mintAmount);

        await shellv2.executeInteractions({ ocean: ocean, signer: deployer, interactions: wraps });

        const MaliciousPrimitive = await ethers.getContractFactory("MaliciousPrimitive", alice);

        maliciousPrimitive = await MaliciousPrimitive.deploy(
            ocean.address
        )

        const MockPrimitive = await ethers.getContractFactory("MockPrimitive", deployer);

        mockPrimitive = await MockPrimitive.deploy(
            ocean.address,
            maliciousPrimitive.address
        )

        await ocean.safeBatchTransferFrom(
            deployer.address,
            alice.address,
            oceanIds,
            [mintAmount.div(100), mintAmount.div(100)],
            []
        )

        await ocean.safeBatchTransferFrom(
            deployer.address,
            mockPrimitive.address,
            oceanIds,
            [mintAmount.div(1000), mintAmount.div(1000)],
            []
        )

        // funding the primitive directly with some balance
        await ocean.safeBatchTransferFrom(
            deployer.address,
            maliciousPrimitive.address,
            oceanIds,
            [mintAmount.div(1000), mintAmount.div(1000)],
            []
        )
    })

    it("Alice is able to swap with the mock primitive by specifying the input amount", async () => {
        const primitiveInputTokenBalanceBeforeSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[0]);
        const aliceInputTokenBalanceBeforeSwap = await ocean.balanceOf( alice.address, oceanIds[0]);
        
        const primitiveOutputTokenBalanceBeforeSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[1]);
        const aliceOutputTokenBalanceBeforeSwap = await ocean.balanceOf( alice.address, oceanIds[1]);

        const swapOutputX = shellv2.interactions.computeOutputAmount({
            address: mockPrimitive.address,
            inputToken: oceanIds[0],
            outputToken: oceanIds[1],
            specifiedAmount: shellv2.utils.numberWithFixedDecimals({ number: "50", decimals }),
            metadata: shellv2.constants.THIRTY_TWO_BYTES_OF_ZERO
        })
        
        expect(await shellv2.executeInteraction({
            ocean, signer: alice, interaction: swapOutputX
        })).to.have.property('hash')

        const primitiveInputTokenBalanceAfterSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[0]);
        const aliceInputTokenBalanceAfterSwap = await ocean.balanceOf( alice.address, oceanIds[0]);

        const primitiveOutputTokenBalanceAfterSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[1]);
        const aliceOutputTokenBalanceAfterSwap = await ocean.balanceOf( alice.address, oceanIds[1]);

        const primitiveInputTokenGain = primitiveInputTokenBalanceAfterSwap.sub(primitiveInputTokenBalanceBeforeSwap)
        const primitiveOutputTokenLoss = primitiveOutputTokenBalanceBeforeSwap.sub(primitiveOutputTokenBalanceAfterSwap)

        const aliceInputTokenLoss = aliceInputTokenBalanceBeforeSwap.sub(aliceInputTokenBalanceAfterSwap)
        const aliceOutputTokenGain = aliceOutputTokenBalanceAfterSwap.sub(aliceOutputTokenBalanceBeforeSwap)

        expect(aliceInputTokenLoss).to.equal(primitiveInputTokenGain)
        expect(aliceOutputTokenGain).to.equal(primitiveOutputTokenLoss)
    })

    it("Alice is able to swap with the mock primitive by specifying the output amount", async () => {
        const primitiveInputTokenBalanceBeforeSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[0]);
        const aliceInputTokenBalanceBeforeSwap = await ocean.balanceOf( alice.address, oceanIds[0]);

        const primitiveOutputTokenBalanceBeforeSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[1]);
        const aliceOutputTokenBalanceBeforeSwap = await ocean.balanceOf( alice.address, oceanIds[1]);

        const swapInputX = shellv2.interactions.computeInputAmount({
            address: mockPrimitive.address,
            inputToken: oceanIds[0],
            outputToken: oceanIds[1],
            specifiedAmount: shellv2.utils.numberWithFixedDecimals({ number: "10", decimals: "10" }), // specifying a very small output amount
            metadata: shellv2.constants.THIRTY_TWO_BYTES_OF_ZERO
        })
        
        expect(await shellv2.executeInteraction({
            ocean, signer: alice, interaction: swapInputX
        })).to.have.property('hash')

        const primitiveInputTokenBalanceAfterSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[0]);
        const aliceInputTokenBalanceAfterSwap = await ocean.balanceOf( alice.address, oceanIds[0]);

        const primitiveOutputTokenBalanceAfterSwap = await ocean.balanceOf( maliciousPrimitive.address, oceanIds[1]);
        const aliceOutputTokenBalanceAfterSwap = await ocean.balanceOf( alice.address, oceanIds[1]);

        const primitiveInputTokenGain = primitiveInputTokenBalanceAfterSwap.sub(primitiveInputTokenBalanceBeforeSwap)
        const primitiveOutputTokenLoss = primitiveOutputTokenBalanceBeforeSwap.sub(primitiveOutputTokenBalanceAfterSwap)

        const aliceInputTokenLoss = aliceInputTokenBalanceBeforeSwap.sub(aliceInputTokenBalanceAfterSwap)
        const aliceOutputTokenGain = aliceOutputTokenBalanceAfterSwap.sub(aliceOutputTokenBalanceBeforeSwap)

        expect(aliceInputTokenLoss).to.equal(primitiveInputTokenGain)
        expect(aliceOutputTokenGain).to.equal(primitiveOutputTokenLoss)
        
    })
})
const { ethers } = require("hardhat")
const { expect } = require("chai")
const shellV2 = require("../../utils-js");

describe("Fee mechanism tests", () => {
    const oneBip = "10000"
    const fiveBips = "2000"
    const tenBips = "1000"
    let ocean
    let alice
    let bob

    before("Deploy Ocean", async () => {
        [alice, bob] = await ethers.getSigners()
        const oceanContract = await ethers.getContractFactory("Ocean", bob)
        ocean = await oceanContract.deploy("")
    })

    it("It initial state is as expected", async () => {
        const [initialFee] = await Promise.all([
            ocean.unwrapFeeDivisor()
        ])
        expect(initialFee).to.equal(ethers.constants.MaxUint256)
    })

    it("Non-owner cannot change fee", async () => {
        await expect(
            ocean.connect(alice).changeUnwrapFee("1")
        ).to.be.revertedWith('Ownable: caller is not the owner')
    })

    it("Owner can change fee to five bips", async () => {
        await expect(
            ocean.connect(bob).changeUnwrapFee(fiveBips)
        ).to.emit(ocean, "ChangeUnwrapFee")
            .withArgs(ethers.constants.MaxUint256, fiveBips, bob.address)
    })

    it("Owner cannot change fee to ten bips", async () => {
        await expect(
            ocean.connect(bob).changeUnwrapFee(tenBips)
        ).to.be.reverted
    })

    it("Owner can change fee to oneBip", async () => {
        await expect(
            ocean.connect(bob).changeUnwrapFee(oneBip)
        ).to.emit(ocean, "ChangeUnwrapFee")
            .withArgs(fiveBips, oneBip, bob.address)
    })

    describe("Fees charged are as expected", () => {
        const decimals = "18"
        const mintAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals })
        let erc20Token
        let erc20TokenOceanId
        const jsIds = ["5", "1337", "1795", "23904823094852039583409", "1", "42"]
        const bigNumIds = jsIds.map((id) => ethers.BigNumber.from(id))
        const mintAmounts = jsIds.map(() => mintAmount)
        let erc1155Token

        const unwrapWithExpects = async ({ alice, bob, oceanId, unwrapAmount, expectedFee, interaction }) => {
            const [
                currentAliceBalance,
                currentBobBalance
            ] = await ocean.balanceOfBatch(
                [alice.address, bob.address],
                [oceanId, oceanId]
            )
            await shellV2.executeInteraction({
                ocean,
                signer: alice,
                interaction
            })
            // bob is the owner so he accrues the fees
            expect(await ocean.balanceOf(bob.address, oceanId)).to.equal(currentBobBalance.add(expectedFee))
            expect(await ocean.balanceOf(alice.address, oceanId)).to.equal(currentAliceBalance.sub(unwrapAmount))
        }

        before("Deploy tokens", async () => {
            const [erc20Contract, erc1155Contract] = await Promise.all([
                ethers.getContractFactory("ERC20MintsToDeployer"),
                ethers.getContractFactory("ERC1155MintsToDeployer")
            ]);
            [erc20Token, erc1155Token] = await Promise.all([
                erc20Contract.deploy(mintAmount, decimals),
                erc1155Contract.deploy(bigNumIds, mintAmounts)
            ])
            erc20TokenOceanId = shellV2.utils.calculateWrappedTokenId({ address: erc20Token.address, id: 0 })
        })

        describe("ERC-20 one bip fee", () => {
            before("Wrap 100 tokens", async () => {
                erc20Token.connect(alice).approve(ocean.address, mintAmount)
                await shellV2.executeInteraction({
                    ocean,
                    signer: alice,
                    interaction: shellV2.interactions.unitWrapERC20({
                        address: erc20Token.address,
                        amount: "100"
                    })
                })
            })
            it("Unwrap < 10,000 tokens, no fee", async () => {
                expect(await ocean.balanceOf(bob.address, erc20TokenOceanId)).to.equal(0)
                expect(await ocean.balanceOf(alice.address, erc20TokenOceanId)).to.equal(mintAmount)
                const unwrapAmount = "5000"
                const expectedFee = "0"
                await unwrapWithExpects({
                    alice,
                    bob,
                    oceanId: erc20TokenOceanId,
                    unwrapAmount,
                    expectedFee,
                    interaction: shellV2.interactions.unwrapERC20({
                        address: erc20Token.address,
                        amount: unwrapAmount
                    })
                })
            })

            it("Unwrap 10,000 tokens, fee", async () => {
                const unwrapAmount = "10000"
                const expectedFee = "1"
                await unwrapWithExpects({
                    alice,
                    bob,
                    oceanId: erc20TokenOceanId,
                    unwrapAmount,
                    expectedFee,
                    interaction: shellV2.interactions.unwrapERC20({
                        address: erc20Token.address,
                        amount: unwrapAmount
                    })
                })
            })

            it("Unwrap > 10,000 tokens, fee is floor", async () => {
                const unwrapAmount = "19999"
                const expectedFee = "1"
                await unwrapWithExpects({
                    alice,
                    bob,
                    oceanId: erc20TokenOceanId,
                    unwrapAmount,
                    expectedFee,
                    interaction: shellV2.interactions.unwrapERC20({
                        address: erc20Token.address,
                        amount: unwrapAmount
                    })
                })
            })
        })

        describe("ERC-1155 one bip fee", () => {
            let tokenId = bigNumIds[0]
            let oceanId
            before("Wrap 100 tokens", async () => {
                oceanId = shellV2.utils.calculateWrappedTokenId({
                    address: erc1155Token.address,
                    id: tokenId
                })
                erc1155Token.connect(alice).setApprovalForAll(ocean.address, true)
                await shellV2.executeInteractions({
                    ocean,
                    signer: alice,
                    interactions:
                        bigNumIds.map((id) => {
                            return shellV2.interactions.wrapERC1155({
                                address: erc1155Token.address,
                                id,
                                amount: mintAmount
                            })
                        })
                })
            })

            it("Unwrap < 10,000 tokens, no fee", async () => {
                expect(await ocean.balanceOf(bob.address, oceanId)).to.equal(0)
                expect(await ocean.balanceOf(alice.address, oceanId)).to.equal(mintAmount)
                const unwrapAmount = "5000"
                const expectedFee = "0"
                await unwrapWithExpects({
                    alice,
                    bob,
                    oceanId,
                    unwrapAmount,
                    expectedFee,
                    interaction: shellV2.interactions.unwrapERC1155({
                        address: erc1155Token.address,
                        id: tokenId,
                        amount: unwrapAmount
                    })
                })
            })


            it("Unwrap 10,000 tokens, fee", async () => {
                const unwrapAmount = "10000"
                const expectedFee = "1"
                await unwrapWithExpects({
                    alice,
                    bob,
                    oceanId,
                    unwrapAmount,
                    expectedFee,
                    interaction: shellV2.interactions.unwrapERC1155({
                        address: erc1155Token.address,
                        id: tokenId,
                        amount: unwrapAmount
                    })
                })
            })

            it("Unwrap > 10,000 tokens, fee is floor", async () => {
                const unwrapAmount = "19999"
                const expectedFee = "1"
                await unwrapWithExpects({
                    alice,
                    bob,
                    oceanId,
                    unwrapAmount,
                    expectedFee,
                    interaction: shellV2.interactions.unwrapERC1155({
                        address: erc1155Token.address,
                        id: tokenId,
                        amount: unwrapAmount
                    })
                })
            })
        })
    })
})
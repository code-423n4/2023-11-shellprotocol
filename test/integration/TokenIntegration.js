const { ethers } = require("hardhat")
const { expect } = require("chai")
const shellV2 = require("../../utils-js");

describe("Token Integration Tests", () => {
    let ocean
    let alice
    let bob

    before("Deploy Ocean", async () => {
        [alice, bob] = await ethers.getSigners()
        const oceanContract = await ethers.getContractFactory("Ocean", bob)
        ocean = await oceanContract.deploy("")
    })

    describe("ERC-20 Tests", () => {
        describe("ERC-20, 6-decimals", () => {
            const decimals = "6"
            const mintAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals })
            let token
            let oceanId

            before("Deploy token", async () => {
                const erc20Contract = await ethers.getContractFactory("ERC20MintsToDeployer")
                token = await erc20Contract.deploy(mintAmount, decimals)
                oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id: 0 })

                const [aliceBalance, oceanBalance] = await Promise.all([
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address)
                ])

                expect(aliceBalance).to.equal(mintAmount)
                expect(oceanBalance).to.equal(0)
            })

            it("Wrap ERC-20", async () => {
                const interaction = shellV2.interactions.unitWrapERC20({
                    address: token.address,
                    amount: "100"
                })

                await token.connect(alice).approve(ocean.address, mintAmount);

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction });

                const [aliceWrappedTokenFinalBalance, aliceExternalTokenFinalBalance, oceanExternalTokenFinalBalance] = await Promise.all([
                    ocean.balanceOf(alice.address, oceanId),
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address)
                ])

                const wrappedAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "18" })

                expect(aliceWrappedTokenFinalBalance).to.equal(wrappedAmount)
                expect(aliceExternalTokenFinalBalance).to.equal(0)
                expect(oceanExternalTokenFinalBalance).to.equal(mintAmount)
            })

            it("Unwrap ERC-20", async () => {
                const interaction = shellV2.interactions.unitUnwrapERC20({
                    address: token.address,
                    amount: "100"
                })

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction })

                const [
                    aliceWrappedTokenFinalBalance,
                    aliceExternalTokenFinalBalance,
                    oceanExternalTokenFinalBalance,
                    bobWrappedTokenFinalBalance,
                    feeDivisor
                ] = await Promise.all([
                    ocean.balanceOf(alice.address, oceanId),
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address),
                    ocean.balanceOf(bob.address, oceanId),
                    ocean.unwrapFeeDivisor()
                ])

                const oceanUnwrapped = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "18" })
                const oceanFeeCharged = oceanUnwrapped.div(feeDivisor)

                const externalUnwrapped = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "6" })
                const externalFeeCharged = externalUnwrapped.div(feeDivisor)

                const externalReceived = externalUnwrapped.sub(externalFeeCharged)

                expect(aliceWrappedTokenFinalBalance).to.equal(0)
                expect(aliceExternalTokenFinalBalance).to.equal(externalReceived)
                expect(oceanExternalTokenFinalBalance).to.equal(oceanFeeCharged)
                expect(bobWrappedTokenFinalBalance).to.equal(oceanFeeCharged)
            })

            it("Wrap amount that does not fit into 6 decimals", async () => {
                const specifiedAmount = ethers.BigNumber.from("123456789012345678")
                const wrapAmount = ethers.BigNumber.from("123457")
                const interaction = shellV2.interactions.wrapERC20({
                    address: token.address,
                    amount: specifiedAmount
                })

                await token.connect(alice).approve(ocean.address, mintAmount);

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction })
                expect(await token.balanceOf(ocean.address)).to.equal(wrapAmount)
                expect(await ocean.balanceOf(alice.address, oceanId)).to.equal(specifiedAmount)
                await shellV2.executeInteraction({
                    ocean: ocean,
                    signer: alice,
                    interaction: shellV2.interactions.unwrapERC20({
                        address: token.address,
                        amount: specifiedAmount
                    })
                })
                expect(await ocean.balanceOf(alice.address, oceanId)).to.equal(0)
            })

            it("Unwrap amount that does fit into 6 decimals", async () => {
                const wrapInteraction = shellV2.interactions.unitWrapERC20({
                    address: token.address,
                    amount: "50"
                })
                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: wrapInteraction })
                const initialBalance = await token.balanceOf(alice.address)
                const specifiedAmount = ethers.BigNumber.from("123456789012345678")
                const unwrapAmount = ethers.BigNumber.from("123456")

                const interaction = shellV2.interactions.unwrapERC20({
                    address: token.address,
                    amount: specifiedAmount
                })

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction })

                expect(await token.balanceOf(alice.address)).to.equal(unwrapAmount.add(initialBalance))
            })
        })

        describe("ERC-20, 18-decimals", () => {
            const decimals = "18"
            const mintAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals })
            let token
            let oceanId

            before("Deploy token", async () => {
                const erc20Contract = await ethers.getContractFactory("ERC20MintsToDeployer")
                token = await erc20Contract.deploy(mintAmount, decimals)
                oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id: 0 })

                const [aliceBalance, oceanBalance] = await Promise.all([
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address)
                ])

                expect(aliceBalance).to.equal(mintAmount)
                expect(oceanBalance).to.equal(0)
            })

            it("Wrap ERC-20", async () => {
                const interaction = shellV2.interactions.unitWrapERC20({
                    address: token.address,
                    amount: "100"
                })

                await token.connect(alice).approve(ocean.address, mintAmount);

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction });

                const [aliceWrappedTokenFinalBalance, aliceExternalTokenFinalBalance, oceanExternalTokenFinalBalance] = await Promise.all([
                    ocean.balanceOf(alice.address, oceanId),
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address)
                ])

                const wrappedAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "18" })

                expect(aliceWrappedTokenFinalBalance).to.equal(wrappedAmount)
                expect(aliceExternalTokenFinalBalance).to.equal(0)
                expect(oceanExternalTokenFinalBalance).to.equal(mintAmount)
            })

            it("Unwrap ERC-20", async () => {
                const interaction = shellV2.interactions.unitUnwrapERC20({
                    address: token.address,
                    amount: "100"
                })

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction })

                const [
                    aliceWrappedTokenFinalBalance,
                    aliceExternalTokenFinalBalance,
                    oceanExternalTokenFinalBalance,
                    bobWrappedTokenFinalBalance,
                    feeDivisor
                ] = await Promise.all([
                    ocean.balanceOf(alice.address, oceanId),
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address),
                    ocean.balanceOf(bob.address, oceanId),
                    ocean.unwrapFeeDivisor()
                ])

                const oceanUnwrapped = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "18" })
                const oceanFeeCharged = oceanUnwrapped.div(feeDivisor)

                const externalUnwrapped = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "18" })
                const externalFeeCharged = externalUnwrapped.div(feeDivisor)

                const externalReceived = externalUnwrapped.sub(externalFeeCharged)

                expect(aliceWrappedTokenFinalBalance).to.equal(0)
                expect(aliceExternalTokenFinalBalance).to.equal(externalReceived)
                expect(oceanExternalTokenFinalBalance).to.equal(oceanFeeCharged)
                expect(bobWrappedTokenFinalBalance).to.equal(oceanFeeCharged)
            })
        })

        describe("ERC-20, 21-decimals", () => {
            const decimals = "21"
            const mintAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals })
            let token
            let oceanId

            before("Deploy token", async () => {
                const erc20Contract = await ethers.getContractFactory("ERC20MintsToDeployer")
                token = await erc20Contract.deploy(mintAmount, decimals)
                oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id: 0 })

                const [aliceBalance, oceanBalance] = await Promise.all([
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address)
                ])

                expect(aliceBalance).to.equal(mintAmount)
                expect(oceanBalance).to.equal(0)
            })

            it("Wrap ERC-20", async () => {
                const interaction = shellV2.interactions.unitWrapERC20({
                    address: token.address,
                    amount: "100"
                })

                await token.connect(alice).approve(ocean.address, mintAmount);

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction });

                const [aliceWrappedTokenFinalBalance, aliceExternalTokenFinalBalance, oceanExternalTokenFinalBalance] = await Promise.all([
                    ocean.balanceOf(alice.address, oceanId),
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address)
                ])

                const wrappedAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "18" })

                expect(aliceWrappedTokenFinalBalance).to.equal(wrappedAmount)
                expect(aliceExternalTokenFinalBalance).to.equal(0)
                expect(oceanExternalTokenFinalBalance).to.equal(mintAmount)
            })

            it("Unwrap ERC-20", async () => {
                const interaction = shellV2.interactions.unitUnwrapERC20({
                    address: token.address,
                    amount: "100"
                })

                await shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction })

                const [
                    aliceWrappedTokenFinalBalance,
                    aliceExternalTokenFinalBalance,
                    oceanExternalTokenFinalBalance,
                    bobWrappedTokenFinalBalance,
                    feeDivisor
                ] = await Promise.all([
                    ocean.balanceOf(alice.address, oceanId),
                    token.balanceOf(alice.address),
                    token.balanceOf(ocean.address),
                    ocean.balanceOf(bob.address, oceanId),
                    ocean.unwrapFeeDivisor()
                ])

                const oceanUnwrapped = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "18" })
                const oceanFeeCharged = oceanUnwrapped.div(feeDivisor)

                const externalUnwrapped = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals: "21" })
                const externalFeeCharged = externalUnwrapped.div(feeDivisor)

                const externalReceived = externalUnwrapped.sub(externalFeeCharged)

                expect(aliceWrappedTokenFinalBalance).to.equal(0)
                expect(aliceExternalTokenFinalBalance).to.equal(externalReceived)
                expect(oceanExternalTokenFinalBalance).to.equal(oceanFeeCharged)
                expect(bobWrappedTokenFinalBalance).to.equal(oceanFeeCharged)
            })
        })

        describe("Contract without decimals", () => {
            let withoutDecimals
            before("deploy contract", async () => {
                const contract = await ethers.getContractFactory("Forwarder")
                withoutDecimals = await contract.deploy()
            })
            it("Wrap without decimals", async () => {
                const interaction = shellV2.interactions.unitWrapERC20({
                    address: withoutDecimals.address,
                    amount: "100"
                })

                await expect(
                    shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction })
                ).to.be.revertedWith("NO_DECIMAL_METHOD()")
            })

            it("Unwrap without decimals", async () => {
                const interaction = shellV2.interactions.unitUnwrapERC20({
                    address: withoutDecimals.address,
                    amount: "100"
                })

                await expect(
                    shellV2.executeInteraction({ ocean: ocean, signer: alice, interaction: interaction })
                ).to.be.revertedWith("NO_DECIMAL_METHOD()")
            })
        })

    })

    describe("ERC-721 Tests", () => {
        let token
        const jsIds = ["5", "1337", "1795", "23904823094852039583409", "1", "42"]
        const bigNumIds = jsIds.map((id) => ethers.BigNumber.from(id))

        before("Deploy token", async () => {
            const erc721Contract = await ethers.getContractFactory("ERC721MintsToDeployer", alice)
            token = await erc721Contract.deploy(bigNumIds)

            const ownerOfs = await Promise.all(
                bigNumIds.map((id) => token.ownerOf(id))
            )
            ownerOfs.map((owner) => expect(owner).to.equal(alice.address))

            const aliceBalance = await token.balanceOf(alice.address)
            expect(aliceBalance).to.equal(ownerOfs.length)
        })

        it("Wrap ERC-721", async () => {
            const id = bigNumIds[0]
            const interaction = shellV2.interactions.wrapERC721({
                address: token.address,
                id
            })

            await token.connect(alice).approve(ocean.address, id)

            await shellV2.executeInteraction({ ocean, signer: alice, interaction })

            const oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id })

            const [ownerOf, aliceBalance, oceanBalance, inOceanTokenBalance] = await Promise.all([
                token.ownerOf(id),
                token.balanceOf(alice.address),
                token.balanceOf(ocean.address),
                ocean.balanceOf(alice.address, oceanId)
            ])

            expect(ownerOf).to.equal(ocean.address)
            expect(aliceBalance).to.equal(bigNumIds.length - 1)
            expect(oceanBalance).to.equal(1)
            expect(inOceanTokenBalance).to.equal(1)
        })

        it("Unwrap ERC-721", async () => {
            const id = bigNumIds[0]
            const interaction = shellV2.interactions.unwrapERC721({
                address: token.address,
                id
            })

            await shellV2.executeInteraction({ ocean, signer: alice, interaction })

            const oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id })

            const [ownerOf, aliceBalance, oceanBalance, inOceanTokenBalance] = await Promise.all([
                token.ownerOf(id),
                token.balanceOf(alice.address),
                token.balanceOf(ocean.address),
                ocean.balanceOf(alice.address, oceanId)
            ])

            expect(ownerOf).to.equal(alice.address)
            expect(aliceBalance).to.equal(bigNumIds.length)
            expect(oceanBalance).to.equal(0)
            expect(inOceanTokenBalance).to.equal(0)
        })

        it("Wrap and then Unwrap using balance delta", async () => {
            const id = bigNumIds[0]

            await token.connect(alice).approve(ocean.address, id)

            const interactions = [
                // normal wrap
                shellV2.interactions.wrapERC721({
                    address: token.address,
                    id
                }),
                // custom unwrap since the library doesn't 
                shellV2.utils.useDelta(shellV2.interactions.unwrapERC721({
                    address: token.address,
                    id
                }))
            ]

            await shellV2.executeInteractions({ ocean, signer: alice, interactions })

            const oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id })

            const [ownerOf, aliceBalance, oceanBalance, inOceanTokenBalance] = await Promise.all([
                token.ownerOf(id),
                token.balanceOf(alice.address),
                token.balanceOf(ocean.address),
                ocean.balanceOf(alice.address, oceanId)
            ])

            expect(ownerOf).to.equal(alice.address)
            expect(aliceBalance).to.equal(bigNumIds.length)
            expect(oceanBalance).to.equal(0)
            expect(inOceanTokenBalance).to.equal(0)
        })

        it("Specifying more than one of an NFT reverts", async () => {
            const id = bigNumIds[0]

            await token.connect(alice).approve(ocean.address, id)

            const malformedWrapInteraction = {
                interactionTypeAndAddress: shellV2.utils.packInteractionTypeAndAddress(
                    {
                        interactionType: shellV2.constants.ERC721_WRAP,
                        address: token.address
                    }),
                inputToken: 0,
                outputToken: 0,
                specifiedAmount: 2,
                metadata: ethers.utils.hexZeroPad(id, 32)
            };

            await expect(
                shellV2.executeInteraction(
                    {
                        ocean,
                        signer: alice,
                        interaction: malformedWrapInteraction
                    }
                )
            ).to.be.revertedWith("INVALID_ERC721_AMOUNT()")

            const fixedWrapInteraction = {
                ...malformedWrapInteraction,
                specifiedAmount: 1
            }
            await shellV2.executeInteraction({ ocean, signer: alice, interaction: fixedWrapInteraction })

            const malformedUnwrapInteraction = {
                ...malformedWrapInteraction,
                interactionTypeAndAddress: shellV2.utils.packInteractionTypeAndAddress({
                    interactionType: shellV2.constants.ERC721_UNWRAP,
                    address: token.address
                })
            }

            await expect(
                shellV2.executeInteraction(
                    {
                        ocean,
                        signer: alice,
                        interaction: malformedUnwrapInteraction
                    }
                )
            ).to.be.revertedWith("INVALID_ERC721_AMOUNT()")

            const fixedUnwrapInteraction = {
                ...malformedUnwrapInteraction,
                specifiedAmount: 1
            }

            await shellV2.executeInteraction({ ocean, signer: alice, interaction: fixedUnwrapInteraction })
        })

        it("Ocean refuses unexpected transfers", async () => {
            await expect(
                token.connect(alice)['safeTransferFrom(address,address,uint256)'](alice.address, ocean.address, bigNumIds[2])
            ).to.be.revertedWith("ERC721: transfer to non ERC721Receiver implementer")
        })
    })

    describe("ERC-1155 Tests", () => {
        let token
        const jsIds = ["5", "1337", "1795", "23904823094852039583409", "1", "42"]
        const bigNumIds = jsIds.map((id) => ethers.BigNumber.from(id))
        const mintAmount = shellV2.utils.numberWithFixedDecimals({
            number: "100",
            decimals: "18"
        })
        const mintAmounts = bigNumIds.map(() => mintAmount)

        before("Deploy token", async () => {
            const erc1155Contract = await ethers.getContractFactory("ERC1155MintsToDeployer")
            token = await erc1155Contract.deploy(bigNumIds, mintAmounts)
            const balances = await token.balanceOfBatch(
                Array.from({ length: bigNumIds.length }, () => alice.address),
                bigNumIds
            )
            balances.map((balance) => expect(balance).to.equal(mintAmount))
        })

        it("Wrap ERC-1155", async () => {
            const id = bigNumIds[0]
            const interaction = shellV2.interactions.wrapERC1155({
                address: token.address,
                id,
                amount: mintAmount
            })

            await token.setApprovalForAll(ocean.address, true)

            await shellV2.executeInteraction({ ocean, signer: alice, interaction })

            const oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id })

            const [aliceWrappedTokenFinalBalance, aliceExternalTokenFinalBalance, oceanExternalTokenFinalBalance] = await Promise.all([
                ocean.balanceOf(alice.address, oceanId),
                token.balanceOf(alice.address, id),
                token.balanceOf(ocean.address, id)
            ])

            expect(aliceWrappedTokenFinalBalance).to.equal(mintAmount)
            expect(aliceExternalTokenFinalBalance).to.equal(0)
            expect(oceanExternalTokenFinalBalance).to.equal(mintAmount)
        })

        it("Unwrap ERC-1155", async () => {
            const id = bigNumIds[0]
            const interaction = shellV2.interactions.unwrapERC1155({
                address: token.address,
                id,
                amount: mintAmount
            })

            await shellV2.executeInteraction({ ocean, signer: alice, interaction })

            const oceanId = shellV2.utils.calculateWrappedTokenId({ address: token.address, id })

            const [
                aliceWrappedTokenFinalBalance,
                aliceExternalTokenFinalBalance,
                oceanExternalTokenFinalBalance,
                bobWrappedTokenFinalBalance,
                feeDivisor
            ] = await Promise.all([
                ocean.balanceOf(alice.address, oceanId),
                token.balanceOf(alice.address, id),
                token.balanceOf(ocean.address, id),
                ocean.balanceOf(bob.address, oceanId),
                ocean.unwrapFeeDivisor()
            ])

            const unwrapped = mintAmount
            const feeCharged = unwrapped.div(feeDivisor)

            const received = unwrapped.sub(feeCharged)

            expect(aliceWrappedTokenFinalBalance).to.equal(0)
            expect(aliceExternalTokenFinalBalance).to.equal(received)
            expect(oceanExternalTokenFinalBalance).to.equal(feeCharged)
            expect(bobWrappedTokenFinalBalance).to.equal(feeCharged)
        })

        it("Ocean refuses unexpected transfers", async () => {
            await expect(token.connect(alice).safeTransferFrom(
                alice.address, ocean.address, bigNumIds[1], 10000, []
            )).to.be.revertedWith("ERC1155: ERC1155Receiver rejected tokens")
            await expect(token.connect(alice).safeBatchTransferFrom(
                alice.address, ocean.address, bigNumIds.slice(1, 3), [10000, 10000], []
            )).to.be.revertedWith("ERC1155: ERC1155Receiver rejected tokens")
        })

        describe("Ocean won't recursively wrap its own tokens", () => {
            before("Wrap some tokens", async () => {
                await shellV2.executeInteraction({
                    ocean,
                    signer: alice,
                    interaction: shellV2.interactions.wrapERC1155({
                        address: token.address,
                        id: bigNumIds[1],
                        amount: mintAmount
                    })

                })
            })

            it("Recursively wrapping an ocean token fails", async () => {
                await expect(
                    ocean.connect(alice).doInteraction(
                        shellV2.interactions.wrapERC1155({
                            address: ocean.address,
                            id: shellV2.utils.calculateWrappedTokenId({
                                address: token.address,
                                id: bigNumIds[1]
                            }),
                            amount: mintAmount
                        })
                    )
                ).to.be.revertedWith("NO_RECURSIVE_WRAPS()")
            })

            it("Recursively unwrapping an ocean token fails", async () => {
                await expect(
                    ocean.connect(alice).doInteraction(
                        shellV2.interactions.unwrapERC1155({
                            address: ocean.address,
                            id: shellV2.utils.calculateWrappedTokenId({
                                address: token.address,
                                id: bigNumIds[1]
                            }),
                            amount: mintAmount
                        })
                    )
                ).to.be.revertedWith("NO_RECURSIVE_UNWRAPS()")
            })
        })
    })

    describe("Ether Tests", () => {
        let WRAPPED_ETHER_ID

        before("Get Wrapped Ether Ocean Id", async () => {
            WRAPPED_ETHER_ID = await ocean.WRAPPED_ETHER_ID()
        })

        it("Can wrap Ether with doInteraction", async () => {
            const initialAliceBalance = await ethers.provider.getBalance(alice.address)
            const initialOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(initialOceanBalance).to.equal(0)
            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(0)

            let responsePromise
            await expect(
                (responsePromise = ocean.connect(alice).doInteraction({
                    interactionTypeAndAddress: shellV2.utils.packInteractionTypeAndAddress({
                        interactionType: "0xff",
                        address: ethers.constants.AddressZero
                    }),
                    inputToken: 0,
                    outputToken: 0,
                    specifiedAmount: 0,
                    metadata: shellV2.constants.THIRTY_TWO_BYTES_OF_ZERO
                }, { value: 1 }))
            ).to.emit(ocean, "EtherWrap")
                .withArgs(1, alice.address)

            const receipt = await (await responsePromise).wait(1)
            const ethGasUsed = receipt.gasUsed.mul(receipt.effectiveGasPrice)

            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(1)

            const finalAliceBalance = await ethers.provider.getBalance(alice.address)
            const finalOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(finalOceanBalance).to.equal(1)
            expect(initialAliceBalance.sub(ethGasUsed).sub(1)).to.equal(finalAliceBalance);
            expect(initialAliceBalance.add(initialOceanBalance)).to.equal(finalAliceBalance.add(finalOceanBalance).add(ethGasUsed));
        })

        it("Can wrap Ether with empty interactions array", async () => {
            const initialAliceBalance = await ethers.provider.getBalance(alice.address)
            const initialOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(initialOceanBalance).to.equal(1)
            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(1)

            let responsePromise
            await expect(
                (responsePromise = ocean.connect(alice).doMultipleInteractions([], [WRAPPED_ETHER_ID], { value: 1 }))
            ).to.emit(ocean, "EtherWrap")
                .withArgs(1, alice.address)

            const receipt = await (await responsePromise).wait(1)
            const ethGasUsed = receipt.gasUsed.mul(receipt.effectiveGasPrice)

            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(2)

            const finalAliceBalance = await ethers.provider.getBalance(alice.address)
            const finalOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(finalOceanBalance).to.equal(2)
            expect(initialAliceBalance.sub(ethGasUsed).sub(1)).to.equal(finalAliceBalance);
            expect(initialAliceBalance.add(initialOceanBalance)).to.equal(finalAliceBalance.add(finalOceanBalance).add(ethGasUsed));
        })

        it("Can unwrap Ether", async () => {
            const initialAliceBalance = await ethers.provider.getBalance(alice.address)
            const initialOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(2).and.to.equal(initialOceanBalance)

            let responsePromise
            await expect(
                (responsePromise = ocean.connect(alice).doMultipleInteractions([
                    {
                        interactionTypeAndAddress: shellV2.utils.packInteractionTypeAndAddress({
                            interactionType: shellV2.constants.ETHER_UNWRAP,
                            address: ethers.constants.AddressZero
                        }),
                        inputToken: 0,
                        outputToken: 0,
                        specifiedAmount: 1,
                        metadata: shellV2.constants.THIRTY_TWO_BYTES_OF_ZERO
                    }
                ], [WRAPPED_ETHER_ID]))
            ).to.emit(ocean, "EtherUnwrap").withArgs(1, 0, alice.address)
                .and.to.emit(ocean, "TransferSingle")
                .withArgs(alice.address, alice.address, ethers.constants.AddressZero, WRAPPED_ETHER_ID, 1)

            const receipt = await (await responsePromise).wait(1)
            const ethGasUsed = receipt.gasUsed.mul(receipt.effectiveGasPrice)

            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(1)

            const finalAliceBalance = await ethers.provider.getBalance(alice.address)
            const finalOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(finalOceanBalance).to.equal(1)
            expect(initialAliceBalance.sub(ethGasUsed).add(1)).to.equal(finalAliceBalance);
            expect(initialAliceBalance.add(initialOceanBalance)).to.equal(finalAliceBalance.add(finalOceanBalance).add(ethGasUsed));
        })

        it("Can wrap and unwrap Ether in one transaction", async () => {
            const initialAliceBalance = await ethers.provider.getBalance(alice.address)
            const initialOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(1).and.to.equal(initialOceanBalance)

            let responsePromise
            await expect(
                (responsePromise = ocean.connect(alice).doMultipleInteractions([
                    {
                        interactionTypeAndAddress: shellV2.utils.packInteractionTypeAndAddress({
                            interactionType: shellV2.constants.ETHER_UNWRAP,
                            address: ethers.constants.AddressZero
                        }),
                        inputToken: 0,
                        outputToken: 0,
                        specifiedAmount: 1,
                        metadata: shellV2.constants.THIRTY_TWO_BYTES_OF_ZERO
                    }
                ], [WRAPPED_ETHER_ID], { value: 1 }))
            ).to.emit(ocean, "EtherWrap").withArgs(1, alice.address)
                .and.to.emit(ocean, "EtherUnwrap")
                .withArgs(1, 0, alice.address)

            const receipt = await (await responsePromise).wait(1)
            const ethGasUsed = receipt.gasUsed.mul(receipt.effectiveGasPrice)

            expect(await ocean.balanceOf(alice.address, WRAPPED_ETHER_ID)).to.equal(1)

            const finalAliceBalance = await ethers.provider.getBalance(alice.address)
            const finalOceanBalance = await ethers.provider.getBalance(ocean.address)

            expect(finalOceanBalance).to.equal(1).and.to.equal(initialOceanBalance)
            expect(initialAliceBalance.sub(ethGasUsed)).to.equal(finalAliceBalance)
            expect(initialAliceBalance.add(initialOceanBalance)).to.equal(finalAliceBalance.add(finalOceanBalance).add(ethGasUsed));
        })
    })

    describe("Malformed Token Interactions", () => {
        const decimals = "18"
        const mintAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals })
        const jsIds = ["5", "1337", "1795", "23904823094852039583409", "1", "42"]
        const bigNumIds = jsIds.map((id) => ethers.BigNumber.from(id))
        const mintAmounts = bigNumIds.map(() => mintAmount)
        const wrapAmount = "10000"
        let erc20Token
        let erc721Token
        let erc1155Token

        before("Deploy and approve tokens", async () => {
            const [
                erc20Contract,
                erc721Contract,
                erc1155Contract
            ] = await Promise.all([
                ethers.getContractFactory("ERC20MintsToDeployer", alice),
                ethers.getContractFactory("ERC721MintsToDeployer", alice),
                ethers.getContractFactory("ERC1155MintsToDeployer", alice)
            ]);
            [erc20Token, erc721Token, erc1155Token] = await Promise.all([
                erc20Contract.deploy(mintAmount, decimals),
                erc721Contract.deploy(bigNumIds),
                erc1155Contract.deploy(bigNumIds, mintAmounts)
            ])

            await Promise.all([
                erc20Token.connect(alice).approve(ocean.address, mintAmount),
                erc721Token.connect(alice).approve(ocean.address, bigNumIds[0]),
                erc1155Token.connect(alice).setApprovalForAll(ocean.address, true)
            ])

        })

        describe("Hand-rolled interactions (no js library)", async () => {
            it("Invalid InteractionTypes revert", async () => {
                await expect(
                    ocean.connect(alice).doInteraction(
                        {
                            interactionTypeAndAddress: shellV2.utils.packInteractionTypeAndAddress({
                                interactionType: "0x09",
                                address: ethers.constants.AddressZero
                            }),
                            inputToken: 0,
                            outputToken: 0,
                            specifiedAmount: 0,
                            metadata: shellV2.constants.THIRTY_TWO_BYTES_OF_ZERO
                        }
                    )
                ).to.be.revertedWith('0x21')
            })
        })

        describe("Malformed Wraps", () => {
            it("ERC-20 contract with ERC-721 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.wrapERC721({
                            address: erc20Token.address,
                            id: bigNumIds[0]
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-20 contract with ERC-1155 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.wrapERC1155({
                            address: erc20Token.address,
                            id: bigNumIds[0],
                            amount: wrapAmount
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-721 contract with ERC-20 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.wrapERC20({
                            address: erc721Token.address,
                            amount: bigNumIds[0]
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-721 contract with ERC-1155 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.wrapERC1155({
                            address: erc721Token.address,
                            id: bigNumIds[0],
                            amount: wrapAmount
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-1155 contract with ERC-20 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.wrapERC20({
                            address: erc1155Token.address,
                            amount: bigNumIds[0]
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-1155 contract with ERC-721 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.wrapERC721({
                            address: erc1155Token.address,
                            id: bigNumIds[0]
                        })
                    })
                ).to.be.reverted
            })
        })

        describe("Malformed Unwraps", () => {
            before("Wrap all tokens", async () => {
                await shellV2.executeInteractions({
                    ocean,
                    signer: alice,
                    interactions: [
                        shellV2.interactions.wrapERC20({
                            address: erc20Token.address,
                            amount: mintAmount
                        }),
                        shellV2.interactions.wrapERC721({
                            address: erc721Token.address,
                            id: bigNumIds[0]
                        }),
                        shellV2.interactions.wrapERC1155({
                            address: erc1155Token.address,
                            id: bigNumIds[0],
                            amount: mintAmount
                        })
                    ]
                })
            })


            it("ERC-20 contract with ERC-721 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.unwrapERC721({
                            address: erc20Token.address,
                            id: bigNumIds[0]
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-20 contract with ERC-1155 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.unwrapERC1155({
                            address: erc20Token.address,
                            id: bigNumIds[0],
                            amount: wrapAmount
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-721 contract with ERC-20 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.unwrapERC20({
                            address: erc721Token.address,
                            amount: bigNumIds[0]
                        })
                    })
                ).to.be.revertedWith("NO_DECIMAL_METHOD()")
            })

            it("ERC-721 contract with ERC-1155 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.unwrapERC1155({
                            address: erc721Token.address,
                            id: bigNumIds[0],
                            amount: wrapAmount
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-1155 contract with ERC-20 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.unwrapERC20({
                            address: erc1155Token.address,
                            amount: bigNumIds[0]
                        })
                    })
                ).to.be.reverted
            })

            it("ERC-1155 contract with ERC-721 interaction", async () => {
                await expect(
                    shellV2.executeInteraction({
                        ocean,
                        signer: alice,
                        interaction: shellV2.interactions.unwrapERC721({
                            address: erc1155Token.address,
                            id: bigNumIds[0]
                        })
                    })
                ).to.be.reverted
            })
        })
    })
})
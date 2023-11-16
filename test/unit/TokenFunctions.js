const { ethers } = require("hardhat")
const { expect } = require("chai")
const shellV2 = require("../../utils-js");

describe("ERC-1155 Token Function Tests", () => {
    const URI = "TEST URI"
    let ocean
    let alice
    let bob

    before("Deploy Ocean", async () => {
        [alice, bob] = await ethers.getSigners()
        const oceanContract = await ethers.getContractFactory("Ocean", bob)
        ocean = await oceanContract.deploy(URI)
    })

    describe("ERC-165 tests", async () => {
        let interfaces

        before("Get interface Ids", async () => {
            const interfacesContract = await ethers.getContractFactory("Interfaces")
            interfaces = await interfacesContract.deploy()
        })

        it("ERC1155Receiver", async () => {
            const i1155r = await interfaces.i1155r()
            expect(await ocean.supportsInterface(i1155r)).to.equal(true)
        })

        it("IERC1155", async () => {
            const i1155 = await interfaces.i1155()
            expect(await ocean.supportsInterface(i1155)).to.equal(true)
        })

        it("IERC1155MetadataURI", async () => {
            const i1155m = await interfaces.i1155m()
            expect(await ocean.supportsInterface(i1155m)).to.equal(true)
        })

        it("IERC165", async () => {
            const i165 = await interfaces.i165()
            expect(await ocean.supportsInterface(i165)).to.equal(true)
        })

        it("Unsupported Interface Reverts", async () => {
            // https://docs.ethers.io/v5/api/utils/bytes/#Bytes
            const unsupported = [255, 0, 128, 64]
            expect(await ocean.supportsInterface(unsupported)).to.equal(false)
        })
    })

    describe("ERC-1155 metadata uri", () => {
        it("Returns URI", async () => {
            expect(await ocean.uri(0)).to.equal(URI)
        })
    })

    describe("Transfers and balances", () => {
        const decimals = "18"
        const mintAmount = shellV2.utils.numberWithFixedDecimals({ number: "100", decimals })
        const transferAmount = shellV2.utils.numberWithFixedDecimals({ number: "1", decimals: "18" })
        let tokens

        before("Deploy and wrap tokens so we have balances to play with", async () => {
            const erc20Contract = await ethers.getContractFactory("ERC20MintsToDeployer", alice)
            tokens = await Promise.all(Array.from({ length: 3 }, async () => {
                return await erc20Contract.deploy(mintAmount, decimals)
            }))
            await Promise.all(tokens.map(async (token) => {
                await token.connect(alice).approve(ocean.address, mintAmount)
            }))
            await shellV2.executeInteractions({
                ocean,
                signer: alice,
                interactions: tokens.map((token) => {
                    return shellV2.interactions.wrapERC20({
                        address: token.address,
                        amount: mintAmount
                    })
                })
            })
            expect(await ocean.balanceOfBatch(
                tokens.map(() => alice.address),
                tokens.map((token) => shellV2.utils.calculateWrappedTokenId({ address: token.address, id: 0 }))
            )).to.deep.equal([mintAmount, mintAmount, mintAmount])
        })

        it("Alice can transfer Bob a single token", async () => {
            expect(
                await ocean
                    .connect(alice)
                    .safeTransferFrom(
                        alice.address,
                        bob.address,
                        shellV2.utils.calculateWrappedTokenId({ address: tokens[0].address, id: 0 }),
                        transferAmount,
                        []
                    )
            ).to.have.property('hash')
            expect(
                await ocean.balanceOf(
                    bob.address,
                    shellV2.utils.calculateWrappedTokenId({ address: tokens[0].address, id: 0 })
                )
            ).to.equal(transferAmount)
        })

        it("Alice can transfer Bob multiple tokens", async () => {
            const multipleTokens = [
                shellV2.utils.calculateWrappedTokenId({ address: tokens[1].address, id: 0 }),
                shellV2.utils.calculateWrappedTokenId({ address: tokens[2].address, id: 0 })
            ]
            const multipleTransfers = [transferAmount, transferAmount]
            expect(
                await ocean
                    .connect(alice)
                    .safeBatchTransferFrom(
                        alice.address,
                        bob.address,
                        multipleTokens,
                        multipleTransfers,
                        []
                    )
            ).to.have.property('hash')
            expect(await ocean.balanceOfBatch([bob.address, bob.address], multipleTokens)).to.deep.equal(multipleTransfers)
        })

        describe("Transfers to a contract", () => {
            let receiver
            let singleToken
            let multipleTokens
            let multipleTransfers

            before("Deploy Receiver", async () => {
                const receive1155Contract = await ethers.getContractFactory("Receive1155")
                receiver = await receive1155Contract.deploy()
                expect(await receiver.supportsInterface("0xDEADBEEF")).to.equal(false)
                expect(await receiver.supportsInterface("0x4e2312e0")).to.equal(true)
                singleToken = shellV2.utils.calculateWrappedTokenId({ address: tokens[0].address, id: 0 })
                multipleTokens = [
                    shellV2.utils.calculateWrappedTokenId({ address: tokens[1].address, id: 0 }),
                    shellV2.utils.calculateWrappedTokenId({ address: tokens[2].address, id: 0 })
                ]
                multipleTransfers = [transferAmount, transferAmount]
            })

            it("Transfers to IERC1155Receiver, accepted", async () => {
                expect(
                    await ocean
                        .connect(alice)
                        .safeTransferFrom(
                            alice.address,
                            receiver.address,
                            singleToken,
                            transferAmount,
                            []
                        )
                ).to.have.property('hash')

                expect(
                    await ocean
                        .connect(alice)
                        .safeBatchTransferFrom(
                            alice.address,
                            receiver.address,
                            multipleTokens,
                            multipleTransfers,
                            []
                        )
                ).to.have.property('hash')
                expect(
                    await ocean.balanceOfBatch(
                        [receiver.address, receiver.address, receiver.address],
                        tokens.map((token) => shellV2.utils.calculateWrappedTokenId({ address: token.address, id: 0 })))
                ).to.deep.equal(tokens.map(() => transferAmount))
            })

            it("Transfers to IERC1155Receiver, rejected", async () => {
                await expect(
                    ocean.connect(alice)
                        .safeTransferFrom(
                            alice.address,
                            receiver.address,
                            singleToken,
                            transferAmount,
                            [2]
                        )
                ).to.be.revertedWith("ERC1155Receiver rejected")

                await expect(
                    ocean.connect(alice)
                        .safeBatchTransferFrom(
                            alice.address,
                            receiver.address,
                            multipleTokens,
                            multipleTransfers,
                            [2]
                        )
                ).to.be.revertedWith("ERC1155Receiver rejected")
            })

            it("Transfers to IERC1155Receiver, reverted", async () => {
                const REVERT_MESSAGE = "Code coverage"
                await expect(
                    ocean.connect(alice)
                        .safeTransferFrom(
                            alice.address,
                            receiver.address,
                            singleToken,
                            transferAmount,
                            [1]
                        )
                ).to.be.revertedWith(REVERT_MESSAGE)

                await expect(
                    ocean.connect(alice)
                        .safeBatchTransferFrom(
                            alice.address,
                            receiver.address,
                            multipleTokens,
                            multipleTransfers,
                            [1]
                        )
                ).to.be.revertedWith(REVERT_MESSAGE)
            })

            it("Transfers to non-IERC1155Receiver", async () => {
                await expect(
                    ocean.connect(alice)
                        .safeTransferFrom(
                            alice.address,
                            tokens[0].address,
                            singleToken,
                            transferAmount,
                            [1]
                        )
                ).to.be.revertedWith("non-ERC1155Receiver")

                await expect(
                    ocean.connect(alice)
                        .safeBatchTransferFrom(
                            alice.address,
                            tokens[0].address,
                            multipleTokens,
                            multipleTransfers,
                            [1]
                        )
                ).to.be.revertedWith("non-ERC1155Receiver")
            })
        })

        it("Cannot set approval for self", async () => {
            await expect(
                ocean.connect(alice).setApprovalForAll(alice.address, true)
            ).to.be.revertedWith("Set approval for self")
        })

        it("Cannot get balance of zero address", async () => {
            await expect(
                ocean.connect(alice).balanceOf(ethers.constants.AddressZero, 1)
            ).to.be.revertedWith("balanceOf(address(0))")
        })

        it("Cannot get balanceOfBatch with mis-matched arrays", async () => {
            await expect(
                ocean.connect(alice).balanceOfBatch(
                    [alice.address, alice.address],
                    [1]
                )
            ).to.be.revertedWith("accounts.length != ids.length")
        })

        it("Cannot safeTransferFrom without approval", async () => {
            await expect(
                ocean.connect(bob).safeTransferFrom(
                    alice.address,
                    bob.address,
                    1,
                    1,
                    []
                )
            ).to.be.revertedWith("not owner nor approved")
        })

        it("Cannot safeBatchTransferFrom without approval", async () => {
            await expect(
                ocean.connect(bob).safeBatchTransferFrom(
                    alice.address,
                    bob.address,
                    [1, 2],
                    [1, 1],
                    []
                )
            ).to.be.revertedWith("not owner nor approved")
        })

        it("Cannot safeBatchTransferFrom with mis-matched arrays", async () => {
            await expect(
                ocean.connect(alice).safeBatchTransferFrom(
                    alice.address,
                    bob.address,
                    [1, 2],
                    [1],
                    []
                )
            ).to.be.revertedWith("ids.length != amounts.length")
        })

        it("Cannot safeTransferFrom to zero address", async () => {
            await expect(
                ocean.connect(alice).safeTransferFrom(
                    alice.address,
                    ethers.constants.AddressZero,
                    1,
                    1,
                    []
                )
            ).to.be.revertedWith("transfer to the zero address")
        })

        it("Cannot safeBatchTransferFrom to zero address", async () => {
            await expect(
                ocean.connect(alice).safeBatchTransferFrom(
                    alice.address,
                    ethers.constants.AddressZero,
                    [1],
                    [1],
                    []
                )
            ).to.be.revertedWith("transfer to the zero address")
        })

        it("Cannot safeTransferFrom amount not owned", async () => {
            await expect(
                ocean.connect(alice).safeTransferFrom(
                    alice.address,
                    bob.address,
                    1,
                    1,
                    []
                )
            ).to.be.revertedWith("insufficient balance")
        })

        it("Cannot safeBatchTransferFrom amount not owned", async () => {
            await expect(
                ocean.connect(alice).safeBatchTransferFrom(
                    alice.address,
                    bob.address,
                    [1],
                    [1],
                    []
                )
            ).to.be.revertedWith("insufficient balance")
        })
    })

    describe("ERC-1155 Permit Signature Extension", () => {
        it("Can derive TYPEHASH", async () => {
            const byteString = ethers.utils.toUtf8Bytes(
                'SetPermitForAll(address owner,address operator,bool approved,uint256 nonce,uint256 deadline)'
            )
            const SETPERMITFORALL_TYPEHASH = ethers.utils.keccak256(byteString)
            expect(
                await ocean.SETPERMITFORALL_TYPEHASH()
            ).to.equal(SETPERMITFORALL_TYPEHASH)
        })

        it("Can derive DOMAIN_SEPARATOR", async () => {
            const typesArray = ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address']
            const eip712String = ethers.utils.toUtf8Bytes(
                'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
            )
            const name = ethers.utils.toUtf8Bytes('shell-protocol-ocean')
            const version = ethers.utils.toUtf8Bytes('1')
            const k256 = ethers.utils.keccak256;

            const DOMAIN_SEPARATOR = k256(ethers.utils.defaultAbiCoder.encode(
                typesArray,
                [
                    k256(eip712String),
                    k256(name),
                    k256(version),
                    31337,
                    ocean.address
                ]
            ))
            expect(
                await ocean.DOMAIN_SEPARATOR()
            ).to.equal(DOMAIN_SEPARATOR)
        })

        it("Alice can sign permission for Bob, Bob can submit", async () => {
            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(false)

            const owner = alice.address
            const operator = bob.address
            const nonce = await ocean.approvalNonces(alice.address)
            const deadline = ethers.constants.MaxUint256
            const approved = true

            const { r, s, v } = ethers.utils.splitSignature(
                await alice._signTypedData(
                    {
                        name: 'shell-protocol-ocean',
                        version: '1',
                        chainId: 31337,
                        verifyingContract: ocean.address
                    },
                    {
                        SetPermitForAll: [
                            { name: 'owner', type: 'address' },
                            { name: 'operator', type: 'address' },
                            { name: 'approved', type: 'bool' },
                            { name: 'nonce', type: 'uint256' },
                            { name: 'deadline', type: 'uint256' }
                        ]
                    },
                    {
                        owner,
                        operator,
                        approved,
                        nonce,
                        deadline
                    }
                )
            )
            await expect(
                ocean.connect(bob).setPermitForAll(
                    alice.address,
                    bob.address,
                    true,
                    deadline,
                    v,
                    r,
                    s
                )
            ).to.emit(ocean, "ApprovalForAll").withArgs(alice.address, bob.address, true)
            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(true)
            await ocean.connect(alice).setApprovalForAll(bob.address, false)
        })

        it("Cannot submit a signature after the deadline", async () => {
            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(false)

            const owner = alice.address
            const operator = bob.address
            const nonce = await ocean.approvalNonces(alice.address)
            const deadline = 1000
            const approved = true

            const { r, s, v } = ethers.utils.splitSignature(
                await alice._signTypedData(
                    {
                        name: 'shell-protocol-ocean',
                        version: '1',
                        chainId: 31337,
                        verifyingContract: ocean.address
                    },
                    {
                        SetPermitForAll: [
                            { name: 'owner', type: 'address' },
                            { name: 'operator', type: 'address' },
                            { name: 'approved', type: 'bool' },
                            { name: 'nonce', type: 'uint256' },
                            { name: 'deadline', type: 'uint256' }
                        ]
                    },
                    {
                        owner,
                        operator,
                        approved,
                        nonce,
                        deadline
                    }
                )
            )
            await expect(
                ocean.connect(bob).setPermitForAll(
                    alice.address,
                    bob.address,
                    true,
                    deadline,
                    v,
                    r,
                    s
                )
            ).to.be.reverted;

            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(false)
        })

        it("Cannot sign a transaction for someone else", async () => {
            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(false)

            const owner = alice.address
            const operator = bob.address
            const nonce = await ocean.approvalNonces(alice.address)
            const deadline = ethers.constants.MaxUint256
            const approved = true

            const { r, s, v } = ethers.utils.splitSignature(
                await bob._signTypedData(
                    {
                        name: 'shell-protocol-ocean',
                        version: '1',
                        chainId: 31337,
                        verifyingContract: ocean.address
                    },
                    {
                        SetPermitForAll: [
                            { name: 'owner', type: 'address' },
                            { name: 'operator', type: 'address' },
                            { name: 'approved', type: 'bool' },
                            { name: 'nonce', type: 'uint256' },
                            { name: 'deadline', type: 'uint256' }
                        ]
                    },
                    {
                        owner,
                        operator,
                        approved,
                        nonce,
                        deadline
                    }
                )
            )
            await expect(
                ocean.connect(bob).setPermitForAll(
                    alice.address,
                    bob.address,
                    true,
                    deadline,
                    v,
                    r,
                    s
                )
            ).to.be.reverted;

            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(false)
        })

        it("Can't ECRECOVER address(0) and steal funds", async () => {
            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(false)

            const owner = alice.address
            const operator = bob.address
            const nonce = await ocean.approvalNonces(alice.address)
            const deadline = ethers.constants.MaxUint256
            const approved = true

            const { r, s, v } = ethers.utils.splitSignature(
                await alice._signTypedData(
                    {
                        name: 'shell-protocol-ocean',
                        version: '1',
                        chainId: 31337,
                        verifyingContract: ocean.address
                    },
                    {
                        SetPermitForAll: [
                            { name: 'owner', type: 'address' },
                            { name: 'operator', type: 'address' },
                            { name: 'approved', type: 'bool' },
                            { name: 'nonce', type: 'uint256' },
                            { name: 'deadline', type: 'uint256' }
                        ]
                    },
                    {
                        owner,
                        operator,
                        approved,
                        nonce,
                        deadline
                    }
                )
            )
            await expect(
                ocean.connect(bob).setPermitForAll(
                    alice.address,
                    bob.address,
                    true,
                    deadline,
                    29,
                    r,
                    s
                )
            ).to.be.reverted
            expect(
                await ocean.isApprovedForAll(alice.address, bob.address)
            ).to.equal(false)
        })

        it("Only owner can burn one way fuse", async () => {
            expect(await ocean.owner()).to.equal(bob.address)
            await expect(
                ocean.connect(alice).breakPermitFuse()
            ).to.be.revertedWith("Ownable: caller is not the owner")
        })

        it("Owner can burn one way fuse", async () => {
            await expect(
                ocean.connect(bob).breakPermitFuse()
            ).to.emit(ocean, "PermitFuseBroken").withArgs(bob.address)
        })

        it("Cannot submit a signature once the fuse is broken", async () => {
            await expect(
                ocean.connect(bob).setPermitForAll(
                    alice.address,
                    bob.address,
                    true,
                    ethers.constants.MaxUint256,
                    27,
                    ethers.constants.HashZero,
                    ethers.constants.HashZero
                )
            ).to.be.revertedWith("Permit Signature Disabled")
        })
    })
})
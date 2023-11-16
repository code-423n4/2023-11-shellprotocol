const { ethers } = require("hardhat")
const { expect } = require("chai")
const shellV2 = require("../../utils-js");

describe("Primitive Tests", () => {
    let ocean
    let alice
    let bob

    before("Deploy Ocean", async () => {
        [alice, bob] = await ethers.getSigners()
        const oceanContract = await ethers.getContractFactory("Ocean", bob)
        ocean = await oceanContract.deploy("")
    })

    it("Can create a new shell", async () => {
        const txData = await ocean.connect(alice).registerNewTokens(0, 1)
        const txReceipt = await txData.wait(1)
        const decodedData = txReceipt.events[0].decode(txReceipt.events[0].data)
        const newShell = ethers.utils.hexlify(decodedData.tokens[0])

        const expectedNewShell = shellV2.utils.calculateWrappedTokenId({
            address: alice.address,
            id: 0
        })
        expect(newShell).to.equal(expectedNewShell)
    })

    it("Can register 100 new Tokens", async () => {
        const currentNumber = 1
        const additional = 100
        const txData = await ocean.connect(alice)
            .registerNewTokens(currentNumber, additional)
        const txReceipt = await txData.wait(1)
        const decodedData = txReceipt.events[0].decode(txReceipt.events[0].data)
        const Tokens = decodedData.tokens.map((token) => ethers.utils.hexlify(token))

        Tokens.map((shell, index) => {
            const expectedToken = shellV2.utils.calculateWrappedTokenId({
                address: alice.address,
                id: currentNumber + index
            })
            expect(shell).to.equal(expectedToken)
        })
    })

    it("Can create shell with random nonce", async () => {
        const nonce = 1298401938
        const txData = await ocean.connect(alice)
            .registerNewTokens(1298401938, 1)
        const txReceipt = await txData.wait(1)
        const decodedData = txReceipt.events[0].decode(txReceipt.events[0].data)
        const shell = ethers.utils.hexlify(decodedData.tokens[0])
        const expectedShell = shellV2.utils.calculateWrappedTokenId({
            address: alice.address,
            id: nonce
        })

        expect(shell).to.equal(expectedShell)
    })
})
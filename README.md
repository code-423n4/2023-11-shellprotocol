# Repo setup

## ⭐️ Sponsor: Add code to this repo

- [ ] Create a PR to this repo with the below changes:
- [ ] Provide a self-contained repository with working commands that will build (at least) all in-scope contracts, and commands that will run tests producing gas reports for the relevant contracts.
- [ ] Make sure your code is thoroughly commented using the [NatSpec format](https://docs.soliditylang.org/en/v0.5.10/natspec-format.html#natspec-format).
- [ ] Please have final versions of contracts and documentation added/updated in this repo **no less than 48 business hours prior to audit start time.**
- [ ] Be prepared for a 🚨code freeze🚨 for the duration of the audit — important because it establishes a level playing field. We want to ensure everyone's looking at the same code, no matter when they look during the audit. (Note: this includes your own repo, since a PR can leak alpha to our wardens!)


---

## ⭐️ Sponsor: Edit this `README.md` file

- [ ] Modify the contents of this `README.md` file. Describe how your code is supposed to work with links to any relevent documentation and any other criteria/details that the C4 Wardens should keep in mind when reviewing. ([Here's a well-constructed example.](https://github.com/code-423n4/2022-08-foundation#readme))
- [ ] Review the Gas award pool amount. This can be adjusted up or down, based on your preference - just flag it for Code4rena staff so we can update the pool totals across all comms channels.
- [ ] Optional / nice to have: pre-record a high-level overview of your protocol (not just specific smart contract functions). This saves wardens a lot of time wading through documentation.
- [ ] [This checklist in Notion](https://code4rena.notion.site/Key-info-for-Code4rena-sponsors-f60764c4c4574bbf8e7a6dbd72cc49b4#0cafa01e6201462e9f78677a39e09746) provides some best practices for Code4rena audits.

## ⭐️ Sponsor: Final touches
- [ ] Review and confirm the details in the section titled "Scoping details" and alert Code4rena staff of any changes.
- [ ] Check that images and other files used in this README have been uploaded to the repo as a file and then linked in the README using absolute path (e.g. `https://github.com/code-423n4/yourrepo-url/filepath.png`)
- [ ] Ensure that *all* links and image/file paths in this README use absolute paths, not relative paths
- [ ] Check that all README information is in markdown format (HTML does not render on Code4rena.com)
- [ ] Remove any part of this template that's not relevant to the final version of the README (e.g. instructions in brackets and italic)
- [ ] Delete this checklist and all text above the line below when you're ready.

---

# Sponsorname audit details
- Total Prize Pool: $52,000 USDC
  - HM awards: $24,750 USDC
  - Analysis awards: $1,500 USDC
  - QA awards: $750 USDC
  - Bot Race awards: $2,250 USDC
  - Gas awards: $750 USDC
  - Judge awards: $3,600 USDC
  - Lookout awards: $2,400 USDC
  - Scout awards: $500 USDC
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2023-11-shellprotocol/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts November 20, 2023 20:00 UTC
- Starts November 30, 2023 20:00 UTC

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://github.com/code-423n4/YYYY-MM-contest-candidate/blob/main/4naly3er-report.md).

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

* Deploying an adapter with invalid parameters
* Integrating with a malicious primitive may result in harmful behavior due to lack of re-entrancy checks
* external contract risk (curve in this case) 


# Overview

# Shell v3
Shell v3 improves upon the fundamentals developed in Shell v2, which you can learn more about [here](https://wiki.shellprotocol.io/how-shell-works/the-ocean-accounting-hub) & [here](https://github.com/Shell-Protocol/Shell-Protocol#the-ocean), we highly recommmend to go through these resources before diving into the v3 improvements.

The goal of Shell v3 is to make the Ocean compatible with external protocols through the use of adapter primitives.

## V3 Updates
### The Ocean
- Removed reentrancy guards for `doInteraction` and `doMultipleInteraction` methods so that adapter primitives may wrap/unwrap tokens to be used with external protocols.

- `doInteraction` has been updated to enable wrapping Ether.

- Refactored the order in which a primitive's balances are updated. Previously, both mints and burns would occur after the primitive had performed its computation in `computeOutputAmount` or `computeInputAmount`. Now, the primitive's balances will be minted the input token or burned the output token before performing the computation step, and then will burn the output token or mint the input token based on the result.

### Liquidity Pools
- [LiquidityPoolProxy.sol](/src/proteus/LiquidityPoolProxy.sol) was refactored to account for the changes in the Ocean updates the primitive's balances. After calling `_getBalances()`, the pool will adjust the values appropriately.

### Adapter Primitives
- Introducing [OceanAdapter.sol](/src/adapters/OceanAdapter.sol), a generalized adapter interface for adapter primitives.
- Demonstrated implementation in two examples, [Curve2PoolAdapter.sol](/src/adapters/Curve2PoolAdapter.sol) and [CurveTricryptoAdapter.sol](/src/adapters/CurveTricryptoAdapter.sol).

## Invariants

The following Ocean invariants should never be violated under any circumstances:
* A user's balances should only move with their permission
    - they are `msg.sender`
    - they've set approval for `msg.sender`
    - they are a contract that was the target of a ComputeInput/Output, and they did not revert the transaction
* Fees should be credited to the Ocean owner's ERC-1155 balance
* Calls to the Ocean cannot cause the Ocean to make external transfers unless a
`doInteraction`/`doMultipleInteractions` function is called and a `wrap` or `unwrap` interaction is provided.
* The way the Ocean calculates wrapped token IDs is correct
* Calls to the Ocean cannot cause it to mint a token without first calling the contract used to calculate its token ID.
* The Ocean should conform to all standards that its code claims to (ERC-1155, ERC-165)
    - EXCEPTION: The Ocean omits the safeTransfer callback during the mint that occurs after a ComputeInput/ComputeOutput.  The contract receiving the transfer was called just before the mint, and should revert the transaction if it does not want to receive the token.
* The Ocean does not support rebasing tokens, fee on transfer tokens
* The Ocean ERC-1155 transfer functions are secure and protected with reentrancy checks
* During any do* call, the Ocean accurately tracks balances of the tokens involved throughout the transaction.
* The Ocean does not provide any guarantees against the underlying token blacklisting the Ocean or any sort of other non-standard behavior


## Security

Currently, we use [Slither](https://github.com/crytic/slither) to help identify well-known issues via static analysis. Other tools may be added in the near future as part of the continuous improvement process.

### Static Analysis

To run the analysis
```shell
slither . --filter-path "mock|openzeppelin|auth|test|lib|scripts|abdk-libraries-solidity|proteus" --foundry-compile-all

```

### Installation

Run `git clone https://github.com/code-423n4/2023-11-shellprotocol.git` & then run `yarn install`

### Testing
Hardhat tests are located [here](https://github.com/code-423n4/2023-11-shellprotocol/tree/main/test), which include tests for the Ocean, Shell native primitives, and code coverage analysis. Foundry tests for the adapter are located [here](https://github.com/code-423n4/2023-11-shellprotocol/tree/main/src/test/fork), which include fuzz tests for the Curve adapters.

To compile the contracts
```shell
forge build
```

To run Hardhat tests
```shell
npx hardhat test
```

To run Foundry tests
```shell
forge test
```

To run coverage for Hardhat tests
```shell
yarn coverage
```

To run coverage for Foundry tests
```shell
forge coverage
```

For coverage for the [Ocean Contract](/src/Ocean/Ocean.sol), run `yarn coverage`
For coverage for the [Adapter Contracts](/src/adapters/OceanAdapter.sol), run `forge coverage`



## Links
- **Previous audits:** https://wiki.shellprotocol.io/getting-started/security-and-bounties#audits
- **Website** : https://shellprotocol.io/
- **Documentation** : https://wiki.shellprotocol.io/getting-started/overview
- **Twitter** : https://twitter.com/CowriLabs
- **Discord** : https://discord.com/invite/S5EU5zmqxP


# Scope

*List all files in scope in the table below (along with hyperlinks) -- and feel free to add notes here to emphasize areas of focus.*

| Contract | SLOC | Purpose | Libraries used |  
| ----------- | ----------- | ----------- | ----------- |
| [Ocean.sol](/src/Ocean/Ocean.sol) | 561 | The accounting engine of the shell protocol | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |
| [Curve2PoolAdapter.sol](/src/adapters/Curve2PoolAdapter.sol) | 139 | Adapter that enables integration with the curve 2 pool | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |
| [CurveTricryptoAdapter.sol](/src/adapters/CurveTricryptoAdapter.sol) | 199 | Adapter that enables integration with the curve tricrypto pool | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |
| [OceanAdapter.sol](/src/adapters/OceanAdapter.sol) | 94 | Helper contract for the adapters | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |

## Out of scope

All the contracts not mentioned in scope including all test files

# Additional Context

- [ ] Describe any novel or unique curve logic or mathematical models implemented in the contracts
- [ ] Please list specific ERC20 that your protocol is anticipated to interact with. Could be "any" (literally anything, fee on transfer tokens, ERC777 tokens and so forth) or a list of tokens you envision using on launch.
- [ ] Please list specific ERC721 that your protocol is anticipated to interact with.
- [ ] Which blockchains will this code be deployed to, and are considered in scope for this audit?
- [ ] Please list all trusted roles (e.g. operators, slashers, pausers, etc.), the privileges they hold, and any conditions under which privilege escalation is expected/allowable
- [ ] In the event of a DOS, could you outline a minimum duration after which you would consider a finding to be valid? This question is asked in the context of most systems' capacity to handle DoS attacks gracefully for a certain period.
- [ ] Is any part of your implementation intended to conform to any EIP's? If yes, please list the contracts in this format: 
  - `Contract1`: Should comply with `ERC/EIPX`
  - `Contract2`: Should comply with `ERC/EIPY`

## Attack ideas (Where to look for bugs)
* Breaking any invariants listed above in the Ocean Contract
* Detection of any malicious behaviour with the curve adapter contracts in scope

## Scoping Details 
[ ⭐️ SPONSORS: please confirm/edit the information below. ]

```
- If you have a public code repo, please share it here: Private repo 
- How many contracts are in scope?: 3  
- Total SLoC for these contracts?: 993  
- How many external imports are there?: 1  
- How many separate interfaces and struct definitions are there for the contracts within scope?: 5  
- Does most of your code generally use composition or inheritance?: Composition  
- How many external calls?: 6   
- What is the overall line coverage percentage provided by your tests?: 98
- Is this an upgrade of an existing system?: False
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): Timelock function, AMM
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?:   
- Please describe required context: True - details mentioned here https://github.com/Shell-Protocol/Shell-Protocol#what-is-the-ocean   
- Does it use an oracle?: No
- Describe any novel or unique curve logic or mathematical models your code uses: 
- Is this either a fork of or an alternate implementation of another project?: False  
- Does it use a side-chain?: no
- Describe any specific areas you would like addressed: not really all 3 contracts are important
```

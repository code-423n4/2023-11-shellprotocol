# Shell Protocol audit details
- Total Prize Pool: $36,500 USDC
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
- Starts November 28, 2023 20:00 UTC

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/4naly3er-report.md).

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-11-shellprotocol/blob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

[ ⭐️ SPONSORS: Are there any known issues or risks deemed acceptable that shouldn't lead to a valid finding? If so, list them here. ]


# Overview

[ ⭐️ SPONSORS: add info here ]

## Links

- **Previous audits:** 
- **Documentation:**
- **Website:**
- **Twitter:** 
- **Discord:** 


# Scope

[ ⭐️ SPONSORS: add scoping and technical details here ]

- [ ] In the table format shown below, provide the name of each contract and:
  - [ ] source lines of code (excluding blank lines and comments) in each *For line of code counts, we recommend running prettier with a 100-character line length, and using [cloc](https://github.com/AlDanial/cloc).* 
  - [ ] external contracts called in each
  - [ ] libraries used in each

*List all files in scope in the table below (along with hyperlinks) -- and feel free to add notes here to emphasize areas of focus.*

| Contract | SLOC | Purpose | Libraries used |  
| ----------- | ----------- | ----------- | ----------- |
| [contracts/folder/sample.sol](https://github.com/code-423n4/repo-name/blob/contracts/folder/sample.sol) | 123 | This contract does XYZ | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |

## Out of scope

*List any files/contracts that are out of scope for this audit.*

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
*List specific areas to address - see [this blog post](https://medium.com/code4rena/the-security-council-elections-within-the-arbitrum-dao-a-comprehensive-guide-aa6d001aae60#9adb) for an example*

## Main invariants
*Describe the project's main invariants (properties that should NEVER EVER be broken).*

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
- Does it use a side-chain?:
- Describe any specific areas you would like addressed:
```

# Tests

*Provide every step required to build the project from a fresh git clone, as well as steps to run the tests with a gas report.* 

*Note: Many wardens run Slither as a first pass for testing.  Please document any known errors with no workaround.* 

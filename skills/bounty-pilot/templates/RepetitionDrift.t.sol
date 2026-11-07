// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Repetition-drift PoC. Use this for a `rounding-map` row (favors_user + repeatable) or any step
// whose single-call error is a wei: the bug is direction x repeatability, so the evidence is the
// drift after N repetitions MINUS what those N repetitions cost. Run it inside a DISPOSABLE
// copy/worktree of the target at the recorded commit (see templates/README.md).
//
//   REPS=65 forge test --match-path test/RepetitionDrift.t.sol -vvv
//
// An iteration that reverts ends the loop and is logged as `reps completed` < requested: on the
// candidate that bounds the profit you can claim; on the control it is the protection holding.
//
// CONVENTION (templates/README.md): both tests are expected to exit 0 (pass).
//   - test_candidate passes IFF repeating the micro-operation leaves the attacker with a profit
//     after every cost (fees, the rounding the protocol keeps, flash-loan premium; gas is
//     accounted separately below, in base units of the profit asset).
//   - test_control passes IFF the same loop yields NO profit on the control path: the documented
//     minimum amount, or the rounding direction fixed in a copy (record which one you used).
//
// A passing candidate proves ONLY its assertions: that this loop, at this state, with these
// amounts, moved the measured quantity. It does not prove reachability on the deployed revision,
// that the state is reachable by an unprivileged actor, or that the amounts fit real liquidity.
//
// Template is skeleton-only: every <placeholder> and TODO must be filled; no real target address
// is hardcoded here, and none belongs in it - read addresses and the RPC URL from the environment.

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {<Target>} from "<relative path into the unmodified target repo>";

contract RepetitionDriftPoC is Test {
    <Target> internal target;
    IERC20 internal asset;

    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");

    // Repetitions per run. Balancer v2 (Nov 2025) needed 65 micro steps in one batchSwap; start
    // from the smallest N that the per-iteration drift you derived by hand says should profit.
    uint256 internal constant DEFAULT_REPS = 100;
    // The micro amount each iteration moves. Pick it where the rounding error is LARGEST relative
    // to the amount (often 1 wei, or the amount that makes the quotient just below an integer).
    uint256 internal constant MICRO = 1; // TODO
    // The protocol's documented minimum (e.g. MIN_DEPOSIT); the control loops at this amount.
    uint256 internal constant DOCUMENTED_MIN = 0; // TODO: quote the line that sets it
    // Gas priced into the profit asset, base units per gas. Leave 0 only if you argue it below.
    uint256 internal constant GAS_PRICE_IN_ASSET = 0; // TODO

    function setUp() public {
        // EITHER fork at a pinned block (address and RPC from env; never hardcode either) ...
        // vm.createSelectFork(vm.envString("RPC_URL"), vm.envUint("FORK_BLOCK"));
        // target = <Target>(vm.envAddress("TARGET"));
        // asset = IERC20(vm.envAddress("ASSET"));
        // ... OR deploy the unmodified contracts locally from the project's deploy script.
        // target = new <Target>(<constructor arguments>);
        // TODO: build the state the row needs (an empty market, an existing victim position,
        // a donation) through ordinary calls, then fund the attacker with what it would really
        // hold or flash-borrow.
        // deal(address(asset), attacker, <attacker capital>);
        revert("fill in setUp");
    }

    function _reps() internal view returns (uint256) {
        return vm.envOr("REPS", DEFAULT_REPS);
    }

    /// One micro-operation as the attacker: the single call whose rounding favours the caller,
    /// e.g. withdraw(MICRO) burning floor(shares), or one GIVEN_OUT swap step.
    function _once(uint256 amount) internal {
        amount; // TODO: target.<operation>(amount, attacker, attacker);
        revert("fill in _once");
    }

    /// The quantity the rounding should move. Pick the one the protocol must keep monotone:
    /// share price (totalAssets * 1e18 / totalSupply), pool invariant D, an accumulator/index.
    function _measured() internal view returns (uint256) {
        // TODO: return target.totalAssets() * 1e18 / target.totalSupply();
        return 0;
    }

    /// Attacker's net position in base units of ONE asset, so profit has a single unit.
    function _attackerValue() internal view returns (uint256) {
        // TODO: asset balance + redeemable value of any shares/LP the attacker still holds, e.g.
        // asset.balanceOf(attacker) + target.previewRedeem(target.balanceOf(attacker)).
        // Counting the asset balance alone books a withdrawal of the attacker's own deposit as
        // profit, so there is deliberately no default here.
        revert("fill in _attackerValue");
    }

    /// One iteration as the attacker, called through `this` so a revert ends the loop instead of
    /// failing the test: on the control path the protection usually holds by reverting (the
    /// attacker runs out of shares, a minimum check fires), and that is "no profit", not an error.
    function onceAsAttacker(uint256 amount) external {
        require(msg.sender == address(this), "self only");
        vm.startPrank(attacker);
        _once(amount);
        vm.stopPrank();
    }

    function _loop(uint256 amount) internal returns (int256 profit, uint256 gasUsed) {
        uint256 valueBefore = _attackerValue();
        uint256 measuredBefore = _measured();
        uint256 reps = _reps();
        uint256 done;
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < reps; i++) {
            try this.onceAsAttacker(amount) {
                done++;
            } catch {
                break;
            }
        }
        gasUsed = g0 - gasleft();
        // TODO: unwind as the attacker - redeem remaining shares, repay any flash loan plus its
        // premium - e.g. vm.startPrank(attacker); ...; vm.stopPrank();
        uint256 valueAfter = _attackerValue();
        uint256 measuredAfter = _measured();
        console2.log("reps requested", reps);
        console2.log("reps completed", done);
        console2.log("measured before", measuredBefore);
        console2.log("measured after ", measuredAfter);
        console2.log("attacker value before", valueBefore);
        console2.log("attacker value after ", valueAfter);
        console2.log("gas used", gasUsed);
        profit = int256(valueAfter) - int256(valueBefore) - int256(gasUsed * GAS_PRICE_IN_ASSET);
    }

    /// CANDIDATE: passes IFF the repeated micro-operation profits after costs.
    function test_candidate_repetitionProfitsAfterCosts() public {
        (int256 profit,) = _loop(MICRO);
        console2.log("net profit (base units)");
        console2.logInt(profit);
        assertGt(profit, 0, "repeating the favourable rounding must leave the attacker ahead");
        // TODO (optional, stronger): assert the measured quantity moved against other holders,
        // e.g. assertLt(_measured(), <before>, "share price fell for every other holder").
    }

    /// NEGATIVE CONTROL: passes IFF the same loop does NOT profit on the control path - at the
    /// documented minimum amount, or against a copy with the rounding direction fixed. If this
    /// fails too, the harness is measuring something other than the rounding.
    function test_control_noProfitAtMinimumOrFixedRounding() public {
        (int256 profit,) = _loop(DOCUMENTED_MIN > MICRO ? DOCUMENTED_MIN : MICRO);
        assertLe(profit, 0, "at the minimum (or with rounding fixed) the loop must not profit");
    }
}

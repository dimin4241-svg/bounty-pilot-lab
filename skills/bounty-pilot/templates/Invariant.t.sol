// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Invariant PoC. Use this when you believe a property must always hold but cannot name the exact
// sequence that breaks it. The fuzzer finds the sequence; the counterexample it prints IS the PoC.
// Run it inside a DISPOSABLE copy/worktree of the target (see templates/README.md).
//
//   forge test --match-path test/Invariant.t.sol -vvv
//
// Keep `fail_on_revert = true`: a handler whose calls revert is testing nothing. That is ONLY
// coherent if the handler sets up each call so it cannot revert for a boring reason — it funds and
// approves the actors, and bounds every amount to what the actor can actually supply. The two go
// together: fund + approve + bound(), then fail_on_revert = true.
//
// If the project already has an invariant suite, extend it rather than starting over, and say which
// invariant you added. For Echidna/Medusa suites, pashov's `fizz` skill generates a full harness;
// a broken invariant from a generated suite is the same quality of evidence as this.

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {<Target>} from "<relative path into the unmodified target repo>";

/// @dev The handler is what makes this honest: it exposes ONLY the calls an unprivileged actor can
///      make, with inputs clamped to values that actor could really supply, and it funds+approves
///      those actors so a call never reverts for lack of balance. A handler that calls admin
///      functions, or that reverts on its own setup, proves nothing about an attacker.
contract Handler is Test {
    <Target> public target;
    IERC20 internal token;
    address[] internal actors;

    // Ghost variables: the fuzzer-independent running totals the invariant is recomputed against.
    uint256 public ghost_depositedSum;
    uint256 public ghost_withdrawnSum;

    constructor(<Target> target_, IERC20 token_) {
        target = target_;
        token = token_;
        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
        // Fund and approve every actor once, so deposits cannot revert for lack of funds/allowance.
        for (uint256 i = 0; i < actors.length; i++) {
            deal(address(token), actors[i], 1e30);
            vm.prank(actors[i]);
            token.approve(address(target), type(uint256).max);
        }
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }

    function deposit(uint256 actorSeed, uint256 amount) external {
        address actor = _actor(actorSeed);
        // Bound to what this actor actually holds: a rejected input is a lost fuzz run.
        amount = bound(amount, 1, token.balanceOf(actor));
        vm.startPrank(actor);
        target.<deposit>(amount);
        vm.stopPrank();
        ghost_depositedSum += amount;
    }

    function withdraw(uint256 actorSeed, uint256 amount) external {
        address actor = _actor(actorSeed);
        // Bound to the actor's redeemable balance inside the target, so this never reverts
        // for an uninteresting reason and fail_on_revert can stay true.
        amount = bound(amount, 0, target.<balanceOf>(actor));
        vm.startPrank(actor);
        target.<withdraw>(amount);
        vm.stopPrank();
        ghost_withdrawnSum += amount;
    }

    // Add one function per unprivileged entry point. The invariant can only break through a call
    // the handler exposes, so a missing entry point is a missing bug.
}

contract InvariantPoC is StdInvariant, Test {
    <Target> target;
    IERC20 token;
    Handler handler;

    function setUp() public {
        token = IERC20(<address of the deploy token, or a deployed mock ERC20>);
        target = new <Target>(<arguments from the project's deploy script>);
        handler = new Handler(target, token);
        targetContract(address(handler));
    }

    /// The property, in words: <state it here, e.g. "the sum of per-user debt equals totalDebt">
    function invariant_<property>() public view {
        assertEq(target.<aggregate>(), <recomputed from first principles / ghost vars>,
            "<the property, in words, so the counterexample is readable>");
    }

    /// Solvency-shaped properties are the highest-value ones: assets held must cover liabilities
    /// recorded, always, after any sequence.
    function invariant_solvency() public view {
        assertGe(token.balanceOf(address(target)),
            handler.ghost_depositedSum() - handler.ghost_withdrawnSum(),
            "assets held must never fall below net deposits recorded");
    }
}

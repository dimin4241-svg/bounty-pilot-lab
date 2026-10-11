// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fork PoC against a DEPLOYED protocol, run inside a DISPOSABLE copy/worktree of the
// target at the recorded commit (see templates/README.md) so --match-path can find it
// without touching the user's working tree.
//   forge test --match-path test/ForkPoC.t.sol -vvvv
// Pin the block. An unpinned fork test is not reproducible evidence.
//
// CONVENTION (templates/README.md): both tests are expected to exit 0 (pass).
//   - The CANDIDATE passes IFF the vulnerability is demonstrated: it asserts the attacker's
//     gain, the broken invariant, or the wrong resulting state.
//   - The CONTROL passes IFF the protection holds on the control path.
//
// The RPC endpoint is read from an environment variable. With scenario_runner.py, name that
// variable in the plan/case `pass_env` list so only it is copied into the test environment
// (its value is redacted from captured output); never hardcode an RPC key here.
//
// Fill every <...> and delete the guidance comments before attaching this to a report.

import {Test, console2} from "forge-std/Test.sol";

interface ITarget {
    // Only the functions the PoC calls. Do not copy the implementation in —
    // the point of a fork test is that the deployed implementation is used.
    function <stateReader>() external view returns (uint256);
    function <attackEntryPoint>(uint256 amount) external;
}

contract ForkPoC is Test {
    // ---- pinned environment -------------------------------------------------
    uint256 constant FORK_BLOCK = <block number>;          // the block this was observed at
    string  constant RPC_ENV    = "<RPC_ENV_VAR>";          // name it in pass_env, never hardcode a key

    ITarget constant TARGET = ITarget(<0xdeployed address>);
    address constant VICTIM = <0x... an address that already holds the position at risk>;

    address attacker = makeAddr("attacker");                // no private keys anywhere

    function setUp() public {
        vm.createSelectFork(vm.envString(RPC_ENV), FORK_BLOCK);
        vm.label(address(TARGET), "target");
        // Fund the attacker only with what the attack genuinely needs, and say what that is.
        deal(attacker, <capital the attacker must supply> ether);
    }

    // ---- the finding (PASSES when the bug is real) --------------------------
    function test_candidate_<property>() public {
        uint256 attackerBefore = attacker.balance;
        uint256 stateBefore = TARGET.<stateReader>();
        console2.log("state before", stateBefore);

        vm.startPrank(attacker);
        TARGET.<attackEntryPoint>(<attacker-chosen value>);
        vm.stopPrank();

        uint256 stateAfter = TARGET.<stateReader>();
        console2.log("state after", stateAfter);
        console2.log("attacker net", int256(attacker.balance) - int256(attackerBefore));

        // Assert the VULNERABILITY: the attacker gained, or the invariant broke. Name it in
        // the message. This test must PASS only because the bug exists.
        assertGt(attacker.balance, attackerBefore,
            "<the attacker extracted value they should not have been able to>");
    }

    // ---- negative control (PASSES when the protection holds) ----------------
    // Same sequence with the one attacker capability removed (or against the patched code).
    // This is what tells a reviewer the harness is not the finding.
    function test_control_<property>() public {
        uint256 stateBefore = TARGET.<stateReader>();

        vm.startPrank(attacker);
        TARGET.<attackEntryPoint>(<the benign value / the legitimate path>);
        vm.stopPrank();

        // On the control path the protection holds: state moves only by the legitimate amount.
        assertEq(TARGET.<stateReader>(), stateBefore + <the expected legitimate change>,
            "control: the same path behaves correctly without the attacker capability");
    }
}

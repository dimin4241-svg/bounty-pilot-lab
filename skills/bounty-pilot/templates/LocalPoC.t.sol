// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Local PoC: the production contracts are deployed into a clean chain and driven into the
// vulnerable state through ordinary calls. Use this when the target is not deployed, or when the
// state you need cannot be reached on a fork. Run it inside a DISPOSABLE copy/worktree of the
// target at the recorded commit (see templates/README.md), never the user's working tree.
//
//   forge test --match-path test/LocalPoC.t.sol -vvvv
//
// CONVENTION (templates/README.md): both tests are expected to exit 0 (pass).
//   - The CANDIDATE passes IFF the vulnerability is demonstrated (assert the broken invariant /
//     the wrong resulting state / the attacker's gain).
//   - The CONTROL passes IFF the protection holds on the legitimate path.
//
// RULE: import the real contracts. Every mock you substitute weakens the evidence, and a mock that
// replaces the component under test destroys it. Where a mock is unavoidable, make it behave like
// the real dependency (including its failure modes) and record it as a limitation in the record.

import {Test, console2} from "forge-std/Test.sol";
import {<Target>} from "<relative path into the unmodified target repo>";

contract LocalPoC is Test {
    <Target> target;

    address admin    = makeAddr("admin");
    address victim   = makeAddr("victim");
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Deploy the way the project's own deploy script deploys it — read that script.
        // Wrong constructor arguments produce a PoC of a configuration nobody runs.
        vm.prank(admin);
        target = new <Target>(<arguments taken from the project's deploy script>);

        // Reach the realistic starting state through the protocol's own entry points.
        // Never write storage directly to set up the bug: vm.store makes the state unreachable,
        // and an unreachable state is the first thing triage rejects.
        vm.startPrank(victim);
        // ... ordinary user actions ...
        vm.stopPrank();
    }

    // ---- the finding (PASSES when the bug is real) --------------------------
    function test_candidate_<property>() public {
        uint256 before = target.<aggregate>();
        console2.log("aggregate before", before);

        vm.prank(attacker);
        target.<entryPoint>(<attacker-chosen value>);

        uint256 observed = target.<aggregate>();
        console2.log("aggregate after", observed);

        // Assert the INVARIANT IS BROKEN: this must PASS only because the bug exists.
        // e.g. totalDebt failed to fall by the amount redeemed, so it now overstates liabilities.
        assertEq(observed, <the wrong value the buggy code produces>,
            "<name the invariant in words: 'totalDebt did not fall by the amount redeemed'>");
    }

    // ---- negative control (PASSES when the protection holds) ----------------
    function test_control_<property>() public {
        // The same sequence through the sibling path that DOES maintain the invariant, proving the
        // mechanism is the specific omission you claim and not the harness.
        uint256 before = target.<aggregate>();
        vm.prank(victim);
        target.<theSiblingEntryPointThatIsCorrect>(<equivalent value>);
        assertEq(target.<aggregate>(), <the correct value, computed from `before`>,
            "control: the sibling path maintains the invariant");
    }
}

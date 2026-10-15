// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../src/Witness.sol";

contract WitnessTest {
    function test_candidate_replay() public {
        Witness target = new Witness();
        target.issue(10);
        target.unsafeClaim(10);
        target.unsafeClaim(10);
        assert(target.credit(address(this)) == 10);
    }

    function test_negative_control_consumes_credit() public {
        Witness target = new Witness();
        target.issue(10);
        target.safeClaim(10);
        assert(target.protectedCredit(address(this)) == 0);
        (bool ok,) = address(target).call(abi.encodeWithSelector(target.safeClaim.selector, 10));
        assert(!ok);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Local synthetic controls for ambiguous tuple framing. These tests do not
// exercise a production contract or prove a historical vulnerability.
contract SemanticIdentityTest {
    function test_packed_dynamic_collision_candidate() public pure {
        bytes memory left = abi.encodePacked(bytes("a"), bytes("bc"));
        bytes memory right = abi.encodePacked(bytes("ab"), bytes("c"));
        require(keccak256(left) == keccak256(right), "expected raw packed collision");
    }

    function test_framed_control_preserves_tuple_boundary() public pure {
        bytes memory left = abi.encode(bytes("a"), bytes("bc"));
        bytes memory right = abi.encode(bytes("ab"), bytes("c"));
        require(keccak256(left) != keccak256(right), "length framing must distinguish tuples");
    }
}

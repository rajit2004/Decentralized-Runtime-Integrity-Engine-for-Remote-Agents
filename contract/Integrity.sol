// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Integrity — tamper-evident diary for remote agents (Track 1.6)
/// @notice Chain proves TIMELINE. Baseline (off-chain, with Boss) proves GOODNESS.
/// Verifier must check H_re==H_chain AND H_re==H_base. See docs/VERIFICATION_LOGIC.md.
contract Integrity {
    struct Record {
        bytes32 hComb;
        uint64 ts;
        bytes sig;
        uint64 nonce;
    }

    mapping(string => Record) public latest;
    mapping(string => uint256) public anchorCount;

    event Anchored(string indexed agentId, bytes32 hComb, uint64 ts, uint64 nonce);
    event Enrolled(string indexed agentId, bytes32 hBase, uint64 ts);

    /// @dev Genesis enrollment anchor (cycle 0). Called once in trusted Phase 0.
    function enroll(string calldata agentId, bytes32 hBase) external {
        require(anchorCount[agentId] == 0, "already enrolled");
        latest[agentId] = Record(hBase, uint64(block.timestamp), "", 0);
        anchorCount[agentId] = 1;
        emit Enrolled(agentId, hBase, uint64(block.timestamp));
    }

    function anchor(string calldata agentId, bytes32 hComb, uint64 nonce, bytes calldata sig) external {
        require(anchorCount[agentId] > 0, "not enrolled");
        latest[agentId] = Record(hComb, uint64(block.timestamp), sig, nonce);
        anchorCount[agentId] += 1;
        emit Anchored(agentId, hComb, uint64(block.timestamp), nonce);
    }

    function getLatest(string calldata agentId) external view returns (bytes32, uint64, bytes memory, uint64) {
        Record storage r = latest[agentId];
        return (r.hComb, r.ts, r.sig, r.nonce);
    }
}

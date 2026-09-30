// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Integrity — tamper-evident diary (Track 1.6, frozen contract)
/// @notice Signed payload (UTF-8 pipe): agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash
/// hComb = SHA256(raw32(hBin)||raw32(hCfg)||raw32(hMem)). Chain=timeline, baseline=goodness.
contract Integrity {
    struct Record {
        bytes32 hBin;
        bytes32 hCfg;
        bytes32 hMem;
        bytes32 hComb;
        bytes32 prevHash;
        uint64 seq;
        uint64 ts;
        bytes sig;
    }

    mapping(string => Record) public latest;
    mapping(string => uint256) public anchorCount;

    event Enrolled(string indexed agentId, bytes32 hComb, uint64 ts);
    event Anchored(string indexed agentId, uint64 seq, bytes32 hComb, bytes32 prevHash, uint64 ts);

    function enroll(string calldata agentId, bytes32 hBin, bytes32 hCfg, bytes32 hMem, bytes32 hComb) external {
        require(anchorCount[agentId] == 0, "already enrolled");
        latest[agentId] = Record(hBin, hCfg, hMem, hComb, bytes32(0), 0, uint64(block.timestamp), "");
        anchorCount[agentId] = 1;
        emit Enrolled(agentId, hComb, uint64(block.timestamp));
    }

    function anchor(string calldata agentId, uint64 seq, bytes32 hBin, bytes32 hCfg, bytes32 hMem,
        bytes32 hComb, bytes32 prevHash, bytes calldata sig) external {
        require(anchorCount[agentId] > 0, "not enrolled");
        Record storage r = latest[agentId];
        require(prevHash == r.hComb || r.hComb == bytes32(0), "prevHash break");
        latest[agentId] = Record(hBin, hCfg, hMem, hComb, prevHash, seq, uint64(block.timestamp), sig);
        anchorCount[agentId] += 1;
        emit Anchored(agentId, seq, hComb, prevHash, uint64(block.timestamp));
    }

    function getLatest(string calldata agentId) external view returns (Record memory) {
        return latest[agentId];
    }
}

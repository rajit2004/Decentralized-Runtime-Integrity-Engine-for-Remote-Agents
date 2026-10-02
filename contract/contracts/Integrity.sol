// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Integrity — tamper-evident diary (Track 1.6, frozen contract)
/// @notice Signed payload (UTF-8 pipe): agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash
/// hComb = SHA256(raw32(hBin)||raw32(hCfg)||raw32(hMem)). Chain=timeline, baseline=goodness.
/// @notice Ed25519 is verified OFF-CHAIN by the Boss (EVM has no native Ed25519).
/// @notice History lives in Anchored events (event log); mapping holds latest only.
/// @notice Freshness uses block.timestamp (authoritative), not Checker ts.
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

    mapping(bytes32 => Record) private records;
    mapping(bytes32 => address) public ownerOf;
    mapping(bytes32 => uint256) public anchorCount;

    event Enrolled(bytes32 indexed agentIdHash, string agentId, bytes32 hComb, uint64 ts);
    event Anchored(bytes32 indexed agentIdHash, string agentId, uint64 seq, bytes32 hComb, bytes32 prevHash, uint64 ts);

    function agentKey(string calldata agentId) public pure returns (bytes32) {
        return keccak256(bytes(agentId));
    }

    function enroll(string calldata agentId, bytes32 hBin, bytes32 hCfg, bytes32 hMem, bytes32 hComb) external {
        bytes32 k = agentKey(agentId);
        require(anchorCount[k] == 0, "already enrolled");
        ownerOf[k] = msg.sender;
        records[k] = Record(hBin, hCfg, hMem, hComb, bytes32(0), 0, uint64(block.timestamp), "");
        anchorCount[k] = 1;
        emit Enrolled(k, agentId, hComb, uint64(block.timestamp));
    }

    function anchor(string calldata agentId, uint64 seq, bytes32 hBin, bytes32 hCfg, bytes32 hMem,
        bytes32 hComb, bytes32 prevHash, bytes calldata sig) external {
        bytes32 k = agentKey(agentId);
        require(anchorCount[k] > 0, "not enrolled");
        require(msg.sender == ownerOf[k], "not owner");
        Record storage r = records[k];
        require(prevHash == r.hComb || r.hComb == bytes32(0), "prevHash break");
        records[k] = Record(hBin, hCfg, hMem, hComb, prevHash, seq, uint64(block.timestamp), sig);
        anchorCount[k] += 1;
        emit Anchored(k, agentId, seq, hComb, prevHash, uint64(block.timestamp));
    }

    function getLatest(string calldata agentId) external view returns (Record memory) {
        return records[agentKey(agentId)];
    }
}

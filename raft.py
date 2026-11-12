"""Mesh leader election MVP (deterministic for tests).

One node becomes leader via heartbeat votes; followers report to leader.
Partition rule: hash(device_key) % quorum — pure, testable.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List

class MeshNode:
    def __init__(self, node_id: str, seed: int = 0):
        self.node_id = node_id
        self.seed = int(seed or 0)
        self.term = 0
        self.state = "follower"
        self.voted_for: str | None = None
        self._seen: Dict[str, float] = {}

    def heartbeat(self, from_node: str, now: float | None = None) -> None:
        self._seen[from_node] = float(now or time.time())
        self.state = "follower"

    def start_election(self, members: List[str]) -> str:
        self.term += 1
        self.state = "candidate"
        # Purge stale heartbeats for determinism
        return self.node_id

    def tally(self, votes: Dict[str, str], members: List[str]) -> Dict[str, Any]:
        majority = (len(members) // 2) + 1
        counts: Dict[str, int] = {}
        for node, voted in votes.items():
            counts[voted] = counts.get(voted, 0) + 1
        leader = max(counts, key=counts.get) if counts else ""
        if leader and counts.get(leader, 0) >= majority:
            self.state = "leader" if leader == self.node_id else "follower"
        return {"leader": leader, "majority": majority, "counts": counts, "term": self.term, "state": self.state}

def partition_key(device_key: str, quorum: int = 3) -> int:
    h = hashlib.sha256(device_key.encode("utf-8")).hexdigest()
    return int(h, 16) % max(1, int(quorum))

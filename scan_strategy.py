"""Adaptive scan-strategy tuner (UCB1 bandit over prober arms).

Each arm is a probe strategy (channel dwell + prober enablement profile).
Reward = Δ confirmed identities / wall-second. Exploration via UCB1.
Pure math — no I/O — so it is fully unit-testable.
"""
from __future__ import annotations

import math
from typing import Dict, List

ARMS = [
    "stealth_light",
    "iot_focus",
    "tv_media",
    "infra_gateway",
    "mesh_sweep",
]

class UCB1Bandit:
    def __init__(self, arms: List[str] | None = None):
        self.arms = list(arms or ARMS)
        self.counts: Dict[str, int] = {a: 0 for a in self.arms}
        self.means: Dict[str, float] = {a: 0.0 for a in self.arms}
        self.total = 0

    def select_arm(self) -> str:
        if self.total == 0:
            return self.arms[0]
        best, best_score = self.arms[0], -1e18
        for a in self.arms:
            c = self.counts[a]
            if c == 0:
                return a  # unexplored arm first
            score = self.means[a] + math.sqrt(2.0 * math.log(self.total) / c)
            if score > best_score:
                best, best_score = a, score
        return best

    def update(self, arm: str, reward: float) -> None:
        if arm not in self.counts:
            self.counts[arm] = 0
            self.means[arm] = 0.0
            self.arms.append(arm)
        self.counts[arm] += 1
        prev_mean = self.means[arm]
        n = self.counts[arm]
        self.means[arm] = prev_mean + (float(reward) - prev_mean) / n
        self.total += 1

    def stats(self) -> Dict[str, Dict[str, float]]:
        return {a: {"count": float(self.counts[a]), "mean_reward": round(self.means[a], 4)} for a in self.arms}

def dwell_for_arm(arm: str) -> int:
    """Channel dwell (ms) per strategy arm."""
    return {"stealth_light": 50, "iot_focus": 80, "tv_media": 80, "infra_gateway": 100, "mesh_sweep": 150}.get(arm, 80)

def reward_for_scan(identities_gained: int, wall_seconds: float, fp_penalties: int = 0) -> float:
    if wall_seconds <= 0:
        return 0.0
    return max(0.0, (float(identities_gained) / float(wall_seconds)) - 0.1 * float(fp_penalties))

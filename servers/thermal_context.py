#!/usr/bin/env python3
"""
Thermal Context Management System

Temperature-based context lifecycle management for MCP servers and tools.
Manages context items across thermal tiers from Plasma (always-in-context)
to Arctic (frozen storage).

Thermal Hierarchy:
- PLASMA:     Ultra-hot, permanent (system prompts, critical state)
- VERY_HOT:   Active this turn (current query, fresh tool results)
- HOT:        Recently used (last 2-3 turns, high frequency)
- NEUTRAL:    Moderate activity (used in session, not recent)
- COOL:       Low activity (old but potentially relevant)
- COLD:       Rarely accessed (candidates for eviction)
- VERY_COLD:  Nearly frozen (about to be evicted)
- ARCTIC:     Frozen storage (evicted but retrievable)
"""

import asyncio
import json
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ThermalTier(str, Enum):
    """Temperature tiers for context items."""
    PLASMA = "plasma"        # ~0-100 tokens, critical
    VERY_HOT = "very_hot"    # ~100-500 tokens, current turn
    HOT = "hot"              # ~500-2k tokens, recent turns
    NEUTRAL = "neutral"      # ~2k-5k tokens, session context
    COOL = "cool"            # ~5k-10k tokens, background context
    COLD = "cold"            # ~10k-15k tokens, rarely accessed
    VERY_COLD = "very_cold"  # ~15k-20k tokens, eviction candidates
    ARCTIC = "arctic"        # Frozen, out of context


class ContextItemType(str, Enum):
    """Types of context items."""
    SYSTEM_PROMPT = "system_prompt"
    USER_PREFERENCE = "user_preference"
    TOOL_RESULT = "tool_result"
    TOOL_SCHEMA = "tool_schema"
    SERVER_METADATA = "server_metadata"
    REASONING_STEP = "reasoning_step"
    EVIDENCE = "evidence"
    MEMORY_FACT = "memory_fact"
    CONVERSATION_TURN = "conversation_turn"
    BACKGROUND_INFO = "background_info"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ThermalMetadata:
    """Thermal metadata for a context item."""
    temperature: ThermalTier = ThermalTier.NEUTRAL
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    created_at: float = field(default_factory=time.time)
    importance: float = 0.5  # 0-1, manual override
    sticky_until: Optional[float] = None  # Keep hot until timestamp
    decay_rate: float = 0.5  # How fast it cools (0-1)
    token_size: int = 0  # Estimated tokens


@dataclass
class ContextItem:
    """A single context item with thermal metadata."""
    id: str
    type: ContextItemType
    content: Any
    thermal: ThermalMetadata
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Thermal Transition Rules
# ---------------------------------------------------------------------------

@dataclass
class ThermalTransition:
    """Rules for thermal tier transitions."""
    promote_to: Optional[ThermalTier] = None
    demote_to: Optional[ThermalTier] = None
    access_threshold: int = 0  # Accesses needed to promote
    age_threshold_ms: float = float('inf')  # Time before demotion
    token_budget: int = 0  # Max tokens for this tier


THERMAL_TRANSITIONS: Dict[ThermalTier, ThermalTransition] = {
    ThermalTier.PLASMA: ThermalTransition(
        access_threshold=999999,
        age_threshold_ms=float('inf'),
        token_budget=100
    ),
    ThermalTier.VERY_HOT: ThermalTransition(
        promote_to=ThermalTier.PLASMA,
        demote_to=ThermalTier.HOT,
        access_threshold=10,
        age_threshold_ms=2 * 60 * 1000,  # 2 minutes
        token_budget=500
    ),
    ThermalTier.HOT: ThermalTransition(
        promote_to=ThermalTier.VERY_HOT,
        demote_to=ThermalTier.NEUTRAL,
        access_threshold=5,
        age_threshold_ms=5 * 60 * 1000,  # 5 minutes
        token_budget=2000
    ),
    ThermalTier.NEUTRAL: ThermalTransition(
        promote_to=ThermalTier.HOT,
        demote_to=ThermalTier.COOL,
        access_threshold=3,
        age_threshold_ms=15 * 60 * 1000,  # 15 minutes
        token_budget=5000
    ),
    ThermalTier.COOL: ThermalTransition(
        promote_to=ThermalTier.NEUTRAL,
        demote_to=ThermalTier.COLD,
        access_threshold=2,
        age_threshold_ms=30 * 60 * 1000,  # 30 minutes
        token_budget=10000
    ),
    ThermalTier.COLD: ThermalTransition(
        promote_to=ThermalTier.COOL,
        demote_to=ThermalTier.VERY_COLD,
        access_threshold=1,
        age_threshold_ms=60 * 60 * 1000,  # 1 hour
        token_budget=15000
    ),
    ThermalTier.VERY_COLD: ThermalTransition(
        promote_to=ThermalTier.COLD,
        demote_to=ThermalTier.ARCTIC,
        access_threshold=1,
        age_threshold_ms=2 * 60 * 60 * 1000,  # 2 hours
        token_budget=20000
    ),
    ThermalTier.ARCTIC: ThermalTransition(
        promote_to=ThermalTier.VERY_COLD,
        access_threshold=1,
        age_threshold_ms=float('inf'),
        token_budget=999999
    ),
}

TIER_PRIORITY: Dict[ThermalTier, int] = {
    ThermalTier.PLASMA: 0,
    ThermalTier.VERY_HOT: 1,
    ThermalTier.HOT: 2,
    ThermalTier.NEUTRAL: 3,
    ThermalTier.COOL: 4,
    ThermalTier.COLD: 5,
    ThermalTier.VERY_COLD: 6,
    ThermalTier.ARCTIC: 7,
}


# ---------------------------------------------------------------------------
# Thermal Context Manager
# ---------------------------------------------------------------------------

class ThermalContextManager:
    """
    Temperature-based context lifecycle management.

    Manages context items across thermal tiers, handling:
    - Automatic promotion based on access frequency
    - Automatic demotion based on age
    - Token budget enforcement with eviction
    - Semantic retrieval from frozen storage
    """

    def __init__(self, global_token_budget: int = 50000):
        self.items: Dict[str, ContextItem] = {}
        self.tier_index: Dict[ThermalTier, Set[str]] = {
            tier: set() for tier in ThermalTier
        }
        self.global_token_budget = global_token_budget

        # Statistics
        self.stats = {
            "promotions": 0,
            "demotions": 0,
            "evictions": 0,
            "thaws": 0,
            "total_accesses": 0,
        }

    def upsert(
        self,
        item_id: str,
        item_type: ContextItemType,
        content: Any,
        tags: Optional[List[str]] = None,
        dependencies: Optional[List[str]] = None,
        initial_tier: ThermalTier = ThermalTier.NEUTRAL,
        importance: float = 0.5,
    ) -> ContextItem:
        """Add or update a context item."""
        existing = self.items.get(item_id)

        if existing:
            existing.content = content
            existing.type = item_type
            existing.tags = tags or existing.tags
            existing.dependencies = dependencies or existing.dependencies
            self.touch(item_id)
            return existing

        # Create new item
        thermal = ThermalMetadata(
            temperature=initial_tier,
            token_size=self._estimate_tokens(content),
            importance=importance,
        )

        new_item = ContextItem(
            id=item_id,
            type=item_type,
            content=content,
            thermal=thermal,
            tags=tags or [],
            dependencies=dependencies or [],
        )

        self.items[item_id] = new_item
        self.tier_index[initial_tier].add(item_id)

        # Enforce budget
        self.enforce_token_budget()

        return new_item

    def touch(self, item_id: str) -> Optional[ContextItem]:
        """Access an item (updates thermal metadata)."""
        item = self.items.get(item_id)
        if not item:
            return None

        now = time.time() * 1000  # ms
        item.thermal.last_accessed = now
        item.thermal.access_count += 1
        self.stats["total_accesses"] += 1

        # Check for promotion
        self._check_promotion(item_id)

        return item

    def get(self, item_id: str) -> Optional[ContextItem]:
        """Get item by ID."""
        return self.items.get(item_id)

    def get_by_tier(self, tier: ThermalTier) -> List[ContextItem]:
        """Get all items in a tier."""
        ids = self.tier_index.get(tier, set())
        return [self.items[id] for id in ids if id in self.items]

    def get_active_context(self) -> List[ContextItem]:
        """Get all active (non-arctic) context sorted by priority."""
        active = []
        for tier, ids in self.tier_index.items():
            if tier != ThermalTier.ARCTIC:
                for id in ids:
                    if id in self.items:
                        active.append(self.items[id])

        return sorted(active, key=lambda x: TIER_PRIORITY[x.thermal.temperature])

    def promote(self, item_id: str, to_tier: Optional[ThermalTier] = None) -> bool:
        """Promote item to hotter tier."""
        item = self.items.get(item_id)
        if not item:
            return False

        current_tier = item.thermal.temperature
        target_tier = to_tier or THERMAL_TRANSITIONS[current_tier].promote_to

        if not target_tier:
            return False

        return self._move_tier(item_id, target_tier)

    def demote(self, item_id: str, to_tier: Optional[ThermalTier] = None) -> bool:
        """Demote item to colder tier."""
        item = self.items.get(item_id)
        if not item:
            return False

        current_tier = item.thermal.temperature
        target_tier = to_tier or THERMAL_TRANSITIONS[current_tier].demote_to

        if not target_tier:
            return False

        return self._move_tier(item_id, target_tier)

    def freeze(self, item_id: str) -> bool:
        """Freeze item to arctic storage."""
        item = self.items.get(item_id)
        if not item or item.thermal.temperature == ThermalTier.PLASMA:
            return False  # Can't freeze plasma

        self.stats["evictions"] += 1
        return self._move_tier(item_id, ThermalTier.ARCTIC)

    def thaw(self, item_id: str, to_tier: ThermalTier = ThermalTier.COOL) -> bool:
        """Thaw item from arctic storage."""
        item = self.items.get(item_id)
        if not item or item.thermal.temperature != ThermalTier.ARCTIC:
            return False

        self.stats["thaws"] += 1
        return self._move_tier(item_id, to_tier)

    def run_decay_cycle(self) -> Dict[str, int]:
        """Run thermal decay cycle (cool down old items)."""
        now = time.time() * 1000
        promoted = 0
        demoted = 0
        frozen = 0

        for item in list(self.items.values()):
            # Skip plasma (never decays)
            if item.thermal.temperature == ThermalTier.PLASMA:
                continue

            # Skip if sticky
            if item.thermal.sticky_until and now < item.thermal.sticky_until:
                continue

            transitions = THERMAL_TRANSITIONS[item.thermal.temperature]
            age = now - item.thermal.last_accessed

            # Check for demotion due to age
            if transitions.demote_to and age > transitions.age_threshold_ms:
                decay_probability = item.thermal.decay_rate * (age / transitions.age_threshold_ms)

                if random.random() < decay_probability:
                    if self.demote(item.id):
                        demoted += 1
                        if item.thermal.temperature == ThermalTier.ARCTIC:
                            frozen += 1

            # Check for promotion due to high access frequency
            if transitions.promote_to and item.thermal.access_count >= transitions.access_threshold:
                if self.promote(item.id):
                    promoted += 1

        # Enforce token budget
        budget_result = self.enforce_token_budget()
        frozen += budget_result["frozen"]

        return {"promoted": promoted, "demoted": demoted, "frozen": frozen}

    def enforce_token_budget(self) -> Dict[str, int]:
        """Enforce global token budget by freezing coldest items."""
        total_tokens = 0
        active_items = []

        for item in self.items.values():
            if item.thermal.temperature != ThermalTier.ARCTIC:
                total_tokens += item.thermal.token_size
                active_items.append(item)

        frozen = 0

        if total_tokens > self.global_token_budget:
            # Sort by temperature (coldest first), then by importance
            sorted_items = sorted(
                active_items,
                key=lambda x: (-TIER_PRIORITY[x.thermal.temperature], x.thermal.importance)
            )

            for item in sorted_items:
                if total_tokens <= self.global_token_budget:
                    break
                if item.thermal.temperature == ThermalTier.PLASMA:
                    continue

                if self.freeze(item.id):
                    total_tokens -= item.thermal.token_size
                    frozen += 1

        return {"frozen": frozen, "total_tokens": total_tokens}

    def get_stats(self) -> Dict[str, Any]:
        """Get thermal statistics."""
        tier_counts = {}
        tier_tokens = {}
        total_tokens = 0

        for item in self.items.values():
            tier = item.thermal.temperature.value
            tier_counts[tier] = tier_counts.get(tier, 0) + 1
            tier_tokens[tier] = tier_tokens.get(tier, 0) + item.thermal.token_size

            if item.thermal.temperature != ThermalTier.ARCTIC:
                total_tokens += item.thermal.token_size

        return {
            "total_items": len(self.items),
            "active_items": len(self.items) - tier_counts.get("arctic", 0),
            "arctic_items": tier_counts.get("arctic", 0),
            "total_tokens": total_tokens,
            "token_budget": self.global_token_budget,
            "budget_utilization": total_tokens / self.global_token_budget if self.global_token_budget > 0 else 0,
            "tier_counts": tier_counts,
            "tier_tokens": tier_tokens,
            **self.stats,
        }

    # Private methods

    def _move_tier(self, item_id: str, target_tier: ThermalTier) -> bool:
        """Move item to a different tier."""
        item = self.items.get(item_id)
        if not item:
            return False

        current_tier = item.thermal.temperature
        if current_tier == target_tier:
            return True

        # Remove from old tier
        self.tier_index[current_tier].discard(item_id)

        # Add to new tier
        self.tier_index[target_tier].add(item_id)
        item.thermal.temperature = target_tier

        # Update stats
        current_priority = TIER_PRIORITY[current_tier]
        target_priority = TIER_PRIORITY[target_tier]

        if target_priority < current_priority:
            self.stats["promotions"] += 1
        elif target_priority > current_priority:
            self.stats["demotions"] += 1

        return True

    def _check_promotion(self, item_id: str) -> None:
        """Check if item should be promoted."""
        item = self.items.get(item_id)
        if not item:
            return

        transitions = THERMAL_TRANSITIONS[item.thermal.temperature]
        if not transitions.promote_to:
            return

        if item.thermal.access_count >= transitions.access_threshold:
            self.promote(item_id)

    def _estimate_tokens(self, content: Any) -> int:
        """Estimate tokens for content."""
        if isinstance(content, str):
            return len(content) // 4
        return len(json.dumps(content, default=str)) // 4


# ---------------------------------------------------------------------------
# Predictive Thermal Manager
# ---------------------------------------------------------------------------

class PredictiveThermalManager(ThermalContextManager):
    """
    Advanced thermal manager with predictive capabilities.

    Features:
    - Access pattern tracking
    - Co-access pattern detection
    - Predictive pre-warming
    - Anomaly detection
    """

    def __init__(self, global_token_budget: int = 50000):
        super().__init__(global_token_budget)
        self.access_patterns: Dict[str, List[float]] = {}  # item_id -> timestamps
        self.co_access_patterns: Dict[str, Dict[str, int]] = {}  # item_id -> {related_id -> count}

    def touch(self, item_id: str) -> Optional[ContextItem]:
        """Override touch to track access patterns."""
        item = super().touch(item_id)

        if item:
            # Track access pattern
            if item_id not in self.access_patterns:
                self.access_patterns[item_id] = []
            self.access_patterns[item_id].append(time.time() * 1000)

            # Limit history
            if len(self.access_patterns[item_id]) > 100:
                self.access_patterns[item_id].pop(0)

            # Track co-access patterns
            self._update_co_access_patterns(item_id)

            # Predictive pre-warming
            asyncio.create_task(self._predictive_pre_warm(item_id))

        return item

    async def _predictive_pre_warm(self, current_item_id: str) -> None:
        """Pre-warm items frequently accessed together."""
        co_accessed = self.co_access_patterns.get(current_item_id)
        if not co_accessed:
            return

        # Sort by co-access frequency
        candidates = sorted(co_accessed.items(), key=lambda x: -x[1])[:5]

        for related_id, count in candidates:
            item = self.get(related_id)
            if not item:
                continue

            # If in ARCTIC and high co-access, thaw to COOL
            if item.thermal.temperature == ThermalTier.ARCTIC and count >= 3:
                self.thaw(related_id, ThermalTier.COOL)
            # If in COLD/VERY_COLD and high co-access, promote to NEUTRAL
            elif item.thermal.temperature in (ThermalTier.COLD, ThermalTier.VERY_COLD) and count >= 5:
                self.promote(related_id, ThermalTier.NEUTRAL)

    def _update_co_access_patterns(self, item_id: str) -> None:
        """Update co-access patterns when an item is accessed."""
        recent_window = time.time() * 1000 - 5 * 60 * 1000  # 5 minutes
        recently_accessed = []

        for id, timestamps in self.access_patterns.items():
            if id == item_id:
                continue
            recent_accesses = [t for t in timestamps if t > recent_window]
            if recent_accesses:
                recently_accessed.append(id)

        if item_id not in self.co_access_patterns:
            self.co_access_patterns[item_id] = {}

        for related_id in recently_accessed:
            self.co_access_patterns[item_id][related_id] = \
                self.co_access_patterns[item_id].get(related_id, 0) + 1

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect access pattern anomalies."""
        anomalies = []

        for item_id, timestamps in self.access_patterns.items():
            if len(timestamps) < 5:
                continue

            # Calculate intervals
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_interval = sum(intervals) / len(intervals)
            std_dev = math.sqrt(sum((i - avg_interval) ** 2 for i in intervals) / len(intervals))

            # Detect sudden burst
            recent_accesses = len([t for t in timestamps if t > time.time() * 1000 - 60000])
            if recent_accesses >= 5 and avg_interval > 60000:
                anomalies.append({
                    "item_id": item_id,
                    "anomaly_type": "sudden_burst",
                    "confidence": min(1, recent_accesses / 10),
                    "recommendation": "Consider promoting to PLASMA or setting sticky flag"
                })

            # Detect long silence
            last_access = timestamps[-1]
            time_since_access = time.time() * 1000 - last_access
            if time_since_access > avg_interval + 2 * std_dev and time_since_access > 3600000:
                anomalies.append({
                    "item_id": item_id,
                    "anomaly_type": "long_silence",
                    "confidence": min(1, time_since_access / (avg_interval + 2 * std_dev)),
                    "recommendation": "Consider archiving to ARCTIC"
                })

        return anomalies

    def get_predictive_recommendations(self) -> List[Dict[str, Any]]:
        """Get recommendations based on access patterns."""
        recommendations = []

        for item in self.items.values():
            pattern = self.access_patterns.get(item.id)
            if not pattern or len(pattern) < 3:
                continue

            # Calculate access frequency (per hour)
            time_span = pattern[-1] - pattern[0]
            if time_span <= 0:
                continue
            frequency = (len(pattern) / time_span) * 3600000

            current_tier = item.thermal.temperature

            if frequency > 10 and current_tier != ThermalTier.PLASMA:
                recommendations.append({
                    "item_id": item.id,
                    "current_tier": current_tier.value,
                    "recommended_tier": ThermalTier.PLASMA.value,
                    "confidence": min(1, frequency / 20),
                    "reason": "High access frequency (>10/hour)"
                })
            elif frequency > 2 and TIER_PRIORITY[current_tier] > 2:
                recommendations.append({
                    "item_id": item.id,
                    "current_tier": current_tier.value,
                    "recommended_tier": ThermalTier.HOT.value,
                    "confidence": min(1, frequency / 5),
                    "reason": "Moderate access frequency (>2/hour)"
                })
            elif frequency < 0.1 and current_tier != ThermalTier.ARCTIC:
                recommendations.append({
                    "item_id": item.id,
                    "current_tier": current_tier.value,
                    "recommended_tier": ThermalTier.ARCTIC.value,
                    "confidence": min(1, 1 - frequency * 10),
                    "reason": "Very low access frequency (<0.1/hour)"
                })

        return sorted(recommendations, key=lambda x: -x["confidence"])


# ---------------------------------------------------------------------------
# Submodular Optimization
# ---------------------------------------------------------------------------

def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    if len(a) != len(b):
        return 0.0

    dot_product = sum(ai * bi for ai, bi in zip(a, b))
    norm_a = math.sqrt(sum(ai * ai for ai in a))
    norm_b = math.sqrt(sum(bi * bi for bi in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot_product / (norm_a * norm_b)


def compute_marginal_gain_diversity(
    new_idx: int,
    current_coverage: List[float],
    similarity_matrix: List[List[float]]
) -> float:
    """Compute marginal gain for diversity objective."""
    n = len(similarity_matrix)
    marginal_gain = 0.0
    row = similarity_matrix[new_idx]

    for i in range(n):
        new_coverage = max(row[i], current_coverage[i])
        marginal_gain += new_coverage - current_coverage[i]

    return marginal_gain


def lazy_greedy_selection(embeddings: List[List[float]], k: int) -> List[int]:
    """
    Submodular maximization using lazy greedy algorithm.
    Selects k diverse items from embeddings.
    """
    n = len(embeddings)
    if k >= n:
        return list(range(n))

    selected = []
    remaining = set(range(n))

    # Pre-compute similarity matrix
    similarity_matrix = []
    for i in range(n):
        row = []
        for j in range(n):
            sim = cosine_similarity(embeddings[i], embeddings[j])
            row.append(max(0, sim))  # Clamp to non-negative
        similarity_matrix.append(row)

    # Coverage vector
    current_coverage = [0.0] * n

    # Priority queue: (negative_gain, last_updated, index)
    pq = []
    for i in range(n):
        gain = compute_marginal_gain_diversity(i, current_coverage, similarity_matrix)
        pq.append((-gain, 0, i))

    pq.sort()

    for iteration in range(k):
        while pq:
            neg_gain, last_updated, best_idx = pq.pop(0)

            if best_idx not in remaining:
                continue

            if last_updated == iteration:
                selected.append(best_idx)
                remaining.discard(best_idx)

                # Update coverage
                row = similarity_matrix[best_idx]
                for i in range(n):
                    current_coverage[i] = max(current_coverage[i], row[i])
                break

            current_gain = compute_marginal_gain_diversity(best_idx, current_coverage, similarity_matrix)
            pq.append((-current_gain, iteration, best_idx))
            pq.sort()

    return selected


def lazy_greedy_with_saturation(
    embeddings: List[List[float]],
    threshold: float = 0.01
) -> Tuple[List[int], int, List[float]]:
    """
    Submodular maximization with automatic k selection via saturation detection.
    """
    n = len(embeddings)
    selected = []
    remaining = set(range(n))
    values = []

    # Pre-compute similarity matrix
    similarity_matrix = []
    for i in range(n):
        row = []
        for j in range(n):
            sim = cosine_similarity(embeddings[i], embeddings[j])
            row.append(max(0, sim))
        similarity_matrix.append(row)

    current_coverage = [0.0] * n
    pq = []

    for i in range(n):
        gain = compute_marginal_gain_diversity(i, current_coverage, similarity_matrix)
        pq.append((-gain, 0, i))

    pq.sort()

    early_stop_k = None

    for iteration in range(n):
        while pq:
            neg_gain, last_updated, best_idx = pq.pop(0)

            if best_idx not in remaining:
                continue

            if last_updated == iteration:
                selected.append(best_idx)
                remaining.discard(best_idx)

                row = similarity_matrix[best_idx]
                for i in range(n):
                    current_coverage[i] = max(current_coverage[i], row[i])

                function_value = sum(current_coverage) / n
                values.append(function_value)

                # Check for saturation
                if len(values) >= 2:
                    delta = values[-1] - values[-2]
                    if delta < threshold:
                        early_stop_k = len(values)

                break

            current_gain = compute_marginal_gain_diversity(best_idx, current_coverage, similarity_matrix)
            pq.append((-current_gain, iteration, best_idx))
            pq.sort()

        if early_stop_k is not None:
            break

    optimal_k = early_stop_k or len(values)
    final_selected = selected[:optimal_k]

    return final_selected, optimal_k, values


# ---------------------------------------------------------------------------
# Thermal Policies
# ---------------------------------------------------------------------------

THERMAL_POLICIES = {
    "aggressive": {
        "global_budget": 30000,
        "decay_cycle_interval_ms": 30000,
        "default_decay_rate": 0.8,
    },
    "balanced": {
        "global_budget": 50000,
        "decay_cycle_interval_ms": 60000,
        "default_decay_rate": 0.5,
    },
    "conservative": {
        "global_budget": 80000,
        "decay_cycle_interval_ms": 120000,
        "default_decay_rate": 0.2,
    },
}


# ---------------------------------------------------------------------------
# Thermal Tool Strategies (for dynamic tool loading)
# ---------------------------------------------------------------------------

THERMAL_TOOL_STRATEGIES = {
    "PLASMA": {
        "budget": 25000,
        "auto_suggest": True,
        "auto_load": True,
        "eviction_delay": 3600000,  # 1 hour
    },
    "MOLTEN": {
        "budget": 18000,
        "auto_suggest": True,
        "auto_load": True,
        "eviction_delay": 1800000,  # 30 min
    },
    "WARM": {
        "budget": 12000,
        "auto_suggest": True,
        "auto_load": False,
        "eviction_delay": 600000,  # 10 min
    },
    "TEPID": {
        "budget": 8000,
        "auto_suggest": False,
        "auto_load": False,
        "eviction_delay": 300000,  # 5 min
    },
    "COOL": {
        "budget": 5000,
        "auto_suggest": False,
        "auto_load": False,
        "eviction_delay": 120000,  # 2 min
    },
    "FROZEN": {
        "budget": 2000,
        "auto_suggest": False,
        "auto_load": False,
        "eviction_delay": 60000,  # 1 min
    },
    "ARCTIC": {
        "budget": 1500,  # Core only
        "auto_suggest": False,
        "auto_load": False,
        "eviction_delay": 0,
    },
}

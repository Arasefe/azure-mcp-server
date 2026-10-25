"""Tool tiers and the single ordered ceiling (MCP_MAX_TIER) that gates them."""

from dataclasses import dataclass
from enum import IntEnum


class Tier(IntEnum):
    """Ordered on purpose: allowing a tier allows every tier below it."""

    READ = 1
    WRITE = 2
    DESTRUCTIVE = 3


@dataclass(frozen=True)
class Decision:
    allowed: bool
    tier: Tier
    reason: str


def parse_tier(value: str) -> Tier:
    """Turn the MCP_MAX_TIER setting into a Tier; anything unknown is an error, never a default."""
    try:
        return Tier[value.strip().upper()]
    except KeyError:
        raise ValueError(
            f"MCP_MAX_TIER must be one of: read, write, destructive (got {value!r})"
        ) from None


def authorize(tier: Tier, max_tier: Tier) -> Decision:
    """Allow a tool call only if its tier is at or below the configured ceiling."""
    if tier <= max_tier:
        return Decision(True, tier, "within MCP_MAX_TIER")
    return Decision(
        False,
        tier,
        f"This is a {tier.name.lower()}-tier tool and MCP_MAX_TIER is "
        f"{max_tier.name.lower()}. Only the operator can raise MCP_MAX_TIER.",
    )

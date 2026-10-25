"""Human confirmation for destructive tools, via an MCP elicitation resolver.

The resolver runs before the tool body. It re-checks the tier first, so a human is
never asked to approve something the policy forbids, then asks the operator to retype
the target. The SDK delivers the question on both protocol generations (mid-call
request on <= 2025-11-25, InputRequiredResult round-trip on >= 2026-07-28). A client
that cannot elicit fails the call before the tool body runs.
"""

import inspect
from collections.abc import Callable
from typing import Annotated, Any

from mcp.server.mcpserver import AcceptedElicitation, Elicit, ElicitationResult, Resolve
from pydantic import BaseModel, Field


class Confirm(BaseModel):
    confirm: bool = Field(description="I understand this cannot be undone")
    retype_target: str = Field(description="Type the target ID exactly")


def confirmation_param(tool: str, target_arg: str, gate: Callable[[dict[str, Any]], None]) -> Any:
    """Type for the hidden `confirm` parameter of a destructive tool."""

    async def resolver(**kwargs: Any) -> Elicit[Confirm]:
        gate(kwargs)  # raises if the tier forbids the call, before anyone is asked
        return Elicit(
            f"{tool} is destructive and cannot be undone.\n"
            f"Target: {kwargs[target_arg]}\nRetype the target to confirm.",
            Confirm,
        )

    # The SDK passes tool arguments to a resolver by parameter name.
    resolver.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [inspect.Parameter(target_arg, inspect.Parameter.KEYWORD_ONLY, annotation=str)],
        return_annotation=Elicit[Confirm],
    )
    return Annotated[ElicitationResult[Confirm], Resolve(resolver)]


def confirmed(result: Any, target: str) -> tuple[bool, str]:
    """Accept only an explicit yes with the exact target retyped."""
    if not isinstance(result, AcceptedElicitation):
        return False, "operator declined"
    if not result.data.confirm:
        return False, "operator did not confirm"
    if result.data.retype_target.strip().lower() != target.lower():
        return False, "retyped target did not match"
    return True, "confirmed by operator"

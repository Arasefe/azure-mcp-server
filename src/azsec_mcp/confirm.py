"""Human confirmation for destructive tools, via an MCP elicitation resolver.

The resolver runs before the tool body. It re-checks the tier first, so a human is
never asked to approve something the policy forbids. It then shows every
security-relevant argument and asks the operator to retype the `retype` arguments
joined by " -> " (for assign_role: "Owner -> emma@..."), so changing any of them
invalidates the answer. The SDK delivers the question on both protocol generations
(mid-call request on <= 2025-11-25, InputRequiredResult round-trip on >= 2026-07-28).
A client that cannot elicit fails the call before the tool body runs.
"""

import inspect
import re
import unicodedata
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.server.mcpserver import AcceptedElicitation, Elicit, ElicitationResult, Resolve
from pydantic import BaseModel, Field

Describe = Callable[[dict[str, Any]], Awaitable[dict[str, str]]]

MAX_DIRECTORY_TEXT = 80


def _clean(value: str) -> str:
    """Control, format (bidi, zero-width) and line/paragraph separators become spaces."""
    cleaned = "".join(
        " " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch for ch in value
    )
    cleaned = " ".join(cleaned.split()).replace('"', "'")
    if len(cleaned) > MAX_DIRECTORY_TEXT:
        cleaned = cleaned[: MAX_DIRECTORY_TEXT - 1] + "…"
    return cleaned


def agent_value(value: Any) -> str:
    """Render an argument the agent supplied. Free text (anything with whitespace or special
    characters) is cleaned, quoted and labelled like directory text, so a justification or
    comment cannot add fake lines to the prompt; plain tokens (IDs, enums, numbers) stay plain.
    """
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9._@'/()+-]{1,200}", text):
        return text
    return f'"{_clean(text)}" (text from the agent)'


def directory_text(value: str) -> str:
    """Render a directory-supplied name safely for the human-approval prompt.

    Names such as a device or AU display name can be set by people other than the
    operator, so they are treated as untrusted: control, format (incl. bidi overrides
    and zero-width) and line/paragraph separator characters become spaces, the text is
    capped, quoted, and labelled so it cannot pose as a line of the prompt itself.
    """
    return f'"{_clean(value)}" (name from directory)'


class Confirm(BaseModel):
    confirm: bool = Field(description="I understand this cannot be undone")
    retype_target: str = Field(description="Type the confirmation text exactly")


def expected_text(args: dict[str, Any], retype: tuple[str, ...]) -> str:
    """What the operator must retype: the `retype` arguments joined by ' -> '."""
    return " -> ".join(str(args[name]) for name in retype)


def _normalize(text: str) -> str:
    # Accept '→' for '->', any spacing around it, and any letter case (GUIDs, UPNs).
    return re.sub(r"\s*(?:->|→)\s*", " -> ", text.strip()).lower()


def confirmation_param(
    tool: str,
    retype: tuple[str, ...],
    show: tuple[str, ...],
    gate: Callable[[dict[str, Any]], None],
    describe: Describe | None = None,
) -> Any:
    """Type for the hidden `confirm` parameter of a destructive tool."""
    names = retype + tuple(n for n in show if n not in retype)

    async def resolver(**kwargs: Any) -> Elicit[Confirm]:
        gate(kwargs)  # raises if the tier forbids the call, before anyone is asked
        lines = [f"{tool} is destructive and cannot be undone."]
        lines += [f"{name}: {agent_value(kwargs[name])}" for name in names]
        if describe is not None:
            try:
                extra = await describe(kwargs)
                lines += [f"{label}: {directory_text(value)}" for label, value in extra.items()]
            except Exception:
                lines.append("details: (name lookup failed; check the IDs above)")
        lines.append(f"Retype exactly to confirm: {expected_text(kwargs, retype)}")
        return Elicit("\n".join(lines), Confirm)

    # The SDK passes tool arguments to a resolver by parameter name.
    resolver.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [inspect.Parameter(n, inspect.Parameter.KEYWORD_ONLY, annotation=Any) for n in names],
        return_annotation=Elicit[Confirm],
    )
    return Annotated[ElicitationResult[Confirm], Resolve(resolver)]


def confirmed(result: Any, expected: str) -> tuple[bool, str]:
    """Accept only an explicit yes with the exact confirmation text retyped."""
    if not isinstance(result, AcceptedElicitation):
        return False, "operator declined"
    if not result.data.confirm:
        return False, "operator did not confirm"
    if _normalize(result.data.retype_target) != _normalize(expected):
        return False, "retyped target did not match"
    return True, "confirmed by operator"

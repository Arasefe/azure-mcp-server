"""Destructive tools: tier first, then a human must retype the target, on both protocols."""

from typing import Literal

import pytest
from mcp import Client, types
from mcp.shared.exceptions import MCPError

pytestmark = pytest.mark.anyio

DEVICE = "0f8fad5b-d9cb-469f-a165-70867728950e"


def answer(
    retype: str,
    action: Literal["accept", "decline", "cancel"] = "accept",
    asked: list | None = None,
):
    """Elicitation callback standing in for the human at the client."""

    async def callback(context, params):
        if asked is not None:
            asked.append(params.message)
        content = {"confirm": True, "retype_target": retype} if action == "accept" else None
        return types.ElicitResult(action=action, content=content)

    return callback


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_destructive_runs_on_correct_confirmation(server_with_tools, audit_records, mode):
    server, calls = server_with_tools("destructive")
    asked: list[str] = []
    async with Client(server.mcp, mode=mode, elicitation_callback=answer(DEVICE, asked=asked)) as c:
        result = await c.call_tool("t_destroy", {"device_id": DEVICE})
    assert result.is_error is False
    assert calls == ["destroy"]
    assert DEVICE in asked[0]
    assert audit_records()[-1]["outcome"] == "ok"


async def test_destructive_requires_retyped_target(server_with_tools, audit_records):
    server, calls = server_with_tools("destructive")
    wrong = "11111111-2222-3333-4444-555555555555"
    async with Client(server.mcp, elicitation_callback=answer(wrong)) as c:
        result = await c.call_tool("t_destroy", {"device_id": DEVICE})
    assert result.is_error is True
    assert calls == []
    record = audit_records()[-1]
    assert record["decision"] == "declined"
    assert record["reason"] == "retyped target did not match"


async def test_retype_is_case_insensitive(server_with_tools):
    server, calls = server_with_tools("destructive")
    async with Client(server.mcp, elicitation_callback=answer(DEVICE.upper())) as c:
        await c.call_tool("t_destroy", {"device_id": DEVICE})
    assert calls == ["destroy"]


async def test_destructive_declined_not_executed(server_with_tools, audit_records):
    server, calls = server_with_tools("destructive")
    async with Client(server.mcp, elicitation_callback=answer("", action="decline")) as c:
        result = await c.call_tool("t_destroy", {"device_id": DEVICE})
    assert result.is_error is True
    assert calls == []
    assert audit_records()[-1]["reason"] == "operator declined"


async def test_destructive_denied_by_tier_never_asks_human(server_with_tools, audit_records):
    server, calls = server_with_tools("write")
    asked: list[str] = []
    async with Client(server.mcp, elicitation_callback=answer(DEVICE, asked=asked)) as c:
        result = await c.call_tool("t_destroy", {"device_id": DEVICE})
    assert result.is_error is True
    assert asked == []
    assert calls == []
    assert audit_records()[-1]["decision"] == "denied"


async def test_destructive_denied_when_client_cannot_elicit(server_with_tools):
    server, calls = server_with_tools("destructive")

    def leaves(exc):
        if isinstance(exc, BaseExceptionGroup):
            return [leaf for sub in exc.exceptions for leaf in leaves(sub)]
        return [exc]

    with pytest.raises(BaseException) as info:
        async with Client(server.mcp) as c:
            await c.call_tool("t_destroy", {"device_id": DEVICE})
    errors = leaves(info.value)
    assert any(isinstance(e, MCPError) and "elicitation" in str(e) for e in errors)
    assert calls == []

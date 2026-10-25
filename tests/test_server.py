import json

import pytest
from mcp import Client
from mcp.types import CallToolResult, TextContent

from azsec_mcp.policy import Tier
from azsec_mcp.untrusted import NOTICE

pytestmark = pytest.mark.anyio


def text(result: CallToolResult) -> str:
    """The single text block of a tool result (fails loudly on any other content type)."""
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


async def test_read_tool_returns_envelope(server_with_tools, audit_records):
    server, calls = server_with_tools("read")
    async with Client(server.mcp) as c:
        result = await c.call_tool("t_read", {})
    out = json.loads(text(result))
    assert result.is_error is False
    assert out["source"] == "t_read"
    assert out["notice"] == NOTICE
    assert out["data"] == [{"id": 1}]
    assert audit_records()[-1]["outcome"] == "ok"


async def test_write_denied_under_read_ceiling_and_audited(server_with_tools, audit_records):
    server, calls = server_with_tools("read")
    async with Client(server.mcp) as c:
        result = await c.call_tool("t_write", {"name": "x"})
    assert result.is_error is True
    assert "MCP_MAX_TIER" in text(result)
    assert calls == []
    record = audit_records()[-1]
    assert record["decision"] == "denied"
    assert record["tool"] == "t_write"


async def test_invalid_guid_rejected_before_handler(server_with_tools):
    server, calls = server_with_tools("destructive")
    async with Client(server.mcp) as c:
        result = await c.call_tool("t_destroy", {"device_id": "X/wipe?"})
    assert result.is_error is True
    assert calls == []


async def test_list_tools_hides_confirm_and_sets_hints(server_with_tools):
    server, _ = server_with_tools("read")
    async with Client(server.mcp) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    destroy, read = tools["t_destroy"], tools["t_read"]
    assert destroy.annotations is not None and read.annotations is not None
    assert list(destroy.input_schema["properties"]) == ["device_id"]
    assert destroy.annotations.destructive_hint is True
    assert read.annotations.read_only_hint is True
    assert read.description == "Read-tier test tool."


async def test_azure_error_audited_and_returned(server_with_tools, audit_records):
    server, _ = server_with_tools("read")
    async with Client(server.mcp) as c:
        result = await c.call_tool("t_azure_fail", {})
    assert result.is_error is True
    assert "Authorization_RequestDenied" in text(result)
    record = audit_records()[-1]
    assert record["outcome"] == "error"
    assert "Authorization_RequestDenied" in record["error"]


async def test_unexpected_exception_not_leaked(server_with_tools, audit_records):
    server, _ = server_with_tools("read")
    async with Client(server.mcp) as c:
        result = await c.call_tool("t_bug", {})
    assert result.is_error is True
    assert "secret detail" not in text(result)
    assert "secret detail" in audit_records()[-1]["error"]


def test_destructive_registration_requires_target_arg(make_server):
    server = make_server("read")
    with pytest.raises(ValueError, match="target_arg"):
        server.tool("bad", Tier.DESTRUCTIVE)
    with pytest.raises(ValueError, match="target_arg"):
        server.tool("bad", Tier.READ, target_arg="x")


def test_unknown_max_tier_stops_startup(make_server):
    with pytest.raises(ValueError, match="MCP_MAX_TIER"):
        make_server("destrutive")

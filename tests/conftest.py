import json

import httpx
import pytest

from azsec_mcp.audit import AuditLog
from azsec_mcp.config import load_settings
from azsec_mcp.http import AzureError
from azsec_mcp.ids import Guid
from azsec_mcp.policy import Tier
from azsec_mcp.server import build_server

BASE_ENV = {
    "AZURE_TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "AZURE_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
    "AZURE_SUBSCRIPTION_ID": "33333333-3333-3333-3333-333333333333",
    "SENTINEL_RESOURCE_GROUP": "rg-sentinel",
    "SENTINEL_WORKSPACE_NAME": "law-test",
}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def http_client():
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture
def audit_records(tmp_path):
    """Return a function that reads the test server's audit log as a list of dicts."""

    def read():
        path = tmp_path / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    return read


@pytest.fixture
def make_server(tmp_path):
    """Factory: a SecureServer (optionally with an AzureHttp) and an audit log in tmp_path."""

    def factory(max_tier="read", http=None):
        path = tmp_path / "audit.jsonl"
        env = {**BASE_ENV, "MCP_MAX_TIER": max_tier, "MCP_AUDIT_PATH": str(path)}
        return build_server(load_settings(env), http, AuditLog(path))  # type: ignore[arg-type]

    return factory


@pytest.fixture
def server_with_tools(make_server):
    """Factory: a SecureServer with test-only tools that record each real execution."""

    def factory(max_tier="read"):
        server = make_server(max_tier)
        calls: list[str] = []

        @server.tool("t_read", Tier.READ)
        async def t_read() -> list:
            """Read-tier test tool."""
            calls.append("read")
            return [{"id": 1}]

        @server.tool("t_write", Tier.WRITE)
        async def t_write(name: str) -> dict:
            """Write-tier test tool."""
            calls.append("write")
            return {"name": name}

        @server.tool("t_destroy", Tier.DESTRUCTIVE, retype=("device_id",))
        async def t_destroy(device_id: Guid) -> dict:
            """Destructive-tier test tool."""
            calls.append("destroy")
            return {"wiped": device_id}

        @server.tool("t_azure_fail", Tier.READ)
        async def t_azure_fail() -> dict:
            """Raises an Azure error."""
            raise AzureError(403, "Authorization_RequestDenied", "Insufficient privileges")

        @server.tool("t_bug", Tier.READ)
        async def t_bug() -> dict:
            """Raises an unexpected exception."""
            raise RuntimeError("secret detail")

        return server, calls

    return factory

"""Entra ID directory audit and sign-in logs."""

from typing import Annotated, Any

from pydantic import Field

from ..http import Api
from ..policy import Tier
from ..server import SecureServer

Top = Annotated[int, Field(ge=1, le=200)]
ODataFilter = Annotated[str, Field(max_length=500, description="OData $filter expression")]


def register(s: SecureServer) -> None:
    async def recent(path: str, top: int, odata_filter: str | None) -> list[dict[str, Any]]:
        params = {"$top": str(top)}
        if odata_filter:
            params["$filter"] = odata_filter
        found = await s.http.request("GET", Api.GRAPH, path, params=params)
        return found.get("value", [])

    @s.tool("list_audit_logs", Tier.READ)
    async def list_audit_logs(top: Top = 50, filter: ODataFilter | None = None) -> list:
        """List recent Entra ID directory audit events."""
        return await recent("/v1.0/auditLogs/directoryAudits", top, filter)

    @s.tool("list_signin_logs", Tier.READ)
    async def list_signin_logs(top: Top = 50, filter: ODataFilter | None = None) -> list:
        """List recent Entra ID sign-in events."""
        return await recent("/v1.0/auditLogs/signIns", top, filter)

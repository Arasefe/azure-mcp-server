"""Microsoft Sentinel tools: incidents, analytics, hunting, watchlists, TI, connectors, KQL."""

import re
import uuid
from typing import Annotated, Any, Literal

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from ..http import Api
from ..ids import Guid, IsoDuration, WatchlistAlias, seg
from ..policy import Tier
from ..server import SecureServer

SENTINEL_API = "2025-09-01"
WORKSPACE_API = "2022-10-01"
MAX_KQL_DAYS = 90

Status = Literal["New", "Active", "Closed"]
Severity = Literal["High", "Medium", "Low", "Informational"]
Classification = Literal["Undetermined", "TruePositive", "BenignPositive", "FalsePositive"]
ClassificationReason = Literal[
    "SuspiciousActivity", "SuspiciousButExpected", "IncorrectAlertLogic", "InaccurateData"
]
CommentText = Annotated[str, Field(min_length=1, max_length=4000)]
KqlText = Annotated[str, Field(min_length=1, max_length=10_000)]
Top = Annotated[int, Field(ge=1, le=200)]

# Writable incident properties per the 2025-09-01 Create Or Update contract.
WRITABLE = (
    "title",
    "severity",
    "status",
    "description",
    "owner",
    "labels",
    "classification",
    "classificationReason",
    "classificationComment",
)
# Functions/operators that reach beyond this server's workspace. This is a defense-in-depth
# check, not a KQL parser: the authoritative control is giving the identity Log Analytics
# Reader on this one workspace only (docs/PERMISSIONS.md).
_SCOPE_NAMES = r"workspace|app|resource|adx|arg|cluster|database|externaldata|external_table"
CROSS_SCOPE = re.compile(
    rf"(?:\b(?:{_SCOPE_NAMES})|\[\s*['\"]\s*(?:{_SCOPE_NAMES})\s*['\"]\s*\])\s*\(",
    re.IGNORECASE,
)


def strip_comments(query: str) -> str:
    """Remove KQL // comments that are outside string literals; strings are kept verbatim.

    Understands '...' and "..." (backslash escapes, ending at a newline), @'...' and @"..."
    (verbatim, no escapes) and ```...``` / ~~~...~~~ (multi-line), so a '//' inside a string
    is not a comment.
    """
    out: list[str] = []
    i, n = 0, len(query)
    while i < n:
        fence = query[i : i + 3]
        if fence in ("```", "~~~"):
            end = query.find(fence, i + 3)
            end = n if end < 0 else end + 3
            out.append(query[i:end])
            i = end
        elif query[i] == "@" and i + 1 < n and query[i + 1] in "'\"":
            end = query.find(query[i + 1], i + 2)
            end = n if end < 0 else end + 1
            out.append(query[i:end])
            i = end
        elif query[i] in "'\"":
            quote, j = query[i], i + 1
            while j < n and query[j] not in (quote, "\n"):
                j += 2 if query[j] == "\\" else 1
            out.append(query[i : j + 1])
            i = j + 1
        elif query.startswith("//", i):
            end = query.find("\n", i)
            out.append(" ")
            i = n if end < 0 else end
        else:
            out.append(query[i])
            i += 1
    return "".join(out)


def cross_scope_reason(query: str) -> str | None:
    """Name of the first cross-scope construct in `query`, else None.

    Checked on three readings of the query (raw, naive // stripping, string-aware stripping)
    and refused if any shows a call: a crafted query can fool one lexer interpretation, but
    must then be visible to another.
    """
    naive = re.sub(r"//[^\n]*", " ", query)
    for candidate in (query, naive, strip_comments(query)):
        found = CROSS_SCOPE.search(candidate)
        if found:
            return found.group(0)
    return None


_DURATION_PART = re.compile(r"(T?)([0-9]+)([DHMS])")
_DAYS_PER_UNIT = {"D": 1.0, "H": 1 / 24, "S": 1 / 86_400}

THREAT_INDICATORS_KQL = """ThreatIntelIndicators
| where IsActive == true and IsDeleted == false
| summarize arg_max(TimeGenerated, *) by Id
| top 200 by TimeGenerated desc
| project TimeGenerated, ObservableKey, ObservableValue, Confidence, SourceSystem,
          ValidFrom, ValidUntil, Tags"""


def duration_days(value: str) -> float:
    """Length of an ISO 8601 duration in days (M before T is months = 30 days)."""
    days, in_time = 0.0, False
    for t, number, unit in _DURATION_PART.findall(value):
        in_time = in_time or t == "T"
        if unit == "M":
            days += int(number) * (1 / 1440 if in_time else 30)
        else:
            days += int(number) * _DAYS_PER_UNIT[unit]
    return days


def table_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    """First result table as a list of {column: value} rows."""
    tables = result.get("tables") or []
    if not tables:
        return []
    columns = [c.get("name") for c in tables[0].get("columns", [])]
    return [dict(zip(columns, row, strict=False)) for row in tables[0].get("rows", [])]


def project_incident(item: dict[str, Any]) -> dict[str, Any]:
    props = item.get("properties", {})
    extra = props.get("additionalData", {})
    return {
        "incidentId": item.get("name"),
        "incidentNumber": props.get("incidentNumber"),
        "title": props.get("title"),
        "severity": props.get("severity"),
        "status": props.get("status"),
        "owner": (props.get("owner") or {}).get("assignedTo"),
        "classification": props.get("classification"),
        "createdTimeUtc": props.get("createdTimeUtc"),
        "lastModifiedTimeUtc": props.get("lastModifiedTimeUtc"),
        "alertsCount": extra.get("alertsCount"),
        "tactics": extra.get("tactics"),
    }


def register(s: SecureServer) -> None:
    workspace = (
        f"/subscriptions/{seg(s.settings.subscription_id)}"
        f"/resourceGroups/{seg(s.settings.sentinel_rg)}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{seg(s.settings.sentinel_workspace)}"
    )
    si = f"{workspace}/providers/Microsoft.SecurityInsights"
    api = {"api-version": SENTINEL_API}
    cache: dict[str, str] = {}

    def incident_path(incident_id: str) -> str:
        return f"{si}/incidents/{seg(incident_id)}"

    async def list_all(path: str, **params: str) -> list[dict[str, Any]]:
        return await s.http.paginate(Api.ARM, f"{si}/{path}", params={**api, **params})

    async def workspace_id() -> str:
        """Log Analytics customerId (workspace GUID) for the query API, looked up once."""
        if "id" not in cache:
            found = await s.http.request(
                "GET", Api.ARM, workspace, params={"api-version": WORKSPACE_API}
            )
            cache["id"] = found["properties"]["customerId"]
        return cache["id"]

    async def query_rows(query: str, timespan: str) -> list[dict[str, Any]]:
        result = await s.http.request(
            "POST",
            Api.LA,
            f"/v1/workspaces/{seg(await workspace_id())}/query",
            json={"query": query, "timespan": timespan},
            headers={"Prefer": "wait=60"},
        )
        return table_rows(result)

    async def describe_incident(args: dict[str, Any]) -> dict[str, str]:
        found = await s.http.request("GET", Api.ARM, incident_path(args["incident_id"]), params=api)
        props = found.get("properties", {})
        return {
            "incident": f"#{props.get('incidentNumber')} {props.get('title')}",
            "current status": f"{props.get('status')} / {props.get('severity')}",
        }

    # ── Incidents ───────────────────────────────────────────────────────────

    @s.tool("list_sentinel_incidents", Tier.READ)
    async def list_sentinel_incidents(top: Top = 50) -> list[dict[str, Any]]:
        """List the most recent Sentinel incidents (newest first)."""
        found = await s.http.request(
            "GET",
            Api.ARM,
            f"{si}/incidents",
            params={**api, "$orderby": "properties/createdTimeUtc desc", "$top": str(top)},
        )
        return [project_incident(i) for i in found.get("value", [])]

    @s.tool("get_sentinel_incident", Tier.READ)
    async def get_sentinel_incident(incident_id: Guid) -> dict[str, Any]:
        """Get one Sentinel incident by its ID (the GUID, not the incident number)."""
        return await s.http.request("GET", Api.ARM, incident_path(incident_id), params=api)

    @s.tool(
        "update_sentinel_incident",
        Tier.DESTRUCTIVE,
        retype=("incident_id",),
        show=(
            "status",
            "severity",
            "classification",
            "classification_reason",
            "classification_comment",
        ),
        describe=describe_incident,
    )
    async def update_sentinel_incident(
        incident_id: Guid,
        status: Status | None = None,
        severity: Severity | None = None,
        classification: Classification | None = None,
        classification_reason: ClassificationReason | None = None,
        classification_comment: CommentText | None = None,
    ) -> dict[str, Any]:
        """Update a Sentinel incident's status, severity or classification.

        Closing an incident or lowering its severity hides it from responders; closing
        requires a classification. Uses the incident's etag, so a concurrent edit fails
        instead of being overwritten.
        """
        current = await s.http.request("GET", Api.ARM, incident_path(incident_id), params=api)
        props = {k: v for k, v in current.get("properties", {}).items() if k in WRITABLE}
        changes = {
            "status": status,
            "severity": severity,
            "classification": classification,
            "classificationReason": classification_reason,
            "classificationComment": classification_comment,
        }
        props.update({k: v for k, v in changes.items() if v is not None})
        if props.get("status") == "Closed" and not props.get("classification"):
            raise ToolError("Closing an incident requires a classification")
        updated = await s.http.request(
            "PUT",
            Api.ARM,
            incident_path(incident_id),
            params=api,
            json={"etag": current.get("etag"), "properties": props},
        )
        return project_incident(updated)

    @s.tool("list_sentinel_incident_comments", Tier.READ)
    async def list_sentinel_incident_comments(incident_id: Guid) -> list[dict[str, Any]]:
        """List the comments on a Sentinel incident."""
        return await list_all(f"incidents/{seg(incident_id)}/comments")

    @s.tool("add_sentinel_incident_comment", Tier.WRITE)
    async def add_sentinel_incident_comment(incident_id: Guid, message: CommentText) -> dict:
        """Add a comment to a Sentinel incident (authored by this server's identity)."""
        comment_id = str(uuid.uuid4())
        await s.http.request(
            "PUT",
            Api.ARM,
            f"{incident_path(incident_id)}/comments/{comment_id}",
            params=api,
            json={"properties": {"message": message}},
        )
        return {"incidentId": incident_id, "commentId": comment_id}

    @s.tool("list_sentinel_incident_alerts", Tier.READ)
    async def list_sentinel_incident_alerts(incident_id: Guid) -> list[dict[str, Any]]:
        """List the alerts in a Sentinel incident."""
        found = await s.http.request(
            "POST", Api.ARM, f"{incident_path(incident_id)}/alerts", params=api
        )
        return found.get("value", [])

    @s.tool("list_sentinel_incident_entities", Tier.READ)
    async def list_sentinel_incident_entities(incident_id: Guid) -> dict[str, Any]:
        """List the entities (accounts, hosts, IPs, URLs) in a Sentinel incident."""
        return await s.http.request(
            "POST", Api.ARM, f"{incident_path(incident_id)}/entities", params=api
        )

    # ── Analytics, automation, hunting ──────────────────────────────────────

    @s.tool("list_sentinel_analytics_rules", Tier.READ)
    async def list_sentinel_analytics_rules() -> list[dict[str, Any]]:
        """List Sentinel analytics rules."""
        rules = await list_all("alertRules")
        return [
            {
                "id": r.get("name"),
                "kind": r.get("kind"),
                "displayName": r.get("properties", {}).get("displayName"),
                "enabled": r.get("properties", {}).get("enabled"),
                "severity": r.get("properties", {}).get("severity"),
                "lastModifiedUtc": r.get("properties", {}).get("lastModifiedUtc"),
            }
            for r in rules
        ]

    @s.tool("list_sentinel_analytics_rule_templates", Tier.READ)
    async def list_sentinel_analytics_rule_templates() -> list[dict[str, Any]]:
        """List Sentinel's built-in analytics rule templates."""
        templates = await list_all("alertRuleTemplates")
        return [
            {
                "id": t.get("name"),
                "kind": t.get("kind"),
                "displayName": t.get("properties", {}).get("displayName"),
                "severity": t.get("properties", {}).get("severity"),
                "status": t.get("properties", {}).get("status"),
            }
            for t in templates
        ]

    @s.tool("list_sentinel_automation_rules", Tier.READ)
    async def list_sentinel_automation_rules() -> list[dict[str, Any]]:
        """List Sentinel automation rules (playbook triggers)."""
        rules = await list_all("automationRules")
        return [
            {
                "id": r.get("name"),
                "displayName": r.get("properties", {}).get("displayName"),
                "order": r.get("properties", {}).get("order"),
                "triggersOn": r.get("properties", {}).get("triggeringLogic", {}).get("triggersOn"),
                "actions": len(r.get("properties", {}).get("actions", [])),
            }
            for r in rules
        ]

    @s.tool("list_sentinel_hunting_queries", Tier.READ)
    async def list_sentinel_hunting_queries() -> list[dict[str, Any]]:
        """List hunting queries installed from the Sentinel content hub."""
        items = await list_all("metadata", **{"$filter": "properties/kind eq 'HuntingQuery'"})
        return [
            {
                "id": q.get("name"),
                "displayName": q.get("properties", {}).get("displayName"),
                "description": q.get("properties", {}).get("description"),
            }
            for q in items
        ]

    @s.tool("list_sentinel_bookmarks", Tier.READ)
    async def list_sentinel_bookmarks() -> list[dict[str, Any]]:
        """List Sentinel hunting bookmarks."""
        return await list_all("bookmarks")

    # ── Watchlists, threat intelligence, connectors ─────────────────────────

    @s.tool("list_sentinel_watchlists", Tier.READ)
    async def list_sentinel_watchlists() -> list[dict[str, Any]]:
        """List Sentinel watchlists."""
        lists = await list_all("watchlists")
        return [
            {
                "alias": w.get("properties", {}).get("watchlistAlias"),
                "displayName": w.get("properties", {}).get("displayName"),
                "searchKey": w.get("properties", {}).get("itemsSearchKey"),
                "provider": w.get("properties", {}).get("provider"),
                "updated": w.get("properties", {}).get("updated"),
            }
            for w in lists
        ]

    @s.tool("list_sentinel_watchlist_items", Tier.READ)
    async def list_sentinel_watchlist_items(watchlist_alias: WatchlistAlias) -> list[Any]:
        """List the items in one Sentinel watchlist."""
        items = await list_all(f"watchlists/{seg(watchlist_alias)}/watchlistItems")
        return [i.get("properties", {}).get("itemsKeyValue") for i in items]

    @s.tool("list_sentinel_threat_indicators", Tier.READ)
    async def list_sentinel_threat_indicators() -> list[dict[str, Any]]:
        """List the 200 most recent active threat indicators (ThreatIntelIndicators, STIX)."""
        return await query_rows(THREAT_INDICATORS_KQL, "P90D")

    @s.tool("list_sentinel_data_connectors", Tier.READ)
    async def list_sentinel_data_connectors() -> list[dict[str, Any]]:
        """List Sentinel data connectors and the state of each data type."""
        connectors = await list_all("dataConnectors")
        return [
            {
                "id": c.get("name"),
                "kind": c.get("kind"),
                "dataTypes": c.get("properties", {}).get("dataTypes"),
            }
            for c in connectors
        ]

    # ── KQL ─────────────────────────────────────────────────────────────────

    @s.tool("run_sentinel_kql_query", Tier.READ)
    async def run_sentinel_kql_query(query: KqlText, timespan: IsoDuration = "P1D") -> list:
        """Run a read-only KQL query against this server's Sentinel workspace.

        Limited to this workspace (cross-workspace/cross-service functions are refused),
        a timespan of at most P90D, and 60 seconds of server time.
        """
        if cross_scope_reason(query):
            raise ToolError(
                "Cross-workspace/cross-service access (workspace, app, resource, adx, arg, "
                "cluster, database, externaldata, external_table) is not allowed"
            )
        if duration_days(timespan) > MAX_KQL_DAYS:
            raise ToolError(f"timespan is capped at P{MAX_KQL_DAYS}D")
        return await query_rows(query, timespan)

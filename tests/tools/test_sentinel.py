"""Sentinel tools against respx-mocked ARM and Log Analytics."""

import json

import pytest
import respx
from helpers import FakeCred, answer, text
from mcp import Client

from azsec_mcp.http import AzureHttp
from azsec_mcp.tools import sentinel

pytestmark = pytest.mark.anyio

ARM = "https://management.azure.com"
LA = "https://api.loganalytics.io"
SUB = "33333333-3333-3333-3333-333333333333"
WS_PATH = (
    f"{ARM}/subscriptions/{SUB}/resourceGroups/rg-sentinel"
    "/providers/Microsoft.OperationalInsights/workspaces/law-test"
)
SI = f"{WS_PATH}/providers/Microsoft.SecurityInsights"
INCIDENT = "73e01a99-5cd7-4139-a149-9f2736ff2ab5"
CUSTOMER_ID = "dddddddd-0000-0000-0000-000000000004"

EXPECTED_TOOLS = {
    "list_sentinel_incidents",
    "get_sentinel_incident",
    "update_sentinel_incident",
    "list_sentinel_analytics_rules",
    "run_sentinel_kql_query",
    "list_sentinel_incident_comments",
    "add_sentinel_incident_comment",
    "list_sentinel_incident_alerts",
    "list_sentinel_incident_entities",
    "list_sentinel_analytics_rule_templates",
    "list_sentinel_hunting_queries",
    "list_sentinel_bookmarks",
    "list_sentinel_watchlists",
    "list_sentinel_watchlist_items",
    "list_sentinel_threat_indicators",
    "list_sentinel_data_connectors",
    "list_sentinel_automation_rules",
}

CURRENT = {
    "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
    "name": INCIDENT,
    "properties": {
        "title": "Suspicious sign-in",
        "severity": "High",
        "status": "Active",
        "description": "d",
        "incidentNumber": 3177,
        "incidentUrl": "https://portal",
        "additionalData": {"alertsCount": 2},
        "createdTimeUtc": "2026-10-24T00:00:00Z",
        "labels": [],
    },
}


@pytest.fixture
def server(make_server, http_client):
    def factory(max_tier="destructive"):
        s = make_server(max_tier, http=AzureHttp(FakeCred(), http_client))
        sentinel.register(s)
        return s

    return factory


def mock_incident():
    return respx.get(f"{SI}/incidents/{INCIDENT}").respond(json=CURRENT)


def mock_workspace():
    return respx.get(WS_PATH).respond(json={"properties": {"customerId": CUSTOMER_ID}})


def la_result(columns, rows):
    return {
        "tables": [
            {"name": "PrimaryResult", "columns": [{"name": c} for c in columns], "rows": rows}
        ]
    }


async def test_all_sentinel_tools_registered(server):
    async with Client(server().mcp) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == EXPECTED_TOOLS


@respx.mock
async def test_arm_calls_use_2025_api(server):
    routes = [
        respx.get(f"{SI}/alertRules").respond(json={"value": []}),
        respx.get(f"{SI}/automationRules").respond(json={"value": []}),
        respx.get(f"{SI}/dataConnectors").respond(json={"value": []}),
        respx.get(f"{SI}/bookmarks").respond(json={"value": []}),
    ]
    async with Client(server("read").mcp) as c:
        for tool in (
            "list_sentinel_analytics_rules",
            "list_sentinel_automation_rules",
            "list_sentinel_data_connectors",
            "list_sentinel_bookmarks",
        ):
            assert (await c.call_tool(tool, {})).is_error is False
    for route in routes:
        assert route.calls.last.request.url.params["api-version"] == "2025-09-01"


# ── update_sentinel_incident ─────────────────────────────────────────────────


@respx.mock
async def test_update_incident_sends_only_writable_fields_and_etag(server):
    mock_incident()
    put = respx.put(f"{SI}/incidents/{INCIDENT}").respond(json=CURRENT)
    args = {
        "incident_id": INCIDENT,
        "status": "Closed",
        "classification": "TruePositive",
        "classification_reason": "SuspiciousActivity",
        "classification_comment": "Confirmed compromise",
    }
    async with Client(server().mcp, elicitation_callback=answer(INCIDENT)) as c:
        result = await c.call_tool("update_sentinel_incident", args)
    assert result.is_error is False
    sent = json.loads(put.calls.last.request.content)
    assert sent["etag"] == CURRENT["etag"]
    props = sent["properties"]
    assert props["status"] == "Closed"
    assert props["classification"] == "TruePositive"
    assert props["title"] == "Suspicious sign-in" and props["severity"] == "High"
    for read_only in ("incidentNumber", "incidentUrl", "additionalData", "createdTimeUtc"):
        assert read_only not in props


@respx.mock(assert_all_called=False)
async def test_close_without_classification_refused(server, respx_mock):
    respx_mock.get(f"{SI}/incidents/{INCIDENT}").respond(json=CURRENT)
    put = respx_mock.put(f"{SI}/incidents/{INCIDENT}").respond(json=CURRENT)
    async with Client(server().mcp, elicitation_callback=answer(INCIDENT)) as c:
        result = await c.call_tool(
            "update_sentinel_incident", {"incident_id": INCIDENT, "status": "Closed"}
        )
    assert result.is_error is True
    assert "classification" in text(result)
    assert put.call_count == 0


@pytest.mark.parametrize(
    "bad",
    [{"status": "Resolved"}, {"severity": "Critical"}, {"classification": "Malicious"}],
)
@respx.mock(assert_all_called=False)
async def test_update_incident_rejects_unknown_enums(server, respx_mock, bad):
    anything = respx_mock.route().respond(json={})
    async with Client(server().mcp, elicitation_callback=answer(INCIDENT)) as c:
        result = await c.call_tool("update_sentinel_incident", {"incident_id": INCIDENT, **bad})
    assert result.is_error is True
    assert anything.call_count == 0


@respx.mock
async def test_update_incident_is_destructive_and_prompt_identifies_it(server):
    mock_incident()
    put = respx.put(f"{SI}/incidents/{INCIDENT}").respond(json=CURRENT)
    asked: list[str] = []
    args = {"incident_id": INCIDENT, "severity": "Low"}
    async with Client(server().mcp, elicitation_callback=answer("3177", asked=asked)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        result = await c.call_tool("update_sentinel_incident", args)
    annotations = tools["update_sentinel_incident"].annotations
    assert annotations is not None and annotations.destructive_hint is True
    assert result.is_error is True
    assert put.call_count == 0
    assert "Suspicious sign-in" in asked[0] and "3177" in asked[0] and "Active" in asked[0]
    assert "severity: Low" in asked[0]


@respx.mock
async def test_update_incident_etag_conflict_reported(server):
    mock_incident()
    respx.put(f"{SI}/incidents/{INCIDENT}").respond(
        412, json={"error": {"code": "PreconditionFailed", "message": "etag mismatch"}}
    )
    async with Client(server().mcp, elicitation_callback=answer(INCIDENT)) as c:
        result = await c.call_tool(
            "update_sentinel_incident", {"incident_id": INCIDENT, "status": "Active"}
        )
    assert result.is_error is True
    assert "PreconditionFailed" in text(result)


# ── KQL ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "query",
    [
        'workspace("other").SecurityEvent | take 1',
        "union app('fabrikam').requests",
        'RESOURCE ("/subscriptions/x").AzureActivity',
        "adx('https://help.kusto.windows.net').StormEvents",
        "arg('').Resources",
        'workspace // hide the call\n("other").SecurityEvent',
        "['workspace'](\"other\").SecurityEvent",
        'print "https://x"; workspace("other").SecurityEvent',
        "cluster('help').database('Samples').StormEvents",
        "database('other').SecurityEvent",
        "externaldata (x:string) ['https://evil.example/a.csv']",
        "external_table('t')",
        'print "//", workspace // c\n("other").SecurityEvent',
        "print @'c:\\//', workspace // c\n('other').SecurityEvent",
        "print 'it\\'s //', workspace // c\n('other').SecurityEvent",
        "print ```//\nmulti```, workspace // c\n('other').SecurityEvent",
        "print ~~~//\nmulti~~~, workspace // c\n('other').SecurityEvent",
        'print \'unterminated\nworkspace // c\n("other").SecurityEvent',
    ],
)
@respx.mock(assert_all_called=False)
async def test_kql_cross_scope_functions_blocked(server, respx_mock, query):
    anything = respx_mock.route().respond(json={})
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("run_sentinel_kql_query", {"query": query})
    assert result.is_error is True
    assert anything.call_count == 0


@respx.mock(assert_all_called=False)
async def test_kql_timespan_capped(server, respx_mock):
    anything = respx_mock.route().respond(json={})
    async with Client(server("read").mcp) as c:
        bad = await c.call_tool(
            "run_sentinel_kql_query", {"query": "Heartbeat", "timespan": "P91D"}
        )
    assert bad.is_error is True
    assert anything.call_count == 0


@respx.mock
async def test_kql_shapes_rows_sends_timeout_and_caches_workspace(server):
    ws = mock_workspace()
    query = respx.post(f"{LA}/v1/workspaces/{CUSTOMER_ID}/query").respond(
        json=la_result(["Computer", "Count"], [["vm-1", 3], ["vm-2", 5]])
    )
    async with Client(server("read").mcp) as c:
        first = await c.call_tool(
            "run_sentinel_kql_query", {"query": "Heartbeat | count", "timespan": "PT12H"}
        )
        await c.call_tool("run_sentinel_kql_query", {"query": "Heartbeat | count"})
    assert json.loads(text(first))["data"] == [
        {"Computer": "vm-1", "Count": 3},
        {"Computer": "vm-2", "Count": 5},
    ]
    assert query.calls.last.request.headers["Prefer"] == "wait=60"
    assert json.loads(query.calls[0].request.content)["timespan"] == "PT12H"
    assert ws.call_count == 1


@respx.mock
async def test_threat_indicators_query_new_table(server):
    mock_workspace()
    query = respx.post(f"{LA}/v1/workspaces/{CUSTOMER_ID}/query").respond(
        json=la_result(["ObservableValue"], [["1.2.3.4"]])
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_sentinel_threat_indicators", {})
    sent = json.loads(query.calls.last.request.content)["query"]
    assert sent.startswith("ThreatIntelIndicators")
    assert (
        "ThreatIntelligenceIndicator " not in sent and "ThreatIntelligenceIndicator\n" not in sent
    )
    assert json.loads(text(result))["data"] == [{"ObservableValue": "1.2.3.4"}]


# ── Lists and mappings ───────────────────────────────────────────────────────


@respx.mock
async def test_list_incidents_top_and_projection(server):
    route = respx.get(f"{SI}/incidents").respond(json={"value": [CURRENT]})
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_sentinel_incidents", {"top": 10})
        too_many = await c.call_tool("list_sentinel_incidents", {"top": 201})
        zero = await c.call_tool("list_sentinel_incidents", {"top": 0})
    params = route.calls.last.request.url.params
    assert params["$top"] == "10"
    assert params["$orderby"] == "properties/createdTimeUtc desc"
    row = json.loads(text(result))["data"][0]
    assert row["incidentNumber"] == 3177 and row["title"] == "Suspicious sign-in"
    assert row["alertsCount"] == 2
    assert "incidentUrl" not in row
    assert too_many.is_error is True and zero.is_error is True


@respx.mock
async def test_watchlist_mapping_fixed(server):
    respx.get(f"{SI}/watchlists").respond(
        json={
            "value": [
                {
                    "properties": {
                        "watchlistAlias": "vip",
                        "displayName": "VIP users",
                        "itemsSearchKey": "UPN",
                    }
                }
            ]
        }
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_sentinel_watchlists", {})
    row = json.loads(text(result))["data"][0]
    assert row["searchKey"] == "UPN"
    assert "itemsCount" not in row


@respx.mock
async def test_data_connector_mapping_fixed(server):
    respx.get(f"{SI}/dataConnectors").respond(
        json={
            "value": [
                {
                    "name": "azureactivedirectory",
                    "kind": "AzureActiveDirectory",
                    "properties": {"dataTypes": {"alerts": {"state": "Enabled"}}},
                }
            ]
        }
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_sentinel_data_connectors", {})
    row = json.loads(text(result))["data"][0]
    assert row["dataTypes"] == {"alerts": {"state": "Enabled"}}
    assert "state" not in row


@respx.mock
async def test_comment_uses_uuid_and_is_bounded(server):
    put = respx.put(url__regex=rf"{SI}/incidents/{INCIDENT}/comments/[0-9a-f-]{{36}}").respond(
        201, json={"name": "c1"}
    )
    async with Client(server("write").mcp) as c:
        ok = await c.call_tool(
            "add_sentinel_incident_comment", {"incident_id": INCIDENT, "message": "Triaged."}
        )
        long = await c.call_tool(
            "add_sentinel_incident_comment", {"incident_id": INCIDENT, "message": "x" * 4001}
        )
    assert ok.is_error is False
    assert put.call_count == 1
    assert json.loads(put.calls.last.request.content) == {"properties": {"message": "Triaged."}}
    assert long.is_error is True


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("get_sentinel_incident", {"incident_id": "../../x"}),
        ("list_sentinel_incident_alerts", {"incident_id": f"{INCIDENT}/../../../x"}),
        ("list_sentinel_incident_entities", {"incident_id": "x?y"}),
        ("list_sentinel_watchlist_items", {"watchlist_alias": "../vip"}),
    ],
)
@respx.mock(assert_all_called=False)
async def test_ids_reject_traversal(server, respx_mock, tool, args):
    anything = respx_mock.route().respond(json={})
    async with Client(server("read").mcp) as c:
        result = await c.call_tool(tool, args)
    assert result.is_error is True
    assert anything.call_count == 0


@respx.mock
async def test_incident_alerts_and_entities_post(server):
    alerts = respx.post(f"{SI}/incidents/{INCIDENT}/alerts").respond(json={"value": [{"a": 1}]})
    entities = respx.post(f"{SI}/incidents/{INCIDENT}/entities").respond(json={"entities": []})
    async with Client(server("read").mcp) as c:
        await c.call_tool("list_sentinel_incident_alerts", {"incident_id": INCIDENT})
        await c.call_tool("list_sentinel_incident_entities", {"incident_id": INCIDENT})
    assert alerts.call_count == 1 and entities.call_count == 1


def test_cross_scope_check_has_no_false_negative_for_plain_queries():
    assert sentinel.cross_scope_reason("SigninLogs | where AppDisplayName has 'workspace'") is None
    assert sentinel.cross_scope_reason("SecurityEvent | summarize count() by Computer") is None


def test_strip_comments_keeps_strings_and_removes_real_comments():
    q = "print \"a//b\", @'x//y' // real comment\n| take 1"
    # The space before // is kept and the comment itself becomes one space.
    assert sentinel.strip_comments(q) == "print \"a//b\", @'x//y'  \n| take 1"

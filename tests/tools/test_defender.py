"""Defender for Cloud tools against respx-mocked ARM."""

import json

import pytest
import respx
from helpers import FakeCred, answer, text
from mcp import Client

from azsec_mcp.http import AzureHttp
from azsec_mcp.tools import defender

pytestmark = pytest.mark.anyio

ARM = "https://management.azure.com"
SUB = "33333333-3333-3333-3333-333333333333"
SEC = f"{ARM}/subscriptions/{SUB}/providers/Microsoft.Security"
ALERT = "2518298467986649999_aaaabbbb-cccc-dddd-eeee-ffff00001111"
RG = "rg-sentinel"
LOC = "centralus"
RG_ALERT = (
    f"{ARM}/subscriptions/{SUB}/resourceGroups/{RG}"
    f"/providers/Microsoft.Security/locations/{LOC}/alerts/{ALERT}"
)


@pytest.fixture
def server(make_server, http_client):
    def factory(max_tier="destructive"):
        s = make_server(max_tier, http=AzureHttp(FakeCred(), http_client))
        defender.register(s)
        return s

    return factory


def mock_alert_description():
    respx.get(RG_ALERT).respond(
        json={"properties": {"alertDisplayName": "Suspicious PowerShell", "severity": "High"}}
    )


async def test_all_defender_tools_registered(server):
    async with Client(server().mcp) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == {
        "list_defender_alerts",
        "get_secure_score",
        "list_defender_recommendations",
        "update_defender_alert",
    }


@pytest.mark.parametrize(
    ("status", "action"),
    [
        ("Dismissed", "dismiss"),
        ("Resolved", "resolve"),
        ("Active", "activate"),
        ("InProgress", "inProgress"),
    ],
)
@respx.mock
async def test_update_alert_uses_documented_post_action(server, status, action):
    mock_alert_description()
    post = respx.post(f"{RG_ALERT}/{action}").respond(204)
    patch = respx.patch(url__regex=r".*").respond(200)
    args = {"alert_name": ALERT, "asc_location": LOC, "status": status, "resource_group": RG}
    async with Client(server().mcp, elicitation_callback=answer(ALERT)) as c:
        result = await c.call_tool("update_defender_alert", args)
    assert result.is_error is False
    assert post.call_count == 1
    assert post.calls.last.request.url.params["api-version"] == defender.ALERTS_API
    assert patch.call_count == 0


@respx.mock
async def test_subscription_level_alert_path(server):
    respx.get(f"{SEC}/locations/{LOC}/alerts/{ALERT}").respond(json={"properties": {}})
    post = respx.post(f"{SEC}/locations/{LOC}/alerts/{ALERT}/resolve").respond(204)
    async with Client(server().mcp, elicitation_callback=answer(ALERT)) as c:
        result = await c.call_tool(
            "update_defender_alert",
            {"alert_name": ALERT, "asc_location": LOC, "status": "Resolved"},
        )
    assert result.is_error is False
    assert post.call_count == 1


@respx.mock
async def test_update_alert_is_destructive_and_confirmed(server):
    mock_alert_description()
    post = respx.post(f"{RG_ALERT}/dismiss").respond(204)
    args = {"alert_name": ALERT, "asc_location": LOC, "status": "Dismissed", "resource_group": RG}
    asked: list[str] = []
    async with Client(server().mcp, elicitation_callback=answer("wrong", asked=asked)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        result = await c.call_tool("update_defender_alert", args)
    annotations = tools["update_defender_alert"].annotations
    assert annotations is not None and annotations.destructive_hint is True
    assert result.is_error is True
    assert post.call_count == 0
    assert "status: Dismissed" in asked[0]
    assert "Suspicious PowerShell" in asked[0] and "High" in asked[0]


@pytest.mark.parametrize(
    "args",
    [
        {"alert_name": "../x", "asc_location": LOC, "status": "Dismissed"},
        {"alert_name": ALERT, "asc_location": "east us", "status": "Dismissed"},
        {"alert_name": ALERT, "asc_location": LOC, "status": "Closed"},
    ],
)
@respx.mock(assert_all_called=False)
async def test_alert_arguments_validated(server, respx_mock, args):
    anything = respx_mock.route().respond(204)
    async with Client(server().mcp, elicitation_callback=answer(ALERT)) as c:
        result = await c.call_tool("update_defender_alert", args)
    assert result.is_error is True
    assert anything.call_count == 0


@respx.mock
async def test_list_alerts_paginates_and_parses_location(server):
    def alert(name, rg_part):
        return {
            "id": f"/subscriptions/{SUB}{rg_part}/providers/Microsoft.Security"
            f"/locations/{LOC}/alerts/{name}",
            "name": name,
            "properties": {"alertDisplayName": "x", "severity": "Low", "status": "Active"},
        }

    respx.get(f"{SEC}/alerts", params={"page": "2"}).respond(json={"value": [alert("b", "")]})
    respx.get(f"{SEC}/alerts").respond(
        json={"value": [alert("a", f"/resourceGroups/{RG}")], "nextLink": f"{SEC}/alerts?page=2"}
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_defender_alerts", {})
    rows = json.loads(text(result))["data"]
    assert [r["name"] for r in rows] == ["a", "b"]
    assert rows[0]["resourceGroup"] == RG and rows[0]["location"] == LOC
    assert rows[1]["resourceGroup"] is None and rows[1]["location"] == LOC


@respx.mock
async def test_recommendations_use_2025_api(server):
    route = respx.get(f"{SEC}/assessments").respond(
        json={
            "value": [
                {
                    "name": "rec-1",
                    "properties": {
                        "displayName": "Enable MFA",
                        "status": {"code": "Unhealthy"},
                        "resourceDetails": {
                            "Id": "/subscriptions/x/resourceGroups/rg/providers/vm/1"
                        },
                    },
                }
            ]
        }
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_defender_recommendations", {})
    assert route.calls.last.request.url.params["api-version"] == "2025-05-04"
    row = json.loads(text(result))["data"][0]
    assert row == {
        "name": "rec-1",
        "displayName": "Enable MFA",
        "status": "Unhealthy",
        "resourceId": "/subscriptions/x/resourceGroups/rg/providers/vm/1",
    }

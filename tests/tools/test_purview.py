"""Purview, eDiscovery and Entra log tools, the capability-gaps resource, and JS parity."""

import json

import pytest
import respx
from helpers import FakeCred, text
from mcp import Client

from azsec_mcp.http import AzureHttp
from azsec_mcp.resources import CAPABILITY_GAPS
from azsec_mcp.tools import register_all

pytestmark = pytest.mark.anyio

GRAPH = "https://graph.microsoft.com"
CASE = "b0073e4e-4184-41c6-9eb7-8c8cc3e2288b"
LABEL = "eeeeeeee-0000-0000-0000-000000000005"
UPN = "emma.richardson@cavalry77.onmicrosoft.com"

# Every tool name the JS server.js exposed (TOOL_TIERS), frozen at the rewrite.
JS_TOOLS = """
list_resource_groups create_resource_group delete_resource_group assign_role create_user
delete_user list_role_assignments list_users list_graph_users list_aus create_au assign_au_role
add_au_member list_intune_devices list_noncompliant_devices sync_intune_device
list_intune_compliance_policies get_intune_device retire_intune_device wipe_intune_device
reboot_intune_device list_intune_configuration_profiles list_intune_apps
list_intune_app_assignments list_intune_autopilot_devices list_intune_enrollment_configurations
list_intune_scripts list_intune_remediation_scripts list_intune_managed_app_policies
list_defender_alerts get_secure_score list_defender_recommendations update_defender_alert
list_sentinel_incidents get_sentinel_incident update_sentinel_incident
list_sentinel_analytics_rules run_sentinel_kql_query list_sentinel_incident_comments
add_sentinel_incident_comment list_sentinel_incident_alerts list_sentinel_incident_entities
list_sentinel_analytics_rule_templates list_sentinel_hunting_queries list_sentinel_bookmarks
list_sentinel_watchlists list_sentinel_watchlist_items list_sentinel_threat_indicators
list_sentinel_data_connectors list_sentinel_automation_rules list_sensitivity_labels
get_sensitivity_label list_sensitive_info_types list_label_policies list_dlp_policies
list_dlp_alerts list_insider_risk_alerts list_insider_risk_policies
list_information_barrier_policies list_information_barrier_segments list_ediscovery_cases
get_ediscovery_case list_ediscovery_custodians list_ediscovery_holds list_ediscovery_searches
list_ediscovery_review_sets list_retention_labels list_retention_event_types list_audit_logs
list_signin_logs list_communication_compliance_policies list_compliance_assessments
get_compliance_assessment list_compliance_improvement_actions get_dspm_insights
""".split()


@pytest.fixture
def server(make_server, http_client):
    def factory(max_tier="read"):
        s = make_server(max_tier, http=AzureHttp(FakeCred(), http_client))
        register_all(s)
        return s

    return factory


async def test_parity_every_js_tool_is_registered_or_a_documented_gap(server):
    assert len(JS_TOOLS) == 75
    async with Client(server().mcp) as c:
        registered = {t.name for t in (await c.list_tools()).tools}
    gaps = set(CAPABILITY_GAPS)
    missing = [name for name in JS_TOOLS if name not in registered and name not in gaps]
    assert missing == []
    assert not (registered & gaps)  # a capability is never both a tool and a gap


async def test_capability_gaps_resource(server):
    async with Client(server().mcp) as c:
        result = await c.read_resource("azsec://capability-gaps")
    gaps = json.loads(result.contents[0].text)  # type: ignore[union-attr]
    assert "delegated" in gaps["list_retention_labels"]["reason"].lower()
    assert "fake" not in json.dumps(gaps).lower()
    for gap in gaps.values():
        assert gap["docsUrl"].startswith("https://learn.microsoft.com/")
        assert gap["reason"] and gap["alternative"]


@respx.mock
async def test_dlp_alerts_are_a_real_tool(server):
    route = respx.get(f"{GRAPH}/v1.0/security/alerts_v2").respond(json={"value": [{"id": "a1"}]})
    async with Client(server().mcp) as c:
        result = await c.call_tool("list_dlp_alerts", {})
    assert route.calls.last.request.url.params["$filter"] == "serviceSource eq 'dataLossPrevention'"
    assert json.loads(text(result))["data"] == [{"id": "a1"}]


@respx.mock
async def test_ediscovery_holds_use_legal_holds(server):
    holds = respx.get(f"{GRAPH}/v1.0/security/cases/ediscoveryCases/{CASE}/legalHolds").respond(
        json={"value": []}
    )
    wrong = respx.get(url__regex=r".*noncustodialDataSources.*").respond(json={"value": []})
    async with Client(server().mcp) as c:
        result = await c.call_tool("list_ediscovery_holds", {"case_id": CASE})
    assert result.is_error is False
    assert holds.call_count == 1 and wrong.call_count == 0


@pytest.mark.parametrize(
    ("tool", "suffix"),
    [
        ("get_ediscovery_case", ""),
        ("list_ediscovery_custodians", "/custodians"),
        ("list_ediscovery_searches", "/searches"),
        ("list_ediscovery_review_sets", "/reviewSets"),
    ],
)
@respx.mock
async def test_ediscovery_case_paths(server, tool, suffix):
    route = respx.get(f"{GRAPH}/v1.0/security/cases/ediscoveryCases/{CASE}{suffix}").respond(
        json={"value": []}
    )
    async with Client(server().mcp) as c:
        result = await c.call_tool(tool, {"case_id": CASE})
    assert result.is_error is False and route.call_count == 1


@respx.mock(assert_all_called=False)
async def test_case_id_rejects_traversal(server, respx_mock):
    anything = respx_mock.route().respond(json={})
    async with Client(server().mcp) as c:
        result = await c.call_tool("list_ediscovery_holds", {"case_id": "../../users"})
    assert result.is_error is True and anything.call_count == 0


@respx.mock
async def test_retention_event_types_real_v1(server):
    route = respx.get(f"{GRAPH}/v1.0/security/triggerTypes/retentionEventTypes").respond(
        json={"value": [{"displayName": "Employee departure"}]}
    )
    async with Client(server().mcp) as c:
        result = await c.call_tool("list_retention_event_types", {})
    assert result.is_error is False and route.call_count == 1


@respx.mock
async def test_sensitivity_labels_use_documented_user_path(server):
    route = respx.get(
        f"{GRAPH}/beta/users/{UPN}/security/informationProtection/sensitivityLabels"
    ).respond(json={"value": [{"id": LABEL, "name": "Confidential"}]})
    one = respx.get(
        f"{GRAPH}/beta/users/{UPN}/security/informationProtection/sensitivityLabels/{LABEL}"
    ).respond(json={"id": LABEL})
    async with Client(server().mcp) as c:
        listed = await c.call_tool("list_sensitivity_labels", {"user": UPN})
        got = await c.call_tool("get_sensitivity_label", {"user": UPN, "label_id": LABEL})
    assert listed.is_error is False and got.is_error is False
    assert route.call_count == 1 and one.call_count == 1


@pytest.mark.parametrize("tool", ["list_audit_logs", "list_signin_logs"])
@respx.mock
async def test_entra_logs_top_bounded_and_filter_passed(server, tool):
    path = "directoryAudits" if tool == "list_audit_logs" else "signIns"
    route = respx.get(f"{GRAPH}/v1.0/auditLogs/{path}").respond(json={"value": []})
    async with Client(server().mcp) as c:
        ok = await c.call_tool(
            tool, {"top": 25, "filter": "createdDateTime ge 2026-10-01T00:00:00Z"}
        )
        too_many = await c.call_tool(tool, {"top": 201})
        long_filter = await c.call_tool(tool, {"filter": "x" * 501})
    params = route.calls.last.request.url.params
    assert ok.is_error is False
    assert params["$top"] == "25"
    assert params["$filter"] == "createdDateTime ge 2026-10-01T00:00:00Z"
    assert too_many.is_error is True and long_filter.is_error is True
    assert route.call_count == 1


async def test_server_exposes_65_tools(server):
    async with Client(server().mcp) as c:
        assert len((await c.list_tools()).tools) == 65

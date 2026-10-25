"""Intune tools against respx-mocked Graph, including the research finding #1 regression."""

import json

import pytest
import respx
from helpers import FakeCred, answer, text
from mcp import Client

from azsec_mcp.http import AzureHttp
from azsec_mcp.tools import intune

pytestmark = pytest.mark.anyio

GRAPH = "https://graph.microsoft.com"
DEVICES = f"{GRAPH}/v1.0/deviceManagement/managedDevices"
DEVICE = "0f8fad5b-d9cb-469f-a165-70867728950e"
APP = "cccccccc-0000-0000-0000-000000000009"

EXPECTED_TOOLS = {
    "list_intune_devices",
    "list_noncompliant_devices",
    "sync_intune_device",
    "list_intune_compliance_policies",
    "get_intune_device",
    "retire_intune_device",
    "wipe_intune_device",
    "reboot_intune_device",
    "list_intune_configuration_profiles",
    "list_intune_apps",
    "list_intune_app_assignments",
    "list_intune_autopilot_devices",
    "list_intune_enrollment_configurations",
    "list_intune_scripts",
    "list_intune_remediation_scripts",
    "list_intune_managed_app_policies",
}


@pytest.fixture
def server(make_server, http_client):
    def factory(max_tier="destructive"):
        s = make_server(max_tier, http=AzureHttp(FakeCred(), http_client))
        intune.register(s)
        return s

    return factory


def mock_device_description():
    respx.get(f"{DEVICES}/{DEVICE}").respond(
        json={
            "deviceName": "CAV-LAPTOP-07",
            "operatingSystem": "Windows",
            "osVersion": "11 24H2",
            "userPrincipalName": "emma.richardson@cavalry77.onmicrosoft.com",
            "serialNumber": "5CG1234XYZ",
        }
    )


async def test_all_intune_tools_registered(server):
    async with Client(server().mcp) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == EXPECTED_TOOLS


@respx.mock(assert_all_called=False)
async def test_reboot_cannot_reach_wipe(server, respx_mock):
    # Research finding #1: in server.js this deviceId turned a WRITE-tier reboot
    # into POST .../managedDevices/X/wipe (a DESTRUCTIVE wipe).
    anything = respx_mock.route().respond(204)
    async with Client(server().mcp) as c:
        result = await c.call_tool("reboot_intune_device", {"device_id": "X/wipe?"})
    assert result.is_error is True
    assert anything.call_count == 0


@pytest.mark.parametrize(
    "tool",
    [
        "sync_intune_device",
        "get_intune_device",
        "retire_intune_device",
        "wipe_intune_device",
        "reboot_intune_device",
    ],
)
@pytest.mark.parametrize("payload", ["../users", f"{DEVICE}%2F..", f"{DEVICE}?x=1", f"{DEVICE}#x"])
@respx.mock(assert_all_called=False)
async def test_device_id_traversal_variants_rejected(server, respx_mock, tool, payload):
    anything = respx_mock.route().respond(204)
    async with Client(server().mcp, elicitation_callback=answer(payload)) as c:
        result = await c.call_tool(tool, {"device_id": payload})
    assert result.is_error is True
    assert anything.call_count == 0


@respx.mock
async def test_wipe_prompt_identifies_physical_device(server):
    mock_device_description()
    respx.post(f"{DEVICES}/{DEVICE}/wipe").respond(204)
    asked: list[str] = []
    async with Client(server().mcp, elicitation_callback=answer(DEVICE, asked=asked)) as c:
        result = await c.call_tool("wipe_intune_device", {"device_id": DEVICE})
    assert result.is_error is False
    prompt = asked[0]
    assert "CAV-LAPTOP-07" in prompt and "5CG1234XYZ" in prompt
    assert "emma.richardson@cavalry77.onmicrosoft.com" in prompt
    assert "keep_user_data: False" in prompt
    assert f"Retype exactly to confirm: {DEVICE}" in prompt


@respx.mock
async def test_wipe_wrong_retype_not_executed(server):
    mock_device_description()
    wipe = respx.post(f"{DEVICES}/{DEVICE}/wipe").respond(204)
    async with Client(server().mcp, elicitation_callback=answer("CAV-LAPTOP-07")) as c:
        result = await c.call_tool("wipe_intune_device", {"device_id": DEVICE})
    assert result.is_error is True
    assert wipe.call_count == 0


@respx.mock
async def test_wipe_body_defaults_and_no_unlock_code(server):
    mock_device_description()
    wipe = respx.post(f"{DEVICES}/{DEVICE}/wipe").respond(204)
    async with Client(server().mcp, elicitation_callback=answer(DEVICE)) as c:
        schema = {t.name: t for t in (await c.list_tools()).tools}[
            "wipe_intune_device"
        ].input_schema
        await c.call_tool("wipe_intune_device", {"device_id": DEVICE})
    assert json.loads(wipe.calls.last.request.content) == {
        "keepUserData": False,
        "keepEnrollmentData": False,
    }
    assert set(schema["properties"]) == {"device_id", "keep_user_data", "keep_enrollment_data"}


@respx.mock
async def test_retire_is_destructive_and_confirmed(server):
    mock_device_description()
    retire = respx.post(f"{DEVICES}/{DEVICE}/retire").respond(204)
    async with Client(server().mcp, elicitation_callback=answer("nope")) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        await c.call_tool("retire_intune_device", {"device_id": DEVICE})
    annotations = tools["retire_intune_device"].annotations
    assert annotations is not None and annotations.destructive_hint is True
    assert retire.call_count == 0
    async with Client(server().mcp, elicitation_callback=answer(DEVICE)) as c:
        result = await c.call_tool("retire_intune_device", {"device_id": DEVICE})
    assert result.is_error is False
    assert retire.call_count == 1


@pytest.mark.parametrize(
    ("tool", "action"),
    [("reboot_intune_device", "rebootNow"), ("sync_intune_device", "syncDevice")],
)
@respx.mock
async def test_write_device_actions_post_without_confirmation(server, tool, action):
    route = respx.post(f"{DEVICES}/{DEVICE}/{action}").respond(204)
    async with Client(server("write").mcp) as c:
        result = await c.call_tool(tool, {"device_id": DEVICE})
    assert result.is_error is False
    assert route.call_count == 1


@respx.mock
async def test_get_device_minimizes_fields(server):
    route = respx.get(f"{DEVICES}/{DEVICE}").respond(json={"id": DEVICE})
    async with Client(server("read").mcp) as c:
        await c.call_tool("get_intune_device", {"device_id": DEVICE})
    selected = route.calls.last.request.url.params["$select"].split(",")
    assert "complianceState" in selected and "serialNumber" in selected
    for pii in ("imei", "phoneNumber", "wiFiMacAddress", "subscriberCarrier", "easDeviceId"):
        assert pii not in selected


@respx.mock
async def test_list_apps_uses_valid_select(server):
    route = respx.get(f"{GRAPH}/v1.0/deviceAppManagement/mobileApps").respond(json={"value": []})
    async with Client(server("read").mcp) as c:
        await c.call_tool("list_intune_apps", {})
    selected = route.calls.last.request.url.params["$select"]
    assert "publishingState" in selected
    assert "appAvailability" not in selected


@pytest.mark.parametrize(
    ("tool", "path", "args"),
    [
        ("list_intune_compliance_policies", "/v1.0/deviceManagement/deviceCompliancePolicies", {}),
        (
            "list_intune_app_assignments",
            f"/v1.0/deviceAppManagement/mobileApps/{APP}/assignments",
            {"app_id": APP},
        ),
        (
            "list_intune_enrollment_configurations",
            "/v1.0/deviceManagement/deviceEnrollmentConfigurations",
            {},
        ),
        ("list_intune_managed_app_policies", "/v1.0/deviceAppManagement/managedAppPolicies", {}),
    ],
)
@respx.mock
async def test_previously_unpaginated_lists_now_paginate(server, tool, path, args):
    respx.get(f"{GRAPH}{path}", params={"page": "2"}).respond(json={"value": [{"id": "2"}]})
    respx.get(f"{GRAPH}{path}").respond(
        json={"value": [{"id": "1"}], "@odata.nextLink": f"{GRAPH}{path}?page=2"}
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool(tool, args)
    assert [i["id"] for i in json.loads(text(result))["data"]] == ["1", "2"]


@pytest.mark.parametrize(
    ("tool", "path"),
    [
        ("list_intune_scripts", "/beta/deviceManagement/deviceManagementScripts"),
        ("list_intune_remediation_scripts", "/beta/deviceManagement/deviceHealthScripts"),
    ],
)
@respx.mock
async def test_scripts_use_beta_endpoint(server, tool, path):
    route = respx.get(f"{GRAPH}{path}").respond(json={"value": []})
    async with Client(server("read").mcp) as c:
        result = await c.call_tool(tool, {})
    assert result.is_error is False
    assert route.call_count == 1


@respx.mock
async def test_noncompliant_filter(server):
    route = respx.get(DEVICES).respond(json={"value": []})
    async with Client(server("read").mcp) as c:
        await c.call_tool("list_noncompliant_devices", {})
    assert route.calls.last.request.url.params["$filter"] == "complianceState eq 'noncompliant'"

"""Identity tools against respx-mocked Graph/ARM: paths, bodies, and the security rules."""

import json

import pytest
import respx
from helpers import FakeCred, answer, text
from mcp import Client

from azsec_mcp.http import AzureHttp
from azsec_mcp.tools import identity

pytestmark = pytest.mark.anyio

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com"
SUB = "33333333-3333-3333-3333-333333333333"  # BASE_ENV subscription
OTHER_SUB = "44444444-4444-4444-4444-444444444444"
SCOPE = f"/subscriptions/{SUB}"
AUTHZ = f"{ARM}{SCOPE}/providers/Microsoft.Authorization"
USER_ID = "aaaaaaaa-0000-0000-0000-000000000001"
UPN = "emma.richardson@cavalry77.onmicrosoft.com"
AU_ID = "bbbbbbbb-0000-0000-0000-000000000002"
JUSTIFICATION = "Lab exercise: test PIM eligibility"


def role_def(guid: str, name: str, actions: list[str]) -> dict:
    return {
        "id": f"{SCOPE}/providers/Microsoft.Authorization/roleDefinitions/{guid}",
        "name": guid,
        "properties": {"roleName": name, "permissions": [{"actions": actions}]},
    }


READER = role_def("acdd72a7-3385-48ef-bd42-f606fba81ae7", "Reader", ["*/read"])
OWNER = role_def("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Owner", ["*"])
UAA = role_def(
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "User Access Administrator",
    ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"],
)
CUSTOM = role_def(
    "cccccccc-0000-0000-0000-000000000003",
    "Lab Role Granter",
    ["Microsoft.Authorization/roleAssignments/write"],
)


@pytest.fixture
def server(make_server, http_client):
    def factory(max_tier="destructive"):
        s = make_server(max_tier, http=AzureHttp(FakeCred(), http_client))
        identity.register(s)
        return s

    return factory


def mock_user_lookup():
    respx.get(f"{GRAPH}/v1.0/users/{UPN}").respond(json={"id": USER_ID})


def mock_role_by_name(definition: dict):
    respx.get(f"{AUTHZ}/roleDefinitions").respond(json={"value": [definition]})


def mock_role_by_id(definition: dict):
    respx.get(f"{AUTHZ}/roleDefinitions/{definition['name']}").respond(json=definition)


def put_assignment():
    return respx.put(url__regex=rf"{AUTHZ}/roleAssignments/[0-9a-f-]{{36}}").respond(201, json={})


def put_eligibility():
    return respx.put(
        url__regex=rf"{AUTHZ}/roleEligibilityScheduleRequests/[0-9a-f-]{{36}}"
    ).respond(201, json={})


def body(route) -> dict:
    return json.loads(route.calls.last.request.content)


EXPECTED_TOOLS = {
    "list_resource_groups",
    "create_resource_group",
    "delete_resource_group",
    "assign_role",
    "list_role_assignments",
    "list_role_eligibilities",
    "create_user",
    "delete_user",
    "list_users",
    "list_graph_users",
    "list_aus",
    "create_au",
    "assign_au_role",
    "add_au_member",
}


async def test_all_identity_tools_registered(server):
    async with Client(server().mcp) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert names == EXPECTED_TOOLS


@pytest.mark.parametrize(
    ("actions", "expected"),
    [
        (["*"], True),
        (["*/read"], False),
        (["Microsoft.Authorization/*"], True),
        (["Microsoft.Authorization/roleAssignments/write"], True),
        (["Microsoft.Authorization/*/read"], False),
        (["Microsoft.Compute/*"], False),
    ],
)
def test_is_privileged(actions, expected):
    assert identity.is_privileged(role_def("x", "x", actions)) is expected


@respx.mock
async def test_list_resource_groups_maps_name_location(server):
    route = respx.get(f"{ARM}{SCOPE}/resourcegroups").respond(
        json={"value": [{"name": "rg-a", "location": "eastus", "id": "/x", "tags": {}}]}
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_resource_groups", {})
    assert json.loads(text(result))["data"] == [{"name": "rg-a", "location": "eastus"}]
    assert route.calls.last.request.url.params["api-version"] == identity.RG_API


@respx.mock
async def test_create_resource_group_puts_location(server):
    route = respx.put(f"{ARM}{SCOPE}/resourcegroups/rg-lab").respond(
        201, json={"name": "rg-lab", "location": "westus2"}
    )
    async with Client(server("write").mcp) as c:
        result = await c.call_tool(
            "create_resource_group", {"name": "rg-lab", "location": "westus2"}
        )
        bad = await c.call_tool("create_resource_group", {"name": "rg-lab", "location": "West US"})
    assert result.is_error is False
    assert body(route) == {"location": "westus2"}
    assert bad.is_error is True
    assert route.call_count == 1


@respx.mock
async def test_delete_resource_group_needs_confirmation(server):
    route = respx.delete(f"{ARM}{SCOPE}/resourcegroups/rg-lab").respond(202)
    async with Client(server().mcp, elicitation_callback=answer("rg-wrong")) as c:
        await c.call_tool("delete_resource_group", {"name": "rg-lab"})
    assert route.call_count == 0
    async with Client(server().mcp, elicitation_callback=answer("rg-lab")) as c:
        result = await c.call_tool("delete_resource_group", {"name": "rg-lab"})
    assert result.is_error is False
    assert route.call_count == 1


@respx.mock(assert_all_called=False)
async def test_assign_role_rejects_foreign_subscription(server, respx_mock, audit_records):
    anything = respx_mock.route().respond(json={})
    async with Client(server().mcp, elicitation_callback=answer(f"Reader -> {UPN}")) as c:
        result = await c.call_tool(
            "assign_role",
            {
                "assignee": UPN,
                "role": "Reader",
                "scope": f"/subscriptions/{OTHER_SUB}",
                "justification": JUSTIFICATION,
            },
        )
    assert result.is_error is True
    assert "inside this server's subscription" in text(result)
    assert anything.call_count == 0
    assert audit_records()[-1]["outcome"] == "refused"


@respx.mock(assert_all_called=False)
async def test_assign_role_rejects_scope_traversal(server, respx_mock, audit_records):
    # Correct retype text, so only the RbacScope validator can make this call fail.
    anything = respx_mock.route().respond(json={})
    asked: list[str] = []
    callback = answer(f"Reader -> {UPN}", asked=asked)
    args = {
        "assignee": UPN,
        "role": "Reader",
        "scope": f"{SCOPE}/../x",
        "justification": JUSTIFICATION,
    }
    async with Client(server().mcp, elicitation_callback=callback) as c:
        result = await c.call_tool("assign_role", args)
    assert result.is_error is True
    assert anything.call_count == 0 and asked == []
    assert all(r["decision"] != "declined" for r in audit_records())


@respx.mock(assert_all_called=False)
async def test_role_name_with_quote_rejected(server, respx_mock):
    anything = respx_mock.route().respond(json={})
    role = "Reader' or 1 eq 1"
    asked: list[str] = []
    callback = answer(f"{role} -> {UPN}", asked=asked)
    args = {"assignee": UPN, "role": role, "scope": SCOPE, "justification": JUSTIFICATION}
    async with Client(server().mcp, elicitation_callback=callback) as c:
        result = await c.call_tool("assign_role", args)
    assert result.is_error is True
    assert anything.call_count == 0 and asked == []


@pytest.mark.parametrize(
    ("role", "definition", "lookup"),
    [
        ("Owner", OWNER, "name"),
        (UAA["name"], UAA, "id"),
        ("Lab Role Granter", CUSTOM, "name"),
    ],
    ids=["owner-by-name", "uaa-by-guid", "custom-roleassignments-write"],
)
@respx.mock
async def test_privileged_role_goes_through_pim(server, role, definition, lookup):
    mock_user_lookup()
    (mock_role_by_name if lookup == "name" else mock_role_by_id)(definition)
    active, eligible = put_assignment(), put_eligibility()
    async with Client(server().mcp, elicitation_callback=answer(f"{role} -> {UPN}")) as c:
        result = await c.call_tool(
            "assign_role",
            {"assignee": UPN, "role": role, "scope": SCOPE, "justification": JUSTIFICATION},
        )
    assert result.is_error is False
    assert active.call_count == 0
    props = body(eligible)["properties"]
    assert props["requestType"] == "AdminAssign"
    assert props["principalId"] == USER_ID
    assert props["roleDefinitionId"] == definition["id"]
    assert props["justification"] == JUSTIFICATION
    assert props["scheduleInfo"]["expiration"] == {"type": "AfterDuration", "duration": "P30D"}
    assert eligible.calls.last.request.url.params["api-version"] == identity.PIM_API
    assert json.loads(text(result))["data"]["assignment"] == "eligible (PIM)"


@respx.mock
async def test_non_privileged_role_stays_active(server):
    mock_user_lookup()
    mock_role_by_name(READER)
    active, eligible = put_assignment(), put_eligibility()
    async with Client(server().mcp, elicitation_callback=answer(f"Reader -> {UPN}")) as c:
        result = await c.call_tool(
            "assign_role",
            {"assignee": UPN, "role": "Reader", "scope": SCOPE, "justification": JUSTIFICATION},
        )
    assert result.is_error is False
    assert eligible.call_count == 0
    props = body(active)["properties"]
    assert props == {
        "roleDefinitionId": READER["id"],
        "principalId": USER_ID,
        "description": JUSTIFICATION,
    }


@pytest.mark.parametrize("justification", [None, "too short"])
@respx.mock(assert_all_called=False)
async def test_justification_required_and_bounded(server, respx_mock, justification):
    anything = respx_mock.route().respond(json={})
    args = {"assignee": UPN, "role": "Reader", "scope": SCOPE}
    if justification is not None:
        args["justification"] = justification
    asked: list[str] = []
    callback = answer(f"Reader -> {UPN}", asked=asked)
    async with Client(server().mcp, elicitation_callback=callback) as c:
        result = await c.call_tool("assign_role", args)
    assert result.is_error is True
    assert anything.call_count == 0 and asked == []


@respx.mock
async def test_prompt_shows_justification(server):
    mock_user_lookup()
    mock_role_by_name(OWNER)
    put_eligibility()
    asked: list[str] = []
    callback = answer(f"Owner -> {UPN}", asked=asked)
    args = {"assignee": UPN, "role": "Owner", "scope": SCOPE, "justification": JUSTIFICATION}
    async with Client(server().mcp, elicitation_callback=callback) as c:
        await c.call_tool("assign_role", args)
    assert f'justification: "{JUSTIFICATION}" (text from the agent)' in asked[0]


@respx.mock
async def test_list_role_eligibilities_projects_fields(server):
    route = respx.get(f"{AUTHZ}/roleEligibilityScheduleInstances").respond(
        json={
            "value": [
                {
                    "properties": {
                        "principalId": USER_ID,
                        "scope": SCOPE,
                        "status": "Provisioned",
                        "startDateTime": "2026-10-24T00:00:00Z",
                        "endDateTime": "2026-11-23T00:00:00Z",
                        "expandedProperties": {
                            "principal": {"displayName": "Emma Richardson"},
                            "roleDefinition": {"displayName": "Owner"},
                        },
                    }
                }
            ]
        }
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_role_eligibilities", {})
    row = json.loads(text(result))["data"][0]
    assert row["principal"] == "Emma Richardson"
    assert row["role"] == "Owner"
    assert row["end"] == "2026-11-23T00:00:00Z"
    assert route.calls.last.request.url.params["$filter"] == "atScope()"


TEMPLATE = "fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Administrator


def mock_au_descriptions():
    respx.get(f"{GRAPH}/v1.0/roleManagement/directory/roleDefinitions/{TEMPLATE}").respond(
        json={"displayName": "User Administrator"}
    )
    respx.get(f"{GRAPH}/v1.0/directory/administrativeUnits/{AU_ID}").respond(
        json={"displayName": "Seattle AU"}
    )


@respx.mock
async def test_assign_au_role_goes_through_pim(server):
    mock_user_lookup()
    mock_au_descriptions()
    eligible = respx.post(
        f"{GRAPH}/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
    ).respond(201, json={"id": "req-1", "status": "Provisioned"})
    active = respx.post(f"{GRAPH}/v1.0/roleManagement/directory/roleAssignments").respond(
        201, json={}
    )
    legacy = respx.route(url__regex=r".*/directoryRoles.*").respond(json={})
    asked: list[str] = []
    async with Client(server().mcp, elicitation_callback=answer(UPN, asked=asked)) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        result = await c.call_tool(
            "assign_au_role",
            {
                "au_id": AU_ID,
                "user": UPN,
                "role_template_id": TEMPLATE,
                "justification": JUSTIFICATION,
            },
        )
    annotations = tools["assign_au_role"].annotations
    assert annotations is not None and annotations.destructive_hint is True
    assert result.is_error is False
    request = body(eligible)
    assert request["action"] == "adminAssign"
    assert request["directoryScopeId"] == f"/administrativeUnits/{AU_ID}"
    assert request["roleDefinitionId"] == TEMPLATE
    assert request["principalId"] == USER_ID
    assert request["justification"] == JUSTIFICATION
    assert request["scheduleInfo"]["expiration"] == {"type": "afterDuration", "duration": "P30D"}
    assert active.call_count == 0
    assert legacy.call_count == 0
    assert "User Administrator" in asked[0] and "Seattle AU" in asked[0]


@respx.mock
async def test_au_prompt_survives_failed_name_lookup(server):
    mock_user_lookup()
    respx.get(url__regex=rf"{GRAPH}/v1.0/roleManagement/directory/roleDefinitions/.*").respond(404)
    respx.get(url__regex=rf"{GRAPH}/v1.0/directory/administrativeUnits/.*").respond(404)
    respx.post(f"{GRAPH}/v1.0/roleManagement/directory/roleEligibilityScheduleRequests").respond(
        201, json={"id": "req-1"}
    )
    asked: list[str] = []
    async with Client(server().mcp, elicitation_callback=answer(UPN, asked=asked)) as c:
        result = await c.call_tool(
            "assign_au_role",
            {
                "au_id": AU_ID,
                "user": UPN,
                "role_template_id": TEMPLATE,
                "justification": JUSTIFICATION,
            },
        )
    assert result.is_error is False
    assert "lookup failed" in asked[0]
    assert TEMPLATE in asked[0]


@respx.mock
async def test_add_au_member_is_destructive_and_confirmed(server):
    mock_user_lookup()
    mock_au_descriptions()
    route = respx.post(f"{GRAPH}/v1.0/directory/administrativeUnits/{AU_ID}/members/$ref").respond(
        204
    )
    async with Client(
        server().mcp, elicitation_callback=answer("someone.else@cavalry77.onmicrosoft.com")
    ) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        await c.call_tool("add_au_member", {"au_id": AU_ID, "user": UPN})
    annotations = tools["add_au_member"].annotations
    assert annotations is not None and annotations.destructive_hint is True
    assert route.call_count == 0
    asked: list[str] = []
    async with Client(server().mcp, elicitation_callback=answer(UPN, asked=asked)) as c:
        result = await c.call_tool("add_au_member", {"au_id": AU_ID, "user": UPN})
    assert result.is_error is False
    assert route.call_count == 1
    assert "Seattle AU" in asked[0]


@respx.mock
async def test_assign_role_prompt_shows_role_and_scope(server):
    mock_user_lookup()
    mock_role_by_name(OWNER)
    put_eligibility()
    asked: list[str] = []
    async with Client(
        server().mcp, elicitation_callback=answer(f"Owner -> {UPN}", asked=asked)
    ) as c:
        await c.call_tool(
            "assign_role",
            {"assignee": UPN, "role": "Owner", "scope": SCOPE, "justification": JUSTIFICATION},
        )
    prompt = asked[0]
    assert "Owner" in prompt and SCOPE in prompt and "30" in prompt
    assert f"Retype exactly to confirm: Owner -> {UPN}" in prompt


@respx.mock(assert_all_called=False)
async def test_assign_role_requires_role_and_assignee_retyped(server, respx_mock):
    respx_mock.get(f"{GRAPH}/v1.0/users/{UPN}").respond(json={"id": USER_ID})
    respx_mock.get(f"{AUTHZ}/roleDefinitions").respond(json={"value": [OWNER]})
    writes = respx_mock.put(url__regex=r".*").respond(201, json={})
    for retyped in (UPN, f"Reader -> {UPN}"):
        async with Client(server().mcp, elicitation_callback=answer(retyped)) as c:
            result = await c.call_tool(
                "assign_role",
                {"assignee": UPN, "role": "Owner", "scope": SCOPE, "justification": JUSTIFICATION},
            )
        assert result.is_error is True
    assert writes.call_count == 0


@respx.mock
async def test_retype_accepts_unicode_arrow(server):
    mock_user_lookup()
    mock_role_by_name(OWNER)
    eligible = put_eligibility()
    async with Client(server().mcp, elicitation_callback=answer(f"owner → {UPN.upper()}")) as c:
        result = await c.call_tool(
            "assign_role",
            {"assignee": UPN, "role": "Owner", "scope": SCOPE, "justification": JUSTIFICATION},
        )
    assert result.is_error is False
    assert eligible.call_count == 1


@respx.mock
async def test_create_user_never_accepts_or_returns_password(server, audit_records):
    route = respx.post(f"{GRAPH}/v1.0/users").respond(201, json={"id": USER_ID})
    async with Client(server("write").mcp) as c:
        schema = {t.name: t for t in (await c.list_tools()).tools}["create_user"].input_schema
        result = await c.call_tool("create_user", {"upn": UPN, "display_name": "Emma Richardson"})
    assert "password" not in schema["properties"]
    password = body(route)["passwordProfile"]["password"]
    assert len(password) >= 32
    assert body(route)["passwordProfile"]["forceChangePasswordNextSignIn"] is True
    assert password not in text(result)
    assert all(password not in json.dumps(r) for r in audit_records())


@respx.mock
async def test_upn_with_apostrophe_is_encoded(server):
    route = respx.delete(f"{GRAPH}/v1.0/users/liam.o%27brien%40cavalry77.onmicrosoft.com").respond(
        204
    )
    upn = "liam.o'brien@cavalry77.onmicrosoft.com"
    async with Client(server().mcp, elicitation_callback=answer(upn)) as c:
        result = await c.call_tool("delete_user", {"user": upn})
    assert result.is_error is False
    assert route.call_count == 1


@respx.mock
async def test_list_users_paginates(server):
    respx.get(f"{GRAPH}/v1.0/users", params={"page": "2"}).respond(json={"value": [{"id": "2"}]})
    respx.get(f"{GRAPH}/v1.0/users").respond(
        json={"value": [{"id": "1"}], "@odata.nextLink": f"{GRAPH}/v1.0/users?page=2"}
    )
    async with Client(server("read").mcp) as c:
        result = await c.call_tool("list_users", {})
    assert [u["id"] for u in json.loads(text(result))["data"]] == ["1", "2"]

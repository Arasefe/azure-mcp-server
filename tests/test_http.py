from types import SimpleNamespace

import httpx
import pytest
import respx

from azsec_mcp.http import Api, AzureError, AzureHttp

GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

pytestmark = pytest.mark.anyio


class FakeCred:
    def __init__(self):
        self.scopes = []

    def get_token(self, *scopes):
        self.scopes.append(scopes[0])
        return SimpleNamespace(token=f"tok:{scopes[0]}")


@respx.mock
async def test_request_sets_bearer_for_matching_scope():
    route = respx.get(f"{GRAPH}/v1.0/users").respond(json={"value": []})
    async with httpx.AsyncClient() as c:
        await AzureHttp(FakeCred(), c).request("GET", Api.GRAPH, "/v1.0/users")
    assert route.calls.last.request.headers["Authorization"] == f"Bearer tok:{GRAPH_SCOPE}"


@respx.mock
async def test_paginate_follows_next_link():
    # Specific route first: respx matches a path route regardless of query string.
    respx.get(f"{GRAPH}/v1.0/users", params={"page": "2"}).respond(json={"value": [{"id": 3}]})
    respx.get(f"{GRAPH}/v1.0/users").respond(
        json={"value": [{"id": 1}, {"id": 2}], "@odata.nextLink": f"{GRAPH}/v1.0/users?page=2"}
    )
    async with httpx.AsyncClient() as c:
        items = await AzureHttp(FakeCred(), c).paginate(Api.GRAPH, "/v1.0/users")
    assert [i["id"] for i in items] == [1, 2, 3]


@respx.mock
async def test_paginate_follows_arm_next_link():
    respx.get(f"{ARM}/subscriptions/s/x", params={"skip": "1"}).respond(json={"value": [{"id": 2}]})
    respx.get(f"{ARM}/subscriptions/s/x").respond(
        json={"value": [{"id": 1}], "nextLink": f"{ARM}/subscriptions/s/x?skip=1"}
    )
    async with httpx.AsyncClient() as c:
        items = await AzureHttp(FakeCred(), c).paginate(Api.ARM, "/subscriptions/s/x")
    assert [i["id"] for i in items] == [1, 2]


@respx.mock
async def test_paginate_stops_at_max_items():
    respx.get(f"{GRAPH}/v1.0/users").respond(
        json={"value": [{"id": 1}, {"id": 2}, {"id": 3}], "@odata.nextLink": f"{GRAPH}/p2"}
    )
    page2 = respx.get(f"{GRAPH}/p2").respond(json={"value": [{"id": 4}]})
    async with httpx.AsyncClient() as c:
        items = await AzureHttp(FakeCred(), c).paginate(Api.GRAPH, "/v1.0/users", max_items=2)
    assert len(items) == 2
    assert page2.call_count == 0


@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/x",
        "https://graph.microsoft.com@evil.example/x",
        "https://graph.microsoft.com.evil.example/x",
        "http://graph.microsoft.com/x",
    ],
)
@respx.mock(assert_all_called=False)
async def test_paginate_refuses_foreign_next_link(link, respx_mock):
    respx_mock.get(f"{GRAPH}/v1.0/users").respond(json={"value": [], "@odata.nextLink": link})
    anything_else = respx_mock.route().respond(json={"value": []})
    cred = FakeCred()
    async with httpx.AsyncClient() as c:
        with pytest.raises(AzureError) as exc:
            await AzureHttp(cred, c).paginate(Api.GRAPH, "/v1.0/users")
    assert exc.value.code == "ForeignHost"
    assert cred.scopes == [GRAPH_SCOPE]  # token fetched for page 1 only
    assert anything_else.call_count == 0


async def test_request_rejects_absolute_path():
    cred = FakeCred()
    async with httpx.AsyncClient() as c:
        with pytest.raises(ValueError):
            await AzureHttp(cred, c).request("GET", Api.GRAPH, "https://evil.example")
    assert cred.scopes == []


@respx.mock
async def test_error_body_trimmed():
    respx.get(f"{GRAPH}/v1.0/users").respond(
        403, json={"error": {"code": "Authorization_RequestDenied", "message": "m" * 5000}}
    )
    async with httpx.AsyncClient() as c:
        with pytest.raises(AzureError) as exc:
            await AzureHttp(FakeCred(), c).request("GET", Api.GRAPH, "/v1.0/users")
    assert exc.value.status == 403
    assert exc.value.code == "Authorization_RequestDenied"
    assert len(exc.value.message) <= 500


@respx.mock
async def test_no_content_returns_empty():
    respx.post(f"{GRAPH}/v1.0/x").respond(204)
    async with httpx.AsyncClient() as c:
        assert await AzureHttp(FakeCred(), c).request("POST", Api.GRAPH, "/v1.0/x") == {}

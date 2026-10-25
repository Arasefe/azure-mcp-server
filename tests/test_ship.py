"""azsec-mcp-ship: off-box copy of the audit chain, with truncation/rewrite detection."""

import json
import stat

import httpx
import pytest
import respx
from helpers import FakeCred

from azsec_mcp.audit import GENESIS, AuditLog
from azsec_mcp.ship import INGEST_API, MONITOR_SCOPE, STREAM, Shipper, load_state

pytestmark = pytest.mark.anyio

ENDPOINT = "https://azsec-audit-a1b2.eastus-1.ingest.monitor.azure.com"
DCR = "dcr-" + "0123456789abcdef" * 2
URL = f"{ENDPOINT}/dataCollectionRules/{DCR}/streams/{STREAM}"


@pytest.fixture
def paths(tmp_path):
    return tmp_path / "audit.jsonl", tmp_path / "audit.jsonl.shipped"


def write_records(audit_path, n, start=0):
    log = AuditLog(audit_path)
    for i in range(start, start + n):
        log.append(
            {"tool": f"t{i}", "tier": "read", "decision": "allowed", "outcome": "ok", "args": {}}
        )


def sent_rows(route):
    return [row for call in route.calls for row in json.loads(call.request.content)]


def shipper(paths, client, cred=None):
    audit, state = paths
    return Shipper(ENDPOINT, DCR, cred or FakeCred(), client, audit, state)


@respx.mock
async def test_first_run_ships_all_and_heartbeat(paths):
    write_records(paths[0], 3)
    route = respx.post(URL).respond(204)
    cred = FakeCred()
    async with httpx.AsyncClient() as c:
        await shipper(paths, c, cred).run()
    rows = sent_rows(route)
    calls = [r for r in rows if r["Kind"] == "call"]
    beat = [r for r in rows if r["Kind"] == "heartbeat"][0]
    assert [r["Seq"] for r in calls] == [1, 2, 3]
    assert beat["ChainOk"] is True and beat["Seq"] == 3
    assert route.calls.last.request.url.params["api-version"] == INGEST_API
    assert cred.scopes[0] == MONITOR_SCOPE
    state = load_state(paths[1])
    assert (
        state.seq == 3 and state.hash == json.loads(paths[0].read_text().splitlines()[-1])["hash"]
    )
    assert stat.S_IMODE(paths[1].stat().st_mode) == 0o600


@respx.mock
async def test_second_run_ships_only_new_records(paths):
    write_records(paths[0], 2)
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        await shipper(paths, c).run()
        write_records(paths[0], 2, start=2)
        before = len(route.calls)
        await shipper(paths, c).run()
    second = [r for call in route.calls[before:] for r in json.loads(call.request.content)]
    assert [r["Seq"] for r in second if r["Kind"] == "call"] == [3, 4]


@respx.mock
async def test_tampered_chain_ships_only_a_failing_heartbeat(paths):
    write_records(paths[0], 3)
    lines = paths[0].read_text().splitlines()
    lines[1] = lines[1].replace('"t1"', '"tX"')
    paths[0].write_text("\n".join(lines) + "\n")
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        await shipper(paths, c).run()
    rows = sent_rows(route)
    assert [r["Kind"] for r in rows] == ["heartbeat"]
    assert rows[0]["ChainOk"] is False and "line 2" in rows[0]["Problem"]
    assert load_state(paths[1]).seq == 0  # state not advanced


@respx.mock
async def test_truncation_after_shipping_is_detected(paths):
    write_records(paths[0], 3)
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        await shipper(paths, c).run()
        paths[0].write_text("\n".join(paths[0].read_text().splitlines()[:-1]) + "\n")
        before = len(route.calls)
        await shipper(paths, c).run()
    beat = json.loads(route.calls[before].request.content)[-1]
    assert beat["ChainOk"] is False and "regressed" in beat["Problem"]


@respx.mock
async def test_full_rewrite_after_shipping_is_detected(paths):
    write_records(paths[0], 3)
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        await shipper(paths, c).run()
        paths[0].unlink()
        write_records(paths[0], 3, start=100)  # a valid but different chain, same length
        before = len(route.calls)
        await shipper(paths, c).run()
    beat = json.loads(route.calls[before].request.content)[-1]
    assert beat["ChainOk"] is False and "changed" in beat["Problem"]


@respx.mock
async def test_empty_log_sends_genesis_heartbeat(paths):
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        await shipper(paths, c).run()
    beat = sent_rows(route)[0]
    assert beat["Kind"] == "heartbeat" and beat["Seq"] == 0 and beat["RecordHash"] == GENESIS


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://azsec.eastus-1.ingest.monitor.azure.com",
        "https://evil.example",
        "https://monitor.azure.com.evil.example",
        "https://x@azsec.eastus-1.ingest.monitor.azure.com",
    ],
)
def test_endpoint_must_be_https_azure_monitor(paths, endpoint):
    with pytest.raises(ValueError, match="endpoint"):
        Shipper(endpoint, DCR, FakeCred(), None, *paths)  # type: ignore[arg-type]


def test_dcr_id_validated(paths):
    with pytest.raises(ValueError, match="DCR"):
        Shipper(ENDPOINT, "dcr-../x", FakeCred(), None, *paths)  # type: ignore[arg-type]


@respx.mock
async def test_failed_upload_does_not_advance_state(paths):
    write_records(paths[0], 2)
    respx.post(URL).respond(403, json={"error": {"code": "Forbidden", "message": "no role"}})
    async with httpx.AsyncClient() as c:
        with pytest.raises(RuntimeError, match="403"):
            await shipper(paths, c).run()
    assert load_state(paths[1]).seq == 0


@respx.mock
async def test_unicode_line_separators_in_args_do_not_break_shipping(paths):
    log = AuditLog(paths[0])
    for sep in (" ", " ", "\x1c", "\x85"):
        log.append({"tool": "t", "decision": "allowed", "args": {"q": f"a{sep}b"}})
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        result = await shipper(paths, c).run()
    rows = sent_rows(route)
    assert result["chainOk"] is True
    assert [r["Seq"] for r in rows if r["Kind"] == "call"] == [1, 2, 3, 4]
    assert rows[1]["Args"] == {"q": "a b"}


@respx.mock
async def test_batches_stay_under_the_ingestion_size_limit(paths):
    log = AuditLog(paths[0])
    for _ in range(30):
        log.append({"tool": "run_sentinel_kql_query", "args": {"query": "x" * 60_000}})
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        await shipper(paths, c).run()
    sizes = [len(call.request.content) for call in route.calls]
    assert max(sizes) < 1_000_000
    assert sum(1 for r in sent_rows(route) if r["Kind"] == "call") == 30


@respx.mock
async def test_broken_chain_heartbeat_reports_last_good_record(paths):
    write_records(paths[0], 3)
    lines = paths[0].read_text().splitlines()
    good_hash = json.loads(lines[1])["hash"]
    lines[2] = lines[2].replace('"t2"', '"tX"')
    paths[0].write_text("\n".join(lines) + "\n")
    route = respx.post(URL).respond(204)
    async with httpx.AsyncClient() as c:
        await shipper(paths, c).run()
    beat = sent_rows(route)[0]
    assert beat["ChainOk"] is False
    assert beat["Seq"] == 2 and beat["RecordHash"] == good_hash

"""azsec-mcp-ship: copy new audit records to Sentinel and anchor the chain head off-box.

The local hash chain detects edited or deleted lines but not tail truncation or a full
rewrite (audit.py). Shipping closes both gaps: Sentinel keeps every record already sent, and
each run sends a heartbeat with the current head (seq, hash). The shipper remembers what it
sent last; if the local log later falls below that seq, or the record at that seq changes,
the heartbeat reports ChainOk=false and nothing new is shipped until a human looks.

Run it every few minutes (launchd/cron). Uses the Logs Ingestion API with a DCR (kind
Direct); the identity needs Monitoring Metrics Publisher on that DCR only (infra/).
"""

import json
import os
import re
import socket
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import httpx
from anyio import to_thread
from azure.identity import CertificateCredential

from .audit import GENESIS, AuditLog
from .config import load_settings
from .http import TokenSource

STREAM = "Custom-AzSecMcpAudit_CL"
INGEST_API = "2023-01-01"
MONITOR_SCOPE = "https://monitor.azure.com//.default"
BATCH = 500
MAX_BATCH_BYTES = 900_000  # the Logs Ingestion API accepts at most 1 MB per call
_DCR_ID = re.compile(r"dcr-[0-9a-f]{32}")


@dataclass(frozen=True)
class ShipState:
    seq: int
    hash: str


def load_state(path: Path) -> ShipState:
    if not path.exists():
        return ShipState(0, GENESIS)
    data = json.loads(path.read_text(encoding="utf-8"))
    return ShipState(int(data["seq"]), str(data["hash"]))


def save_state(path: Path, state: ShipState) -> None:
    """Write atomically and owner-only, so a crash never leaves a half-written state."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"seq": state.seq, "hash": state.hash}, f)
    os.replace(tmp, path)


def _check_endpoint(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    host = parts.hostname or ""
    if (
        parts.scheme != "https"
        or parts.username is not None
        or parts.port not in (None, 443)
        or not host.endswith(".monitor.azure.com")
    ):
        raise ValueError(f"Ingestion endpoint must be https on *.monitor.azure.com: {endpoint!r}")
    return f"https://{host}"


def _row(record: dict[str, Any], host: str) -> dict[str, Any]:
    return {
        "TimeGenerated": record.get("ts"),
        "Kind": "call",
        "Host": host,
        "Seq": record.get("seq"),
        "Tool": record.get("tool"),
        "Tier": record.get("tier"),
        "Decision": record.get("decision"),
        "Outcome": record.get("outcome"),
        "Reason": record.get("reason"),
        "Error": record.get("error"),
        "Args": record.get("args"),
        "RecordHash": record.get("hash"),
        "PrevHash": record.get("prev"),
        "ChainOk": True,
        "Problem": None,
    }


def _batches(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split rows into calls of at most BATCH rows and MAX_BATCH_BYTES of JSON."""
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    size = 2  # the enclosing [ ]
    for row in rows:
        row_size = len(json.dumps(row, default=str).encode("utf-8")) + 1
        if current and (len(current) >= BATCH or size + row_size > MAX_BATCH_BYTES):
            batches.append(current)
            current, size = [], 2
        current.append(row)
        size += row_size
    if current:
        batches.append(current)
    return batches


class Shipper:
    def __init__(
        self,
        endpoint: str,
        dcr_immutable_id: str,
        credential: TokenSource,
        client: httpx.AsyncClient,
        audit_path: Path,
        state_path: Path,
    ) -> None:
        self._endpoint = _check_endpoint(endpoint)
        if not _DCR_ID.fullmatch(dcr_immutable_id):
            raise ValueError(f"DCR immutable ID must look like dcr-<32 hex>: {dcr_immutable_id!r}")
        self._url = f"{self._endpoint}/dataCollectionRules/{dcr_immutable_id}/streams/{STREAM}"
        self._credential = credential
        self._client = client
        self._audit = audit_path
        self._state_path = state_path
        self._host = socket.gethostname()

    def _plan(self, state: ShipState) -> tuple[list[dict[str, Any]], dict[str, Any], ShipState]:
        """Rows to ship, the heartbeat, and the state to save if the upload succeeds."""
        problems: list[str] = []
        records: list[dict[str, Any]] = []
        good: list[dict[str, Any]] = []
        if self._audit.exists():
            # One parser for verify and shipping, so they can never disagree about records.
            ok, bad_line, good = AuditLog.load(self._audit)
            if ok:
                records = good
            else:
                problems.append(f"chain broken at line {bad_line}")
        # The heartbeat reports the last record that still verifies, even when the chain breaks.
        head = ShipState(good[-1]["seq"], good[-1]["hash"]) if good else ShipState(0, GENESIS)

        if not problems and state.seq:
            if head.seq < state.seq:
                problems.append(
                    f"sequence regressed: head seq {head.seq} < last shipped {state.seq} "
                    "(tail truncation or rewrite)"
                )
            elif records[state.seq - 1]["hash"] != state.hash:
                problems.append(f"record seq {state.seq} changed after it was shipped (rewrite)")

        rows = [] if problems else [_row(r, self._host) for r in records if r["seq"] > state.seq]
        heartbeat = {
            "TimeGenerated": datetime.now(UTC).isoformat(),
            "Kind": "heartbeat",
            "Host": self._host,
            "Seq": head.seq,
            "RecordHash": head.hash,
            "ChainOk": not problems,
            "Problem": "; ".join(problems) or None,
        }
        return rows, heartbeat, (state if problems else head)

    async def _post(self, rows: list[dict[str, Any]]) -> None:
        token = await to_thread.run_sync(self._credential.get_token, MONITOR_SCOPE)
        resp = await self._client.post(
            self._url,
            params={"api-version": INGEST_API},
            json=rows,
            headers={"Authorization": f"Bearer {token.token}"},
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"Logs ingestion failed: {resp.status_code} {resp.text[:300]}")

    async def run(self) -> dict[str, Any]:
        """Ship new records, then the heartbeat; save state only after both succeed."""
        state = load_state(self._state_path)
        rows, heartbeat, next_state = self._plan(state)
        for batch in _batches(rows):
            await self._post(batch)
        await self._post([heartbeat])
        save_state(self._state_path, next_state)
        return {"shipped": len(rows), "chainOk": heartbeat["ChainOk"], "head": next_state.seq}


def main() -> None:
    settings = load_settings()
    endpoint = os.environ.get("MCP_AUDIT_DCR_ENDPOINT", "")
    dcr = os.environ.get("MCP_AUDIT_DCR_IMMUTABLE_ID", "")
    if not endpoint or not dcr:
        sys.exit("Set MCP_AUDIT_DCR_ENDPOINT and MCP_AUDIT_DCR_IMMUTABLE_ID (see infra/README.md)")
    credential = CertificateCredential(
        settings.tenant_id, settings.client_id, certificate_path=str(settings.cert_path)
    )
    state_path = settings.audit_path.with_name(settings.audit_path.name + ".shipped")

    async def go() -> None:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            shipper = Shipper(endpoint, dcr, credential, client, settings.audit_path, state_path)
            print(json.dumps(await shipper.run()))

    anyio.run(go)

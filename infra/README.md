# Off-box audit: ship the azsec-mcp audit chain to Sentinel

The local `audit.jsonl` hash chain shows edited or deleted lines, but on its own it cannot show
**tail truncation** or a **full rewrite** (see `src/azsec_mcp/audit.py`). `azsec-mcp-ship` closes
both gaps by copying each record to Sentinel and sending a heartbeat with the chain head. If the
local log later falls below what was shipped, or a shipped record changes, the heartbeat reports
`ChainOk=false`. `detections/agent-misuse.kql` raises an incident for that, and for agent misuse.

## 1. Deploy (once)

Creates a custom table `AzSecMcpAudit_CL`, a direct-ingestion DCR, and **one** role assignment:
*Monitoring Metrics Publisher* for the shipper's service principal, scoped to that DCR only.

```bash
SP_OBJECT_ID=$(az ad sp show --id "$AZURE_CLIENT_ID" --query id -o tsv)
az deployment group what-if -g "$SENTINEL_RESOURCE_GROUP" -f infra/audit-ingestion.bicep \
  -p workspaceName="$SENTINEL_WORKSPACE_NAME" shipperPrincipalId="$SP_OBJECT_ID"
az deployment group create -g "$SENTINEL_RESOURCE_GROUP" -f infra/audit-ingestion.bicep \
  -p workspaceName="$SENTINEL_WORKSPACE_NAME" shipperPrincipalId="$SP_OBJECT_ID" \
  --query properties.outputs
```

Cost: the DCR and role assignment are free. Ingestion is billed per GB at the workspace's
Analytics rate; one audit row is about 0.5 KB, so typical lab volume is far below 1 MB a day.

## 2. Configure

Add the two deployment outputs to `.env`:

```
MCP_AUDIT_DCR_ENDPOINT=<logsIngestionEndpoint>
MCP_AUDIT_DCR_IMMUTABLE_ID=<dcrImmutableId>
```

Role assignments can take up to 30 minutes to apply; until then uploads return 403.

## 3. Run every 5 minutes

```bash
uv run --directory ~/dev/azure-mcp-server azsec-mcp-ship
# {"shipped": 12, "chainOk": true, "head": 41}
```

Schedule it with launchd (macOS) or cron. A failed upload never advances the shipper's state
(`audit.jsonl.shipped`), so the next run retries the same records.

## 4. Detect

Create a scheduled analytics rule from `detections/agent-misuse.kql`: run every 15 minutes,
look back 1 hour, one alert per result row, entity mapping `Host` -> Host. It covers:

| Finding | Severity |
|---|---|
| A destructive tool call refused or declined | High |
| More than 3 refused calls in 10 minutes | Medium |
| Audit chain integrity failure (edited, truncated, rewritten) | High |
| Heartbeat missing for 30 minutes from a host that sent them before | Medium |

The query was validated against the live Log Analytics engine with synthetic rows covering each
finding and a benign host; all four findings fired, and nothing fired for the benign host.

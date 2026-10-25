# azure-mcp-showcase — Research

## Problem statement
Turn `azure-mcp-server` (a public repo at Arasefe/azure-mcp-server) into a portfolio example of
**AI-assisted Cloud Security Engineering**: an MCP server that lets an AI agent work on
Entra / Intune / Defender / Sentinel / Purview, and that is itself built and governed the way
a senior cloud security engineer would build an agent integration (least privilege, enforced
authorization, untrusted-input handling, audit, tests, a CI security gate). Decide whether to
rewrite it in Python as part of that.

## Success criteria
- No tool can do more than its declared tier allows (no tier bypass through crafted arguments). Proven by tests.
- Every tool argument that ends up in a URL is validated against its type (GUID, enum, alias pattern) before the request is built.
- Destructive actions need an explicit per-call human confirmation, not only a session-wide env flag.
- Tool output is size-capped and marked as untrusted data (indirect prompt-injection defense).
- The audit log is append-only, hash-chained, and can be forwarded to Sentinel; at least one KQL detection covers agent misuse.
- An automated test suite (unit + security regression + MCP protocol) runs in CI. CI also runs lint, types, dependency scan, secret scan and SAST, all pinned.
- Every Graph/ARM permission the server needs is documented with its least-privileged choice.
- The README tells the story: threat model, architecture, demo transcript, what is not covered and why.

## Current state
**Shape:** a single file, `server.js` (794 lines). Plain JavaScript (not TypeScript), ESM, `@modelcontextprotocol/sdk ^1.29.0`, `axios`, `@azure/identity`.
It has 75 tools in one `switch` (`server.js:281-781`) and the schemas are hand-written JSON (`server.js:189-265`). There are no tests.
Auth is a certificate service principal (`server.js:23-27`). Git history is clean: no PEM, `.env` or `audit.log` has ever been committed.

**Strengths to keep:**
- A per-call authorization tier map with deny-by-default for unknown tools (`server.js:68-159`). The confused-deputy rationale in its comment is correct and interview-worthy.
- A local audit log of allowed and denied decisions (`server.js:166-180`).
- The CI has four static gates with actions pinned to SHAs and images pinned to exact versions (`.github/workflows/ci.yml`).
- Certificate auth instead of a client secret, and the az CLI shell-outs are already removed (commit 74d0aa5).

**Findings (ranked):**
1. **HIGH: path injection lets a call bypass its tier.** IDs go into URL paths unvalidated and unencoded:
   `deviceId` (`:406,418,424,430,436`), `incidentId` (`:527,533,559,567,574,581`), `auId` (`:378,386`),
   `appId` (`:456`), `alertName`/`resourceGroup` (`:514`), `watchlistAlias` (`:619`), `labelId` (`:654`), `caseId` (`:705-729`).
   Example: `reboot_intune_device` is WRITE tier, but a `deviceId` of `X/wipe?` turns it into a POST to `.../X/wipe`, which is a DESTRUCTIVE action.
   Another: `list_sentinel_incident_alerts` is READ tier and issues a **POST**. With `../` segments it can reach other ARM POST actions (for example `listKeys`) using the SP's permissions.
   An agent steered by injected content in an incident or alert could produce exactly these arguments.
2. **HIGH: OData filter injection.** `roleName eq '${...}'` (`:50`) and `roleTemplateId eq '${...}'` (`:370`, which is also not URL-encoded).
3. **HIGH: tier logic is not hierarchical, and the current `.env` inverts it.** `MCP_ALLOW_DESTRUCTIVE=true` is set while `MCP_ALLOW_WRITE` is unset.
   Result: `wipe_intune_device` and `delete_user` are allowed, but `create_user` is denied.
   This server is registered in Claude Code as `azure-mcp-local`, so the wipe/delete tools are live in agent sessions today.
4. **MEDIUM: tier misclassified.** `assign_au_role` is WRITE (`:80`) but grants a scoped directory role and can activate a directory role (`:375`). By the code's own definition ("grants access") it is DESTRUCTIVE.
5. **MEDIUM: no indirect prompt-injection boundary.** Raw API JSON, including attacker-controllable fields such as incident comments, alert descriptions and display names, goes straight to the model (`:784`). There is no size cap, and `top` is unbounded (`:743,751`). This maps to OWASP LLM01 (prompt injection) and LLM06 (excessive agency).
6. **MEDIUM: the audit log is not tamper-evident, despite the comment** (`:162`). It is plain async `appendFile`, so writes can be lost or reordered and failures only go to stderr (`:177`). Redaction covers only the `password` key (`:168-173`).
7. **MEDIUM: no input validation against `inputSchema`.** Arguments are used as received.
8. **LOW: stale or incorrect content.**
   - Sentinel `api-version=2023-02-01` is used everywhere; the current stable version is `2025-09-01`.
   - The `list_retention_event_types` stub claims application permissions are unsupported (`:738`). Microsoft Learn says Application `RecordsManagement.Read.All` **is** supported. The claim is only true for `retentionLabels`.
   - The `list_users` description says "via Azure CLI" (`:197`).
   - `list_sentinel_watchlists` maps `itemsSearchKey` to `itemsCount` (`:613`).
   - `list_sentinel_data_connectors` labels `dataTypes` as `state` (`:636`).
9. **LOW: about 10 stub tools return only a "not available" note** (`:671-772`). They inflate the tool count and spend agent context.
10. **LOW: dead legacy files from the Express era are tracked in a public repo.** `chat.js` contains a real subscription ID and a hardcoded password literal. `mcp-client.js`, `tools.json`, and `provision-users.js` (which uses a client secret, contradicting the cert-only posture) are also tracked. They are CommonJS inside a `"type":"module"` package, so they cannot run anyway.
11. **LOW: supply chain and runtime.** Dependencies use `^` ranges (not exact). Local and CI run Node 20, which is EOL; the local 20.17.0 is flagged for CVE-2026-111497.
12. **Positioning:** the name collides with Microsoft's official Azure MCP Server (already installed here as the `azure` MCP). That server covers ARM broadly. This project's differentiators are M365 security operations plus the governance layer.

## Language decision: JavaScript → Python
| Factor | Stay JS / TypeScript | Python |
|---|---|---|
| MCP SDK | Reference SDK (mcp v1 in use, so a major-version migration is coming either way) | Official `mcp` 2.3.0 (2026-10-02), `MCPServer` decorator API, Python ≥3.10 |
| Tool schemas | Hand-written JSON today; zod if moved to TS | Generated from type hints + pydantic, which removes `:189-265` and gives validation for free (fixes findings 1, 2, 7 structurally) |
| Azure / Graph SDKs | `@azure/*`, Graph JS | `azure-identity` 1.26 (`CertificateCredential`), `azure-monitor-query` 2.0 (`LogsQueryClient`), `azure-mgmt-*`, `msgraph-sdk` |
| Security-engineering ecosystem | Smaller | Lingua franca of detection eng / SOAR: MSTICPy, Sentinel notebooks, Azure Functions playbooks, pandas for KQL results |
| Portfolio signal (CSE job descriptions) | Fine | Stronger: Python is the expected automation language for cloud security roles |
| Rewrite cost | n/a | Low: ~800 lines, no tests to port; most cost is the restructure, which is needed regardless |
| Runtime risk | Requires Node upgrade (EOL + CVE) | Python 3.12.5 and `uv` already installed locally |

**Recommendation: rewrite in Python as part of the restructure**, not as a line-by-line transliteration.
The language matters less than the architecture fixes. Python makes those fixes the default path (typed arguments → validated → schema) and fits the security-engineering audience.
If you prefer to stay on JavaScript, the minimum is to convert to TypeScript with zod schemas and apply the same architecture.

## Constraints
- Live tenant: Cavalry77. The cert SP and `.env` stay out of git and out of iCloud (the repo is in `~/dev`, which is correct).
- Pin exact versions (uv lockfile with hashes, actions by SHA, images by version).
- You run the git pushes yourself (repo is public).
- The `azure-mcp-local` registration in Claude Code will need its command updated after the rewrite.

## Sources
- Sentinel REST API versions (stable 2025-09-01): https://learn.microsoft.com/rest/api/securityinsights/api-versions
- List retentionLabels (application: not supported): https://learn.microsoft.com/graph/api/security-labelsroot-list-retentionlabel?view=graph-rest-1.0
- List retentionEventTypes (application: RecordsManagement.Read.All supported): https://learn.microsoft.com/graph/api/security-retentioneventtype-list?view=graph-rest-1.0
- azure-identity for Python 1.26.0: https://learn.microsoft.com/python/api/overview/azure/identity-readme?view=azure-python
- azure-monitor-query for Python 2.0.0: https://learn.microsoft.com/python/api/overview/azure/monitor-query-readme?view=azure-python
- Azure SDK for Python authorization / Graph SDK: https://learn.microsoft.com/azure/developer/python/sdk/authorization/overview
- MCP Python SDK on PyPI (2.3.0): https://pypi.org/project/mcp/
- MCP Python SDK v2.0.0 release notes: https://newreleases.io/project/github/modelcontextprotocol/python-sdk/release/v2.0.0
- context7 was not available (needs auth); library facts above come from Microsoft Learn and PyPI.

## Open questions
1. Python rewrite (recommended), or stay JS and convert to TypeScript?
2. Keep the 10 stub tools, delete them, or merge them into one `capability_gaps` resource?
3. Identity model: one cert SP with tiers (current); split reader/responder SPs; or delegated (on-behalf-of user) for write/destructive so actions are attributed to a human in Entra logs?
4. Rename the project to avoid the Microsoft collision (for example `azsec-mcp` / `cavalry-secops-mcp`)?
5. Immediate hygiene now, before planning: set `MCP_ALLOW_DESTRUCTIVE=false`, and delete the legacy files from the public repo?

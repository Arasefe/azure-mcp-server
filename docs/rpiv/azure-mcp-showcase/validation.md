# azure-mcp-showcase — Validation

Branch `python-rewrite`, validated 2026-10-25. Every row was run, and the evidence is the
command's own output.

| Check | Command / tool | Result | Evidence |
|---|---|---|---|
| Unit + security tests | `uv run pytest -q` | ✅ 264 passed | incl. security/confirmation and security/prompt_injection; gates run through a script that never hides exit codes |
| Lint / format | `ruff check`, `ruff format --check` | ✅ clean | incl. flake8-bandit (S) rules |
| Types | `uv run pyright` | ✅ 0 errors | standard mode, project venv |
| SAST | Semgrep 1.182.1 `--config auto --error` | ✅ 0 findings | final HEAD |
| Secrets (full history) | gitleaks v8.28.0 | ✅ no leaks | 45 commits; see F1 for what it can't see |
| Dependencies | Trivy 0.76.0 `fs --severity HIGH,CRITICAL` | ✅ 0 | Trivy reads `uv.lock` natively |
| Mutation checks | protection deliberately removed, test re-run | ✅ every mutant caught | reboot→wipe Guid/seg; Defender PATCH, tier downgrade, action map, location parse; Sentinel close rule, cross-scope block, writable filter, timespan cap; KQL scanner string handling |
| Real stdio launch | `uv run azsec-mcp` via MCP `StdioServerParameters` | ✅ 64 tools | same launch path as Claude Code |
| Live read-only smoke (Cavalry77) | 28 tool calls at `MCP_MAX_TIER=read` | ✅ 22 ok, 1 write correctly denied, 6 errors explained | errors = SP permissions / Purview setup (PERMISSIONS.md) + 1 JS bug fixed (`sensitiveTypes`) |
| Live audit log | `AuditLog.load(audit.jsonl)` | ✅ chain intact, 0600, gitignored | 90 records from several server processes (flock-protected appends) |
| Detection rule | `agent-misuse.kql` run live through `run_sentinel_kql_query` on a synthetic stand-in table | ✅ 4/4 findings fire, benign host silent | first run found a harness bug (`datatable` rejects `now()`), confirmed by a probe query |
| IaC | `az bicep build infra/audit-ingestion.bicep` | ✅ compiles, 0 warnings | not deployed (outward change kept for the user) |
| Automated security review (per commit) | security-guidance plugin | ✅ 12 findings, all fixed | envelope cap amplification; Azure error envelope; confirmation context ×3; directory-name and agent-text prompt spoofing; KQL scope ×3; shipper splitlines DoS; short audit writes |
| Independent branch review | fresh `code-reviewer` agent, whole tree | ✅ 5 defects + 3 minor, all fixed | see 'Independent review' below; no confirmation, tier or path-segment bypass found |
| CI on GitHub | `.github/workflows/ci.yml` | ⏳ not yet run | needs `git push` (user's step), then `gh run watch` |

## Findings

**F1 — CRITICAL (live tenant, outside the code): 18 of 20 test users are still on a public password.**
`provision-users.js` gave 20 Cavalry77 users one shared initial password, and the old README
published it. It stays in public git history even though the files are now removed. A read-only
Graph check (createdDateTime vs lastPasswordChangeDateTime) showed **18 accounts enabled and never
changed**. *Status: deferred to the user*, because changing live accounts is outside the authorized
coding work. Remediation: block sign-in or reset each account (commands in the final report), then
optionally rewrite history. gitleaks didn't flag it: human-chosen passwords look like prose to a
secret scanner.

**F2 — HIGH (identity): the service principal is over-privileged.** It holds Contributor on the
subscription and 6 unused high-risk Graph scopes, including Application.ReadWrite.All.
*Accepted for the lab with reason:* the server narrows how the identity is used, and
PERMISSIONS.md documents the least-privilege and reader/responder target. *Deferred:* the tenant
change is the user's call.

**F3 — MEDIUM: KQL scope rule enforced only by the server.** Contributor can read every workspace,
so the cross-scope check (defense in depth) is the only scope control. *Deferred:* a
workspace-scoped Log Analytics Reader identity is the authoritative fix (PERMISSIONS.md).

**F4 — LOW: permission gaps break 6 tools in Cavalry77.** Intune apps and scripts (missing
DeviceManagementApps/Scripts.Read.All), eDiscovery (Purview role group setup), retention event
types (likely a Purview role; unverified). *Accepted with reason:* they're configuration, not code;
they fail cleanly with an enveloped Azure error and are documented.

**F5 — LOW: `list_sentinel_hunting_queries` unverified.** It returned 0 items live, which may mean
no content-hub hunting queries are installed. *Deferred:* recheck after installing a solution.

## Independent review (fixed)

| # | Finding | Fix | Commit |
|---|---|---|---|
| R1 | 3 identity tests passed whatever the validator did (wrong retype text) | correct retype + assert no request and no prompt; mutation-checked | 10a0a55 |
| R2 | destructive actions audited only after running; a post-action audit failure misreported success | `outcome=started` written first (fail closed); final-write failure doesn't fail a done action | 15ddc48 |
| R3 | attempts failing before the wrapper (no elicitation) left no record | resolver records `confirmation_requested` | 15ddc48 |
| R4 | two server processes on one audit file broke the chain | flock + re-read head under the lock | 211c505 |
| R5 | the 500-item pagination cap was silent (`truncated:false`) | call-scoped flag → `truncated`, `more_in_azure`, note | 6bba111 |
| minor | `_error` crashed on odd bodies; free text missing from prompts; RG create could wipe tags; shipper batch size; broken-chain heartbeat head | fixed with tests | 10a0a55, 70876c4, 00680a1 |

Not changed (judgment calls, recorded): reboot and create_user stay WRITE; argument-validation rejections from the SDK aren't audited, since no request reaches Azure.

## Success criteria (research.md)

| Criterion | Met? | Evidence |
|---|---|---|
| No tool can do more than its tier allows via crafted arguments | ✅ | 20 Intune traversal cases, reboot→wipe regression (mutation-checked), identity/Sentinel/Defender/Purview traversal tests |
| Every URL-bound argument validated before the request | ✅ | typed IDs on every tool; settings values pass through `seg()` |
| Destructive actions need per-call human confirmation | ✅ | tests/security/test_confirmation.py, on both protocol generations |
| Output size-capped and marked untrusted | ✅ | test_untrusted.py, incl. escape amplification; Azure errors too |
| Append-only hash-chained audit, forwardable, with a KQL detection | ✅ built / ⏳ deploy | audit.py, ship.py, infra/, detections/ (validated live) |
| Automated tests + CI with pinned gates | ✅ local / ⏳ GitHub | ci.yml; all four gates run locally on HEAD |
| Every permission documented with least privilege | ✅ | docs/PERMISSIONS.md, from live token roles + ARM assignments |
| README tells the story | ✅ | README.md, docs/THREAT_MODEL.md |

## Ship decision

**Ready to push as the portfolio branch**, with two conditions the user owns:
1. **Fix F1 in the tenant first** (it's live exposure regardless of this code), and
2. after `git push`, confirm the four CI jobs pass (`gh run watch`).

# Threat model

**System:** a local MCP server that lets an AI agent (Claude Code) read and act on a Microsoft
tenant (Entra ID, Intune, Defender for Cloud, Sentinel, Purview) as one certificate-authenticated
service principal.

**Primary threat:** an **honest agent steered by attacker-written content**. Attackers can write
text that the agent reads: incident comments, alert descriptions, display names, device names,
email subjects inside DLP alerts. That's indirect prompt injection (OWASP LLM01). Its payoff is
excessive agency (LLM06): getting the agent to wipe, delete, grant or close something.

**Out of scope:** a malicious MCP client (it answers the human-confirmation prompts itself), an
attacker with code execution on the operator's Mac, and compromise of Microsoft's services.

Each control below links to the test that proves it.

| # | Threat | Control | Proof |
|---|---|---|---|
| 1 | Path injection: an ID like `X/wipe?` turns a reboot into a wipe (the original JS bug) | Allowlist ID types plus `seg()` encoding; fixed API hosts | `tests/tools/test_intune.py::test_reboot_cannot_reach_wipe` (mutation-checked), `tests/test_ids.py` |
| 2 | OData injection through role or filter values | `RoleName` forbids quotes; `odata_str()` escaping | `tests/tools/test_identity.py::test_role_name_with_quote_rejected` |
| 3 | Token sent to a foreign host via pagination `nextLink` or redirects | Exact-host allowlist checked before a token is fetched; no redirects | `tests/test_http.py::test_paginate_refuses_foreign_next_link` |
| 4 | Agent does more than the session needs | One ordered ceiling, `MCP_MAX_TIER`, read by default; typos stop startup | `tests/test_policy.py`, `tests/security/test_prompt_injection.py::test_layer2…` |
| 5 | Agent wipes/deletes/grants/closes on injected instructions | Destructive tools need a human to retype a composite target; the prompt shows every security-relevant argument; the tier is checked before anyone is asked; fails closed without elicitation | `tests/security/test_confirmation.py`, `…test_prompt_injection.py::test_layer3…` |
| 6 | The confirmation prompt is spoofed by a crafted directory name (newlines, bidi) | `directory_text()` strips control/format/separator characters, quotes, caps and labels names | `tests/test_confirm.py` |
| 7 | Arguments changed after the human approved | Answers are pinned to a SHA-256 digest of the exact rendered question (SDK `resolve.py` `_request_digest`), and every shown argument is in that text | SDK behavior; see plan.md Task 9 note |
| 8 | Agent grants standing privileged access (Owner, UAA, RBAC Admin, AU admin roles) | Privileged roles (Microsoft's action-based definition) and all AU-scoped roles become **time-bound PIM eligibility** with a justification; the user activates with MFA | `tests/tools/test_identity.py::test_privileged_role_goes_through_pim`, `…test_assign_au_role_goes_through_pim` |
| 9 | Agent hides an attack by closing alerts/incidents (T1562) | `update_defender_alert` and `update_sentinel_incident` are destructive; closing an incident requires a classification | `tests/tools/test_defender.py`, `tests/tools/test_sentinel.py` |
| 10 | Injected text treated as instructions | Spotlighting envelope on every result **and every Azure error**; attacker text can't forge envelope fields | `tests/test_untrusted.py`, `…test_prompt_injection.py::test_layer1…`, `tests/test_server.py::test_azure_error_message_is_enveloped` |
| 11 | Context flooding (huge results bury the important line) | 40,000-char cap measured after encoding; lists keep a prefix and report `omitted_items` | `tests/test_untrusted.py::test_cap_holds_against_escape_amplification` |
| 12 | KQL reaches other workspaces/clusters (scope escape) | Refuses `workspace/app/resource/adx/arg/cluster/database/externaldata/external_table`, checked on three lexer readings; P90D cap; 60 s timeout | `tests/tools/test_sentinel.py::test_kql_cross_scope_functions_blocked` |
| 13 | Secrets in the agent's context | No tool accepts passwords (`create_user` generates a random one that is never revealed) or the macOS recovery PIN | `…test_create_user_never_accepts_or_returns_password`, `…test_wipe_body_defaults_and_no_unlock_code` |
| 14 | Actions can't be reconstructed afterwards | Hash-chained, fsync'd, 0600 audit log with redaction; every decision recorded | `tests/test_audit.py` |
| 15 | Audit log truncated or rewritten to hide activity | `azsec-mcp-ship` anchors the chain head in Sentinel; regression or changed records → `ChainOk=false`; KQL rule alerts | `tests/test_ship.py`, `detections/agent-misuse.kql` (validated live) |
| 16 | Agent edits `.env` to raise its own ceiling (self-escalation) | Deny messages don't explain how to unlock; human confirmation still applies at any ceiling; **recommended:** a Claude Code deny rule on `.env` (README) | `tests/test_policy.py::test_deny_reason_does_not_teach_unlock` |

## Known limits (stated so nobody overclaims)

- **Spotlighting is probabilistic.** The envelope lowers the odds that the model obeys injected
  text. The deterministic controls are the tier ceiling and human confirmation.
- **Confirmation isn't a security boundary against the client**, only against a misled agent.
  In this setup, the client is Claude Code on the operator's Mac.
- **The KQL scope check is defense in depth, not a parser.** The authoritative control is a
  workspace-scoped Log Analytics Reader identity, which Cavalry77 doesn't have yet
  (PERMISSIONS.md: the SP is Contributor on the subscription).
- **The local audit chain alone** detects edits and deletions but not tail truncation or a
  full rewrite; shipping (infra/) closes that once deployed.
- **A Claude Code `Edit` deny rule** doesn't stop shell edits (`sed`) by an agent with Bash
  access, which is why control 5 doesn't depend on it.
- **Secret scanners miss human-chosen passwords:** gitleaks scanned all 32 commits clean, yet a
  shared test-user password sat in the README's git history (see validation.md).
- **The service principal is over-privileged** (PERMISSIONS.md). The server narrows its use but
  can't shrink its grants.

## Related hardening outside this server
- Make the daily-driver account PIM-*eligible* for Global Administrator, keeping a separate
  break-glass account permanently active (the SC-300 lab already flagged a daily GA in the
  break-glass Conditional Access exclusion).

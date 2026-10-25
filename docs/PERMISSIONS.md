# Permissions

The server can only **reduce** what its identity may do; it never adds rights. So the
identity's grants are the real blast radius, and this page lists what each tool group needs,
the least-privileged choice per Microsoft Learn, and what the Cavalry77 service principal
holds today (checked live on 2026-10-25 from its token's `roles` claim and its ARM role
assignments).

## Microsoft Graph (application permissions)

| Tools | Least-privileged permission | Cavalry77 SP |
|---|---|---|
| `list_users`, `list_graph_users`, UPN lookups | User.Read.All | User.ReadWrite.All (needed for create/delete) |
| `create_user`, `delete_user` | User.ReadWrite.All | ✓ |
| `list_aus`, `create_au`, `add_au_member` | AdministrativeUnit.ReadWrite.All | ✓ |
| `assign_au_role` (PIM eligibility) | RoleEligibilitySchedule.ReadWrite.Directory | ✗, works through the higher-privileged RoleManagement.ReadWrite.Directory |
| Intune device lists, `get_intune_device` | DeviceManagementManagedDevices.Read.All | ✓ |
| `sync`/`reboot`/`retire`/`wipe_intune_device` | DeviceManagementManagedDevices.PrivilegedOperations.All | ✓ |
| Intune policies, profiles, enrollment, Autopilot | DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All | Configuration ✓ |
| `list_intune_apps`, `list_intune_app_assignments`, `list_intune_managed_app_policies` | DeviceManagementApps.Read.All | ✗ (live: 403) |
| `list_intune_scripts`, `list_intune_remediation_scripts` | DeviceManagementScripts.Read.All | ✗ (live: 403) |
| `list_dlp_alerts`, `list_insider_risk_alerts` | SecurityAlert.Read.All | ✓ |
| Sensitivity labels | InformationProtectionPolicy.Read.All | ✓ |
| eDiscovery tools | eDiscovery.Read.All **plus Purview setup** (below) | scope ✓, Purview setup ✗ (live: 401) |
| `list_retention_event_types` | RecordsManagement.Read.All | ✓, but live call returned 500 `DataInsights … Forbidden` (likely a missing Purview role; unverified) |
| `list_audit_logs`, `list_signin_logs` | AuditLog.Read.All | ✓ |

**Over-granted today:** Application.ReadWrite.All, Group.ReadWrite.All, SecurityAlert.ReadWrite.All,
RecordsManagement.ReadWrite.All, eDiscovery.ReadWrite.All and DeviceManagementConfiguration.ReadWrite.All
are not used by any tool. Application.ReadWrite.All is the most dangerous: an identity holding it
can add credentials to other apps, including more privileged ones.

### eDiscovery app-only setup (Purview side)
Graph scopes are not enough. Per Microsoft Learn, register the SP in Purview and add it to the
**eDiscovery Manager** role group (least privileged for app-only), from Security & Compliance PowerShell:
```powershell
Connect-IPPSSession
New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "azsec-mcp"
Add-RoleGroupMember -Identity "eDiscoveryManager" -Member <enterprise-app-object-id>
```
App-only access also requires eDiscovery cases with premium features enabled.

## Azure RBAC (ARM)

| Tools | Least-privileged role | Scope |
|---|---|---|
| `list_resource_groups` | Reader | subscription |
| `create_resource_group`, `delete_resource_group` | Contributor | subscription |
| `assign_role`, PIM eligibility, `list_role_eligibilities` | Role Based Access Control Administrator, ideally with a condition limiting assignable roles | the scopes it may grant on |
| Defender for Cloud lists | Security Reader | subscription |
| `update_defender_alert` | Security Admin | subscription |
| Sentinel lists | Microsoft Sentinel Reader | workspace |
| `update_sentinel_incident`, comments | Microsoft Sentinel Responder | workspace |
| `run_sentinel_kql_query`, threat indicators | Log Analytics Reader | **this workspace only** |
| `azsec-mcp-ship` | Monitoring Metrics Publisher | the audit DCR only (infra/) |

**Cavalry77 today:** Contributor (subscription), Security Reader (subscription), User Access
Administrator (`rg-cavalry-offices` only). So `assign_role` can grant only inside that resource
group, `update_defender_alert` and Sentinel writes rely on Contributor, and the KQL scope rule
(see THREAT_MODEL.md) is enforced by the server alone, because Contributor can read every
workspace in the subscription.

## Target: split reader and responder identities

| Identity | Holds | Used when |
|---|---|---|
| `azsec-mcp-reader` | all `*.Read.All` scopes, Reader, Security Reader, Sentinel Reader, Log Analytics Reader on one workspace | `MCP_MAX_TIER=read` (the default) |
| `azsec-mcp-responder` | the write/privileged scopes above, Sentinel Responder, Security Admin, RBAC Administrator with a role condition | write/destructive sessions, started deliberately |

With the split, a read-only session can't do damage even if every control in this server
failed, because its certificate simply can't. Not implemented yet: it needs two app
registrations, which is a tenant change.

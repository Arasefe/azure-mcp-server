# Azure MCP Server

A local **Model Context Protocol (MCP) stdio server** that exposes Azure and Microsoft 365 management operations as tools Claude Code can invoke directly during a conversation.

## Table of Contents

1. [What is an MCP Server?](#1-what-is-an-mcp-server)
2. [Architecture Overview](#2-architecture-overview)
3. [Prerequisites](#3-prerequisites)
4. [Project Setup](#4-project-setup)
5. [Authentication — Service Principal with Certificate](#5-authentication--service-principal-with-certificate)
6. [Environment Configuration](#6-environment-configuration)
7. [Server Structure](#7-server-structure)
8. [Tool Authorization Tiers](#8-tool-authorization-tiers)
9. [Integrated Services](#9-integrated-services)
   - [Azure Portal (Resource Groups, Users, RBAC, Administrative Units)](#91-azure-portal)
   - [Microsoft Intune](#92-microsoft-intune)
   - [Microsoft Defender for Cloud](#93-microsoft-defender-for-cloud)
   - [Microsoft Sentinel](#94-microsoft-sentinel)
   - [Microsoft Purview M365](#95-microsoft-purview-m365)
10. [Required Permissions Summary](#10-required-permissions-summary)
11. [Integrating with Claude Code](#11-integrating-with-claude-code)
12. [Testing the Server](#12-testing-the-server)
13. [Troubleshooting](#13-troubleshooting)
14. [Bulk User Provisioning](#14-bulk-user-provisioning)

---

## 1. What is an MCP Server?

**Model Context Protocol (MCP)** is an open standard that allows AI models like Claude to securely interact with external tools, APIs, and data sources. An MCP server exposes capabilities (tools) that Claude can invoke during a conversation.

This server is a **Node.js MCP stdio server** that:

- Speaks JSON-RPC 2.0 over stdin/stdout — Claude Code spawns it as a subprocess
- Authenticates to Azure/Microsoft 365 using a Service Principal with certificate-based auth
- Registers all 47 tools inline in `server.js` so Claude Code can discover and invoke them
- Requires no running port or separate process — Claude Code manages the lifecycle

---

## 2. Architecture Overview

```
Claude Code (AI)
      │
      │  spawns process, communicates via stdio (JSON-RPC 2.0)
      ▼
server.js  (MCP stdio server — node server.js)
      │
      ├── Graph API (graph.microsoft.com)  ──── Intune, Purview, Entra ID
      ├── ARM API (management.azure.com)   ──── Defender, Sentinel, Resources
      └── Azure CLI (exec)                 ──── RBAC, legacy operations
```

**Authentication flow:**

```
server.js
   └── ClientCertificateCredential (cavalry-sp.combined.pem)
         ├── getGraphToken()  →  https://graph.microsoft.com/.default
         └── getARMToken()    →  https://management.azure.com/.default
```

---

## 3. Prerequisites

| Requirement          | Details                                                |
| -------------------- | ------------------------------------------------------ |
| Node.js              | v18 or later                                           |
| Azure CLI            | Installed and authenticated (`az login`)               |
| Azure Subscription   | Active subscription                                    |
| Microsoft 365 Tenant | With E3/E5 licensing for Purview features              |
| Service Principal    | With certificate-based authentication                  |
| Claude Code          | Installed (`npm install -g @anthropic-ai/claude-code`) |

---

## 4. Project Setup

### 4.1 Install dependencies

```bash
cd azure-mcp-server
npm install
```

### 4.2 Project structure

```
azure-mcp-server/
├── server.js                  # MCP stdio server — all 47 tools registered here
├── mcp-client.js              # Thin client library used by chat.js
├── chat.js                    # Interactive CLI for manual tool testing
├── provision-users.js         # One-shot bulk user provisioning script (20 users)
├── .env                       # Environment variables (never commit this)
├── .gitignore                 # Must include .env and *.pem
├── cavalry-sp.combined.pem    # Service principal certificate (never commit)
└── package.json
```

### 4.3 .gitignore

```
.env
*.pem
node_modules/
```

---

## 5. Authentication — Service Principal with Certificate

The server uses **certificate-based Service Principal authentication** — the most secure option for automated workloads.

### 5.1 Create the Service Principal

```bash
# Create the SP and generate a self-signed certificate
az ad sp create-for-rbac \
  --name "cavalry-sp" \
  --create-cert \
  --cert cavalry-sp-cert \
  --keyvault <your-keyvault-name>
```

Or with a local certificate:

```bash
# Generate certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout cavalry-sp.key \
  -out cavalry-sp.crt \
  -subj "/CN=cavalry-sp"

# Combine into PEM (required by @azure/identity)
cat cavalry-sp.crt cavalry-sp.key > cavalry-sp.combined.pem

# Upload public cert to the app registration
az ad app credential reset \
  --id <CLIENT_ID> \
  --cert @cavalry-sp.crt
```

### 5.2 Find your credentials

```bash
# Tenant ID
az account show --query tenantId -o tsv

# Client ID (App ID of service principal)
az ad sp show --display-name "cavalry-sp" --query appId -o tsv

# Subscription ID
az account show --query id -o tsv
```

### 5.3 Authentication code in server.js

```javascript
import { ClientCertificateCredential } from "@azure/identity";

const credential = new ClientCertificateCredential(
  process.env.AZURE_TENANT_ID,
  process.env.AZURE_CLIENT_ID,
  path.join(__dirname, "cavalry-sp.combined.pem"),
);

async function getGraphToken() {
  const r = await credential.getToken("https://graph.microsoft.com/.default");
  return r.token;
}

async function getARMToken() {
  const r = await credential.getToken("https://management.azure.com/.default");
  return r.token;
}
```

---

## 6. Environment Configuration

### 6.1 .env file

```env
AZURE_CLIENT_ID="<your-service-principal-client-id>"
AZURE_TENANT_ID="<your-tenant-id>"
AZURE_SUBSCRIPTION_ID="<your-subscription-id>"
SENTINEL_RESOURCE_GROUP="<resource-group-containing-sentinel-workspace>"
SENTINEL_WORKSPACE_NAME="<log-analytics-workspace-name>"

# Optional — both default to false. See section 8, Tool Authorization Tiers.
# MCP_ALLOW_WRITE="true"
# MCP_ALLOW_DESTRUCTIVE="true"

# Required only for provision-users.js (uses client secret auth instead of certificate)
AZURE_CLIENT_SECRET="<your-client-secret>"
```

### 6.2 Find Sentinel workspace details

```bash
az resource list \
  --resource-type "Microsoft.OperationsManagement/solutions" \
  --query "[?contains(name,'SecurityInsights')].{name:name, resourceGroup:resourceGroup}" \
  -o table
```

---

## 7. Server Structure

### 7.1 Tool registration pattern

Each tool is declared in the `tools` array in `server.js` with a name, description, and JSON schema:

```javascript
{
  name: "list_resource_groups",
  description: "List all Azure resource groups in the subscription",
  inputSchema: { type: "object", properties: {} }
}
```

### 7.2 Tool handler pattern

Each tool name is handled in the `CallToolRequestSchema` switch block:

```javascript
case "list_resource_groups": {
  const groups = [];
  for await (const rg of resourceClient.resourceGroups.list()) groups.push(rg.name);
  result = { resourceGroups: groups };
  break;
}
```

Errors are returned as MCP error responses (not thrown), so Claude Code always gets a readable message.

### 7.3 Adding a new tool (checklist)

1. Add an entry to the `tools` array in `server.js`
2. Add a `case` block in the `CallToolRequestSchema` handler
3. Grant the service principal the required permission
4. Add the tool to `TOOL_TIERS` in `server.js` (`read`, `write`, or `destructive`)
5. Test with the MCP stdio test below
6. Restart Claude Code (or run `/mcp` to reload)

---

## 8. Tool Authorization Tiers

The service principal's Azure RBAC and Graph grants are the same for every
tool call — Azure has no concept of "this specific call, from this specific
session." Left alone, that means the only thing standing between Claude and
a destructive operation is whatever permissions the SP happens to hold: a
classic **confused-deputy** setup, where the server lends its full privilege
to any caller without checking whether that particular call should be
allowed.

`server.js` closes that gap with an authorization layer that sits in front
of every tool call, independent of Azure/Graph permissions:

### 8.1 Tool tiers

Every tool in `TOOL_TIERS` is classified into one of three tiers:

| Tier          | Meaning                                              | Examples                                                    |
| ------------- | ----------------------------------------------------- | ------------------------------------------------------------ |
| `read`        | Read-only, always allowed                            | `list_resource_groups`, `list_sentinel_incidents`             |
| `write`       | State-changing but reversible/scoped                 | `create_resource_group`, `sync_intune_device`, `update_sentinel_incident` |
| `destructive` | Deletes, wipes, or grants access                     | `delete_resource_group`, `delete_user`, `wipe_intune_device`, `assign_role` |

### 8.2 Opt-in flags

`write` and `destructive` tools are refused by default. Two environment
variables enable them independently:

```env
# Both default to false/unset — write and destructive tools are blocked
# until you explicitly opt in for the session.
MCP_ALLOW_WRITE="true"
MCP_ALLOW_DESTRUCTIVE="true"
```

A denied call never reaches Azure — the check happens before any token is
requested or any API call is made. Claude gets back a clear reason instead
of a generic permission error:

```json
{
  "content": [{ "type": "text", "text": "Authorization denied: \"delete_resource_group\" is a destructive-tier tool (deletes, wipes, or grants access). Set MCP_ALLOW_DESTRUCTIVE=true in .env to enable destructive operations for this session." }],
  "isError": true
}
```

### 8.3 Local audit log

Every call — allowed or denied — is appended to `audit.log` (gitignored) in
the project root as a JSON line: timestamp, tool name, tier, the
authorization decision, and the outcome. This is a second, tamper-evident
record of server activity independent of whatever Azure/Entra logs the
service principal's activity on the cloud side. Obvious secret fields (e.g.
`password`) are redacted before logging.

```json
{"ts":"2026-08-03T00:45:04.489Z","tool":"delete_resource_group","tier":"destructive","decision":"denied","reason":"...","args":{"name":"rg-example"}}
{"ts":"2026-08-03T00:45:25.223Z","tool":"list_resource_groups","tier":"read","decision":"allowed","outcome":"ok","args":{}}
```

---

## 9. Integrated Services

### 9.1 Azure Portal

Covers resource management, identity, RBAC, and Administrative Units.

**API used:** Azure Resource Manager SDK + Microsoft Graph API + Azure CLI

**Tools:**

| Tool Name               | Description                                                          |
| ----------------------- | -------------------------------------------------------------------- |
| `list_resource_groups`  | List all resource groups in the subscription                         |
| `create_resource_group` | Create a new resource group (params: `name`, `location`)             |
| `delete_resource_group` | Delete a resource group (params: `name`)                             |
| `create_user`           | Create an Entra ID user (params: `upn`, `displayName`, `password`)   |
| `delete_user`           | Delete an Entra ID user (params: `upn`)                              |
| `list_users`            | List all Entra ID users via Azure CLI                                |
| `list_graph_users`      | List users via Graph API with pagination                             |
| `assign_role`           | Assign RBAC role (params: `assignee`, `role`, `scope`)               |
| `list_role_assignments` | List role assignments for a user (params: `assignee`)                |
| `list_aus`              | List all Administrative Units                                        |
| `create_au`             | Create an Administrative Unit (params: `displayName`, `description`) |
| `assign_au_role`        | Assign scoped role in AU (params: `auId`, `upn`, `roleTemplateId`)   |
| `add_au_member`         | Add user to Administrative Unit (params: `auId`, `upn`)              |

**Required permissions:**

| Permission                           | Type                      | Purpose                     |
| ------------------------------------ | ------------------------- | --------------------------- |
| `User.ReadWrite.All`                 | Graph Application         | Create/delete users         |
| `RoleManagement.ReadWrite.Directory` | Graph Application         | Assign directory roles      |
| `AdministrativeUnit.ReadWrite.All`   | Graph Application         | Manage Administrative Units |
| `Contributor`                        | Azure RBAC (Subscription) | Manage resource groups      |

---

### 9.2 Microsoft Intune

**API used:** Microsoft Graph API v1.0 (`/deviceManagement/...`)

**Tools:**

| Tool Name                         | Description                                       |
| --------------------------------- | ------------------------------------------------- |
| `list_intune_devices`             | List all Intune-managed devices                   |
| `list_noncompliant_devices`       | List devices with compliance state = noncompliant |
| `sync_intune_device`              | Trigger device sync (params: `deviceId`)          |
| `list_intune_compliance_policies` | List all device compliance policies               |

**Required permissions:**

| Permission                                     | Type              | Purpose                  |
| ---------------------------------------------- | ----------------- | ------------------------ |
| `DeviceManagementManagedDevices.Read.All`      | Graph Application | List/get managed devices |
| `DeviceManagementManagedDevices.ReadWrite.All` | Graph Application | Trigger device sync      |
| `DeviceManagementConfiguration.Read.All`       | Graph Application | List compliance policies |

**How to grant:** Azure Portal → Entra ID → App registrations → your app → API permissions → Add a permission → Microsoft Graph → Application permissions → search, add, then **Grant admin consent**.

---

### 9.3 Microsoft Defender for Cloud

**API used:** Azure Resource Manager REST API (`management.azure.com`)

**Token:** `getARMToken()` — scope: `https://management.azure.com/.default`

**Tools:**

| Tool Name                       | Description                                                          |
| ------------------------------- | -------------------------------------------------------------------- |
| `list_defender_alerts`          | List all Defender for Cloud security alerts                          |
| `get_secure_score`              | Get the subscription's secure score                                  |
| `list_defender_recommendations` | List security recommendations/assessments                            |
| `update_defender_alert`         | Update alert status (params: `alertName`, `resourceGroup`, `status`) |

**Required permissions:**

| Role              | Scope        | Purpose                                    |
| ----------------- | ------------ | ------------------------------------------ |
| `Security Reader` | Subscription | Read alerts, secure score, recommendations |
| `Security Admin`  | Subscription | Update/dismiss alerts                      |

```bash
az role assignment create \
  --assignee <CLIENT_ID> \
  --role "Security Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

---

### 9.4 Microsoft Sentinel

**API used:** Azure Resource Manager REST API + Log Analytics Query API

**Prerequisites:** Sentinel must be onboarded to a Log Analytics workspace. Verify with:

```bash
az resource list \
  --resource-type "Microsoft.OperationsManagement/solutions" \
  --query "[?contains(name,'SecurityInsights')].{name:name,resourceGroup:resourceGroup}" \
  -o table
```

**Tools:**

| Tool Name                       | Description                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `list_sentinel_incidents`       | List all Sentinel incidents (ordered by creation time)                                                  |
| `get_sentinel_incident`         | Get incident details (params: `incidentId`)                                                             |
| `update_sentinel_incident`      | Update incident (params: `incidentId`, `status`, `severity`, `classification`, `classificationComment`) |
| `list_sentinel_analytics_rules` | List all analytics/detection rules                                                                      |
| `run_sentinel_kql_query`        | Run KQL query (params: `query`, `timespan`)                                                             |

**Required permissions:**

| Role                           | Scope          | Purpose               |
| ------------------------------ | -------------- | --------------------- |
| `Microsoft Sentinel Reader`    | Resource Group | List incidents, rules |
| `Microsoft Sentinel Responder` | Resource Group | Update incidents      |
| `Log Analytics Reader`         | Resource Group | Run KQL queries       |

```bash
az role assignment create --assignee <CLIENT_ID> --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
az role assignment create --assignee <CLIENT_ID> --role "Log Analytics Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
```

**Environment variables required:**

```env
SENTINEL_RESOURCE_GROUP="your-resource-group"
SENTINEL_WORKSPACE_NAME="your-workspace-name"
```

---

### 9.5 Microsoft Purview M365

**API used:** Microsoft Graph API beta (`/beta/...`)

**Token:** `getGraphToken()` — scope: `https://graph.microsoft.com/.default`

> Most Purview Graph endpoints are in `/beta` and require Microsoft 365 E3/E5 licensing.

#### 9.5.1 Information Protection

| Tool Name                   | Description                                             |
| --------------------------- | ------------------------------------------------------- |
| `list_sensitivity_labels`   | List all configured sensitivity labels                  |
| `get_sensitivity_label`     | Get label details (params: `labelId`)                   |
| `list_sensitive_info_types` | List sensitive info types (SSN, PHI, credit card, etc.) |
| `list_label_policies`       | List sensitivity label policies                         |

**Required permissions:** `InformationProtectionPolicy.Read.All`, `SensitivityLabels.Read.All`

#### 9.5.2 Data Loss Prevention (DLP)

| Tool Name           | Description                       |
| ------------------- | --------------------------------- |
| `list_dlp_policies` | List DLP policies (beta endpoint) |
| `list_dlp_alerts`   | List DLP alerts via Security API  |

**Required permissions:** `SecurityAlert.Read.All`

> DLP policy creation/modification requires `Security & Compliance PowerShell` — not available via Graph API.

#### 9.5.3 Insider Risk Management (IRM)

| Tool Name                    | Description                                |
| ---------------------------- | ------------------------------------------ |
| `list_insider_risk_alerts`   | List IRM alerts filtered by service source |
| `list_insider_risk_policies` | List IRM policies (beta endpoint)          |

**Required permissions:** `SecurityAlert.Read.All`

#### 9.5.4 Information Barriers

| Tool Name                           | Description                           |
| ----------------------------------- | ------------------------------------- |
| `list_information_barrier_policies` | List all Information Barrier policies |
| `list_information_barrier_segments` | List all IB segments (user groups)    |

**Required permissions:** `InformationBarrierPolicy.Read.All`

#### 9.5.5 eDiscovery

| Tool Name                    | Description                                   |
| ---------------------------- | --------------------------------------------- |
| `list_ediscovery_cases`      | List all eDiscovery cases                     |
| `get_ediscovery_case`        | Get case details (params: `caseId`)           |
| `list_ediscovery_custodians` | List custodians in a case (params: `caseId`)  |
| `list_ediscovery_holds`      | List legal holds in a case (params: `caseId`) |

**Required permissions:** `eDiscovery.Read.All`

> The service principal must also be added to the **eDiscovery Manager** role group in the Microsoft Purview compliance portal.

#### 9.5.6 Records Management & Retention

| Tool Name                    | Description                                          |
| ---------------------------- | ---------------------------------------------------- |
| `list_retention_labels`      | List all retention labels                            |
| `list_retention_event_types` | List retention event types for event-based retention |

**Required permissions:** `RecordsManagement.Read.All`

#### 9.5.7 Audit

| Tool Name          | Description                                         |
| ------------------ | --------------------------------------------------- |
| `list_audit_logs`  | List directory audit logs (params: `filter`, `top`) |
| `list_signin_logs` | List sign-in audit logs (params: `filter`, `top`)   |

**Example filter values:**

- `activityDisplayName eq 'Add user'`
- `initiatedBy/user/userPrincipalName eq 'admin@domain.com'`

**Required permissions:** `AuditLog.Read.All`

> Sign-in logs require Microsoft Entra ID P1 or P2 license.

#### 9.5.8 Communication Compliance

| Tool Name                                | Description                                   |
| ---------------------------------------- | --------------------------------------------- |
| `list_communication_compliance_policies` | List Communication Compliance policies (beta) |

**Required permissions:** `CommunicationCompliance.Read.All`

#### 9.5.9 Compliance Manager

| Tool Name                     | Description                                |
| ----------------------------- | ------------------------------------------ |
| `list_compliance_assessments` | List Compliance Manager assessments (beta) |

**Required permissions:** `ComplianceManagement.Read.All`

#### 9.5.10 Data Security and Posture Management (DSPM)

| Tool Name           | Description                                              |
| ------------------- | -------------------------------------------------------- |
| `get_dspm_insights` | Get sensitive data type summary and DSPM insights (beta) |

**Required permissions:** `InformationProtectionPolicy.Read.All`

---

## 10. Required Permissions Summary

### Azure RBAC (assign via CLI or Portal)

```bash
# Defender for Cloud
az role assignment create --assignee <CLIENT_ID> --role "Security Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>

# Sentinel
az role assignment create --assignee <CLIENT_ID> --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
az role assignment create --assignee <CLIENT_ID> --role "Log Analytics Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
```

### Graph API Application Permissions (grant via Portal → Grant admin consent)

| Permission                                     | Service                             |
| ---------------------------------------------- | ----------------------------------- |
| `User.ReadWrite.All`                           | Azure Portal — Users                |
| `RoleManagement.ReadWrite.Directory`           | Azure Portal — RBAC                 |
| `AdministrativeUnit.ReadWrite.All`             | Azure Portal — Administrative Units |
| `DeviceManagementManagedDevices.Read.All`      | Intune — Devices                    |
| `DeviceManagementManagedDevices.ReadWrite.All` | Intune — Device sync                |
| `DeviceManagementConfiguration.Read.All`       | Intune — Compliance policies        |
| `SecurityAlert.Read.All`                       | Defender, DLP, Insider Risk         |
| `InformationProtectionPolicy.Read.All`         | Purview — Sensitivity labels, DSPM  |
| `SensitivityLabels.Read.All`                   | Purview — Sensitivity labels        |
| `InformationBarrierPolicy.Read.All`            | Purview — Information Barriers      |
| `eDiscovery.Read.All`                          | Purview — eDiscovery                |
| `RecordsManagement.Read.All`                   | Purview — Retention                 |
| `AuditLog.Read.All`                            | Purview — Audit logs                |
| `CommunicationCompliance.Read.All`             | Purview — Communication Compliance  |
| `ComplianceManagement.Read.All`                | Purview — Compliance Manager        |

---

## 11. Integrating with Claude Code

The server is registered in `~/.claude/settings.json`. Claude Code spawns `node server.js` automatically — no manual startup needed.

```json
{
  "mcpServers": {
    "azure": {
      "command": "node",
      "args": ["/Users/ismailyildirim/Desktop/azure-mcp-server/server.js"]
    }
  }
}
```

After changing `settings.json`, reload the server in Claude Code with `/mcp` or by restarting Claude Code.

In a conversation, ask:

> "What Azure tools do you have available?"

Claude will list all 47 registered tools.

---

## 12. Testing the Server

### MCP protocol smoke test (stdio)

Send the MCP handshake + a `tools/list` request directly over stdin:

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.1"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' \
  | node server.js 2>/dev/null
```

You should see an `initialize` response followed by a `tools/list` response containing all 47 tools.

### Test a live tool call

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.1"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_resource_groups","arguments":{}}}\n' \
  | node server.js 2>/dev/null
```

### Test with a parameterised tool

```bash
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.1"}}}\n{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_sentinel_kql_query","arguments":{"query":"SecurityAlert | take 5","timespan":"P1D"}}}\n' \
  | node server.js 2>/dev/null
```

### Interactive CLI testing with chat.js

`chat.js` is a minimal readline CLI for manually invoking tools without Claude Code. It requires the server to be running. See `chat.js` for supported commands.

---

## 13. Troubleshooting

| Error                                    | Cause                                              | Fix                                                                                      |
| ---------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `tenantId and clientId are required`     | Env vars not loaded                                | Check `.env` exists and `import "dotenv/config"` is the first line in `server.js`        |
| `Application is not authorized`          | Missing Graph permission                           | Add permission in App registrations → Grant admin consent                                |
| `AuthorizationFailed`                    | Missing Azure RBAC role                            | Assign required role via CLI or Portal                                                   |
| `Workspace not onboarded to Sentinel`    | Wrong workspace name                               | Run `az resource list` to find correct name                                              |
| `Cannot find module`                     | Missing package                                    | Run `npm install`                                                                        |
| `MODULE_NOT_FOUND` for `@azure/identity` | Corrupted install                                  | Run `rm -rf node_modules/@azure/identity && npm install @azure/identity`                 |
| MCP server not appearing in Claude Code  | Settings not reloaded                              | Run `/mcp` in Claude Code or restart it                                                  |
| No response on stdio                     | `console.log` polluting stdout                     | Use `process.stderr.write()` for all logging — stdout is reserved for MCP JSON-RPC       |
| `Authorization denied: "<tool>" is a write/destructive-tier tool` | Expected — tool tier isn't enabled | Set `MCP_ALLOW_WRITE` and/or `MCP_ALLOW_DESTRUCTIVE` to `"true"` in `.env` (see section 8) |

---

## 14. Bulk User Provisioning

`provision-users.js` is a standalone one-shot script that creates 20 pre-defined Entra ID test users in bulk. It is independent of the MCP server.

### How it works

- Authenticates using **client secret** (not certificate) via `AZURE_CLIENT_SECRET`
- Calls `POST https://graph.microsoft.com/v1.0/users` directly for each user
- Normalises names to email-safe format (strips accents, apostrophes, etc.)
- All users are created under the `Cavalry77.onmicrosoft.com` domain with temporary password `Cavalry!2026` and `forceChangePasswordNextSignIn: true`

### Before running

1. Add `AZURE_CLIENT_SECRET` to your `.env` file
2. Update the domain in `provision-users.js` if your tenant domain differs:
   ```javascript
   const upn = `${...}@Cavalry77.onmicrosoft.com`; // ← change this
   ```
3. Optionally update the default password to meet your tenant's password policy

### Run

```bash
node provision-users.js
```

Expected output:

```
Acquiring token...
Token acquired. Provisioning 20 users...

[OK]   emma.richardson@Cavalry77.onmicrosoft.com — Created
[OK]   marcus.chen@Cavalry77.onmicrosoft.com — Created
...
Done. 20 created, 0 failed.
```

### Required permissions

| Permission           | Type              | Purpose               |
| -------------------- | ----------------- | --------------------- |
| `User.ReadWrite.All` | Graph Application | Create Entra ID users |

> `provision-users.js` uses `AZURE_CLIENT_SECRET`. The main `server.js` uses certificate-based auth (`cavalry-sp.combined.pem`). The same app registration must have both a client secret and the certificate uploaded if you use both.

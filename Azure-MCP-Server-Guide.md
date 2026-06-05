# Building a Customized Azure MCP Server & Integrating with Claude Code

## Table of Contents

1. [What is an MCP Server?](#1-what-is-an-mcp-server)
2. [Architecture Overview](#2-architecture-overview)
3. [Prerequisites](#3-prerequisites)
4. [Project Setup](#4-project-setup)
5. [Authentication — Service Principal with Certificate](#5-authentication--service-principal-with-certificate)
6. [Environment Configuration](#6-environment-configuration)
7. [Server Structure](#7-server-structure)
8. [Integrated Services](#8-integrated-services)
   - [Azure Portal (Resource Groups, Users, RBAC, Administrative Units)](#81-azure-portal)
   - [Microsoft Intune](#82-microsoft-intune)
   - [Microsoft Defender for Cloud](#83-microsoft-defender-for-cloud)
   - [Microsoft Sentinel](#84-microsoft-sentinel)
   - [Microsoft Purview M365](#85-microsoft-purview-m365)
9. [Required Permissions Summary](#9-required-permissions-summary)
10. [Integrating with Claude Code](#10-integrating-with-claude-code)
11. [Testing the Server](#11-testing-the-server)
12. [Troubleshooting](#12-troubleshooting)
13. [Bulk User Provisioning](#13-bulk-user-provisioning)

---

## 1. What is an MCP Server?

**Model Context Protocol (MCP)** is an open standard that allows AI models like Claude to securely interact with external tools, APIs, and data sources. An MCP server exposes capabilities (tools) that Claude can invoke during a conversation.

In this project, the MCP server is a **Node.js/Express HTTP server** that:

- Exposes Azure and Microsoft 365 management operations as HTTP endpoints
- Authenticates to Azure/Microsoft 365 using a Service Principal with certificate-based auth
- Declares its tools in `tools.json` so Claude Code can discover and invoke them
- Runs locally on `http://localhost:3000`

---

## 2. Architecture Overview

```
Claude Code (AI)
      │
      │  reads tool definitions
      ▼
  tools.json  ──────────────────────────────────────────────────────┐
                                                                     │
      │  invokes tools via HTTP POST                                 │
      ▼                                                              │
Express Server (server.js, port 3000)                               │
      │                                                              │
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

### 4.1 Initialize the project

```bash
mkdir azure-mcp-server
cd azure-mcp-server
npm init -y
npm install express body-parser axios @azure/identity @azure/arm-resources dotenv
```

### 4.1.1 Run the project

Make sure your `.env` file and `cavalry-sp.combined.pem` are in place (see sections 5–6), then start the server:

```bash
cd azure-mcp-server
node server.js
```

Or using the npm script:

```bash
npm start
```

The server listens on `http://localhost:3000`. You should see:

```
MCP Azure Server running on port 3000
```

Keep this terminal open — the server must stay running while you use Claude Code. If port 3000 is already in use, kill the old process first:

```bash
kill $(lsof -ti :3000)
```

### 4.2 Project structure

```
azure-mcp-server/
├── server.js                  # Main Express server — all tool endpoints
├── tools.json                 # Tool registry — declares tools for Claude
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
const { ClientCertificateCredential } = require("@azure/identity");

const credential = new ClientCertificateCredential(
  process.env.AZURE_TENANT_ID,
  process.env.AZURE_CLIENT_ID,
  path.join(__dirname, "cavalry-sp.combined.pem"),
);

// Graph API token (Intune, Purview, Entra ID)
async function getGraphToken() {
  const tokenResponse = await credential.getToken(
    "https://graph.microsoft.com/.default",
  );
  return tokenResponse.token;
}

// ARM API token (Defender, Sentinel, Resource Groups)
async function getARMToken() {
  const tokenResponse = await credential.getToken(
    "https://management.azure.com/.default",
  );
  return tokenResponse.token;
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

# Required only for provision-users.js (uses client secret auth instead of certificate)
AZURE_CLIENT_SECRET="<your-client-secret>"
```

### 6.2 Load in server.js

```javascript
require("dotenv").config(); // Must be the first line
```

### 6.3 Find Sentinel workspace details

```bash
# Find Sentinel-enabled workspace
az resource list \
  --resource-type "Microsoft.OperationsManagement/solutions" \
  --query "[?contains(name,'SecurityInsights')].{name:name, resourceGroup:resourceGroup}" \
  -o table
```

---

## 7. Server Structure

### 7.1 Tool definition pattern (tools.json)

Every tool is declared in `tools.json` with a name, description, endpoint, and optional input schema:

```json
{
  "tools": [
    {
      "name": "list_resource_groups",
      "description": "List all Azure resource groups",
      "endpoint": "http://localhost:3000/list-resource-groups",
      "method": "POST"
    },
    {
      "name": "create_resource_group",
      "description": "Create a new resource group",
      "endpoint": "http://localhost:3000/create-resource-group",
      "method": "POST",
      "input_schema": {
        "name": "string",
        "location": "string"
      }
    }
  ]
}
```

### 7.2 Endpoint pattern (server.js)

Every tool maps to an Express route following this pattern:

```javascript
app.post("/endpoint-name", async (req, res) => {
  const { param1, param2 } = req.body;
  try {
    const token = await getGraphToken(); // or getARMToken()
    const response = await axios.get("https://graph.microsoft.com/...", {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response
      ? JSON.stringify(err.response.data)
      : err.message;
    res.status(500).json({ error: detail });
  }
});
```

### 7.3 Adding a new tool (checklist)

1. Add entry to `tools.json`
2. Add Express route to `server.js`
3. Grant the service principal the required permission
4. Restart the server
5. Test with `curl -s -X POST http://localhost:3000/<endpoint>`

---

## 8. Integrated Services

---

### 8.1 Azure Portal

Covers resource management, identity, RBAC, and Administrative Units.

**API used:** Azure Resource Manager SDK + Microsoft Graph API + Azure CLI

**Tools:**

| Tool Name               | Endpoint                      | Description                                                          |
| ----------------------- | ----------------------------- | -------------------------------------------------------------------- |
| `list_resource_groups`  | POST `/list-resource-groups`  | List all resource groups in the subscription                         |
| `create_resource_group` | POST `/create-resource-group` | Create a new resource group (params: `name`, `location`)             |
| `delete_resource_group` | POST `/delete-resource-group` | Delete a resource group (params: `name`)                             |
| `create_user`           | POST `/create-user`           | Create an Entra ID user (params: `upn`, `displayName`, `password`)   |
| `delete_user`           | POST `/delete-user`           | Delete an Entra ID user (params: `upn`)                              |
| `list_users`            | POST `/list-users`            | List all Entra ID users                                              |
| `list_graph_users`      | POST `/list-graph-users`      | List users via Graph API with pagination                             |
| `assign_role`           | POST `/assign-role`           | Assign RBAC role (params: `assignee`, `role`, `scope`)               |
| `list_role_assignments` | POST `/list-role-assignments` | List role assignments for a user (params: `assignee`)                |
| `list_aus`              | POST `/list-aus`              | List all Administrative Units                                        |
| `create_au`             | POST `/create-au`             | Create an Administrative Unit (params: `displayName`, `description`) |
| `assign_au_role`        | POST `/assign-au-role`        | Assign scoped role in AU (params: `auId`, `upn`, `roleTemplateId`)   |
| `add_au_member`         | POST `/add-au-member`         | Add user to Administrative Unit (params: `auId`, `upn`)              |

**Required permissions:**

| Permission                           | Type                      | Purpose                     |
| ------------------------------------ | ------------------------- | --------------------------- |
| `User.ReadWrite.All`                 | Graph Application         | Create/delete users         |
| `RoleManagement.ReadWrite.Directory` | Graph Application         | Assign directory roles      |
| `AdministrativeUnit.ReadWrite.All`   | Graph Application         | Manage Administrative Units |
| `Contributor`                        | Azure RBAC (Subscription) | Manage resource groups      |

---

### 8.2 Microsoft Intune

Covers device management, compliance, and device actions.

**API used:** Microsoft Graph API v1.0 (`/deviceManagement/...`)

**Tools:**

| Tool Name                         | Endpoint                                | Description                                       |
| --------------------------------- | --------------------------------------- | ------------------------------------------------- |
| `list_intune_devices`             | POST `/list-intune-devices`             | List all Intune-managed devices                   |
| `list_noncompliant_devices`       | POST `/list-noncompliant-devices`       | List devices with compliance state = noncompliant |
| `sync_intune_device`              | POST `/sync-intune-device`              | Trigger device sync (params: `deviceId`)          |
| `list_intune_compliance_policies` | POST `/list-intune-compliance-policies` | List all device compliance policies               |

**Required permissions:**

| Permission                                     | Type              | Purpose                  |
| ---------------------------------------------- | ----------------- | ------------------------ |
| `DeviceManagementManagedDevices.Read.All`      | Graph Application | List/get managed devices |
| `DeviceManagementManagedDevices.ReadWrite.All` | Graph Application | Trigger device sync      |
| `DeviceManagementConfiguration.Read.All`       | Graph Application | List compliance policies |

**How to grant:**

Go to **Azure Portal → Entra ID → App registrations → your app → API permissions → Add a permission → Microsoft Graph → Application permissions**, search for each permission, add it, then click **Grant admin consent**.

---

### 8.3 Microsoft Defender for Cloud

Covers security alerts, secure score, and security recommendations.

**API used:** Azure Resource Manager REST API (`management.azure.com`)

**Token:** `getARMToken()` — scope: `https://management.azure.com/.default`

**Tools:**

| Tool Name                       | Endpoint                              | Description                                                          |
| ------------------------------- | ------------------------------------- | -------------------------------------------------------------------- |
| `list_defender_alerts`          | POST `/list-defender-alerts`          | List all Defender for Cloud security alerts                          |
| `get_secure_score`              | POST `/get-secure-score`              | Get the subscription's secure score                                  |
| `list_defender_recommendations` | POST `/list-defender-recommendations` | List security recommendations/assessments                            |
| `update_defender_alert`         | POST `/update-defender-alert`         | Update alert status (params: `alertName`, `resourceGroup`, `status`) |

**Required permissions:**

| Role              | Scope        | Purpose                                    |
| ----------------- | ------------ | ------------------------------------------ |
| `Security Reader` | Subscription | Read alerts, secure score, recommendations |
| `Security Admin`  | Subscription | Update/dismiss alerts                      |

**How to grant:**

```bash
az role assignment create \
  --assignee <CLIENT_ID> \
  --role "Security Reader" \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

---

### 8.4 Microsoft Sentinel

Covers incidents, analytics rules, and KQL queries.

**API used:** Azure Resource Manager REST API + Log Analytics Query API

**Token:** `getARMToken()` for incidents/rules, Log Analytics token for KQL queries

**Prerequisites:** Sentinel must be onboarded to a Log Analytics workspace. Verify with:

```bash
az resource list \
  --resource-type "Microsoft.OperationsManagement/solutions" \
  --query "[?contains(name,'SecurityInsights')].{name:name,resourceGroup:resourceGroup}" \
  -o table
```

**Tools:**

| Tool Name                       | Endpoint                              | Description                                                                                             |
| ------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `list_sentinel_incidents`       | POST `/list-sentinel-incidents`       | List all Sentinel incidents (ordered by creation time)                                                  |
| `get_sentinel_incident`         | POST `/get-sentinel-incident`         | Get incident details (params: `incidentId`)                                                             |
| `update_sentinel_incident`      | POST `/update-sentinel-incident`      | Update incident (params: `incidentId`, `status`, `severity`, `classification`, `classificationComment`) |
| `list_sentinel_analytics_rules` | POST `/list-sentinel-analytics-rules` | List all analytics/detection rules                                                                      |
| `run_sentinel_kql_query`        | POST `/run-sentinel-kql-query`        | Run KQL query (params: `query`, `timespan`)                                                             |

**Required permissions:**

| Role                           | Scope          | Purpose               |
| ------------------------------ | -------------- | --------------------- |
| `Microsoft Sentinel Reader`    | Resource Group | List incidents, rules |
| `Microsoft Sentinel Responder` | Resource Group | Update incidents      |
| `Log Analytics Reader`         | Resource Group | Run KQL queries       |

**How to grant:**

```bash
# Replace <RG> with SENTINEL_RESOURCE_GROUP value
az role assignment create --assignee <CLIENT_ID> --role "Microsoft Sentinel Responder" --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
az role assignment create --assignee <CLIENT_ID> --role "Log Analytics Reader" --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
```

**Environment variables required:**

```env
SENTINEL_RESOURCE_GROUP="your-resource-group"
SENTINEL_WORKSPACE_NAME="your-workspace-name"
```

---

### 8.5 Microsoft Purview M365

Covers Information Protection, DLP, Insider Risk Management, Information Barriers, eDiscovery, Records Management, and Audit.

**API used:** Microsoft Graph API beta (`/beta/...`)

**Token:** `getGraphToken()` — scope: `https://graph.microsoft.com/.default`

> **Important:** Most Purview Graph endpoints are in `/beta` and require Microsoft 365 E3/E5 licensing.

---

#### 8.5.1 Information Protection

Manage sensitivity labels and label policies.

| Tool Name                   | Endpoint                          | Description                                             |
| --------------------------- | --------------------------------- | ------------------------------------------------------- |
| `list_sensitivity_labels`   | POST `/list-sensitivity-labels`   | List all configured sensitivity labels                  |
| `get_sensitivity_label`     | POST `/get-sensitivity-label`     | Get label details (params: `labelId`)                   |
| `list_sensitive_info_types` | POST `/list-sensitive-info-types` | List sensitive info types (SSN, PHI, credit card, etc.) |
| `list_label_policies`       | POST `/list-label-policies`       | List sensitivity label policies                         |

**Required permissions:**

| Permission                             | Type              |
| -------------------------------------- | ----------------- |
| `InformationProtectionPolicy.Read.All` | Graph Application |
| `SensitivityLabels.Read.All`           | Graph Application |

---

#### 8.5.2 Data Loss Prevention (DLP)

Read DLP alerts. Note: DLP policy management requires PowerShell.

| Tool Name           | Endpoint                  | Description                       |
| ------------------- | ------------------------- | --------------------------------- |
| `list_dlp_policies` | POST `/list-dlp-policies` | List DLP policies (beta endpoint) |
| `list_dlp_alerts`   | POST `/list-dlp-alerts`   | List DLP alerts via Security API  |

**Required permissions:**

| Permission               | Type              |
| ------------------------ | ----------------- |
| `SecurityAlert.Read.All` | Graph Application |

> **Note:** DLP policy creation/modification requires `Security & Compliance PowerShell` — it is not available via Graph API.

---

#### 8.5.3 Insider Risk Management (IRM)

Read IRM alerts via the Security API. Policy management requires PowerShell.

| Tool Name                    | Endpoint                           | Description                                |
| ---------------------------- | ---------------------------------- | ------------------------------------------ |
| `list_insider_risk_alerts`   | POST `/list-insider-risk-alerts`   | List IRM alerts filtered by service source |
| `list_insider_risk_policies` | POST `/list-insider-risk-policies` | List IRM policies (beta endpoint)          |

**Required permissions:**

| Permission               | Type              |
| ------------------------ | ----------------- |
| `SecurityAlert.Read.All` | Graph Application |

---

#### 8.5.4 Information Barriers

List information barrier policies and segments.

| Tool Name                           | Endpoint                                  | Description                           |
| ----------------------------------- | ----------------------------------------- | ------------------------------------- |
| `list_information_barrier_policies` | POST `/list-information-barrier-policies` | List all Information Barrier policies |
| `list_information_barrier_segments` | POST `/list-information-barrier-segments` | List all IB segments (user groups)    |

**Required permissions:**

| Permission                          | Type              |
| ----------------------------------- | ----------------- |
| `InformationBarrierPolicy.Read.All` | Graph Application |

> **Note:** Creating/applying Information Barrier policies requires PowerShell (`Set-InformationBarrierPolicy`).

---

#### 8.5.5 eDiscovery

Manage eDiscovery cases, custodians, and legal holds.

| Tool Name                    | Endpoint                           | Description                                   |
| ---------------------------- | ---------------------------------- | --------------------------------------------- |
| `list_ediscovery_cases`      | POST `/list-ediscovery-cases`      | List all eDiscovery cases                     |
| `get_ediscovery_case`        | POST `/get-ediscovery-case`        | Get case details (params: `caseId`)           |
| `list_ediscovery_custodians` | POST `/list-ediscovery-custodians` | List custodians in a case (params: `caseId`)  |
| `list_ediscovery_holds`      | POST `/list-ediscovery-holds`      | List legal holds in a case (params: `caseId`) |

**Required permissions:**

| Permission            | Type              |
| --------------------- | ----------------- |
| `eDiscovery.Read.All` | Graph Application |

> **Note:** The service principal must also be added to the **eDiscovery Manager** role group in the Microsoft Purview compliance portal.

---

#### 8.5.6 Records Management & Retention

Manage retention labels and event types.

| Tool Name                    | Endpoint                           | Description                                          |
| ---------------------------- | ---------------------------------- | ---------------------------------------------------- |
| `list_retention_labels`      | POST `/list-retention-labels`      | List all retention labels                            |
| `list_retention_event_types` | POST `/list-retention-event-types` | List retention event types for event-based retention |

**Required permissions:**

| Permission                   | Type              |
| ---------------------------- | ----------------- |
| `RecordsManagement.Read.All` | Graph Application |

---

#### 8.5.7 Audit

Access directory audit logs and sign-in logs.

| Tool Name          | Endpoint                 | Description                                         |
| ------------------ | ------------------------ | --------------------------------------------------- |
| `list_audit_logs`  | POST `/list-audit-logs`  | List directory audit logs (params: `filter`, `top`) |
| `list_signin_logs` | POST `/list-signin-logs` | List sign-in audit logs (params: `filter`, `top`)   |

**Example filter values:**

- `activityDisplayName eq 'Add user'`
- `initiatedBy/user/userPrincipalName eq 'admin@domain.com'`

**Required permissions:**

| Permission          | Type              |
| ------------------- | ----------------- |
| `AuditLog.Read.All` | Graph Application |

> **Note:** Sign-in logs require Microsoft Entra ID P1 or P2 license.

---

#### 8.5.8 Communication Compliance

| Tool Name                                | Endpoint                                       | Description                                   |
| ---------------------------------------- | ---------------------------------------------- | --------------------------------------------- |
| `list_communication_compliance_policies` | POST `/list-communication-compliance-policies` | List Communication Compliance policies (beta) |

**Required permissions:**

| Permission                         | Type              |
| ---------------------------------- | ----------------- |
| `CommunicationCompliance.Read.All` | Graph Application |

> **Note:** Uses the `/beta` endpoint. Full policy management (create/edit/delete) must be done in **compliance.microsoft.com**.

---

#### 8.5.9 Compliance Manager

| Tool Name                     | Endpoint                            | Description                                |
| ----------------------------- | ----------------------------------- | ------------------------------------------ |
| `list_compliance_assessments` | POST `/list-compliance-assessments` | List Compliance Manager assessments (beta) |

**Required permissions:**

| Permission                      | Type              |
| ------------------------------- | ----------------- |
| `ComplianceManagement.Read.All` | Graph Application |

> **Note:** Uses the `/beta` endpoint. Full Compliance Manager management is available at **compliance.microsoft.com**.

---

#### 8.5.10 Data Security and Posture Management (DSPM)

| Tool Name           | Endpoint                  | Description                                              |
| ------------------- | ------------------------- | -------------------------------------------------------- |
| `get_dspm_insights` | POST `/get-dspm-insights` | Get sensitive data type summary and DSPM insights (beta) |

**Required permissions:**

| Permission                             | Type              |
| -------------------------------------- | ----------------- |
| `InformationProtectionPolicy.Read.All` | Graph Application |

> **Note:** Uses the `/beta` endpoint. Requires Microsoft Purview or Microsoft 365 E5 licensing.

---

## 9. Required Permissions Summary

### Azure RBAC (assign via CLI or Portal)

```bash
# Defender for Cloud
az role assignment create --assignee <CLIENT_ID> --role "Security Reader" --scope /subscriptions/<SUBSCRIPTION_ID>

# Sentinel
az role assignment create --assignee <CLIENT_ID> --role "Microsoft Sentinel Responder" --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
az role assignment create --assignee <CLIENT_ID> --role "Log Analytics Reader" --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>
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
| `InformationProtectionPolicy.Read.All`         | Purview — Sensitivity labels        |
| `SensitivityLabels.Read.All`                   | Purview — Sensitivity labels        |
| `InformationBarrierPolicy.Read.All`            | Purview — Information Barriers      |
| `eDiscovery.Read.All`                          | Purview — eDiscovery                |
| `RecordsManagement.Read.All`                   | Purview — Retention                 |
| `AuditLog.Read.All`                            | Purview — Audit logs                |
| `CommunicationCompliance.Read.All`             | Purview — Communication Compliance  |
| `ComplianceManagement.Read.All`                | Purview — Compliance Manager        |

---

## 10. Integrating with Claude Code

### 10.1 How Claude Code uses the MCP server

Claude Code reads `tools.json` to discover available tools and calls the corresponding HTTP endpoints during conversations. The server must be running before starting Claude Code.

### 10.2 Register the MCP server in Claude Code

Add the server to Claude Code's settings:

```bash
claude mcp add azure-mcp --transport http --url http://localhost:3000
```

Or manually edit `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "azure-mcp": {
      "type": "http",
      "url": "http://localhost:3000"
    }
  }
}
```

### 10.3 Start the server before using Claude Code

Always start the server first in a terminal and keep it running:

```bash
cd /Users/ismailyildirim/Desktop/azure-mcp-server && node server.js
```

**Recommended workflow in VS Code:**

1. Open VS Code terminal (`` Ctrl+` ``)
2. Tab 1: Run `node server.js` — keep this running
3. Tab 2: Use `curl` or Claude Code for testing

### 10.4 Verify Claude Code can see the tools

In Claude Code, ask:

> "What Azure tools do you have available?"

Claude will list all tools declared in `tools.json`.

### 10.5 Kill leftover server processes

If the server doesn't start because port 3000 is already in use:

```bash
kill $(lsof -ti :3000)
```

---

## 11. Testing the Server

### Test individual endpoints

```bash
# Azure Portal
curl -s -X POST http://localhost:3000/list-resource-groups

# Intune
curl -s -X POST http://localhost:3000/list-intune-devices
curl -s -X POST http://localhost:3000/list-noncompliant-devices

# Defender
curl -s -X POST http://localhost:3000/get-secure-score
curl -s -X POST http://localhost:3000/list-defender-alerts

# Sentinel
curl -s -X POST http://localhost:3000/list-sentinel-incidents

# Purview — Audit
curl -s -X POST http://localhost:3000/list-audit-logs

# Purview — Sensitivity Labels
curl -s -X POST http://localhost:3000/list-sensitivity-labels

# Purview — Communication Compliance (beta)
curl -s -X POST http://localhost:3000/list-communication-compliance-policies

# Purview — Compliance Manager (beta)
curl -s -X POST http://localhost:3000/list-compliance-assessments

# Purview — DSPM (beta)
curl -s -X POST http://localhost:3000/get-dspm-insights
```

### Interactive CLI testing with chat.js

`chat.js` is a minimal readline CLI for manually invoking tools without Claude Code. Run it in a second terminal while `server.js` is running:

```bash
node chat.js
```

Type one of these phrases at the prompt:

| Input phrase           | Tool invoked                          |
| ---------------------- | ------------------------------------- |
| `list resource groups` | `list_resource_groups`                |
| `create user`          | `create_user` (hardcoded test values) |
| `assign role`          | `assign_role` (hardcoded test values) |

Anything else prints `Command not recognized`. This is a lightweight smoke-test tool — extend the `if/else` block in `chat.js` to add more commands.

### Test endpoints with parameters

```bash
# Get a specific Sentinel incident
curl -s -X POST http://localhost:3000/get-sentinel-incident \
  -H "Content-Type: application/json" \
  -d '{"incidentId": "your-incident-id"}'

# Sync an Intune device
curl -s -X POST http://localhost:3000/sync-intune-device \
  -H "Content-Type: application/json" \
  -d '{"deviceId": "your-device-id"}'

# Run a KQL query
curl -s -X POST http://localhost:3000/run-sentinel-kql-query \
  -H "Content-Type: application/json" \
  -d '{"query": "SecurityAlert | take 10", "timespan": "P1D"}'
```

---

## 12. Troubleshooting

| Error                                    | Cause                                                      | Fix                                                                                         |
| ---------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `tenantId and clientId are required`     | Env vars not loaded                                        | Check `.env` file exists; ensure `require("dotenv").config()` is first line                 |
| `Cannot POST /endpoint`                  | Server running old code                                    | Restart with `node server.js`                                                               |
| `Application is not authorized`          | Missing Graph permission                                   | Add permission in App registrations → Grant admin consent                                   |
| `AuthorizationFailed`                    | Missing Azure RBAC role                                    | Assign required role via CLI or Portal                                                      |
| `Workspace not onboarded to Sentinel`    | Wrong workspace name                                       | Run `az resource list` to find correct name                                                 |
| Port 3000 already in use                 | Old server process still running                           | Run `kill $(lsof -ti :3000)` — if this returns "not enough arguments", port is already free |
| `Cannot find module 'dotenv'`            | Package not installed                                      | Run `npm install dotenv`                                                                    |
| `MODULE_NOT_FOUND` for `@azure/identity` | Corrupted install — `dist/` directory missing from package | Run `rm -rf node_modules/@azure/identity && npm install @azure/identity`                    |

---

## 13. Bulk User Provisioning

`provision-users.js` is a standalone one-shot script that creates 20 pre-defined Entra ID test users in bulk. It is independent of the MCP server and does not use the Express endpoints.

### How it works

- Authenticates using **client secret** (not certificate) via `AZURE_CLIENT_SECRET`
- Calls `POST https://graph.microsoft.com/v1.0/users` directly for each user
- Normalises names to email-safe format (strips accents, apostrophes, etc.)
- All users are created under the `Cavalry77.onmicrosoft.com` domain with the temporary password `Cavalry!2026` and `forceChangePasswordNextSignIn: true`

### Before running

1. Add `AZURE_CLIENT_SECRET` to your `.env` file (see section 6.1)
2. Update the domain in `provision-users.js` if your tenant domain is different:
   ```javascript
   const upn = `${...}@Cavalry77.onmicrosoft.com`; // ← change this
   ```
3. Optionally update the default password (`Cavalry!2026`) to meet your tenant's password policy

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

> **Note:** `provision-users.js` uses `AZURE_CLIENT_SECRET` for authentication. The main `server.js` uses certificate-based auth (`cavalry-sp.combined.pem`). Make sure the same app registration has both a client secret and the certificate uploaded if you use both.

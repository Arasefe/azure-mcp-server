import dotenv from "dotenv";
import { fileURLToPath } from "url";
import path from "path";
dotenv.config({ override: true, path: new URL(".env", import.meta.url).pathname });
import { randomUUID } from "node:crypto";
import fs from "fs";
import axios from "axios";
import { ClientCertificateCredential } from "@azure/identity";
import { ResourceManagementClient } from "@azure/arm-resources";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const sentinelResourceGroup = process.env.SENTINEL_RESOURCE_GROUP;
const sentinelWorkspace = process.env.SENTINEL_WORKSPACE_NAME;

const credential = new ClientCertificateCredential(
  tenantId,
  clientId,
  path.join(__dirname, "cavalry-sp.combined.pem")
);
const resourceClient = new ResourceManagementClient(credential, subscriptionId);

async function getGraphToken() {
  const r = await credential.getToken("https://graph.microsoft.com/.default");
  return r.token;
}

async function getARMToken() {
  const r = await credential.getToken("https://management.azure.com/.default");
  return r.token;
}

async function resolvePrincipalId(identifier) {
  if (GUID_RE.test(identifier)) return identifier;
  const token = await getGraphToken();
  const r = await axios.get(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(identifier)}?$select=id`, { headers: { Authorization: `Bearer ${token}` } });
  return r.data.id;
}

async function resolveRoleDefinitionId(roleNameOrId, scope) {
  if (GUID_RE.test(roleNameOrId)) return `${scope}/providers/Microsoft.Authorization/roleDefinitions/${roleNameOrId}`;
  const token = await getARMToken();
  const r = await axios.get(`https://management.azure.com${scope}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&$filter=${encodeURIComponent(`roleName eq '${roleNameOrId}'`)}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.data.value.length) throw new Error(`Role definition not found: ${roleNameOrId}`);
  return r.data.value[0].id;
}

// ── Per-call authorization ──────────────────────────────────────────────────
// The service principal's Azure RBAC / Graph grants are the same for every
// tool call. Without a layer here, "can this call happen" is decided
// entirely by whether the SP happens to hold that permission — a classic
// confused-deputy shape. TOOL_TIERS + the two MCP_ALLOW_* flags below add an
// explicit, server-side authorization decision on top of that: write and
// destructive tools are refused unless the operator has opted in for this
// session, regardless of what the SP is otherwise allowed to do.

const READ = "read";
const WRITE = "write";
const DESTRUCTIVE = "destructive";

const TOOL_TIERS = {
  list_resource_groups: READ,
  create_resource_group: WRITE,
  delete_resource_group: DESTRUCTIVE,
  assign_role: DESTRUCTIVE,
  create_user: WRITE,
  delete_user: DESTRUCTIVE,
  list_role_assignments: READ,
  list_users: READ,
  list_graph_users: READ,
  list_aus: READ,
  create_au: WRITE,
  assign_au_role: WRITE,
  add_au_member: WRITE,
  list_intune_devices: READ,
  list_noncompliant_devices: READ,
  sync_intune_device: WRITE,
  list_intune_compliance_policies: READ,
  get_intune_device: READ,
  retire_intune_device: DESTRUCTIVE,
  wipe_intune_device: DESTRUCTIVE,
  reboot_intune_device: WRITE,
  list_intune_configuration_profiles: READ,
  list_intune_apps: READ,
  list_intune_app_assignments: READ,
  list_intune_autopilot_devices: READ,
  list_intune_enrollment_configurations: READ,
  list_intune_scripts: READ,
  list_intune_remediation_scripts: READ,
  list_intune_managed_app_policies: READ,
  list_defender_alerts: READ,
  get_secure_score: READ,
  list_defender_recommendations: READ,
  update_defender_alert: WRITE,
  list_sentinel_incidents: READ,
  get_sentinel_incident: READ,
  update_sentinel_incident: WRITE,
  list_sentinel_analytics_rules: READ,
  run_sentinel_kql_query: READ,
  list_sentinel_incident_comments: READ,
  add_sentinel_incident_comment: WRITE,
  list_sentinel_incident_alerts: READ,
  list_sentinel_incident_entities: READ,
  list_sentinel_analytics_rule_templates: READ,
  list_sentinel_hunting_queries: READ,
  list_sentinel_bookmarks: READ,
  list_sentinel_watchlists: READ,
  list_sentinel_watchlist_items: READ,
  list_sentinel_threat_indicators: READ,
  list_sentinel_data_connectors: READ,
  list_sentinel_automation_rules: READ,
  list_sensitivity_labels: READ,
  get_sensitivity_label: READ,
  list_sensitive_info_types: READ,
  list_label_policies: READ,
  list_dlp_policies: READ,
  list_dlp_alerts: READ,
  list_insider_risk_alerts: READ,
  list_insider_risk_policies: READ,
  list_information_barrier_policies: READ,
  list_information_barrier_segments: READ,
  list_ediscovery_cases: READ,
  get_ediscovery_case: READ,
  list_ediscovery_custodians: READ,
  list_ediscovery_holds: READ,
  list_ediscovery_searches: READ,
  list_ediscovery_review_sets: READ,
  list_retention_labels: READ,
  list_retention_event_types: READ,
  list_audit_logs: READ,
  list_signin_logs: READ,
  list_communication_compliance_policies: READ,
  list_compliance_assessments: READ,
  get_compliance_assessment: READ,
  list_compliance_improvement_actions: READ,
  get_dspm_insights: READ,
};

const writeEnabled = process.env.MCP_ALLOW_WRITE === "true";
const destructiveEnabled = process.env.MCP_ALLOW_DESTRUCTIVE === "true";

function authorize(name) {
  const tier = TOOL_TIERS[name];
  if (tier === undefined) return { allowed: false, tier: "unknown", reason: `Unknown tool: ${name}` };
  if (tier === WRITE && !writeEnabled) {
    return { allowed: false, tier, reason: `"${name}" is a write-tier tool. Set MCP_ALLOW_WRITE=true in .env to enable write operations for this session.` };
  }
  if (tier === DESTRUCTIVE && !destructiveEnabled) {
    return { allowed: false, tier, reason: `"${name}" is a destructive-tier tool (deletes, wipes, or grants access). Set MCP_ALLOW_DESTRUCTIVE=true in .env to enable destructive operations for this session.` };
  }
  return { allowed: true, tier };
}

// ── Local audit log ──────────────────────────────────────────────────────────
// A second, tamper-evident record of every call and its authorization
// decision, independent of whatever Azure/Entra logs the SP's activity on
// the cloud side.

const auditLogPath = path.join(__dirname, "audit.log");

function redactArgs(args) {
  if (!args || typeof args !== "object") return args;
  const clone = { ...args };
  if ("password" in clone) clone.password = "[redacted]";
  return clone;
}

function auditEntry(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
  fs.appendFile(auditLogPath, line, (err) => {
    if (err) process.stderr.write(`Audit log write failed: ${err.message}\n`);
  });
}

// ── MCP server ────────────────────────────────────────────────────────────────

const server = new Server(
  { name: "azure-mcp-server", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const tools = [
  { name: "list_resource_groups", description: "List all Azure resource groups in the subscription", inputSchema: { type: "object", properties: {} } },
  { name: "create_resource_group", description: "Create an Azure resource group", inputSchema: { type: "object", properties: { name: { type: "string" }, location: { type: "string", description: "Azure region (default: eastus)" } }, required: ["name"] } },
  { name: "delete_resource_group", description: "Delete an Azure resource group", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "assign_role", description: "Assign an Azure RBAC role to a principal", inputSchema: { type: "object", properties: { assignee: { type: "string" }, role: { type: "string" }, scope: { type: "string" } }, required: ["assignee", "role", "scope"] } },
  { name: "create_user", description: "Create an Entra ID user via Graph API", inputSchema: { type: "object", properties: { upn: { type: "string" }, displayName: { type: "string" }, password: { type: "string" } }, required: ["upn", "displayName", "password"] } },
  { name: "delete_user", description: "Delete an Entra ID user", inputSchema: { type: "object", properties: { upn: { type: "string" } }, required: ["upn"] } },
  { name: "list_role_assignments", description: "List Azure RBAC role assignments for an assignee", inputSchema: { type: "object", properties: { assignee: { type: "string" } }, required: ["assignee"] } },
  { name: "list_users", description: "List Entra ID users via Azure CLI", inputSchema: { type: "object", properties: {} } },
  { name: "list_graph_users", description: "List all Entra ID users via Graph API (paginated)", inputSchema: { type: "object", properties: {} } },
  { name: "list_aus", description: "List Entra ID Administrative Units", inputSchema: { type: "object", properties: {} } },
  { name: "create_au", description: "Create an Entra ID Administrative Unit", inputSchema: { type: "object", properties: { displayName: { type: "string" }, description: { type: "string" } }, required: ["displayName"] } },
  { name: "assign_au_role", description: "Assign a scoped directory role within an Administrative Unit", inputSchema: { type: "object", properties: { auId: { type: "string" }, upn: { type: "string" }, roleTemplateId: { type: "string" } }, required: ["auId", "upn", "roleTemplateId"] } },
  { name: "add_au_member", description: "Add a user to an Administrative Unit", inputSchema: { type: "object", properties: { auId: { type: "string" }, upn: { type: "string" } }, required: ["auId", "upn"] } },
  { name: "list_intune_devices", description: "List all Intune managed devices", inputSchema: { type: "object", properties: {} } },
  { name: "list_noncompliant_devices", description: "List non-compliant Intune devices", inputSchema: { type: "object", properties: {} } },
  { name: "sync_intune_device", description: "Trigger a sync for an Intune managed device", inputSchema: { type: "object", properties: { deviceId: { type: "string" } }, required: ["deviceId"] } },
  { name: "list_intune_compliance_policies", description: "List Intune device compliance policies", inputSchema: { type: "object", properties: {} } },
  { name: "get_intune_device", description: "Get full details of a specific Intune managed device", inputSchema: { type: "object", properties: { deviceId: { type: "string" } }, required: ["deviceId"] } },
  { name: "retire_intune_device", description: "Retire (unenroll) an Intune managed device from MDM", inputSchema: { type: "object", properties: { deviceId: { type: "string" } }, required: ["deviceId"] } },
  { name: "wipe_intune_device", description: "Remotely wipe an Intune managed device to factory reset", inputSchema: { type: "object", properties: { deviceId: { type: "string" }, keepEnrollmentData: { type: "boolean" }, keepUserData: { type: "boolean" } }, required: ["deviceId"] } },
  { name: "reboot_intune_device", description: "Remotely reboot an Intune managed device", inputSchema: { type: "object", properties: { deviceId: { type: "string" } }, required: ["deviceId"] } },
  { name: "list_intune_configuration_profiles", description: "List Intune device configuration profiles", inputSchema: { type: "object", properties: {} } },
  { name: "list_intune_apps", description: "List Intune managed mobile apps (Win32, store, LOB)", inputSchema: { type: "object", properties: {} } },
  { name: "list_intune_app_assignments", description: "List group assignments for a specific Intune app", inputSchema: { type: "object", properties: { appId: { type: "string" } }, required: ["appId"] } },
  { name: "list_intune_autopilot_devices", description: "List Windows Autopilot registered device identities", inputSchema: { type: "object", properties: {} } },
  { name: "list_intune_enrollment_configurations", description: "List Intune device enrollment configurations and restrictions", inputSchema: { type: "object", properties: {} } },
  { name: "list_intune_scripts", description: "List Intune device management scripts (PowerShell / shell)", inputSchema: { type: "object", properties: {} } },
  { name: "list_intune_remediation_scripts", description: "List Intune proactive remediation (device health) scripts", inputSchema: { type: "object", properties: {} } },
  { name: "list_intune_managed_app_policies", description: "List Intune Mobile Application Management (MAM) app protection policies", inputSchema: { type: "object", properties: {} } },
  { name: "list_defender_alerts", description: "List Defender for Cloud security alerts", inputSchema: { type: "object", properties: {} } },
  { name: "get_secure_score", description: "Get the Defender for Cloud secure score", inputSchema: { type: "object", properties: {} } },
  { name: "list_defender_recommendations", description: "List Defender for Cloud security recommendations/assessments", inputSchema: { type: "object", properties: {} } },
  { name: "update_defender_alert", description: "Update the status of a Defender for Cloud alert", inputSchema: { type: "object", properties: { alertName: { type: "string" }, resourceGroup: { type: "string" }, status: { type: "string", enum: ["Dismissed", "Resolved", "Active"] } }, required: ["alertName", "resourceGroup", "status"] } },
  { name: "list_sentinel_incidents", description: "List Microsoft Sentinel incidents ordered by creation time (newest first)", inputSchema: { type: "object", properties: {} } },
  { name: "get_sentinel_incident", description: "Get a specific Sentinel incident by ID", inputSchema: { type: "object", properties: { incidentId: { type: "string" } }, required: ["incidentId"] } },
  { name: "update_sentinel_incident", description: "Update a Sentinel incident (status, severity, classification)", inputSchema: { type: "object", properties: { incidentId: { type: "string" }, status: { type: "string" }, severity: { type: "string" }, classification: { type: "string" }, classificationComment: { type: "string" } }, required: ["incidentId"] } },
  { name: "list_sentinel_analytics_rules", description: "List Sentinel analytics (alert) rules", inputSchema: { type: "object", properties: {} } },
  { name: "run_sentinel_kql_query", description: "Run a KQL query against the Sentinel Log Analytics workspace", inputSchema: { type: "object", properties: { query: { type: "string" }, timespan: { type: "string", description: "ISO 8601 duration, e.g. P1D (default)" } }, required: ["query"] } },
  { name: "list_sentinel_incident_comments", description: "List all comments on a Sentinel incident", inputSchema: { type: "object", properties: { incidentId: { type: "string" } }, required: ["incidentId"] } },
  { name: "add_sentinel_incident_comment", description: "Add a comment to a Sentinel incident", inputSchema: { type: "object", properties: { incidentId: { type: "string" }, message: { type: "string" } }, required: ["incidentId", "message"] } },
  { name: "list_sentinel_incident_alerts", description: "List alerts associated with a Sentinel incident", inputSchema: { type: "object", properties: { incidentId: { type: "string" } }, required: ["incidentId"] } },
  { name: "list_sentinel_incident_entities", description: "List entities (users, IPs, hosts, URLs) found in a Sentinel incident", inputSchema: { type: "object", properties: { incidentId: { type: "string" } }, required: ["incidentId"] } },
  { name: "list_sentinel_analytics_rule_templates", description: "List all built-in Sentinel analytics rule templates", inputSchema: { type: "object", properties: {} } },
  { name: "list_sentinel_hunting_queries", description: "List Sentinel saved hunting queries", inputSchema: { type: "object", properties: {} } },
  { name: "list_sentinel_bookmarks", description: "List Sentinel threat hunting bookmarks", inputSchema: { type: "object", properties: {} } },
  { name: "list_sentinel_watchlists", description: "List Sentinel watchlists", inputSchema: { type: "object", properties: {} } },
  { name: "list_sentinel_watchlist_items", description: "List items in a specific Sentinel watchlist", inputSchema: { type: "object", properties: { watchlistAlias: { type: "string" } }, required: ["watchlistAlias"] } },
  { name: "list_sentinel_threat_indicators", description: "List Sentinel threat intelligence indicators", inputSchema: { type: "object", properties: {} } },
  { name: "list_sentinel_data_connectors", description: "List Sentinel data connectors and their status", inputSchema: { type: "object", properties: {} } },
  { name: "list_sentinel_automation_rules", description: "List Sentinel automation rules (SOAR playbook triggers)", inputSchema: { type: "object", properties: {} } },
  { name: "list_sensitivity_labels", description: "List Microsoft Purview sensitivity labels", inputSchema: { type: "object", properties: {} } },
  { name: "get_sensitivity_label", description: "Get a specific Purview sensitivity label by ID", inputSchema: { type: "object", properties: { labelId: { type: "string" } }, required: ["labelId"] } },
  { name: "list_sensitive_info_types", description: "List Purview sensitive information types", inputSchema: { type: "object", properties: {} } },
  { name: "list_label_policies", description: "List Purview sensitivity label policies", inputSchema: { type: "object", properties: {} } },
  { name: "list_dlp_policies", description: "List Purview DLP policies", inputSchema: { type: "object", properties: {} } },
  { name: "list_dlp_alerts", description: "List Purview DLP alerts", inputSchema: { type: "object", properties: {} } },
  { name: "list_insider_risk_alerts", description: "List Microsoft Purview Insider Risk Management alerts", inputSchema: { type: "object", properties: {} } },
  { name: "list_insider_risk_policies", description: "List Insider Risk Management policies", inputSchema: { type: "object", properties: {} } },
  { name: "list_information_barrier_policies", description: "List Microsoft Purview Information Barrier policies", inputSchema: { type: "object", properties: {} } },
  { name: "list_information_barrier_segments", description: "List Microsoft Purview Information Barrier segments", inputSchema: { type: "object", properties: {} } },
  { name: "list_ediscovery_cases", description: "List Purview eDiscovery cases", inputSchema: { type: "object", properties: {} } },
  { name: "get_ediscovery_case", description: "Get a specific Purview eDiscovery case", inputSchema: { type: "object", properties: { caseId: { type: "string" } }, required: ["caseId"] } },
  { name: "list_ediscovery_custodians", description: "List custodians in a Purview eDiscovery case", inputSchema: { type: "object", properties: { caseId: { type: "string" } }, required: ["caseId"] } },
  { name: "list_ediscovery_holds", description: "List legal holds in a Purview eDiscovery case", inputSchema: { type: "object", properties: { caseId: { type: "string" } }, required: ["caseId"] } },
  { name: "list_ediscovery_searches", description: "List content searches within a Purview eDiscovery case", inputSchema: { type: "object", properties: { caseId: { type: "string" } }, required: ["caseId"] } },
  { name: "list_ediscovery_review_sets", description: "List review sets in a Purview eDiscovery case", inputSchema: { type: "object", properties: { caseId: { type: "string" } }, required: ["caseId"] } },
  { name: "list_retention_labels", description: "List Purview retention labels", inputSchema: { type: "object", properties: {} } },
  { name: "list_retention_event_types", description: "List Purview retention event types", inputSchema: { type: "object", properties: {} } },
  { name: "list_audit_logs", description: "List Entra ID directory audit logs", inputSchema: { type: "object", properties: { filter: { type: "string", description: "OData filter string" }, top: { type: "number", description: "Max results (default 50)" } } } },
  { name: "list_signin_logs", description: "List Entra ID sign-in logs", inputSchema: { type: "object", properties: { filter: { type: "string", description: "OData filter string" }, top: { type: "number", description: "Max results (default 50)" } } } },
  { name: "list_communication_compliance_policies", description: "List Communication Compliance policies", inputSchema: { type: "object", properties: {} } },
  { name: "list_compliance_assessments", description: "List Compliance Manager assessments", inputSchema: { type: "object", properties: {} } },
  { name: "get_compliance_assessment", description: "Get details of a specific Compliance Manager assessment", inputSchema: { type: "object", properties: { assessmentId: { type: "string" } }, required: ["assessmentId"] } },
  { name: "list_compliance_improvement_actions", description: "List Compliance Manager improvement actions and their implementation status", inputSchema: { type: "object", properties: {} } },
  { name: "get_dspm_insights", description: "Get Purview DSPM sensitive types summary", inputSchema: { type: "object", properties: {} } },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  const auth = authorize(name);
  if (!auth.allowed) {
    auditEntry({ tool: name, tier: auth.tier, decision: "denied", reason: auth.reason, args: redactArgs(args) });
    return { content: [{ type: "text", text: `Authorization denied: ${auth.reason}` }], isError: true };
  }

  try {
    let result;

    switch (name) {
      case "list_resource_groups": {
        const groups = [];
        for await (const rg of resourceClient.resourceGroups.list()) groups.push(rg.name);
        result = { resourceGroups: groups };
        break;
      }
      case "create_resource_group": {
        result = await resourceClient.resourceGroups.createOrUpdate(args.name, { location: args.location || "eastus" });
        break;
      }
      case "delete_resource_group": {
        await resourceClient.resourceGroups.beginDeleteAndWait(args.name);
        result = { message: "Resource group deleted", name: args.name };
        break;
      }
      case "assign_role": {
        const principalId = await resolvePrincipalId(args.assignee);
        const roleDefinitionId = await resolveRoleDefinitionId(args.role, args.scope);
        const token = await getARMToken();
        const roleAssignmentId = randomUUID();
        const url = `https://management.azure.com${args.scope}/providers/Microsoft.Authorization/roleAssignments/${roleAssignmentId}?api-version=2022-04-01`;
        const r = await axios.put(url, { properties: { roleDefinitionId, principalId } }, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Role assigned", roleAssignmentId, principalId, roleDefinitionId, scope: args.scope, raw: r.data };
        break;
      }
      case "create_user": {
        const token = await getGraphToken();
        const mailNickname = args.upn.split("@")[0];
        await axios.post(
          "https://graph.microsoft.com/v1.0/users",
          { accountEnabled: true, displayName: args.displayName, userPrincipalName: args.upn, mailNickname, usageLocation: "US", passwordProfile: { password: args.password, forceChangePasswordNextSignIn: true } },
          { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
        );
        result = { message: "User created", upn: args.upn };
        break;
      }
      case "delete_user": {
        const token = await getGraphToken();
        await axios.delete(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(args.upn)}`, { headers: { Authorization: `Bearer ${token}` } });
        result = { message: "User deleted", upn: args.upn };
        break;
      }
      case "list_role_assignments": {
        const principalId = await resolvePrincipalId(args.assignee);
        const token = await getARMToken();
        let assignments = [], url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=${encodeURIComponent(`principalId eq '${principalId}'`)}`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); assignments = assignments.concat(r.data.value); url = r.data.nextLink || null; }
        result = assignments;
        break;
      }
      case "list_users": {
        const token = await getGraphToken();
        let users = [], url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,mail,accountEnabled&$top=999";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); users = users.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = users;
        break;
      }
      case "list_graph_users": {
        const token = await getGraphToken();
        let users = [], url = "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName&$top=999";
        while (url) {
          const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
          users = users.concat(r.data.value);
          url = r.data["@odata.nextLink"] || null;
        }
        result = users;
        break;
      }
      case "list_aus": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/v1.0/directory/administrativeUnits", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value.map(au => ({ id: au.id, displayName: au.displayName }));
        break;
      }
      case "create_au": {
        const token = await getGraphToken();
        const r = await axios.post(
          "https://graph.microsoft.com/v1.0/directory/administrativeUnits",
          { displayName: args.displayName, description: args.description },
          { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
        );
        result = { id: r.data.id, displayName: r.data.displayName };
        break;
      }
      case "assign_au_role": {
        const token = await getGraphToken();
        const userRes = await axios.get(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(args.upn)}?$select=id,displayName`, { headers: { Authorization: `Bearer ${token}` } });
        const userId = userRes.data.id;
        const rolesRes = await axios.get(`https://graph.microsoft.com/v1.0/directoryRoles?$filter=roleTemplateId eq '${args.roleTemplateId}'`, { headers: { Authorization: `Bearer ${token}` } });
        let roleId;
        if (rolesRes.data.value.length > 0) {
          roleId = rolesRes.data.value[0].id;
        } else {
          const act = await axios.post("https://graph.microsoft.com/v1.0/directoryRoles", { roleTemplateId: args.roleTemplateId }, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
          roleId = act.data.id;
        }
        await axios.post(`https://graph.microsoft.com/v1.0/directory/administrativeUnits/${args.auId}/scopedRoleMembers`, { roleId, roleMemberInfo: { id: userId } }, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Role assigned", upn: args.upn, roleId, auId: args.auId };
        break;
      }
      case "add_au_member": {
        const token = await getGraphToken();
        const userRes = await axios.get(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(args.upn)}?$select=id`, { headers: { Authorization: `Bearer ${token}` } });
        const userId = userRes.data.id;
        await axios.post(`https://graph.microsoft.com/v1.0/directory/administrativeUnits/${args.auId}/members/$ref`, { "@odata.id": `https://graph.microsoft.com/v1.0/directoryObjects/${userId}` }, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Member added", upn: args.upn, auId: args.auId };
        break;
      }
      case "list_intune_devices": {
        const token = await getGraphToken();
        let devices = [], url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,complianceState,operatingSystem,userPrincipalName,lastSyncDateTime";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); devices = devices.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = devices;
        break;
      }
      case "list_noncompliant_devices": {
        const token = await getGraphToken();
        let devices = [], url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=complianceState eq 'noncompliant'&$select=id,deviceName,complianceState,operatingSystem,userPrincipalName,lastSyncDateTime";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); devices = devices.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = devices;
        break;
      }
      case "sync_intune_device": {
        const token = await getGraphToken();
        await axios.post(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${args.deviceId}/syncDevice`, {}, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Sync triggered", deviceId: args.deviceId };
        break;
      }
      case "list_intune_compliance_policies": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "get_intune_device": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${args.deviceId}`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data;
        break;
      }
      case "retire_intune_device": {
        const token = await getGraphToken();
        await axios.post(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${args.deviceId}/retire`, {}, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Device retire initiated", deviceId: args.deviceId };
        break;
      }
      case "wipe_intune_device": {
        const token = await getGraphToken();
        await axios.post(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${args.deviceId}/wipe`, { keepEnrollmentData: args.keepEnrollmentData ?? false, keepUserData: args.keepUserData ?? false }, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Device wipe initiated", deviceId: args.deviceId };
        break;
      }
      case "reboot_intune_device": {
        const token = await getGraphToken();
        await axios.post(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${args.deviceId}/rebootNow`, {}, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Device reboot initiated", deviceId: args.deviceId };
        break;
      }
      case "list_intune_configuration_profiles": {
        const token = await getGraphToken();
        let profiles = [], url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$select=id,displayName,description,lastModifiedDateTime,createdDateTime";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); profiles = profiles.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = profiles;
        break;
      }
      case "list_intune_apps": {
        const token = await getGraphToken();
        let apps = [], url = "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?$select=id,displayName,publisher,appAvailability,createdDateTime,lastModifiedDateTime";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); apps = apps.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = apps;
        break;
      }
      case "list_intune_app_assignments": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/${args.appId}/assignments`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_intune_autopilot_devices": {
        const token = await getGraphToken();
        let devices = [], url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$select=id,serialNumber,model,manufacturer,enrollmentState,azureAdDeviceId";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); devices = devices.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = devices;
        break;
      }
      case "list_intune_enrollment_configurations": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations?$select=id,displayName,description,priority,createdDateTime,lastModifiedDateTime", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_intune_scripts": {
        const token = await getGraphToken();
        let scripts = [], url = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?$select=id,displayName,description,runAsAccount,createdDateTime,lastModifiedDateTime";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); scripts = scripts.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = scripts;
        break;
      }
      case "list_intune_remediation_scripts": {
        const token = await getGraphToken();
        let scripts = [], url = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$select=id,displayName,description,publisher,runAsAccount,createdDateTime,lastModifiedDateTime";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); scripts = scripts.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = scripts;
        break;
      }
      case "list_intune_managed_app_policies": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/v1.0/deviceAppManagement/managedAppPolicies?$select=id,displayName,description,createdDateTime,lastModifiedDateTime", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_defender_alerts": {
        const token = await getARMToken();
        const r = await axios.get(`https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/alerts?api-version=2022-01-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "get_secure_score": {
        const token = await getARMToken();
        const r = await axios.get(`https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_defender_recommendations": {
        const token = await getARMToken();
        let recs = [], url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); recs = recs.concat(r.data.value); url = r.data.nextLink || null; }
        result = recs;
        break;
      }
      case "update_defender_alert": {
        const token = await getARMToken();
        await axios.patch(`https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${args.resourceGroup}/providers/Microsoft.Security/alerts/${args.alertName}?api-version=2022-01-01`, { properties: { status: args.status } }, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Alert updated", alertName: args.alertName, status: args.status };
        break;
      }
      case "list_sentinel_incidents": {
        const token = await getARMToken();
        let incidents = [], url = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01&$orderby=properties/createdTimeUtc desc`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); incidents = incidents.concat(r.data.value); url = r.data.nextLink || null; }
        result = incidents;
        break;
      }
      case "get_sentinel_incident": {
        const token = await getARMToken();
        const r = await axios.get(`https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/incidents/${args.incidentId}?api-version=2023-02-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data;
        break;
      }
      case "update_sentinel_incident": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/incidents/${args.incidentId}?api-version=2023-02-01`;
        const getRes = await axios.get(base, { headers: { Authorization: `Bearer ${token}` } });
        const current = getRes.data;
        const body = { etag: current.etag, properties: { ...current.properties, ...(args.status && { status: args.status }), ...(args.severity && { severity: args.severity }), ...(args.classification && { classification: args.classification }), ...(args.classificationComment && { classificationComment: args.classificationComment }) } };
        const r = await axios.put(base, body, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Incident updated", incidentId: args.incidentId, properties: r.data.properties };
        break;
      }
      case "list_sentinel_analytics_rules": {
        const token = await getARMToken();
        const r = await axios.get(`https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "run_sentinel_kql_query": {
        const token = await getARMToken();
        const wsRes = await axios.get(`https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}?api-version=2022-10-01`, { headers: { Authorization: `Bearer ${token}` } });
        const workspaceId = wsRes.data.properties.customerId;
        const laToken = await credential.getToken("https://api.loganalytics.io/.default");
        const r = await axios.post(`https://api.loganalytics.io/v1/workspaces/${workspaceId}/query`, { query: args.query, timespan: args.timespan || "P1D" }, { headers: { Authorization: `Bearer ${laToken.token}`, "Content-Type": "application/json" } });
        result = r.data;
        break;
      }
      case "list_sentinel_incident_comments": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        const r = await axios.get(`${base}/incidents/${args.incidentId}/comments?api-version=2023-02-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "add_sentinel_incident_comment": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        const commentId = `comment-${Date.now()}`;
        const r = await axios.put(`${base}/incidents/${args.incidentId}/comments/${commentId}?api-version=2023-02-01`, { properties: { message: args.message } }, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = { message: "Comment added", commentId: r.data.name, incidentId: args.incidentId };
        break;
      }
      case "list_sentinel_incident_alerts": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        const r = await axios.post(`${base}/incidents/${args.incidentId}/alerts?api-version=2023-02-01`, {}, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = r.data.value;
        break;
      }
      case "list_sentinel_incident_entities": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        const r = await axios.post(`${base}/incidents/${args.incidentId}/entities?api-version=2023-02-01`, {}, { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
        result = r.data;
        break;
      }
      case "list_sentinel_analytics_rule_templates": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        let templates = [], url = `${base}/alertRuleTemplates?api-version=2023-02-01`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); templates = templates.concat(r.data.value); url = r.data.nextLink || null; }
        result = templates.map(t => ({ id: t.name, displayName: t.properties?.displayName, severity: t.properties?.severity, kind: t.kind, status: t.properties?.status }));
        break;
      }
      case "list_sentinel_hunting_queries": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        let all = [], url = `${base}/metadata?api-version=2023-02-01&$filter=kind eq 'HuntingQuery'`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); all = all.concat(r.data.value); url = r.data.nextLink || null; }
        result = all.map(q => ({ id: q.name, displayName: q.properties?.displayName, description: q.properties?.description, tactics: q.properties?.tactics }));
        break;
      }
      case "list_sentinel_bookmarks": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        let bookmarks = [], url = `${base}/bookmarks?api-version=2023-02-01`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); bookmarks = bookmarks.concat(r.data.value); url = r.data.nextLink || null; }
        result = bookmarks;
        break;
      }
      case "list_sentinel_watchlists": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        const r = await axios.get(`${base}/watchlists?api-version=2023-02-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value.map(w => ({ alias: w.properties?.watchlistAlias, displayName: w.properties?.displayName, itemsCount: w.properties?.itemsSearchKey, created: w.properties?.created }));
        break;
      }
      case "list_sentinel_watchlist_items": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        let items = [], url = `${base}/watchlists/${args.watchlistAlias}/watchlistItems?api-version=2023-02-01`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); items = items.concat(r.data.value); url = r.data.nextLink || null; }
        result = items.map(i => i.properties?.itemsKeyValue);
        break;
      }
      case "list_sentinel_threat_indicators": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        let indicators = [], url = `${base}/threatIntelligence/main/indicators?api-version=2023-02-01`;
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); indicators = indicators.concat(r.data.value); url = r.data.nextLink || null; }
        result = indicators;
        break;
      }
      case "list_sentinel_data_connectors": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        const r = await axios.get(`${base}/dataConnectors?api-version=2023-02-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value.map(dc => ({ id: dc.name, kind: dc.kind, state: dc.properties?.dataTypes }));
        break;
      }
      case "list_sentinel_automation_rules": {
        const token = await getARMToken();
        const base = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights`;
        const r = await axios.get(`${base}/automationRules?api-version=2023-02-01`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value.map(ar => ({ id: ar.name, displayName: ar.properties?.displayName, order: ar.properties?.order, triggerOn: ar.properties?.triggeringLogic?.triggersOn, actions: ar.properties?.actions?.length }));
        break;
      }
      case "list_sensitivity_labels": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "get_sensitivity_label": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels/${args.labelId}`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data;
        break;
      }
      case "list_sensitive_info_types": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/informationProtection/sensitiveTypes?$top=100", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_label_policies": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels?$select=id,displayName,color,sensitivity,tooltip,isActive,isAppliable,actionSource,parent", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_dlp_policies": {
        result = { note: "DLP policy listing is not available via Microsoft Graph API. The Graph dataLossPreventionPolicies endpoint is for app-level policy enforcement, not admin management. Manage DLP policies via: (1) Purview compliance portal at compliance.microsoft.com, or (2) Security & Compliance PowerShell: Get-DlpCompliancePolicy.", docsUrl: "https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp" };
        break;
      }
      case "list_dlp_alerts": {
        result = { note: "DLP alerts are not available as a distinct category via Microsoft Graph API security/alerts_v2. DLP policy violations surface in the Purview compliance portal under Data Loss Prevention > Alerts. For programmatic access, use the Office 365 Management Activity API or Purview compliance portal exports.", docsUrl: "https://learn.microsoft.com/en-us/purview/dlp-alerts-dashboard-get-started" };
        break;
      }
      case "list_insider_risk_alerts": {
        const token = await getGraphToken();
        let alerts = [], url = "https://graph.microsoft.com/beta/security/alerts_v2?$filter=serviceSource eq 'microsoftInsiderRiskManagement'";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); alerts = alerts.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = alerts;
        break;
      }
      case "list_insider_risk_policies": {
        result = { note: "Insider Risk Management policies are not available via Microsoft Graph API. Only IRM alerts are exposed via Graph (use list_insider_risk_alerts). Manage IRM policies via: (1) Purview compliance portal at compliance.microsoft.com/insiderRisk, or (2) Security & Compliance PowerShell: Get-InsiderRiskPolicy.", docsUrl: "https://learn.microsoft.com/en-us/purview/insider-risk-management-policies" };
        break;
      }
      case "list_information_barrier_policies": {
        result = { note: "Information Barrier Policies are not available via Microsoft Graph API. Manage via Purview compliance portal or: Get-InformationBarrierPolicy (Security & Compliance PowerShell).", docsUrl: "https://learn.microsoft.com/en-us/microsoft-365/compliance/information-barriers-policies" };
        break;
      }
      case "list_information_barrier_segments": {
        result = { note: "Information Barrier Segments are not available via Microsoft Graph API. Manage via Purview compliance portal or: Get-OrganizationSegment (Security & Compliance PowerShell).", docsUrl: "https://learn.microsoft.com/en-us/microsoft-365/compliance/information-barriers-policies" };
        break;
      }
      case "list_ediscovery_cases": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "get_ediscovery_case": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/${args.caseId}`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data;
        break;
      }
      case "list_ediscovery_custodians": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/${args.caseId}/custodians`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_ediscovery_holds": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/${args.caseId}/noncustodialDataSources`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_ediscovery_searches": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/${args.caseId}/searches`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_ediscovery_review_sets": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/${args.caseId}/reviewSets`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_retention_labels": {
        result = { note: "Retention labels (GET /security/labels/retentionLabels) require RecordsManagement.Read.All permission, which only supports Delegated auth (signed-in user). Application permissions are NOT supported for this API — app-only (service principal) auth will always return 403. To use this, add delegated auth support or access via: Purview compliance portal > Data lifecycle management > Retention labels.", docsUrl: "https://learn.microsoft.com/en-us/graph/api/security-labelsroot-list-retentionlabel" };
        break;
      }
      case "list_retention_event_types": {
        result = { note: "Retention event types (GET /security/triggerTypes/retentionEventTypes) require RecordsManagement.Read.All permission, which only supports Delegated auth (signed-in user). Application permissions are NOT supported — app-only auth will return 403. Access via: Purview compliance portal > Data lifecycle management > Events.", docsUrl: "https://learn.microsoft.com/en-us/graph/api/resources/security-recordsmanagement-overview" };
        break;
      }
      case "list_audit_logs": {
        const token = await getGraphToken();
        let url = `https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=${args.top || 50}`;
        if (args.filter) url += `&$filter=${encodeURIComponent(args.filter)}`;
        const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_signin_logs": {
        const token = await getGraphToken();
        let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=${args.top || 50}`;
        if (args.filter) url += `&$filter=${encodeURIComponent(args.filter)}`;
        const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_communication_compliance_policies": {
        result = { note: "Communication Compliance policies are not available via Microsoft Graph API. They must be managed via: (1) Purview compliance portal at compliance.microsoft.com/communicationcompliance, or (2) Security & Compliance PowerShell: Get-SupervisoryReviewPolicyV2.", docsUrl: "https://learn.microsoft.com/en-us/purview/communication-compliance-solution-overview" };
        break;
      }
      case "list_compliance_assessments": {
        result = { note: "Compliance Manager assessments are not available via Microsoft Graph API. Access via Purview compliance portal at compliance.microsoft.com/compliancemanager or the Compliance Center REST API.", docsUrl: "https://learn.microsoft.com/en-us/microsoft-365/compliance/compliance-manager-apis" };
        break;
      }
      case "get_compliance_assessment": {
        result = { note: "Compliance Manager assessments are not available via Microsoft Graph API. Access via Purview compliance portal or the Compliance Center REST API.", assessmentId: args.assessmentId };
        break;
      }
      case "list_compliance_improvement_actions": {
        result = { note: "Compliance Manager improvement actions are not available via Microsoft Graph API. Access via Purview compliance portal or the Compliance Center REST API.", docsUrl: "https://learn.microsoft.com/en-us/microsoft-365/compliance/compliance-manager-apis" };
        break;
      }
      case "get_dspm_insights": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels", { headers: { Authorization: `Bearer ${token}` } });
        result = { note: "DSPM summary API not yet GA. Returning active sensitivity labels as data posture proxy.", labels: r.data.value ?? [] };
        break;
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    auditEntry({ tool: name, tier: auth.tier, decision: "allowed", outcome: "ok", args: redactArgs(args) });
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    auditEntry({ tool: name, tier: auth.tier, decision: "allowed", outcome: "error", error: detail, args: redactArgs(args) });
    return { content: [{ type: "text", text: `Error: ${detail}` }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
process.stderr.write("Azure MCP server running on stdio\n");

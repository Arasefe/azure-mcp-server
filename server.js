import dotenv from "dotenv";
dotenv.config({ override: true });
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import { ClientCertificateCredential } from "@azure/identity";
import { ResourceManagementClient } from "@azure/arm-resources";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
  { name: "list_defender_alerts", description: "List Defender for Cloud security alerts", inputSchema: { type: "object", properties: {} } },
  { name: "get_secure_score", description: "Get the Defender for Cloud secure score", inputSchema: { type: "object", properties: {} } },
  { name: "list_defender_recommendations", description: "List Defender for Cloud security recommendations/assessments", inputSchema: { type: "object", properties: {} } },
  { name: "update_defender_alert", description: "Update the status of a Defender for Cloud alert", inputSchema: { type: "object", properties: { alertName: { type: "string" }, resourceGroup: { type: "string" }, status: { type: "string", enum: ["Dismissed", "Resolved", "Active"] } }, required: ["alertName", "resourceGroup", "status"] } },
  { name: "list_sentinel_incidents", description: "List Microsoft Sentinel incidents ordered by creation time (newest first)", inputSchema: { type: "object", properties: {} } },
  { name: "get_sentinel_incident", description: "Get a specific Sentinel incident by ID", inputSchema: { type: "object", properties: { incidentId: { type: "string" } }, required: ["incidentId"] } },
  { name: "update_sentinel_incident", description: "Update a Sentinel incident (status, severity, classification)", inputSchema: { type: "object", properties: { incidentId: { type: "string" }, status: { type: "string" }, severity: { type: "string" }, classification: { type: "string" }, classificationComment: { type: "string" } }, required: ["incidentId"] } },
  { name: "list_sentinel_analytics_rules", description: "List Sentinel analytics (alert) rules", inputSchema: { type: "object", properties: {} } },
  { name: "run_sentinel_kql_query", description: "Run a KQL query against the Sentinel Log Analytics workspace", inputSchema: { type: "object", properties: { query: { type: "string" }, timespan: { type: "string", description: "ISO 8601 duration, e.g. P1D (default)" } }, required: ["query"] } },
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
  { name: "list_retention_labels", description: "List Purview retention labels", inputSchema: { type: "object", properties: {} } },
  { name: "list_retention_event_types", description: "List Purview retention event types", inputSchema: { type: "object", properties: {} } },
  { name: "list_audit_logs", description: "List Entra ID directory audit logs", inputSchema: { type: "object", properties: { filter: { type: "string", description: "OData filter string" }, top: { type: "number", description: "Max results (default 50)" } } } },
  { name: "list_signin_logs", description: "List Entra ID sign-in logs", inputSchema: { type: "object", properties: { filter: { type: "string", description: "OData filter string" }, top: { type: "number", description: "Max results (default 50)" } } } },
  { name: "list_communication_compliance_policies", description: "List Communication Compliance policies", inputSchema: { type: "object", properties: {} } },
  { name: "list_compliance_assessments", description: "List Compliance Manager assessments", inputSchema: { type: "object", properties: {} } },
  { name: "get_dspm_insights", description: "Get Purview DSPM sensitive types summary", inputSchema: { type: "object", properties: {} } },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

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
        const cmd = `az role assignment create --assignee ${args.assignee} --role "${args.role}" --scope ${args.scope}`;
        const { stdout } = await execAsync(cmd);
        result = { message: "Role assigned", output: JSON.parse(stdout) };
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
        await execAsync(`az ad user delete --id ${args.upn}`);
        result = { message: "User deleted", upn: args.upn };
        break;
      }
      case "list_role_assignments": {
        const { stdout } = await execAsync(`az role assignment list --assignee ${args.assignee} -o json`);
        result = JSON.parse(stdout);
        break;
      }
      case "list_users": {
        const { stdout } = await execAsync("az ad user list -o json");
        result = JSON.parse(stdout);
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
        const r = await axios.get("https://graph.microsoft.com/beta/security/informationProtection/sensitiveTypes", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_label_policies": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/informationProtection/labelPolicies", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_dlp_policies": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/dataLossPreventionPolicies", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_dlp_alerts": {
        const token = await getGraphToken();
        let alerts = [], url = "https://graph.microsoft.com/beta/security/alerts_v2?$filter=serviceSource eq 'microsoftPurview'";
        while (url) { const r = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } }); alerts = alerts.concat(r.data.value); url = r.data["@odata.nextLink"] || null; }
        result = alerts;
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
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/insiderRiskManagement/policies", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_information_barrier_policies": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/informationBarrierPolicies", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_information_barrier_segments": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/informationBarrierSegments", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_ediscovery_cases": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/compliance/ediscovery/cases", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "get_ediscovery_case": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/beta/compliance/ediscovery/cases/${args.caseId}`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data;
        break;
      }
      case "list_ediscovery_custodians": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/beta/compliance/ediscovery/cases/${args.caseId}/custodians`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_ediscovery_holds": {
        const token = await getGraphToken();
        const r = await axios.get(`https://graph.microsoft.com/beta/compliance/ediscovery/cases/${args.caseId}/legalHolds`, { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_retention_labels": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/labels/retentionLabels", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
        break;
      }
      case "list_retention_event_types": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/triggerTypes/retentionEventTypes", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value;
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
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/compliance/communicationCompliance/policies", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "list_compliance_assessments": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/compliance/complianceManagement/complianceAssessments", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      case "get_dspm_insights": {
        const token = await getGraphToken();
        const r = await axios.get("https://graph.microsoft.com/beta/security/dataSecurityAndGovernance/sensitiveTypesSummary", { headers: { Authorization: `Bearer ${token}` } });
        result = r.data.value ?? r.data;
        break;
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    return { content: [{ type: "text", text: `Error: ${detail}` }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
process.stderr.write("Azure MCP server running on stdio\n");

require("dotenv").config();
const { exec } = require("child_process");
const crypto = require("crypto");
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const axios = require("axios");
const { ClientCertificateCredential } = require("@azure/identity");
const { ResourceManagementClient } = require("@azure/arm-resources");

const app = express();
app.use(bodyParser.json());

// ENV VARIABLES (set these!)
const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;

// Sentinel workspace config (set these for Sentinel endpoints)
const sentinelResourceGroup = process.env.SENTINEL_RESOURCE_GROUP;
const sentinelWorkspace = process.env.SENTINEL_WORKSPACE_NAME;

const credential = new ClientCertificateCredential(
  tenantId,
  clientId,
  path.join(__dirname, "cavalry-sp.combined.pem")
);
const client = new ResourceManagementClient(credential, subscriptionId);

// Example tool: list resource groups
app.post("/list-resource-groups", async (req, res) => {
  try {
    const groups = [];
    for await (const rg of client.resourceGroups.list()) {
      groups.push(rg.name);
    }
    res.json({ resourceGroups: groups });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(3000, () => {
  console.log("MCP Azure Server running on port 3000");
});

app.post("/create-resource-group", async (req, res) => {
  const { name, location } = req.body;

  try {
    const result = await client.resourceGroups.createOrUpdate(name, {
      location: location || "eastus"
    });

    res.json({ message: "Resource group created", result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/delete-resource-group", async (req, res) => {
  const { name } = req.body;

  try {
    await client.resourceGroups.beginDeleteAndWait(name);
    res.json({ message: "Resource group deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/assign-role", (req, res) => {
  const { assignee, role, scope } = req.body;

  const cmd = `
    az role assignment create \
    --assignee ${assignee} \
    --role "${role}" \
    --scope ${scope}
  `;

  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ message: "Role assigned", output: stdout });
  });
});

app.post("/create-user", async (req, res) => {
  const { upn, displayName, password } = req.body;

  try {
    const tokenResponse = await credential.getToken("https://graph.microsoft.com/.default");
    const token = tokenResponse.token;

    const mailNickname = upn.split("@")[0];

    await axios.post(
      "https://graph.microsoft.com/v1.0/users",
      {
        accountEnabled: true,
        displayName: displayName,
        userPrincipalName: upn,
        mailNickname: mailNickname,
        usageLocation: "US",
        passwordProfile: {
          password: password,
          forceChangePasswordNextSignIn: true
        }
      },
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );

    res.json({ message: "User created", upn });
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/delete-user", (req, res) => {
  const { upn } = req.body;

  const cmd = `az ad user delete --id ${upn}`;

  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ message: "User deleted" });
  });
});

app.post("/list-role-assignments", (req, res) => {
  const { assignee } = req.body;

  const cmd = `az role assignment list --assignee ${assignee} -o json`;

  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json(JSON.parse(stdout));
  });
});

app.post("/list-users", (req, res) => {
  const cmd = `az ad user list -o json`;

  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json(JSON.parse(stdout));
  });
});

// ── Token helpers ─────────────────────────────────────────────────────────────

async function getGraphToken() {
  const tokenResponse = await credential.getToken("https://graph.microsoft.com/.default");
  return tokenResponse.token;
}

async function getARMToken() {
  const tokenResponse = await credential.getToken("https://management.azure.com/.default");
  return tokenResponse.token;
}

// ── Administrative Unit endpoints ────────────────────────────────────────────

app.post("/list-graph-users", async (req, res) => {
  try {
    const token = await getGraphToken();
    let users = [];
    let url = "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName&$top=999";
    while (url) {
      const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
      users = users.concat(response.data.value);
      url = response.data["@odata.nextLink"] || null;
    }
    res.json(users);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-aus", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/v1.0/directory/administrativeUnits",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value.map(au => ({ id: au.id, displayName: au.displayName })));
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/create-au", async (req, res) => {
  const { displayName, description } = req.body;
  try {
    const token = await getGraphToken();
    const response = await axios.post(
      "https://graph.microsoft.com/v1.0/directory/administrativeUnits",
      { displayName, description },
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );
    res.json({ id: response.data.id, displayName: response.data.displayName });
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/assign-au-role", async (req, res) => {
  const { auId, upn, roleTemplateId } = req.body;
  try {
    const token = await getGraphToken();

    // Step 1 — resolve user object ID
    const userRes = await axios.get(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(upn)}?$select=id,displayName`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const userId = userRes.data.id;

    // Step 2 — ensure the directory role is activated, get its ID
    let roleId;
    const rolesRes = await axios.get(
      `https://graph.microsoft.com/v1.0/directoryRoles?$filter=roleTemplateId eq '${roleTemplateId}'`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (rolesRes.data.value.length > 0) {
      roleId = rolesRes.data.value[0].id;
    } else {
      // Activate the role in the tenant
      const activateRes = await axios.post(
        "https://graph.microsoft.com/v1.0/directoryRoles",
        { roleTemplateId },
        { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
      );
      roleId = activateRes.data.id;
    }

    // Step 3 — create scoped role member on the AU
    await axios.post(
      `https://graph.microsoft.com/v1.0/directory/administrativeUnits/${auId}/scopedRoleMembers`,
      { roleId, roleMemberInfo: { id: userId } },
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );

    res.json({ message: "Role assigned", upn, roleId, auId });
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/add-au-member", async (req, res) => {
  const { auId, upn } = req.body;
  try {
    const token = await getGraphToken();
    const userRes = await axios.get(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(upn)}?$select=id`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const userId = userRes.data.id;
    await axios.post(
      `https://graph.microsoft.com/v1.0/directory/administrativeUnits/${auId}/members/$ref`,
      { "@odata.id": `https://graph.microsoft.com/v1.0/directoryObjects/${userId}` },
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );
    res.json({ message: "Member added", upn, auId });
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Intune endpoints ──────────────────────────────────────────────────────────

app.post("/list-intune-devices", async (req, res) => {
  try {
    const token = await getGraphToken();
    let devices = [];
    let url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,complianceState,operatingSystem,userPrincipalName,lastSyncDateTime";
    while (url) {
      const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
      devices = devices.concat(response.data.value);
      url = response.data["@odata.nextLink"] || null;
    }
    res.json(devices);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-noncompliant-devices", async (req, res) => {
  try {
    const token = await getGraphToken();
    let devices = [];
    let url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=complianceState eq 'noncompliant'&$select=id,deviceName,complianceState,operatingSystem,userPrincipalName,lastSyncDateTime";
    while (url) {
      const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
      devices = devices.concat(response.data.value);
      url = response.data["@odata.nextLink"] || null;
    }
    res.json(devices);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/sync-intune-device", async (req, res) => {
  const { deviceId } = req.body;
  try {
    const token = await getGraphToken();
    await axios.post(
      `https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceId}/syncDevice`,
      {},
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );
    res.json({ message: "Sync triggered", deviceId });
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-intune-compliance-policies", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Defender for Cloud endpoints ──────────────────────────────────────────────

app.post("/list-defender-alerts", async (req, res) => {
  try {
    const token = await getARMToken();
    const response = await axios.get(
      `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/alerts?api-version=2022-01-01`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/get-secure-score", async (req, res) => {
  try {
    const token = await getARMToken();
    const response = await axios.get(
      `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-defender-recommendations", async (req, res) => {
  try {
    const token = await getARMToken();
    let recommendations = [];
    let url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01`;
    while (url) {
      const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
      recommendations = recommendations.concat(response.data.value);
      url = response.data.nextLink || null;
    }
    res.json(recommendations);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/update-defender-alert", async (req, res) => {
  const { alertName, resourceGroup, status } = req.body;
  try {
    const token = await getARMToken();
    await axios.patch(
      `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.Security/alerts/${alertName}?api-version=2022-01-01`,
      { properties: { status } },
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );
    res.json({ message: "Alert updated", alertName, status });
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Microsoft Sentinel endpoints ──────────────────────────────────────────────

app.post("/list-sentinel-incidents", async (req, res) => {
  try {
    const token = await getARMToken();
    let incidents = [];
    let url = `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01&$orderby=properties/createdTimeUtc desc`;
    while (url) {
      const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
      incidents = incidents.concat(response.data.value);
      url = response.data.nextLink || null;
    }
    res.json(incidents);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/get-sentinel-incident", async (req, res) => {
  const { incidentId } = req.body;
  try {
    const token = await getARMToken();
    const response = await axios.get(
      `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=2023-02-01`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/update-sentinel-incident", async (req, res) => {
  const { incidentId, status, severity, classification, classificationComment } = req.body;
  try {
    const token = await getARMToken();

    // Fetch current incident to get required etag and existing properties
    const getRes = await axios.get(
      `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=2023-02-01`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const current = getRes.data;

    const body = {
      etag: current.etag,
      properties: {
        ...current.properties,
        ...(status && { status }),
        ...(severity && { severity }),
        ...(classification && { classification }),
        ...(classificationComment && { classificationComment })
      }
    };

    const response = await axios.put(
      `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=2023-02-01`,
      body,
      { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } }
    );
    res.json({ message: "Incident updated", incidentId, properties: response.data.properties });
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-sentinel-analytics-rules", async (req, res) => {
  try {
    const token = await getARMToken();
    const response = await axios.get(
      `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/run-sentinel-kql-query", async (req, res) => {
  const { query, timespan } = req.body;
  try {
    const token = await getARMToken();

    // Get the Log Analytics workspace ID first
    const wsRes = await axios.get(
      `https://management.azure.com/subscriptions/${subscriptionId}/resourceGroups/${sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${sentinelWorkspace}?api-version=2022-10-01`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const workspaceId = wsRes.data.properties.customerId;

    // Use Log Analytics Query API (requires different token scope)
    const laToken = await credential.getToken("https://api.loganalytics.io/.default");
    const response = await axios.post(
      `https://api.loganalytics.io/v1/workspaces/${workspaceId}/query`,
      { query, timespan: timespan || "P1D" },
      { headers: { Authorization: `Bearer ${laToken.token}`, "Content-Type": "application/json" } }
    );
    res.json(response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: Information Protection ──────────────────────────────────────────

app.post("/list-sensitivity-labels", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/get-sensitivity-label", async (req, res) => {
  const { labelId } = req.body;
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      `https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels/${labelId}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-sensitive-info-types", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/informationProtection/sensitiveTypes",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-label-policies", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/informationProtection/labelPolicies",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: DLP ──────────────────────────────────────────────────────────────

app.post("/list-dlp-policies", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/dataLossPreventionPolicies",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-dlp-alerts", async (req, res) => {
  try {
    const token = await getGraphToken();
    let alerts = [];
    let url = "https://graph.microsoft.com/beta/security/alerts_v2?$filter=serviceSource eq 'microsoftPurview'";
    while (url) {
      const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
      alerts = alerts.concat(response.data.value);
      url = response.data["@odata.nextLink"] || null;
    }
    res.json(alerts);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: Insider Risk Management ─────────────────────────────────────────

app.post("/list-insider-risk-alerts", async (req, res) => {
  try {
    const token = await getGraphToken();
    let alerts = [];
    let url = "https://graph.microsoft.com/beta/security/alerts_v2?$filter=serviceSource eq 'microsoftInsiderRiskManagement'";
    while (url) {
      const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
      alerts = alerts.concat(response.data.value);
      url = response.data["@odata.nextLink"] || null;
    }
    res.json(alerts);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-insider-risk-policies", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/insiderRiskManagement/policies",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: Information Barriers ─────────────────────────────────────────────

app.post("/list-information-barrier-policies", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/informationBarrierPolicies",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-information-barrier-segments", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/informationBarrierSegments",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: eDiscovery ───────────────────────────────────────────────────────

app.post("/list-ediscovery-cases", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/compliance/ediscovery/cases",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/get-ediscovery-case", async (req, res) => {
  const { caseId } = req.body;
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      `https://graph.microsoft.com/beta/compliance/ediscovery/cases/${caseId}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-ediscovery-custodians", async (req, res) => {
  const { caseId } = req.body;
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      `https://graph.microsoft.com/beta/compliance/ediscovery/cases/${caseId}/custodians`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-ediscovery-holds", async (req, res) => {
  const { caseId } = req.body;
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      `https://graph.microsoft.com/beta/compliance/ediscovery/cases/${caseId}/legalHolds`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: Records Management & Retention ───────────────────────────────────

app.post("/list-retention-labels", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/labels/retentionLabels",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-retention-event-types", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/triggerTypes/retentionEventTypes",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: Audit ────────────────────────────────────────────────────────────

app.post("/list-audit-logs", async (req, res) => {
  const { filter, top } = req.body;
  try {
    const token = await getGraphToken();
    let url = `https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=${top || 50}`;
    if (filter) url += `&$filter=${encodeURIComponent(filter)}`;
    const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

app.post("/list-signin-logs", async (req, res) => {
  const { filter, top } = req.body;
  try {
    const token = await getGraphToken();
    let url = `https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=${top || 50}`;
    if (filter) url += `&$filter=${encodeURIComponent(filter)}`;
    const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
    res.json(response.data.value);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: Communication Compliance ────────────────────────────────────────

app.post("/list-communication-compliance-policies", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/compliance/communicationCompliance/policies",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: Compliance Manager ───────────────────────────────────────────────

app.post("/list-compliance-assessments", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/compliance/complianceManagement/complianceAssessments",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

// ── Purview: DSPM ─────────────────────────────────────────────────────────────

app.post("/get-dspm-insights", async (req, res) => {
  try {
    const token = await getGraphToken();
    const response = await axios.get(
      "https://graph.microsoft.com/beta/security/dataSecurityAndGovernance/sensitiveTypesSummary",
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.json(response.data.value || response.data);
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    res.status(500).json({ error: detail });
  }
});

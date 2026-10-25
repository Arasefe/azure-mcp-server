// Off-box copy of the azsec-mcp audit chain: custom table + direct-ingestion DCR in the existing
// Sentinel workspace, and the narrowest role the shipper needs (Monitoring Metrics Publisher on
// this DCR only). Deploy into the resource group that holds the Sentinel workspace.
//
//   az deployment group create -g <sentinel-rg> -f infra/audit-ingestion.bicep \
//     -p workspaceName=<workspace> shipperPrincipalId=<service-principal-object-id>

@description('Existing Log Analytics workspace that has Microsoft Sentinel enabled.')
param workspaceName string

@description('Object ID of the service principal that runs azsec-mcp-ship.')
param shipperPrincipalId string

param location string = resourceGroup().location

@description('Days to keep audit rows (interactive retention).')
@minValue(30)
@maxValue(730)
param retentionInDays int = 365

var tableName = 'AzSecMcpAudit_CL'
var streamName = 'Custom-${tableName}'
var monitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'Kind', type: 'string' }
  { name: 'Host', type: 'string' }
  { name: 'Seq', type: 'long' }
  { name: 'Tool', type: 'string' }
  { name: 'Tier', type: 'string' }
  { name: 'Decision', type: 'string' }
  { name: 'Outcome', type: 'string' }
  { name: 'Reason', type: 'string' }
  { name: 'Error', type: 'string' }
  { name: 'Args', type: 'dynamic' }
  { name: 'RecordHash', type: 'string' }
  { name: 'PrevHash', type: 'string' }
  { name: 'ChainOk', type: 'boolean' }
  { name: 'Problem', type: 'string' }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    schema: {
      name: tableName
      columns: columns
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-azsec-mcp-audit'
  location: location
  kind: 'Direct'
  properties: {
    description: 'azsec-mcp audit chain shipped by azsec-mcp-ship'
    streamDeclarations: {
      '${streamName}': {
        columns: columns
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'sentinel'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['sentinel']
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [table]
}

resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, shipperPrincipalId, monitoringMetricsPublisher)
  scope: dcr
  properties: {
    principalId: shipperPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      monitoringMetricsPublisher
    )
  }
}

output logsIngestionEndpoint string = dcr.properties.endpoints.logsIngestion
output dcrImmutableId string = dcr.properties.immutableId

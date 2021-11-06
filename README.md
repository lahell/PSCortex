## PSCortex

Get endpoints, incidents and alerts from the Cortex XDR API. 

### Before you begin
First of all you have to obtain a API Key and API Key ID: [Get Started with Cortex XDR APIs](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis.html)

### Installation

```PowerShell
Install-Module -Name PSCortex
```

### Usage
 Store API Key ID and API Key as `$Credential` and pass it to `Initialize-CortexConfig`.
```PowerShell
$Credential = Get-Credential
Initialize-CortexConfig -TenantName yourcompany -SecurityLevel Advanced -Region EU -Credential $Credential
```

[Get All Endpoints](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/endpoint-management/get-all-endpoints.html). Returns a list of all endpoints with a limited number of properties.
```PowerShell
Get-CortexEndpointList
```

[Get Endpoints](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/endpoint-management/get-endpoints.html) where status is lost and [Delete Endpoints](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/endpoint-management/delete-endpoints.html). Running `Get-CortexEndpoint` without parameters will return all endpoints.
```PowerShell
$LostEndpoints = Get-CortexEndpoint -EndpointStatus Lost
Remove-CortexEndpoint -EndpointId $LostEndpoints.EndpointId -WhatIf
```

[Get Incidents](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/incident-management/get-incidents.html). Running `Get-CortexIncident` without parameters will return all incidents.
```PowerShell
Get-CortexIncident -Status New
```

[Get Alerts](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/incident-management/get-alerts.html). Running `Get-CortexAlert` without parameters will return all alerts.
```PowerShell
Get-CortexAlert -Severity High
```

[Get Audit Agent Reports](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/audit-logs/get-audit-agent-report.html). Running `Get-CortexAuditAgentReport` without parameters will return all reports.
```PowerShell
Get-CortexAuditAgentReport -Category Status
```

[Get Audit Management Logs](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-apis/audit-logs/get-audit-management-log.html). Running `Get-CortexAuditManagementLog` without parameters will return all logs.
```PowerShell
Get-CortexAuditManagementLog -CreatedAfter (Get-Date).AddDays(-7)
```

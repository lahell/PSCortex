![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/PSCortex?color=808000&logo=powershell&logoColor=lightgrey&style=flat-square)
![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/PSCortex?color=808000&style=flat-square)
![GitHub](https://img.shields.io/github/license/lahell/PSCortex?color=808000&style=flat-square)
## PSCortex

Get endpoints, incidents and alerts from the Cortex XDR API.

> [!IMPORTANT]
> This module is no longer maintained.

### Before you begin
First of all you have to obtain a API Key and API Key ID: [Get Started with Cortex XDR APIs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-API-Reference/Get-Started-with-APIs)

### Installation

```PowerShell
Install-Module -Name PSCortex
```

### Usage
Below are some examples of how you can use this module. Please use `Get-Help` for more details about each function.

 Store API Key ID and API Key as `$Credential` and pass it to `Initialize-CortexConfig`.
```PowerShell
$Credential = Get-Credential
Initialize-CortexConfig -TenantName yourcompany -SecurityLevel Advanced -Region EU -Credential $Credential
```

[Get All Endpoints](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-All-Endpoints). Returns a list of all endpoints with a limited number of properties.
```PowerShell
Get-CortexEndpointList
```

[Get Endpoint](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Endpoint) where status is lost and [Delete Endpoints](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Delete-Endpoints). Running `Get-CortexEndpoint` without parameters will return all endpoints.
```PowerShell
$LostEndpoints = Get-CortexEndpoint -EndpointStatus Lost
Remove-CortexEndpoint -EndpointId $LostEndpoints.EndpointId -WhatIf
```

[Get Incidents](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-all-Incidents). Running `Get-CortexIncident` without parameters will return all incidents.
```PowerShell
Get-CortexIncident -Status New
```

[Get Alerts](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-all-Alerts). Running `Get-CortexAlert` without parameters will return all alerts.
```PowerShell
Get-CortexAlert -Severity High
```

[Get Audit Agent Report](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Audit-Agent-Report). Running `Get-CortexAuditAgentReport` without parameters will return all reports.
```PowerShell
Get-CortexAuditAgentReport -Category Status
```

[Get Audit Management Log](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Audit-Management-Log). Running `Get-CortexAuditManagementLog` without parameters will return all logs.
```PowerShell
Get-CortexAuditManagementLog -CreatedAfter (Get-Date).AddDays(-7)
```

[Get Violations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Violations). Running `Get-CortexViolation` without parameters will return all violations.
```PowerShell
Get-CortexViolation -CreatedAfter (Get-Date).AddDays(-7) -Type PortableDevice
```

### Use Case: Find Duplicates
If a computer is reinstalled you could end up with duplicates in Cortex XDR.
```PowerShell
Get-CortexEndpointList | Group-Object HostName | Where-Object Count -gt 1 | Select-Object -ExpandProperty Group
```

### Use Case: Delete Endpoints that do not exist in AD
If the endpoint is uninstalled or lost and the computer no longer exist in AD you probably want to remove it from Cortex XDR.
```PowerShell
$Endpoints = Get-CortexEndpointList -InactiveOnly | Where-Object HostName -notin (Get-ADComputer -Filter *).Name
Remove-CortexEndpoint -EndpointId $Endpoints.AgentId -WhatIf
```

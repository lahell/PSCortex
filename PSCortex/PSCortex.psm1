#region enums
enum CortexRegion {
    EU
    US
    DE
}

enum CortexSecurityLevel {
    Advanced
    Standard
}

enum CortexEndpointStatus {
    Connected
    Disconnected
    Lost
    Uninstalled
}

enum CortexIncidentStatus {
    ResolvedThreatHandled
    UnderInvestigation
    New
    ResolvedFalsePositive
    ResolvedKnownIssue
    ResolvedAuto
    ResolvedDuplicate
    ResolvedOther
}

enum CortexAlertSeverity {
    Low
    Medium
    High
    Unknown
}

enum CortexAuditAgentReportCategory {
    Status
    Audit
    Monitoring
}
#endregion

#region classes
class CortexConfig {
    [PSCredential]$Credential
    [CortexSecurityLevel]$SecurityLevel
    [String]$TenantName
    [CortexRegion]$Region
    [Uri]$BaseUri

    CortexConfig(
        [PSCredential]$Credential,
        [CortexSecurityLevel]$SecurityLevel,
        [String]$TenantName,
        [CortexRegion]$Region
    ) {
        $this.Credential = $Credential
        $this.SecurityLevel = $SecurityLevel
        $this.TenantName = $TenantName
        $this.Region = $Region
        $this.BaseUri = 'https://api-{0}.xdr.{1}.paloaltonetworks.com/public_api/v1' -f $TenantName.ToLower(), $Region.ToString().ToLower()
    }
}

class CortexEndpointSummary {
    [String]$AgentId
    [String]$AgentStatus
    [String]$HostName
    [String]$AgentType
    [IPAddress[]]$IPAddress
    [DateTime]$LastSeen

    CortexEndpointSummary(
        [PSCustomObject]$EndpointSummary
    ) {
        $this.AgentId = $EndpointSummary.agent_id
        $this.AgentStatus = (Get-Culture).TextInfo.ToTitleCase($EndpointSummary.agent_status.ToLower())
        $this.HostName = $EndpointSummary.host_name
        $this.AgentType = $EndpointSummary.agent_type
        $this.IPAddress = $EndpointSummary.ip -as [IPAddress[]]
        $this.LastSeen = ConvertFrom-UnixTimestamp $EndpointSummary.last_seen
    }
}

class CortexEndpoint {
    [String]$EndpointId
    [String]$EndpointName
    [String]$EndpointType
    [String]$EndpointStatus
    [String]$OperatingSystemType
    [IPAddress[]]$IPAddress
    [String[]]$Users
    [String]$Domain
    [String]$Alias
    [DateTime]$FirstSeen
    [DateTime]$LastSeen
    [String]$ContentVersion
    [String]$InstallationPackage
    [String]$ActiveDirectory
    [DateTime]$InstallDate
    [Version]$EndpointVersion
    [String]$IsIsolated
    [Nullable[DateTime]]$IsolatedDate
    [String[]]$GroupName
    [String]$OperationalStatus
    [Object[]]$OperationalStatusDescription
    [String]$ScanStatus

    CortexEndpoint(
        [PSCustomObject]$Endpoint
    ) {
        $this.EndpointId = $Endpoint.endpoint_id
        $this.EndpointName = $Endpoint.endpoint_name
        $this.EndpointType = $Endpoint.endpoint_type
        $this.EndpointStatus = ConvertTo-PascalCase $Endpoint.endpoint_status.ToLower()
        $this.OperatingSystemType = $Endpoint.os_type
        $this.IPAddress = $Endpoint.ip -as [IPAddress[]]
        $this.Users = $Endpoint.users
        $this.Domain = $Endpoint.domain
        $this.Alias = $Endpoint.Alias
        $this.FirstSeen = ConvertFrom-UnixTimestamp $Endpoint.first_seen
        $this.LastSeen = ConvertFrom-UnixTimestamp $Endpoint.last_seen
        $this.ContentVersion = $Endpoint.content_version
        $this.InstallationPackage = $Endpoint.installation_package
        $this.ActiveDirectory = $Endpoint.active_directory
        $this.InstallDate = ConvertFrom-UnixTimestamp $Endpoint.install_date
        $this.EndpointVersion = $Endpoint.endpoint_version
        $this.IsIsolated = $Endpoint.is_isolated
        $this.IsolatedDate = ConvertFrom-UnixTimestamp $Endpoint.isolated_date
        $this.GroupName = $Endpoint.group_name
        $this.OperationalStatus = $Endpoint.operational_status
        $this.OperationalStatusDescription = $Endpoint.operational_status_description
        $this.ScanStatus = $Endpoint.scan_status
    }
}

class CortexIncident {
    [Int]$IncidentId
    [String]$IncidentName
    [DateTime]$CreationTime
    [DateTime]$ModificationTime
    [Nullable[DateTime]]$DetectionTime
    [String]$Status
    [String]$Severity
    [String]$Description
    [String]$AssignedUserMail
    [String]$AssignedUserPrettyName
    [Int]$AlertCount
    [Int]$LowSeverityAlertCount
    [Int]$MediumSeverityAlertCount
    [Int]$HighSeverityAlertCount
    [Int]$UserCount
    [Int]$HostCount
    [String]$Notes
    [String]$ResolveComment
    [String]$ManualSeverity
    [String]$ManualDescription
    [String]$XdrUrl
    [Boolean]$Starred
    [String[]]$Hosts
    [String[]]$Users
    [String[]]$IncidentSources
    [String]$RuleBasedScore
    [String]$ManualScore

    CortexIncident(
        [PSCustomObject]$Incident
    ) {
        $this.IncidentId = $Incident.incident_id
        $this.IncidentName = $Incident.incident_name
        $this.CreationTime = ConvertFrom-UnixTimestamp $Incident.creation_time
        $this.ModificationTime = ConvertFrom-UnixTimestamp $Incident.modification_time
        $this.DetectionTime = ConvertFrom-UnixTimestamp $Incident.detection_time
        $this.Status = ConvertTo-PascalCase $Incident.status
        $this.Severity = ConvertTo-PascalCase $Incident.severity
        $this.Description = $Incident.description
        $this.AssignedUserMail = $Incident.assigned_user_mail
        $this.AssignedUserPrettyName = $Incident.assigned_user_pretty_name
        $this.AlertCount = $Incident.alert_count
        $this.LowSeverityAlertCount = $Incident.low_severity_alert_count
        $this.MediumSeverityAlertCount = $Incident.med_severity_alert_count
        $this.HighSeverityAlertCount = $Incident.high_severity_alert_count
        $this.UserCount = $Incident.user_count
        $this.HostCount = $Incident.host_count
        $this.Notes = $Incident.notes
        $this.ResolveComment = $Incident.resolve_comment
        $this.ManualSeverity = $Incident.manual_severity
        $this.ManualDescription = $Incident.manual_description
        $this.XdrUrl = $Incident.xdr_url
        $this.Starred = $Incident.starred
        $this.Hosts = $Incident.hosts
        $this.Users = $Incident.users
        $this.IncidentSources = $Incident.incident_sources
        $this.RuleBasedScore = $Incident.rule_based_score
        $this.ManualScore = $Incident.manual_score
    }
}

class CortexEvent {
    [String]$AgentInstallType
    [Nullable[DateTime]]$AgentHostBootTime
    [String]$EventSubType
    [String]$ModuleId
    [String]$AssociationStrength
    [String]$DstAssociationStrength
    [String]$StoryId
    [String]$EventId
    [String]$EventType
    [DateTime]$EventTimestamp
    [String]$ActorProcessInstanceId
    [String]$ActorProcessImagePath
    [String]$ActorProcessImageName
    [String]$ActorProcessCommandLine
    [String]$ActorProcessSignatureStatus
    [String]$ActorProcessSignatureVendor
    [String]$ActorProcessImageSha256
    [String]$ActorProcessImageMd5
    [String]$ActorProcessCausalityId
    [String]$ActorCausalityId
    [String]$ActorProcessOsPid
    [String]$ActorThreadThreadId
    [String]$CausalityActorProcessImageName
    [String]$CausalityActorProcessCommandLine
    [String]$CausalityActorProcessImagePath
    [String]$CausalityActorProcessSignatureVendor
    [String]$CausalityActorProcessSignatureStatus
    [String]$CausalityActorCausalityId
    [String]$CausalityActorProcessExecutionTime
    [String]$CausalityActorProcessImageMd5
    [String]$CausalityActorProcessImageSha256
    [String]$ActionFilePath
    [String]$ActionFileName
    [String]$ActionFileMd5
    [String]$ActionFileSha256
    [String]$ActionFileMacroSha256
    [String]$ActionRegistryData
    [String]$ActionRegistryKeyName
    [String]$ActionRegistryValueName
    [String]$ActionRegistryFullKey

    CortexEvent(
        [PSCustomObject]$CortexEvent
    ) {
        $this.AgentInstallType = $CortexEvent.agent_install_type
        $this.AgentHostBootTime = ConvertFrom-UnixTimestamp $CortexEvent.agent_host_boot_time
        $this.EventSubType = $CortexEvent.event_sub_type
        $this.ModuleId = $CortexEvent.module_id
        $this.AssociationStrength = $CortexEvent.association_strength
        $this.DstAssociationStrength = $CortexEvent.dst_association_strength
        $this.StoryId = $CortexEvent.story_id
        $this.EventId = $CortexEvent.event_id
        $this.EventType = $CortexEvent.event_type
        $this.EventTimestamp = ConvertFrom-UnixTimestamp $CortexEvent.event_timestamp
        $this.ActorProcessInstanceId = $CortexEvent.actor_process_instance_id
        $this.ActorProcessImagePath = $CortexEvent.actor_process_image_path
        $this.ActorProcessImageName = $CortexEvent.actor_process_image_name
        $this.ActorProcessCommandLine = $CortexEvent.actor_process_command_line
        $this.ActorProcessSignatureStatus = $CortexEvent.actor_process_signature_status
        $this.ActorProcessSignatureVendor = $CortexEvent.actor_process_signature_vendor
        $this.ActorProcessImageSha256 = $CortexEvent.actor_process_image_sha256
        $this.ActorProcessImageMd5 = $CortexEvent.actor_process_image_md5
        $this.ActorProcessCausalityId = $CortexEvent.actor_process_causality_id
        $this.ActorCausalityId = $CortexEvent.actor_causality_id
        $this.ActorProcessOsPid = $CortexEvent.actor_process_os_pid
        $this.ActorThreadThreadId = $CortexEvent.actor_thread_thread_id
        $this.CausalityActorProcessImageName = $CortexEvent.causality_actor_process_image_name
        $this.CausalityActorProcessCommandLine = $CortexEvent.causality_actor_process_command_line
        $this.CausalityActorProcessImagePath = $CortexEvent.causality_actor_process_image_path
        $this.CausalityActorProcessSignatureVendor = $CortexEvent.causality_actor_process_signature_vendor
        $this.CausalityActorProcessSignatureStatus = $CortexEvent.causality_actor_process_signature_status
        $this.CausalityActorCausalityId = $CortexEvent.causality_actor_causality_id
        $this.CausalityActorProcessExecutionTime = $CortexEvent.causality_actor_process_execution_time
        $this.CausalityActorProcessImageMd5 = $CortexEvent.causality_actor_process_image_md5
        $this.CausalityActorProcessImageSha256 = $CortexEvent.causality_actor_process_image_sha256
        $this.ActionFilePath = $CortexEvent.action_file_path
        $this.ActionFileName = $CortexEvent.action_file_name
        $this.ActionFileMd5 = $CortexEvent.action_file_md5
        $this.ActionFileSha256 = $CortexEvent.action_file_sha256
        $this.ActionFileMacroSha256 = $CortexEvent.action_file_macro_sha256
        $this.ActionRegistryData = $CortexEvent.action_registry_data
        $this.ActionRegistryKeyName = $CortexEvent.action_registry_key_name
        $this.ActionRegistryValueName = $CortexEvent.action_registry_value_name
        $this.ActionRegistryFullKey = $CortexEvent.action_registry_full_key
    }
}

class CortexAlert {
    [String]$ExternalId
    [String]$Severity
    [String]$MatchingStatus
    [Nullable[DateTime]]$EndMatchAttemptTimestamp
    [DateTime]$LocalInsertTimestamp
    [String]$BiocIndicator
    [String]$MatchingServiceRuleId
    [Int]$AttemptCounter
    [String]$BiocCategoryEnumKey
    [Boolean]$IsWhitelisted
    [Boolean]$Starred
    [String]$DeduplicateTokens
    [String]$FilterRuleId
    [String]$MitreTechniqueIdAndName
    [String]$MitreTacticIdAndName
    [String]$AgentVersion
    [String]$AgentDeviceDomain
    [String]$AgentFqdn
    [String]$AgentOsType
    [String]$AgentOsSubType
    [String]$AgentDataCollectionStatus
    [String]$Mac
    [CortexEvent[]]$Events
    [Int]$AlertId
    [DateTime]$DetectionTimestamp
    [String]$Name
    [String]$Category
    [String]$EndpointId
    [String]$Description
    [IPAddress[]]$HostIp
    [String]$HostName
    [String[]]$MacAddresses
    [String]$Source
    [String]$Action
    [String]$ActionPretty

    CortexAlert(
        [PSCustomObject]$Alert
    ) {
        $this.ExternalId = $Alert.external_id
        $this.Severity = ConvertTo-PascalCase $Alert.severity
        $this.MatchingStatus = $Alert.matching_status
        $this.EndMatchAttemptTimestamp = ConvertFrom-UnixTimestamp $Alert.end_match_attempt_ts
        $this.LocalInsertTimestamp = ConvertFrom-UnixTimestamp $Alert.local_insert_ts
        $this.BiocIndicator = $Alert.bioc_indicator
        $this.MatchingServiceRuleId = $Alert.matching_service_rule_id
        $this.AttemptCounter = $Alert.attempt_counter
        $this.BiocCategoryEnumKey = $Alert.bioc_category_enum_key
        $this.IsWhitelisted = $Alert.is_whitelisted
        $this.Starred = $Alert.starred
        $this.DeduplicateTokens = $Alert.deduplicate_tokens
        $this.FilterRuleId = $Alert.filter_rule_id
        $this.MitreTechniqueIdAndName = $Alert.mitre_technique_id_and_name
        $this.MitreTacticIdAndName = $Alert.mitre_tactic_id_and_name
        $this.AgentVersion = $Alert.agent_version
        $this.AgentDeviceDomain = $Alert.agent_device_domain
        $this.AgentFqdn = $Alert.agent_fqdn
        $this.AgentOsType = $Alert.agent_os_type
        $this.AgentOsSubType = $Alert.agent_os_sub_type
        $this.AgentDataCollectionStatus = $Alert.agent_data_collection_status
        $this.Mac = $Alert.mac
        $this.Events = $Alert.events -as [CortexEvent[]]
        $this.AlertId = $Alert.alert_id
        $this.DetectionTimestamp = ConvertFrom-UnixTimestamp $Alert.detection_timestamp
        $this.Name = $Alert.name
        $this.Category = $Alert.category
        $this.EndpointId = $Alert.endpoint_id
        $this.Description = $Alert.description
        $this.HostIp = $Alert.host_ip
        $this.HostName = $Alert.host_name
        $this.MacAddresses = $Alert.mac_addresses
        $this.Source = $Alert.source
        $this.Action = $Alert.action
        $this.ActionPretty = $Alert.action_pretty
    }
}

class CortexAuditAgentReport {
    [DateTime]$Timestamp
    [DateTime]$ReceivedTime
    [String]$EndpointId
    [String]$EndpointName
    [String]$Domain
    [String]$XdrVersion
    [String]$Category
    [String]$Type
    [String]$SubType
    [String]$Result
    [String]$Reason
    [String]$Description

    CortexAuditAgentReport(
        [PSCustomObject]$AuditAgentReport
    ) {
        $this.Timestamp = ConvertFrom-UnixTimestamp $AuditAgentReport.TIMESTAMP
        $this.ReceivedTime = ConvertFrom-UnixTimestamp $AuditAgentReport.RECEIVEDTIME
        $this.EndpointId = $AuditAgentReport.ENDPOINTID
        $this.EndpointName = $AuditAgentReport.ENDPOINTNAME
        $this.Domain = $AuditAgentReport.DOMAIN
        $this.XdrVersion = $AuditAgentReport.XDRVERSION
        $this.Category = $AuditAgentReport.CATEGORY
        $this.Type = $AuditAgentReport.TYPE
        $this.SubType = $AuditAgentReport.SUBTYPE
        $this.Result = $AuditAgentReport.RESULT
        $this.Reason = $AuditAgentReport.REASON
        $this.Description = $AuditAgentReport.DESCRIPTION
    }
}

class CortexAuditManagementLog {
    [Int]$AuditId
    [String]$AuditOwnerName
    [String]$AuditOwnerEmail
    [String]$AuditAssetJson
    [String]$AuditAssetNames
    [String]$AuditHostname
    [String]$AuditResult
    [String]$AuditReason
    [String]$AuditDescription
    [String]$AuditEntity
    [String]$AuditEntitySubtype
    [String]$AuditSessionId
    [String]$AuditCaseId
    [String]$AuditInsertTime
    [String]$AuditSeverity

    CortexAuditManagementLog(
        [PSCustomObject]$AuditManagementLog
    ) {
        $this.AuditId = $AuditManagementLog.AUDIT_ID
        $this.AuditOwnerName = $AuditManagementLog.AUDIT_OWNER_NAME
        $this.AuditOwnerEmail = $AuditManagementLog.AUDIT_OWNER_EMAIL
        $this.AuditAssetJson = $AuditManagementLog.AUDIT_ASSET_JSON
        $this.AuditAssetNames = $AuditManagementLog.AUDIT_ASSET_NAMES
        $this.AuditHostname = $AuditManagementLog.AUDIT_HOSTNAME
        $this.AuditResult = $AuditManagementLog.AUDIT_RESULT
        $this.AuditReason = $AuditManagementLog.AUDIT_REASON
        $this.AuditDescription = $AuditManagementLog.AUDIT_DESCRIPTION
        $this.AuditEntity = $AuditManagementLog.AUDIT_ENTITY
        $this.AuditEntitySubtype = $AuditManagementLog.AUDIT_ENTITY_SUBTYPE
        $this.AuditSessionId = $AuditManagementLog.AUDIT_SESSION_ID
        $this.AuditCaseId = $AuditManagementLog.AUDIT_CASE_ID
        $this.AuditInsertTime = ConvertFrom-UnixTimestamp $AuditManagementLog.AUDIT_INSERT_TIME
        $this.AuditSeverity = $AuditManagementLog.AUDIT_SEVERITY
    }
}
#endregion

#region private functions
function Get-CortexConfig {
    [CmdletBinding()]
    param()

    if ($Script:CortexConfig -is [CortexConfig]) {
        $Script:CortexConfig
    }
    else {
        throw "Please run Initialize-CortexConfig before calling any other functions."
    }
}

function Get-Nonce {
    [CmdletBinding()]
    param(
        [Int32]
        $Length = 64
    )

    #   0..9       A..Z       a..z
    (((48..57) + (65..90) + (97..122)) * $Length | Get-Random -Count $Length).ForEach( { [char]$_ }) -join ''
}

function Get-UnixTimestamp {
    [CmdletBinding()]
    [OutputType('System.Int64')]
    param(
        [DateTime]
        $DateTime
    )

    if (-not $PSBoundParameters.ContainsKey('DateTime')) {
        $DateTime = (Get-Date -Millisecond 0).ToUniversalTime()
    }

    $UnixEpochUtc = [DateTime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    [Int64][Double]::Parse((New-TimeSpan -Start $UnixEpochUtc -End $DateTime.ToUniversalTime()).TotalMilliseconds.ToString())
}

function ConvertFrom-UnixTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Int64]
        $UnixTimestamp
    )

    if ($UnixTimestamp -gt 0) {
        (Get-Date -Year 1970 -Month 1 -Date 1).AddMilliseconds($UnixTimestamp).ToLocalTime()
    }
    else {
        $null
    }
}

function ConvertTo-PascalCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]
        $SnakeCase
    )

    (Get-Culture).TextInfo.ToTitleCase(($SnakeCase.ToLower() -replace '_', ' ')) -replace ' '
}

function Get-CortexApiKeyHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]
        $ApiKey,

        [Parameter(Mandatory)]
        [String]
        $Nonce,

        [Parameter(Mandatory)]
        [String]
        $Timestamp
    )

    $AuthKey = '{0}{1}{2}' -f $ApiKey, $Nonce, $Timestamp
    $Hasher = [System.Security.Cryptography.HashAlgorithm]::Create('SHA256')
    $Hash = $Hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($AuthKey))
    [System.BitConverter]::ToString($Hash).Replace('-', '').ToLower()
}

function Get-CortexApiUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]
        $ApiName,

        [Parameter(Mandatory)]
        [String]
        $CallName
    )

    '{0}/{1}/{2}/' -f $Script:CortexConfig.BaseUri.AbsoluteUri, $ApiName, $CallName
}

function Get-CortexApiHeader {
    [CmdletBinding()]
    [OutputType('System.Collections.Hashtable')]
    param()

    $Config = Get-CortexConfig
    $ApiKeyId = $Config.Credential.UserName.ToString()
    $ApiKey = $Config.Credential.GetNetworkCredential().Password
    $SecurityLevel = $Config.SecurityLevel

    switch ($SecurityLevel) {
        'Advanced' {
            $Nonce = Get-Nonce
            $Timestamp = Get-UnixTimestamp
            $ApiKeyHash = Get-CortexApiKeyHash -ApiKey $ApiKey -Nonce $Nonce -Timestamp $Timestamp

            @{
                'x-xdr-timestamp' = $Timestamp
                'x-xdr-nonce'     = $Nonce
                'x-xdr-auth-id'   = $ApiKeyId
                'Authorization'   = $ApiKeyHash
            }
        }

        'Standard' {
            @{
                'x-xdr-auth-id' = $ApiKeyId
                'Authorization' = $ApiKey
            }
        }
    }
}

function Get-CortexUserAgent {
    [CmdletBinding()]
    param()

    $Module = $MyInvocation.MyCommand.ScriptBlock.Module.Name
    $Version = $MyInvocation.MyCommand.ScriptBlock.Module.Version

    try {
        $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent].GetProperty(
            'UserAgent',
            [System.Reflection.BindingFlags]::Static -bor
            [System.Reflection.BindingFlags]::NonPublic
        ).GetValue([Microsoft.PowerShell.Commands.PSUserAgent])
    } catch {
        $UserAgent = $null
    }

    $UserAgent, "$Module/$Version" -join ' '
}

function Invoke-CortexApiRequest {
    [CmdletBinding()]
    param(
        [String]$ApiName,
        [String]$CallName,
        [String]$Body
    )

    $Headers = Get-CortexApiHeader
    $Uri = Get-CortexApiUri -ApiName $ApiName -CallName $CallName
    $UserAgent = Get-CortexUserAgent

    Write-Verbose $UserAgent

    (Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $Body -UserAgent $UserAgent).reply
}

function Get-CortexFilter {
    [CmdletBinding()]
    [OutputType('System.Collections.Hashtable')]
    param(
        [String]$Field,
        [String]$Operator,
        [PSObject]$Value
    )

    $NewValue = switch ($Operator) {
        'gte' { Get-UnixTimestamp $Value }
        'lte' { Get-UnixTimestamp $Value }
        'in'  { ,($Value) }
        'eq'  { $Value }
    }

    @{
        field    = $Field
        operator = $Operator
        value    = $NewValue
    }
}
#endregion

#region public functions
function Initialize-CortexConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCredential]
        $Credential,

        [CortexSecurityLevel]
        $SecurityLevel = 'Advanced',

        [Parameter(Mandatory)]
        [String]
        $TenantName,

        [CortexRegion]
        $Region = 'EU'
    )

    $Script:CortexConfig = [CortexConfig]::new($Credential, $SecurityLevel, $TenantName, $Region)
}

function Get-CortexEndpointList {
    [CmdletBinding()]
    [OutputType('CortexEndpointSummary')]
    param()

    $Endpoints = Invoke-CortexApiRequest -ApiName endpoints -CallName get_endpoints -Body '{}'
    $Endpoints -as [CortexEndpointSummary[]]
}

function Get-CortexActiveEndpointList {
    [CmdletBinding()]
    [OutputType('CortexEndpointSummary')]
    param()

    $Endpoints = Get-CortexEndpointList
    $FilteredEndpoints = $Endpoints | Where-Object { ($_.AgentStatus -eq 'Connected') -or ($_.AgentStatus -eq 'Disconnected') }
    $FilteredEndpoints -as [CortexEndpointSummary[]]
        
}

function Get-CortexInActiveEndpointList {
    [CmdletBinding()]
    [OutputType('CortexEndpointSummary')]
    param()

    $Endpoints = Get-CortexEndpointList
    $FilteredEndpoints = $Endpoints | Where-Object {($_.AgentStatus -eq 'Lost') -or ($_.AgentStatus -eq 'Uninstalled') }
    $FilteredEndpoints -as [CortexEndpointSummary[]]
        
}

function Get-CortexEndpoint {
    [CmdletBinding()]
    param(
        [String[]]
        $EndpointId,

        [CortexEndpointStatus[]]
        $EndpointStatus,

        [String[]]
        $HostName,

        [String[]]
        $GroupName,

        [DateTime]
        $FirstSeenAfter,

        [DateTime]
        $FirstSeenBefore,

        [DateTime]
        $LastSeenAfter,

        [DateTime]
        $LastSeenBefore
    )

    $Filters = New-Object 'System.Collections.Generic.List[hashtable]'

    $Request = @{
        request_data = @{
            search_from = 0
            search_to   = 100
            filters     = $Filters
            sort        = @{
                field   = 'endpoint_id'
                keyword = 'asc'
            }
        }
    }

    $TotalCount = 0
    $SearchFrom = 0

    if ($PSBoundParameters.ContainsKey('EndpointId')) {
        $Filters.Add((Get-CortexFilter -Field endpoint_id_list -Operator in -Value $EndpointId))
    }

    if ($PSBoundParameters.ContainsKey('EndpointStatus')) {
        $Filters.Add((Get-CortexFilter -Field endpoint_status -Operator in -Value ($EndpointStatus -as [String[]])))
    }

    if ($PSBoundParameters.ContainsKey('HostName')) {
        $Filters.Add((Get-CortexFilter -Field hostname -Operator in -Value $HostName))
    }

    if ($PSBoundParameters.ContainsKey('GroupName')) {
        $Filters.Add((Get-CortexFilter -Field group_name -Operator in -Value $GroupName))
    }

    if ($PSBoundParameters.ContainsKey('FirstSeenAfter')) {
        $Filters.Add((Get-CortexFilter -Field first_seen -Operator gte -Value $FirstSeenAfter))
    }

    if ($PSBoundParameters.ContainsKey('FirstSeenBefore')) {
        $Filters.Add((Get-CortexFilter -Field first_seen -Operator lte -Value $FirstSeenBefore))
    }

    if ($PSBoundParameters.ContainsKey('LastSeenAfter')) {
        $Filters.Add((Get-CortexFilter -Field last_seen -Operator gte -Value $LastSeenAfter))
    }

    if ($PSBoundParameters.ContainsKey('LastSeenBefore')) {
        $Filters.Add((Get-CortexFilter -Field last_seen -Operator lte -Value $LastSeenBefore))
    }

    while ($SearchFrom -le $TotalCount) {
        $Body = $Request | ConvertTo-Json -Depth 4 -Compress

        Write-Verbose $Body

        $Result = Invoke-CortexApiRequest -ApiName endpoints -CallName get_endpoint -Body $Body
        $Result.endpoints -as [CortexEndpoint[]]

        Write-Verbose ($Result | Select-Object result_count, total_count | ConvertTo-Json -Compress)

        $Request.Item('request_data').Item('search_from') += 100
        $Request.Item('request_data').Item('search_to') += 100

        $SearchFrom = $Request.Item('request_data').Item('search_from')
        $TotalCount = $Result.total_count
    }
}

function Remove-CortexEndpoint {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [String[]]
        $EndpointId
    )

    $Body = @{
        request_data = @{
            filters = @(
                @{
                    field    = 'endpoint_id_list'
                    operator = 'in'
                    value    = @($EndpointId)
                }
            )
        }
    } | ConvertTo-Json -Depth 4 -Compress

    if ($PSCmdlet.ShouldProcess($EndpointId, 'delete')) {
        Invoke-CortexApiRequest -ApiName endpoints -CallName delete -Body $Body
    }
}

function Get-CortexIncident {
    [CmdletBinding()]
    param(
        [CortexIncidentStatus]
        $Status,

        [DateTime]
        $CreatedAfter,

        [DateTime]
        $CreatedBefore
    )

    $AllowedStatus = @{
        ResolvedThreatHandled = 'resolved_threat_handled'
        UnderInvestigation    = 'under_investigation'
        New                   = 'new'
        ResolvedFalsePositive = 'resolved_false_positive'
        ResolvedKnownIssue    = 'resolved_known_issue'
        ResolvedAuto          = 'resolved_auto'
        ResolvedDuplicate     = 'resolved_duplicate'
        ResolvedOther         = 'resolved_other'
    }

    $Filters = New-Object 'System.Collections.Generic.List[hashtable]'

    $Request = @{
        request_data = @{
            search_from = 0
            search_to   = 100
            filters     = $Filters
            sort        = @{
                field   = 'creation_time'
                keyword = 'asc'
            }
        }
    }

    $TotalCount = 0
    $SearchFrom = 0

    if ($PSBoundParameters.ContainsKey('Status')) {
        $Filters.Add((Get-CortexFilter -Field status -Operator eq -Value $AllowedStatus[[String]$Status]))
    }

    if ($PSBoundParameters.ContainsKey('CreatedAfter')) {
        $Filters.Add((Get-CortexFilter -Field creation_time -Operator gte -Value $CreatedAfter))
    }

    if ($PSBoundParameters.ContainsKey('CreatedBefore')) {
        $Filters.Add((Get-CortexFilter -Field creation_time -Operator lte -Value $CreatedBefore))
    }

    while ($SearchFrom -le $TotalCount) {
        $Body = $Request | ConvertTo-Json -Depth 4 -Compress

        Write-Verbose $Body

        $Result = Invoke-CortexApiRequest -ApiName incidents -CallName get_incidents -Body $Body
        $Result.incidents -as [CortexIncident[]]

        Write-Verbose ($Result | Select-Object result_count, total_count | ConvertTo-Json -Compress)

        $Request.Item('request_data').Item('search_from') += 100
        $Request.Item('request_data').Item('search_to') += 100

        $SearchFrom = $Request.Item('request_data').Item('search_from')
        $TotalCount = $Result.total_count
    }
}

function Get-CortexIncidentExtraData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String]
        $IncidentId
    )

    $Body = @{
        request_data = @{
            incident_id = $IncidentId
        }
    } | ConvertTo-Json -Compress

    Invoke-CortexApiRequest -ApiName incidents -CallName get_incident_extra_data -Body $Body
}

function Get-CortexAlert {
    [CmdletBinding()]
    param(
        [Int[]]
        $AlertId,

        [CortexAlertSeverity[]]
        $Severity,

        [DateTime]
        $CreatedAfter,

        [DateTime]
        $CreatedBefore
    )

    $Filters = New-Object 'System.Collections.Generic.List[hashtable]'

    $Request = @{
        request_data = @{
            search_from = 0
            search_to   = 100
            filters     = $Filters
            sort        = @{
                field   = 'creation_time'
                keyword = 'asc'
            }
        }
    }

    $TotalCount = 0
    $SearchFrom = 0

    if ($PSBoundParameters.ContainsKey('AlertId')) {
        $Filters.Add((Get-CortexFilter -Field alert_id_list -Operator in -Value $AlertId))
    }

    if ($PSBoundParameters.ContainsKey('Severity')) {
        $Filters.Add((Get-CortexFilter -Field severity -Operator in -Value ($Severity -as [String[]])))
    }

    if ($PSBoundParameters.ContainsKey('CreatedAfter')) {
        $Filters.Add((Get-CortexFilter -Field creation_time -Operator gte -Value $CreatedAfter))
    }

    if ($PSBoundParameters.ContainsKey('CreatedBefore')) {
        $Filters.Add((Get-CortexFilter -Field creation_time -Operator lte -Value $CreatedBefore))
    }

    while ($SearchFrom -le $TotalCount) {
        $Body = $Request | ConvertTo-Json -Depth 4 -Compress

        Write-Verbose $Body

        $Result = Invoke-CortexApiRequest -ApiName alerts -CallName get_alerts_multi_events -Body $Body
        $Result.alerts -as [CortexAlert[]]

        Write-Verbose ($Result | Select-Object result_count, total_count | ConvertTo-Json -Compress)

        $Request.Item('request_data').Item('search_from') += 100
        $Request.Item('request_data').Item('search_to') += 100

        $SearchFrom = $Request.Item('request_data').Item('search_from')
        $TotalCount = $Result.total_count
    }
}

function Get-CortexAuditAgentReport {
    [CmdletBinding()]
    param(
        [String[]]
        $EndpointName,

        [CortexAuditAgentReportCategory[]]
        $Category,

        [DateTime]
        $CreatedAfter,

        [DateTime]
        $CreatedBefore
    )

    $Filters = New-Object 'System.Collections.Generic.List[hashtable]'

    $Request = @{
        request_data = @{
            search_from = 0
            search_to   = 100
            filters     = $Filters
            sort        = @{
                field   = 'timestamp'
                keyword = 'asc'
            }
        }
    }

    $TotalCount = 0
    $SearchFrom = 0

    if ($PSBoundParameters.ContainsKey('EndpointName')) {
        $Filters.Add((Get-CortexFilter -Field endpoint_name -Operator in -Value $EndpointName))
    }

    if ($PSBoundParameters.ContainsKey('Category')) {
        $Filters.Add((Get-CortexFilter -Field category -Operator in -Value ($Category -as [String[]])))
    }

    if ($PSBoundParameters.ContainsKey('CreatedAfter')) {
        $Filters.Add((Get-CortexFilter -Field timestamp -Operator gte -Value $CreatedAfter))
    }

    if ($PSBoundParameters.ContainsKey('CreatedBefore')) {
        $Filters.Add((Get-CortexFilter -Field timestamp -Operator lte -Value $CreatedBefore))
    }

    while ($SearchFrom -le $TotalCount) {
        $Body = $Request | ConvertTo-Json -Depth 4 -Compress

        Write-Verbose $Body

        $Result = Invoke-CortexApiRequest -ApiName audits -CallName agents_reports -Body $Body
        $Result.data -as [CortexAuditAgentReport[]]

        Write-Verbose ($Result | Select-Object result_count, total_count | ConvertTo-Json -Compress)

        $Request.Item('request_data').Item('search_from') += 100
        $Request.Item('request_data').Item('search_to') += 100

        $SearchFrom = $Request.Item('request_data').Item('search_from')
        $TotalCount = $Result.total_count
    }
}

function Get-CortexAuditManagementLog {
    [CmdletBinding()]
    param(
        [String[]]
        $EmailAddress,

        [DateTime]
        $CreatedAfter,

        [DateTime]
        $CreatedBefore
    )

    $Filters = New-Object 'System.Collections.Generic.List[hashtable]'

    $Request = @{
        request_data = @{
            search_from = 0
            search_to   = 100
            filters     = $Filters
            sort        = @{
                field   = 'timestamp'
                keyword = 'asc'
            }
        }
    }

    $TotalCount = 0
    $SearchFrom = 0

    if ($PSBoundParameters.ContainsKey('EmailAddress')) {
        $Filters.Add((Get-CortexFilter -Field email -Operator in -Value $EmailAddress))
    }

    if ($PSBoundParameters.ContainsKey('CreatedAfter')) {
        $Filters.Add((Get-CortexFilter -Field timestamp -Operator gte -Value $CreatedAfter))
    }

    if ($PSBoundParameters.ContainsKey('CreatedBefore')) {
        $Filters.Add((Get-CortexFilter -Field timestamp -Operator lte -Value $CreatedBefore))
    }

    while ($SearchFrom -le $TotalCount) {
        $Body = $Request | ConvertTo-Json -Depth 4 -Compress

        Write-Verbose $Body

        $Result = Invoke-CortexApiRequest -ApiName audits -CallName management_logs -Body $Body
        $Result.data -as [CortexAuditManagementLog[]]

        Write-Verbose ($Result | Select-Object result_count, total_count | ConvertTo-Json -Compress)

        $Request.Item('request_data').Item('search_from') += 100
        $Request.Item('request_data').Item('search_to') += 100

        $SearchFrom = $Request.Item('request_data').Item('search_from')
        $TotalCount = $Result.total_count
    }
}
#endregion

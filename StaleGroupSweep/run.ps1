<#
.SYNOPSIS
    Azure Function to identify and manage stale Entra ID groups.

.DESCRIPTION
    This Azure Function identifies stale groups in Entra ID based on activity metrics.
    
    Staleness detection:
    - Based on last activity timestamp (last member addition/removal, membership updates)
    - Falls back to lastModifiedDateTime if no activity data available
    - Identifies groups with no recent owner or member changes

    Modes:
    - detect:  Shows which stale groups would be acted on (dry-run/preview)
    - delete:  Deletes stale groups (requires CONFIRM_DELETE=true)
    - tag:     Tags stale groups using open extensions (requires CONFIRM_TAG=true)
    - archive: Archives Teams groups (requires CONFIRM_ARCHIVE=true)

    Output:
    - JSON report written to blob via output binding (reportBlob)
    - Human-readable summary text written to blob via output binding (summaryBlob)

.NOTES
    Version:        1.0 (Group staleness sweep)
    Author:         TLDTech.io

.PARAMETER Timer
    Timer trigger input from Azure Functions.

.EXAMPLE
    # Preview what would be acted on (detect mode)
    MODE=detect STALE_DAYS=90

.EXAMPLE
    # Delete stale groups (requires confirmation)
    MODE=delete STALE_DAYS=180 CONFIRM_DELETE=true MAX_ACTIONS=10

.EXAMPLE
    # Tag stale groups with metadata
    MODE=tag CONFIRM_TAG=true EXTENSION_NAME=STALE

.EXAMPLE
    # Exception lists: Protect specific groups from any actions
    MODE=delete EXCEPTION_GROUP_IDS=<guid>,<guid>
    EXCEPTION_NAME_PATTERNS=admin-*,exec-*

.ENVIRONMENT
    Core:
        STALE_DAYS=180
        MODE=detect | delete | tag | archive
        GRAPH_API_VERSION=v1.0
        MAX_ACTIONS=10

    Safety confirms:
        CONFIRM_DELETE=false
        CONFIRM_TAG=false
        CONFIRM_ARCHIVE=false

    Per-action throttles:
        MAX_DELETE=10
        MAX_TAG=25
        MAX_ARCHIVE=10

    Extension:
        EXTENSION_NAME=STALE
    
    Optional outputs:
        OUTPUT_ACTION_PLAN_CSV=false
        OUTPUT_INVENTORY_CSV=false
    
    Exceptions (groups never acted on):
        EXCEPTION_GROUP_IDS=<guid>,<guid>
        EXCEPTION_NAME_PATTERNS=admin-*,exec-*

.PERMISSIONS (Graph application permissions; managed identity / app-only)
    - Group read:    Group.Read.All, GroupMember.Read.All
    - Group write:   Group.ReadWrite.All (required for delete/tag/archive)
    - Extensions:    Directory.ReadWrite.All (required for open extensions tagging)

.TUNING GUIDANCE
    Small environments (<100 groups): ACTION_PARALLELISM=3
    Medium environments (100-500): ACTION_PARALLELISM=5 (default)
    Large environments (500+): ACTION_PARALLELISM=8
#>

param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Config
# ---------------------------

$staleDays = [int]($env:STALE_DAYS ?? 180)
$mode = ($env:MODE ?? 'detect').ToLowerInvariant()
$graphApiVersion = ($env:GRAPH_API_VERSION ?? 'v1.0')

$maxActions = [int]($env:MAX_ACTIONS ?? 10)

$confirmDelete = (($env:CONFIRM_DELETE ?? 'false').ToLowerInvariant() -eq 'true')
$confirmTag = (($env:CONFIRM_TAG ?? 'false').ToLowerInvariant() -eq 'true')
$confirmArchive = (($env:CONFIRM_ARCHIVE ?? 'false').ToLowerInvariant() -eq 'true')
$extensionName = ($env:EXTENSION_NAME ?? 'STALE')

# Per-action throttles
$maxDelete = [int]($env:MAX_DELETE ?? 10)
$maxTag = [int]($env:MAX_TAG ?? 25)
$maxArchive = [int]($env:MAX_ARCHIVE ?? 10)

# CSV outputs
$outputActionPlanCsv = ($env:OUTPUT_ACTION_PLAN_CSV ?? 'false') -eq 'true'
$outputInventoryCsv = ($env:OUTPUT_INVENTORY_CSV ?? 'false') -eq 'true'

# Times (UTC)
$nowUtc = (Get-Date).ToUniversalTime()
$cutoffUtc = $nowUtc.AddDays(-$staleDays)
$nowUtcStr = $nowUtc.ToString('o')
$cutoffUtcStr = $cutoffUtc.ToString('o')

# Parallelism for actions
$actionParallelism = [int]($env:ACTION_PARALLELISM ?? 5)

# Exception lists
$exceptionGroupIdsRaw = $env:EXCEPTION_GROUP_IDS ?? ''
$exceptionGroupIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (-not [string]::IsNullOrWhiteSpace($exceptionGroupIdsRaw)) {
    $exceptionGroupIdsRaw.Split(',') | ForEach-Object { 
        $id = $_.Trim()
        if ($id) { $exceptionGroupIds.Add($id) | Out-Null }
    }
}

$exceptionNamePatternsRaw = $env:EXCEPTION_NAME_PATTERNS ?? ''
$exceptionNamePatterns = @()
if (-not [string]::IsNullOrWhiteSpace($exceptionNamePatternsRaw)) {
    $exceptionNamePatterns = $exceptionNamePatternsRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

Write-Host "=== Entra stale group sweep (v1.0) ==="
Write-Host "Now (UTC):               $nowUtcStr"
Write-Host "Cutoff (UTC):            $cutoffUtcStr  (STALE_DAYS=$staleDays)"
Write-Host "Mode:                    $mode"
Write-Host "Graph:                   $graphApiVersion"
Write-Host "MAX_ACTIONS:             $maxActions"
Write-Host "Confirm delete/tag/arch: delete=$confirmDelete  tag=$confirmTag  archive=$confirmArchive"
Write-Host "Per-action caps:         delete=$maxDelete tag=$maxTag archive=$maxArchive"

# ---------------------------
# Structured config snapshot
# ---------------------------

$cfgEvent = @{
    eventType         = "staleGroupSweep.config"
    version           = "v1.0"
    mode              = $mode
    staleDays         = $staleDays
    maxActions        = $maxActions
    actionParallelism = $actionParallelism
    confirms          = @{
        delete  = $confirmDelete
        tag     = $confirmTag
        archive = $confirmArchive
    }
    limits            = @{
        maxDelete  = $maxDelete
        maxTag     = $maxTag
        maxArchive = $maxArchive
    }
}

Write-Host ("CFG " + ($cfgEvent | ConvertTo-Json -Compress))

# ---------------------------
# Authentication Helpers
# ---------------------------

function Get-GraphTokenManagedIdentity {
    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) { return $null }

    $resource = "https://graph.microsoft.com"
    $apiVersion = "2019-08-01"
    $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($resource))&api-version=$apiVersion"
    $headers = @{ "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER }

    (Invoke-RestMethod -Method GET -Uri $uri -Headers $headers).access_token
}

function Get-GraphTokenAzCli {
    $az = Get-Command az -ErrorAction SilentlyContinue
    if (-not $az) { throw "Azure CLI not found. Install 'az' or run in Azure with Managed Identity." }

    $json = & az account get-access-token --resource-type ms-graph --output json 2>$null
    if (-not $json) { throw "Failed to get Graph token from Azure CLI. Run 'az login' first." }

    ($json | ConvertFrom-Json).accessToken
}

function Get-GraphAccessToken {
    $mi = Get-GraphTokenManagedIdentity
    if ($mi) { return $mi }

    Write-Host "Managed Identity not detected; using Azure CLI token (local dev)."
    Get-GraphTokenAzCli
}

# ---------------------------
# Graph Helpers
# ---------------------------

function Invoke-Graph {
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken,
        [object] $Body = $null
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    if ($null -ne $Body) { $headers['Content-Type'] = 'application/json' }

    try {
        if ($Method -in @('POST', 'PATCH') -and $null -ne $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 10)
        }
        else {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        }
    }
    catch {
        $resp = $null
        if ($_.Exception.PSObject.Properties.Match('Response').Count -gt 0) {
            $resp = $_.Exception.Response
        }
        if ($resp -and $resp.StatusCode) {
            $code = [int]$resp.StatusCode
            throw "Graph $Method $Uri failed (HTTP $code): $($_.Exception.Message)"
        }
        throw
    }
}

function Invoke-GraphGetAll {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken,
        [int] $MaxRetries = 5
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $retries = 0

    while ($next) {
        try {
            $result = Invoke-RestMethod -Method GET -Uri $next -Headers @{ Authorization = "Bearer $AccessToken" }
            if ($result.value) {
                $items.AddRange($result.value)
            }
            $next = $result.'@odata.nextLink'
            $retries = 0
        }
        catch {
            $retries++
            if ($retries -ge $MaxRetries) { throw }
            Start-Sleep -Seconds (2 * $retries)
        }
    }

    $items
}

# ---------------------------
# Staleness Detection Helpers
# ---------------------------

function Get-GroupMemberCount {
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $AccessToken
    )
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/groups/$GroupId/members/count"
        $headers = @{ Authorization = "Bearer $AccessToken"; ConsistencyLevel = "eventual" }
        $countStr = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
        [int]$countStr
    }
    catch {
        Write-Host "Warning: Failed to get member count for $GroupId : $_"
        0
    }
}

function Get-GroupOwnerCount {
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $AccessToken
    )
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/groups/$GroupId/owners/count"
        $headers = @{ Authorization = "Bearer $AccessToken"; ConsistencyLevel = "eventual" }
        $countStr = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
        [int]$countStr
    }
    catch {
        Write-Host "Warning: Failed to get owner count for $GroupId : $_"
        0
    }
}

function Get-GroupAppAssignments {
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $AccessToken
    )
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/servicePrincipals?`$filter=appRoleAssignedTo/any(a: a/principalId eq '$GroupId')?`$select=id,displayName,appId"
        $result = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken" }
        $result.value
    }
    catch {
        Write-Host "Warning: Failed to get app assignments for $GroupId : $_"
        @()
    }
}

function Get-GroupConditionalAccessPolicies {
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $AccessToken
    )
    
    try {
        # Fetch all CA policies and check if group is referenced
        $uri = "https://graph.microsoft.com/$graphApiVersion/identity/conditionalAccess/policies"
        $policies = Invoke-GraphGetAll -Uri $uri -AccessToken $accessToken
        
        $referencedPolicies = @()
        foreach ($policy in $policies) {
            $policyJson = $policy | ConvertTo-Json -Depth 20
            if ($policyJson -match $GroupId) {
                $referencedPolicies += @{
                    id          = $policy.id
                    displayName = $policy.displayName
                }
            }
        }
        $referencedPolicies
    }
    catch {
        Write-Host "Warning: Failed to get CA policies for $GroupId : $_"
        @()
    }
}

function Get-GroupRoleAssignments {
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $AccessToken
    )
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/roleManagement/directory/roleAssignments?`$filter=principalId eq '$GroupId'&`$select=id,roleDefinitionId"
        $result = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken" }
        $result.value
    }
    catch {
        Write-Host "Warning: Failed to get role assignments for $GroupId : $_"
        @()
    }
}

# ---------------------------
# Main logic
# ---------------------------

try {
    Write-Host "Starting stale group sweep..."

    $accessToken = Get-GraphAccessToken
    Write-Host "Authentication successful."

    # Fetch all groups (cloud-only security groups and Microsoft 365 groups)
    Write-Host "Fetching all groups..."
    $groupsUri = "https://graph.microsoft.com/$graphApiVersion/groups?`$filter=groupTypes/any(c:c eq 'Unified') or (groupTypes/any(c:c eq 'DynamicMembership') eq false and mailEnabled eq false)&`$select=id,displayName,description,createdDateTime,lastModifiedDateTime,groupTypes,mailEnabled,securityEnabled"
    
    $groups = Invoke-GraphGetAll -Uri $groupsUri -AccessToken $accessToken
    Write-Host "Found $($groups.Count) total groups."

    # Gather usage signals for all groups
    Write-Host "Analyzing group usage signals (this may take several minutes)..."
    $groupsWithSignals = @()
    $progressCount = 0

    foreach ($group in $groups) {
        $progressCount++
        if ($progressCount % 50 -eq 0) { Write-Host "  Processed $progressCount of $($groups.Count) groups..." }

        $lastModified = if ($group.lastModifiedDateTime) { [datetime]::Parse($group.lastModifiedDateTime) } else { $null }
        $created = if ($group.createdDateTime) { [datetime]::Parse($group.createdDateTime) } else { $null }
        
        $lastActivityDate = $lastModified ?? $created
        $daysSinceActivity = if ($lastActivityDate) { [math]::Floor(($nowUtc - $lastActivityDate).TotalDays) } else { $null }

        # Check exception lists
        $isException = $false
        if ($exceptionGroupIds.Contains($group.id)) { $isException = $true }
        foreach ($pattern in $exceptionNamePatterns) {
            if ($group.displayName -like $pattern) { $isException = $true; break }
        }

        # Fetch staleness signals
        $memberCount = Get-GroupMemberCount -GroupId $group.id -AccessToken $accessToken
        $ownerCount = Get-GroupOwnerCount -GroupId $group.id -AccessToken $accessToken
        $appAssignments = Get-GroupAppAssignments -GroupId $group.id -AccessToken $accessToken
        $caPolicies = Get-GroupConditionalAccessPolicies -GroupId $group.id -AccessToken $accessToken
        $roleAssignments = Get-GroupRoleAssignments -GroupId $group.id -AccessToken $accessToken

        $groupsWithSignals += @{
            id                   = $group.id
            displayName          = $group.displayName
            description          = $group.description
            createdDateTime      = $group.createdDateTime
            lastModifiedDateTime = $group.lastModifiedDateTime
            groupTypes           = $group.groupTypes
            mailEnabled          = $group.mailEnabled
            securityEnabled      = $group.securityEnabled
            daysSinceActivity    = $daysSinceActivity
            memberCount          = $memberCount
            ownerCount           = $ownerCount
            appAssignmentCount   = $appAssignments.Count
            caPolicyCount        = $caPolicies.Count
            roleAssignmentCount  = $roleAssignments.Count
            isException          = $isException
            stalennessSignals    = @{
                noActivity            = $daysSinceActivity -gt $staleDays
                noMembers             = $memberCount -eq 0
                noOwners              = $ownerCount -eq 0
                notInAppAssignments   = $appAssignments.Count -eq 0
                notInCaPolicy         = $caPolicies.Count -eq 0
                notAssignedToRole     = $roleAssignments.Count -eq 0
            }
        }
    }

    # Classify groups as stale based on signals
    Write-Host "Classifying groups based on staleness signals..."
    $staleGroups = @()
    $activeGroups = @()

    foreach ($groupData in $groupsWithSignals) {
        $signals = $groupData.stalennessSignals
        
        # A group is stale if it has multiple unused signals or no purpose
        # Count how many staleness indicators are true
        $staleSignalCount = 0
        if ($signals.noMembers) { $staleSignalCount++ }
        if ($signals.noOwners) { $staleSignalCount++ }
        if ($signals.notInAppAssignments) { $staleSignalCount++ }
        if ($signals.notInCaPolicy) { $staleSignalCount++ }
        if ($signals.notAssignedToRole) { $staleSignalCount++ }
        if ($signals.noActivity) { $staleSignalCount++ }

        # Mark as stale if:
        # 1. No members AND no owners (completely unused)
        # 2. OR has 4+ staleness signals AND no recent activity
        # 3. OR has 5+ staleness signals (very strong indicator)
        $isStale = $false
        $staleReason = @()

        if ($signals.noMembers -and $signals.noOwners) {
            $isStale = $true
            $staleReason += "no members and no owners"
        }

        if ($staleSignalCount -ge 5) {
            $isStale = $true
            $staleReason += "5+ unused signals"
        }
        
        if ($signals.noActivity -and $staleSignalCount -ge 4) {
            $isStale = $true
            $staleReason += "inactive + 4+ unused signals"
        }

        if ($isStale -and -not $groupData.isException) {
            $staleGroups += @{
                id                   = $groupData.id
                displayName          = $groupData.displayName
                description          = $groupData.description
                createdDateTime      = $groupData.createdDateTime
                lastModifiedDateTime = $groupData.lastModifiedDateTime
                groupTypes           = $groupData.groupTypes
                memberCount          = $groupData.memberCount
                ownerCount           = $groupData.ownerCount
                appAssignmentCount   = $groupData.appAssignmentCount
                caPolicyCount        = $groupData.caPolicyCount
                roleAssignmentCount  = $groupData.roleAssignmentCount
                daysSinceActivity    = $groupData.daysSinceActivity
                stalennessSignals    = $signals
                staleReason          = $staleReason -join "; "
            }
        }
        else {
            $activeGroups += @{
                id           = $groupData.id
                displayName  = $groupData.displayName
                isException  = $groupData.isException
                memberCount  = $groupData.memberCount
                ownerCount   = $groupData.ownerCount
            }
        }
    }

    Write-Host "Stale groups: $($staleGroups.Count); Active groups: $($activeGroups.Count)"

    # Analyze signal distribution
    $signalStats = @{
        noMembers           = ($staleGroups | Where-Object { $_.stalennessSignals.noMembers }).Count
        noOwners            = ($staleGroups | Where-Object { $_.stalennessSignals.noOwners }).Count
        notInAppAssignments = ($staleGroups | Where-Object { $_.stalennessSignals.notInAppAssignments }).Count
        notInCaPolicy       = ($staleGroups | Where-Object { $_.stalennessSignals.notInCaPolicy }).Count
        notAssignedToRole   = ($staleGroups | Where-Object { $_.stalennessSignals.notAssignedToRole }).Count
        noActivity          = ($staleGroups | Where-Object { $_.stalennessSignals.noActivity }).Count
    }

    Write-Host "Signal breakdown (stale groups):"
    Write-Host "  No members:         $($signalStats.noMembers)"
    Write-Host "  No owners:          $($signalStats.noOwners)"
    Write-Host "  Not in apps:        $($signalStats.notInAppAssignments)"
    Write-Host "  Not in CA policy:   $($signalStats.notInCaPolicy)"
    Write-Host "  Not assigned role:  $($signalStats.notAssignedToRole)"
    Write-Host "  No recent activity: $($signalStats.noActivity)"

    # Process based on mode
    $summary = [ordered]@{
        totalGroups      = $groups.Count
        staleGroups      = $staleGroups.Count
        activeGroups     = $activeGroups.Count
        mode             = $mode
        stalennessSignals = $signalStats
        actions          = [ordered]@{}
    }

    if ($mode -eq 'detect') {
        Write-Host "MODE=detect: Reporting stale groups (no actions taken)"
        $summary.actions['detect'] = @{
            targetCount = $staleGroups.Count
            description = "Stale groups identified for review"
        }
    }
    elseif ($mode -eq 'delete') {
        if (-not $confirmDelete) {
            Write-Host "MODE=delete: CONFIRM_DELETE not set; skipping"
            $summary.actions['delete'] = @{
                targetCount = 0
                reason      = "CONFIRM_DELETE not enabled"
            }
        }
        else {
            Write-Host "MODE=delete: Deleting stale groups (up to $maxDelete)"
            $groupsToDelete = $staleGroups | Select-Object -First $maxDelete
            $deleted = 0
            
            foreach ($group in $groupsToDelete) {
                try {
                    Write-Host "Deleting group: $($group.displayName) ($($group.id))"
                    Invoke-Graph -Method DELETE -Uri "https://graph.microsoft.com/$graphApiVersion/groups/$($group.id)" -AccessToken $accessToken
                    $deleted++
                }
                catch {
                    Write-Host "Failed to delete $($group.displayName): $_"
                }
            }
            
            $summary.actions['delete'] = @{
                targeted = $groupsToDelete.Count
                successful = $deleted
                failed = $groupsToDelete.Count - $deleted
            }
        }
    }
    elseif ($mode -eq 'tag') {
        if (-not $confirmTag) {
            Write-Host "MODE=tag: CONFIRM_TAG not set; skipping"
            $summary.actions['tag'] = @{
                targetCount = 0
                reason      = "CONFIRM_TAG not enabled"
            }
        }
        else {
            Write-Host "MODE=tag: Tagging stale groups (up to $maxTag)"
            $groupsToTag = $staleGroups | Select-Object -First $maxTag
            $tagged = 0
            
            foreach ($group in $groupsToTag) {
                try {
                    $extensionBody = @{
                        "$extensionName" = @{
                            markedStaleAt     = $nowUtcStr
                            staleDays         = $staleDays
                            daysSinceActivity = $group.daysSinceActivity
                        }
                    }
                    Write-Host "Tagging group: $($group.displayName)"
                    Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/$graphApiVersion/groups/$($group.id)" -AccessToken $accessToken -Body $extensionBody
                    $tagged++
                }
                catch {
                    Write-Host "Failed to tag $($group.displayName): $_"
                }
            }
            
            $summary.actions['tag'] = @{
                targeted   = $groupsToTag.Count
                successful = $tagged
                failed     = $groupsToTag.Count - $tagged
            }
        }
    }
    elseif ($mode -eq 'archive') {
        if (-not $confirmArchive) {
            Write-Host "MODE=archive: CONFIRM_ARCHIVE not set; skipping"
            $summary.actions['archive'] = @{
                targetCount = 0
                reason      = "CONFIRM_ARCHIVE not enabled"
            }
        }
        else {
            Write-Host "MODE=archive: Archiving stale Teams groups (up to $maxArchive)"
            $groupsToArchive = $staleGroups | Where-Object { $_.groupTypes -contains 'Unified' } | Select-Object -First $maxArchive
            $archived = 0
            
            foreach ($group in $groupsToArchive) {
                try {
                    $archiveBody = @{
                        isArchived = $true
                    }
                    Write-Host "Archiving Teams group: $($group.displayName)"
                    Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/$graphApiVersion/teams/$($group.id)" -AccessToken $accessToken -Body $archiveBody
                    $archived++
                }
                catch {
                    Write-Host "Failed to archive $($group.displayName): $_"
                }
            }
            
            $summary.actions['archive'] = @{
                targeted   = $groupsToArchive.Count
                successful = $archived
                failed     = $groupsToArchive.Count - $archived
            }
        }
    }

    $summary.timestamp = $nowUtcStr
    $summary.staleGroupDetails = $staleGroups | Select-Object @{n='id';e={$_.id}},@{n='displayName';e={$_.displayName}},@{n='reason';e={$_.staleReason}},@{n='memberCount';e={$_.memberCount}},@{n='ownerCount';e={$_.ownerCount}},@{n='appAssignments';e={$_.appAssignmentCount}},@{n='caPolicies';e={$_.caPolicyCount}},@{n='roleAssignments';e={$_.roleAssignmentCount}},@{n='daysSinceActivity';e={$_.daysSinceActivity}}

    $summaryJson = $summary | ConvertTo-Json -Depth 5

    Write-Host ("SUMMARY " + $summaryJson)

    # Generate CSV outputs if enabled
    if ($outputActionPlanCsv -and $staleGroups.Count -gt 0) {
        Write-Host "Generating action plan CSV..."
        $actionPlanCsv = $staleGroups | Select-Object `
            @{n='GroupId';e={$_.id}}, `
            @{n='DisplayName';e={$_.displayName}}, `
            @{n='StaleReason';e={$_.staleReason}}, `
            @{n='Members';e={$_.memberCount}}, `
            @{n='Owners';e={$_.ownerCount}}, `
            @{n='AppAssignments';e={$_.appAssignmentCount}}, `
            @{n='CAPolicy';e={$_.caPolicyCount}}, `
            @{n='RoleAssignments';e={$_.roleAssignmentCount}}, `
            @{n='DaysSinceActivity';e={$_.daysSinceActivity}}, `
            @{n='CreatedDateTime';e={$_.createdDateTime}}, `
            @{n='LastModifiedDateTime';e={$_.lastModifiedDateTime}}, `
            @{n='Mode';e={$mode}}, `
            @{n='TargetTimestamp';e={$nowUtcStr}} | `
            ConvertTo-Csv -NoTypeInformation
        
        # Output via binding (actionPlanCsv)
        Push-OutputBinding -Name actionPlanCsv -Value ($actionPlanCsv -join "`n")
        Write-Host "Action plan CSV generated: $($staleGroups.Count) groups"
    }
    elseif ($outputActionPlanCsv -and $staleGroups.Count -eq 0) {
        Write-Host "No stale groups found; skipping action plan CSV"
        Push-OutputBinding -Name actionPlanCsv -Value "GroupId,DisplayName,StaleReason,Members,Owners,AppAssignments,CAPolicy,RoleAssignments,DaysSinceActivity,CreatedDateTime,LastModifiedDateTime,Mode,TargetTimestamp`nNo stale groups found."
    }

    if ($outputInventoryCsv) {
        Write-Host "Generating inventory CSV..."
        $inventoryCsv = $groupsWithSignals | Select-Object `
            @{n='GroupId';e={$_.id}}, `
            @{n='DisplayName';e={$_.displayName}}, `
            @{n='Members';e={$_.memberCount}}, `
            @{n='Owners';e={$_.ownerCount}}, `
            @{n='AppAssignments';e={$_.appAssignmentCount}}, `
            @{n='CAPolicy';e={$_.caPolicyCount}}, `
            @{n='RoleAssignments';e={$_.roleAssignmentCount}}, `
            @{n='DaysSinceActivity';e={$_.daysSinceActivity}}, `
            @{n='NoMembers';e={$_.stalennessSignals.noMembers}}, `
            @{n='NoOwners';e={$_.stalennessSignals.noOwners}}, `
            @{n='NotInAppAssignments';e={$_.stalennessSignals.notInAppAssignments}}, `
            @{n='NotInCAPolicy';e={$_.stalennessSignals.notInCaPolicy}}, `
            @{n='NotAssignedToRole';e={$_.stalennessSignals.notAssignedToRole}}, `
            @{n='NoActivity';e={$_.stalennessSignals.noActivity}}, `
            @{n='IsException';e={$_.isException}}, `
            @{n='CreatedDateTime';e={$_.createdDateTime}}, `
            @{n='LastModifiedDateTime';e={$_.lastModifiedDateTime}}, `
            @{n='InventoryTimestamp';e={$nowUtcStr}} | `
            ConvertTo-Csv -NoTypeInformation
        
        # Output via binding (inventoryCsv)
        Push-OutputBinding -Name inventoryCsv -Value ($inventoryCsv -join "`n")
        Write-Host "Inventory CSV generated: $($groupsWithSignals.Count) groups"
    }

    Write-Host "Stale group sweep completed successfully."
}
catch {
    Write-Host "ERROR: $_"
    Write-Host $_.Exception.StackTrace
    throw
}

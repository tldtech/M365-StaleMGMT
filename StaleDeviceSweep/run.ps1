<#
.SYNOPSIS
    Azure Function to identify and manage stale Entra ID devices.

.DESCRIPTION
    This Azure Function automatically identifies stale devices in Entra ID (Azure AD) based on their
    last sign-in date and performs actions according to the configured mode. It supports four modes:
    
    - report:  Simply generates a report of all devices with their staleness classification
    - detect:  Creates an action plan showing what would be done, but doesn't execute
    - disable: Disables stale devices (requires CONFIRM_DISABLE=true for safety)
    - tag:     Tags stale devices with metadata using open extensions (requires CONFIRM_TAG=true)
    
    The function uses the approximateLastSignInDateTime property from Microsoft Graph API to determine
    if a device hasn't been used within the configured threshold (default 90 days). For devices without
    sign-in data, it falls back to the createdDateTime.
    
    Classification logic:
    - Active:         Device has signed in recently (within threshold)
    - Stale:          Device has not signed in within the threshold period
    - Stale-NoSignIn: Device was created before threshold but has no sign-in data
    - Unknown:        Unable to determine staleness (conservative approach - no action taken)
    
    Safety features:
    - MAX_ACTIONS limits the number of actions per run to prevent accidental bulk operations
    - CONFIRM_DISABLE and CONFIRM_TAG flags must be explicitly set to true for those modes
    - Comprehensive logging and reporting with action plans before execution
    
    Authentication:
    - In Azure: Uses Managed Identity automatically
    - Local dev: Falls back to Azure CLI authentication (requires 'az login')
    
    Output:
    - Generates a JSON report written to blob storage via output binding
    - Report includes device inventory, classifications, action plans, and execution results

.PARAMETER Timer
    Timer trigger input from Azure Functions. This is provided automatically by the Azure Functions runtime.

.NOTES
    Version:        1.1 (Entra-only)
    Author:         TLDTech.io
    Purpose:        Automated stale device lifecycle management for Entra ID
    
.EXAMPLE
    # Run in report mode (default)
    MODE=report
    
.EXAMPLE
    # Run in detect mode to see what would be disabled
    MODE=detect STALE_DAYS=60
    
.EXAMPLE
    # Actually disable stale devices (requires confirmation)
    MODE=disable CONFIRM_DISABLE=true MAX_ACTIONS=100
#>

param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Config
# ---------------------------
# Load configuration from environment variables with sensible defaults
# These can be set in the Function App's Application Settings or local.settings.json

# Core staleness configuration
$staleDays = [int]($env:STALE_DAYS ?? 90) # Days of inactivity before a device is considered stale
$mode = ($env:MODE ?? 'report').ToLowerInvariant() # Operating mode: report | detect | disable | tag
$graphApiVersion = ($env:GRAPH_API_VERSION ?? 'v1.0') # Microsoft Graph API version to use

# V1.1 safety rails and tagging configuration
# These settings prevent accidental bulk operations and require explicit confirmation
$maxActions     = [int]($env:MAX_ACTIONS ?? 50) # Maximum number of devices to act on per execution (throttle)
$confirmDisable = (($env:CONFIRM_DISABLE ?? 'false').ToLowerInvariant() -eq 'true') # Must be explicitly set to 'true' to disable devices
$confirmTag     = (($env:CONFIRM_TAG ?? 'false').ToLowerInvariant() -eq 'true') # Must be explicitly set to 'true' to tag devices
$extensionName  = ($env:EXTENSION_NAME ?? 'com.staleDeviceSweep') # Open extension name for storing metadata on devices

# Calculate time boundaries for staleness evaluation
# All times are stored in UTC to avoid timezone issues
$nowUtc = (Get-Date).ToUniversalTime()
$cutoffUtc = $nowUtc.AddDays(-$staleDays)  # Devices active before this date are considered stale
$nowUtcStr = $nowUtc.ToString('o')          # ISO 8601 format for consistent reporting
$cutoffUtcStr = $cutoffUtc.ToString('o')

# Display configuration summary for visibility in function logs
Write-Host "=== Entra stale device sweep (v1.1: Entra-only) ==="
Write-Host "Now (UTC):     $nowUtcStr"
Write-Host "Cutoff (UTC):  $cutoffUtcStr"
Write-Host "Mode:          $mode"
Write-Host "Graph:         $graphApiVersion"
Write-Host "Max actions:   $maxActions"
Write-Host "Ext name:      $extensionName"

# ---------------------------
# Authentication Helpers
# ---------------------------
# These functions handle authentication to Microsoft Graph API using two methods:
# 1. Managed Identity (production in Azure)
# 2. Azure CLI (local development)

function Get-GraphTokenManagedIdentity {
    <#
    .SYNOPSIS
        Obtains an access token using Azure Managed Identity.
    .DESCRIPTION
        When running in Azure (Function App, VM, etc.), this uses the Managed Identity
        endpoint to securely get an access token without credentials. Returns null if
        not running in an Azure environment with Managed Identity enabled.
    #>
    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
        return $null  # Not running in Azure with Managed Identity
    }

    $resource = "https://graph.microsoft.com"
    $apiVersion = "2019-08-01"
    $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($resource))&api-version=$apiVersion"
    $headers = @{ "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER }

    $tokenResponse = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
    return $tokenResponse.access_token
}

function Get-GraphTokenAzCli {
    <#
    .SYNOPSIS
        Obtains an access token using Azure CLI credentials.
    .DESCRIPTION
        Fallback method for local development. Uses the currently logged-in Azure CLI
        account to get a token. Requires 'az login' to have been run first.
    #>
    # Check if Azure CLI is installed and available
    $az = Get-Command az -ErrorAction SilentlyContinue
    if (-not $az) {
        throw "Azure CLI not found. Install 'az' or run in Azure with Managed Identity."
    }

    $json = & az account get-access-token --resource-type ms-graph --output json 2>$null
    if (-not $json) { throw "Failed to get Graph token from Azure CLI. Run 'az login' first." }

    ($json | ConvertFrom-Json).accessToken
}

function Get-GraphAccessToken {
    <#
    .SYNOPSIS
        Intelligently obtains a Graph API access token using the best available method.
    .DESCRIPTION
        Tries Managed Identity first (production), then falls back to Azure CLI (dev).
        This allows the same code to work seamlessly in both Azure and local environments.
    #>
    $mi = Get-GraphTokenManagedIdentity
    if ($mi) { return $mi }  # Production path: use Managed Identity

    # Development path: fallback to Azure CLI
    Write-Host "Managed Identity not detected; using Azure CLI token (local dev)."
    return Get-GraphTokenAzCli
}

# ---------------------------
# Microsoft Graph API Helpers
# ---------------------------
# Wrapper functions for interacting with Microsoft Graph API
# These handle authentication, pagination, and error handling consistently

function Invoke-Graph {
    <#
    .SYNOPSIS
        Makes an authenticated request to Microsoft Graph API.
    .DESCRIPTION
        Low-level wrapper that handles authorization headers, JSON serialization,
        and provides consistent error handling for Graph API calls.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('GET','POST','PATCH')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken,
        [object] $Body = $null  # Optional request body for POST/PATCH operations
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    if ($null -ne $Body) { $headers['Content-Type'] = 'application/json' }

    try {
        if ($null -ne $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 8)
        } else {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        }
    }
    catch {
        $resp = $_.Exception.Response
        if ($resp -and $resp.StatusCode) {
            $code = [int]$resp.StatusCode
            throw "Graph $Method $Uri failed (HTTP $code): $($_.Exception.Message)"
        }
        throw
    }
}

function Invoke-GraphGetAll {
    <#
    .SYNOPSIS
        Retrieves all pages of results from a Microsoft Graph API query.
    .DESCRIPTION
        Automatically handles pagination by following @odata.nextLink until all results
        are retrieved. Essential for queries that return more than one page of data (>100 items).
    #>
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri

    # Follow pagination links until all results are retrieved
    while ($next) {
        $resp = Invoke-Graph -Method GET -Uri $next -AccessToken $AccessToken

        # Add items from this page to our collection
        if ($resp.value) {
            foreach ($v in $resp.value) { $items.Add($v) }
        }

        # Check if there's another page of results
        $next = if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') {
            $resp.'@odata.nextLink'
        } else {
            $null  # No more pages
        }
    }

    return $items
}

function Disable-EntraDevice {
    <#
    .SYNOPSIS
        Disables a device in Entra ID by setting accountEnabled to false.
    .DESCRIPTION
        Uses the Microsoft Graph API to disable a device, preventing it from authenticating
        to Entra ID and accessing resources. This is a reversible operation.
    #>
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $uri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId"
    # PATCH the device object to set accountEnabled = false
    Invoke-Graph -Method PATCH -Uri $uri -AccessToken $AccessToken -Body @{ accountEnabled = $false } | Out-Null
}

function Update-DeviceOpenExtension {
    <#
    .SYNOPSIS
        Updates or creates an open extension on a device to store custom metadata.
    .DESCRIPTION
        Open extensions allow storing custom data on Entra ID objects. This function
        tries to update an existing extension first, and if it doesn't exist, creates it.
        This is used to tag devices with staleness information for auditing and reporting.
    #>
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion,
        [Parameter(Mandatory)][string]$ExtensionName,
        [Parameter(Mandatory)][hashtable]$Properties  # Custom metadata to store
    )

    # Try PATCH first (update existing extension); create via POST if not found
    $patchUri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId/extensions/$ExtensionName"
    try {
        # Try to update existing extension
        Invoke-Graph -Method PATCH -Uri $patchUri -AccessToken $AccessToken -Body $Properties | Out-Null
        return "patched"  # Extension already existed and was updated
    } catch {
        # If extension doesn't exist (404), create it
        if ($_ -match 'HTTP 404') {
            $postUri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId/extensions"
            $body = @{
                "@odata.type"  = "microsoft.graph.openTypeExtension"
                extensionName  = $ExtensionName
            } + $Properties

            Invoke-Graph -Method POST -Uri $postUri -AccessToken $AccessToken -Body $body | Out-Null
            return "created"  # New extension was created
        }
        throw  # Unexpected error, propagate it
    }
}

# ---------------------------
# Staleness Evaluation Logic
# ---------------------------
# Functions to determine if a device is stale based on its activity

function ConvertTo-GraphDateUtc {
    <#
    .SYNOPSIS
        Safely converts Graph API date strings to UTC DateTime objects.
    .DESCRIPTION
        Graph API returns dates in ISO 8601 format. This helper parses them safely
        and normalizes to UTC. Returns null for empty/invalid dates.
    #>
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return ([datetime]::Parse($Value)).ToUniversalTime() } catch { return $null }
}

function Get-DeviceClassification {
    <#
    .SYNOPSIS
        Classifies a device as Active, Stale, Stale-NoSignIn, or Unknown.
    .DESCRIPTION
        Determines device staleness using approximateLastSignInDateTime when available,
        falling back to createdDateTime. Uses a conservative approach to avoid
        accidentally acting on devices we can't confidently classify.
        
        Classification rules:
        - Active: Has sign-in data and signed in after cutoff date
        - Stale: Has sign-in data but last sign-in before cutoff date
        - Stale-NoSignIn: No sign-in data, but created before cutoff date
        - Unknown: Cannot determine staleness (too new or missing data) - no action taken
    #>
    param(
        [Parameter(Mandatory)] $Device,
        [Parameter(Mandatory)] [datetime] $CutoffUtc
    )

    # Parse timestamps from the device object
    # Note: approximateLastSignInDateTime may be null in some tenants or for some device types
    $lastSignInUtc = ConvertTo-GraphDateUtc -Value $Device.approximateLastSignInDateTime
    $createdUtc    = ConvertTo-GraphDateUtc -Value $Device.createdDateTime

    # Primary classification: use sign-in data if available (most reliable)
    if ($lastSignInUtc) {
        if ($lastSignInUtc -lt $CutoffUtc) { return 'Stale' }      # Last activity before threshold
        return 'Active'                                             # Recent activity detected
    }

    # Fallback classification: if no sign-in data, use creation date
    if ($createdUtc -and $createdUtc -lt $CutoffUtc) {
        return 'Stale-NoSignIn'  # Old device with no recorded sign-in
    }

    # Conservative approach: if we can't determine staleness reliably, mark as Unknown
    # These devices will be reported but no actions will be taken on them
    return 'Unknown'
}

# ---------------------------
# Main Execution Flow
# ---------------------------
# 1. Authenticate to Graph API
# 2. Fetch all devices from Entra ID
# 3. Classify each device by staleness
# 4. Build action plan based on mode
# 5. Execute actions (if confirmed)
# 6. Generate comprehensive report

try {
    # Step 1: Get authentication token using best available method
    $token = Get-GraphAccessToken

    # Step 2: Fetch all devices from Entra ID
    # Keep $select tight to reduce payload size and minimize API throttling
    # NOTE: approximateLastSignInDateTime may be null for some devices/tenants
    $select = "id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,trustType,createdDateTime,approximateLastSignInDateTime"
    $uri = "https://graph.microsoft.com/$graphApiVersion/devices?`$select=$([uri]::EscapeDataString($select))&`$top=999"

    $devices = Invoke-GraphGetAll -Uri $uri -AccessToken $token
    Write-Host "Devices fetched: $($devices.Count)"

    # Step 3: Process each device and classify its staleness
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $devices) {
        # Determine if this device is Active, Stale, Stale-NoSignIn, or Unknown
        $classification = Get-DeviceClassification -Device $d -CutoffUtc $cutoffUtc

        # Parse device timestamps
        $lastSignInUtc = ConvertTo-GraphDateUtc -Value $d.approximateLastSignInDateTime
        $createdUtc = ConvertTo-GraphDateUtc -Value $d.createdDateTime

        # Calculate days since last activity for reporting purposes
        # Uses last sign-in if available, otherwise falls back to creation date
        $daysSinceLastActivity = if ($lastSignInUtc) {
            [int]($nowUtc - $lastSignInUtc).TotalDays
        } elseif ($createdUtc) {
            [int]($nowUtc - $createdUtc).TotalDays
        } else {
            $null  # No timestamps available
        }

        # Build enriched device record with original properties plus our analysis
        $results.Add([pscustomobject]@{
            id                            = $d.id
            displayName                   = $d.displayName
            deviceId                      = $d.deviceId
            accountEnabled                = $d.accountEnabled
            operatingSystem               = $d.operatingSystem
            operatingSystemVersion        = $d.operatingSystemVersion
            trustType                     = $d.trustType
            createdDateTime               = $d.createdDateTime
            approximateLastSignInDateTime = $d.approximateLastSignInDateTime
            lastSignInUtc                 = if ($lastSignInUtc) { $lastSignInUtc.ToString('o') } else { $null }
            classification                = $classification         # Our staleness assessment
            daysSinceLastActivity         = $daysSinceLastActivity  # Days since last seen
            staleThresholdDateUtc         = $cutoffUtcStr           # Cutoff date used
            staleDaysThreshold            = $staleDays              # Threshold configuration
        })
    }

    # Generate summary statistics by classification
    $counts = @($results | Group-Object classification | ForEach-Object {
        [pscustomobject]@{ classification = $_.Name; count = $_.Count }
    })

    # Build base report object (action metadata will be appended later)
    $report = [pscustomobject]@{
        version            = "v1.1-entra-only"
        generatedAtUtc     = $nowUtcStr
        staleDaysThreshold = $staleDays
        totalDevices       = $devices.Count
        summary            = $counts
        items              = $results
    }

    # ---------------------------
    # Step 4: Build Action Pipeline
    # ---------------------------
    # Determine which devices to act on based on mode and safety settings

    # Only act on confidently stale devices; ignore 'Unknown' and 'Active' classifications
    # This conservative approach prevents accidental actions on devices we can't assess
    $candidates = @($results | Where-Object { $_.classification -in @('Stale','Stale-NoSignIn') })

    # Build action plan, respecting MAX_ACTIONS limit to prevent bulk accidents
    $actionPlan = [System.Collections.Generic.List[object]]::new()
    $plannedCount = [Math]::Min($candidates.Count, $maxActions)  # Apply throttle
    for ($i = 0; $i -lt $plannedCount; $i++) {
        $c = $candidates[$i]
        $actionPlan.Add([pscustomobject]@{
            deviceObjectId = $c.id
            displayName    = $c.displayName
            classification = $c.classification
            daysSince      = $c.daysSinceLastActivity
            plannedAction  = $mode
        })
    }

    $actionSummary = [pscustomobject]@{
        modeRequested      = $mode
        candidateCount     = $candidates.Count
        plannedActionCount = $actionPlan.Count
        maxActions         = $maxActions
        willExecute        = $false
        confirmDisable     = $confirmDisable
        confirmTag         = $confirmTag
        extensionName      = $extensionName
    }

    # Step 5: Execute actions based on mode
    $actionsExecuted = [System.Collections.Generic.List[object]]::new()

    switch ($mode) {
        'report' {
            # Report mode: just generate the report, no actions
        }

        'detect' {
            # Detect mode: show what would be done, but don't execute
        }

        'disable' {
            # Disable mode: requires explicit confirmation flag for safety
            if (-not $confirmDisable) {
                Write-Warning "MODE=disable requested but CONFIRM_DISABLE=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true

            # Actually disable each device in the action plan
            foreach ($a in $actionPlan) {
                Disable-EntraDevice -DeviceObjectId $a.deviceObjectId -AccessToken $token -GraphApiVersion $graphApiVersion
                $actionsExecuted.Add([pscustomobject]@{
                    deviceObjectId = $a.deviceObjectId
                    action         = 'disable'
                    status         = 'ok'
                })
            }
        }

        'tag' {
            # Tag mode: adds metadata to devices via open extensions, requires confirmation
            if (-not $confirmTag) {
                Write-Warning "MODE=tag requested but CONFIRM_TAG=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true

            # Tag each device with staleness metadata for auditing
            foreach ($a in $actionPlan) {
                $props = @{
                    status             = "stale"
                    classification     = $a.classification
                    version            = "v1.1-entra-only"
                    evaluatedAtUtc     = $nowUtcStr
                    staleDaysThreshold = $staleDays
                    cutoffUtc          = $cutoffUtcStr
                }

                $result = Update-DeviceOpenExtension -DeviceObjectId $a.deviceObjectId -AccessToken $token -GraphApiVersion $graphApiVersion -ExtensionName $extensionName -Properties $props

                $actionsExecuted.Add([pscustomobject]@{
                    deviceObjectId = $a.deviceObjectId
                    action         = 'tag'
                    status         = $result
                })
            }
        }

        default {
            Write-Warning "Unknown MODE='$mode'. No actions executed."
        }
    }

    # Step 6: Finalize and output comprehensive report
    # Attach action metadata to the base report
    $report | Add-Member -NotePropertyName mode -NotePropertyValue $mode -Force
    $report | Add-Member -NotePropertyName actionSummary -NotePropertyValue $actionSummary -Force
    $report | Add-Member -NotePropertyName actionPlan -NotePropertyValue $actionPlan -Force
    $report | Add-Member -NotePropertyName actionsExecuted -NotePropertyValue $actionsExecuted -Force

    # Serialize report to JSON and write to blob storage via Function App output binding
    # This provides a persistent audit trail of all device evaluations and actions
    $json = $report | ConvertTo-Json -Depth 8
    Push-OutputBinding -Name reportBlob -Value $json

    Write-Host "Report written to blob output binding."
}
catch {
    Write-Error $_
    throw
}
# Entra ID Stale Resource Management - Azure Functions

Azure Functions for identifying and managing stale devices and user accounts in Microsoft Entra ID with optional Intune integration for intelligent device lifecycle management.

## Overview

This solution provides three complementary functions:

- **StaleDeviceSweep**: Manages device lifecycle with optional Intune integration for intelligent decision-making
- **StaleUserSweep**: Manages user account lifecycle based on sign-in activity
- **StaleGroupSweep**: Manages Entra ID group lifecycle based on member activity and usage signals

All functions run on timer schedules to scan resources in your Entra ID tenant, classify them based on activity, and optionally take automated actions with built-in safety controls.

## Features

### StaleDeviceSweep

- **Automated Device Classification**: Categorizes devices as Active, Stale, Stale-NoSignIn, or Unknown
- **Intune Integration**: Optional enrichment with Intune managed device data for smarter decisions
- **Multiple Operation Modes**: detect, disable, tag, decide, execute
- **Intelligent Decision Rules**: Prevent false positives with configurable safety checks
- **Flexible Activity Sources**: Use Entra sign-in, Intune sync, or most recent timestamp
- **Action Execution**: Disable, tag, retire, wipe, or delete devices
- **Safety Controls**: Per-action confirmation flags and throttle limits
- **Dual Authentication**: Supports both Managed Identity (production) and Azure CLI (local development)
- **Comprehensive Reporting**: JSON reports and human-readable summaries to Azure Blob Storage
- **Azure Monitor Workbook**: Pre-built workbook for visualizing run history, trends, and metrics

### StaleUserSweep

- **User Account Classification**: Categorizes member and guest users with activity-based staleness detection
  - Member accounts: Active, Stale, Stale-NoSignIn, Unknown
  - Guest accounts: Guest-PendingActive, Guest-PendingStale, Guest-AcceptedActive, Guest-AcceptedStale, Guest-AcceptedNoActivity
- **Sign-In Activity Tracking**: Uses Entra ID sign-in activity data (requires AuditLog.Read.All)
- **Guest Lifecycle Awareness**: Differentiates pending vs. accepted guest invitations for appropriate lifecycle management
- **Operation Modes**: detect, disable, tag
- **Exception Handling**: Protect specific users via groups, UPN patterns, or explicit IDs
- **Action Execution**: Disable accounts or tag with metadata
- **Safety Controls**: Confirmation flags and throttle limits
- **Comprehensive Reporting**: JSON reports and human-readable summaries to Azure Blob Storage

### StaleGroupSweep

- **Group Staleness Detection**: Multi-signal analysis to identify unused groups:
  - Activity tracking (last modification/member changes)
  - Membership analysis (no members or no owners)
  - Usage signals (app assignments, conditional access policies, role assignments)
- **Multi-Signal Scoring**: Groups classified as stale based on combined signals
- **Operation Modes**: detect, delete, tag, archive
- **Teams Integration**: Archive Microsoft 365 teams groups
- **Exception Handling**: Protect specific groups via ID patterns or display name wildcards
- **Action Execution**: Delete, tag with metadata, or archive Teams groups
- **Safety Controls**: Confirmation flags and per-action throttle limits
- **Comprehensive Reporting**: JSON reports and human-readable summaries to Azure Blob Storage

## Version History

### StaleDeviceSweep
- **v2.0**: Intune-aware decision rules + optional Intune actions + correlation improvements
- **v1.0**: Basic Entra-only reporting and simple disable/tag actions

### StaleUserSweep
- **v1.0**: User account staleness detection and management

### StaleGroupSweep
- **v1.0**: Group staleness detection with multi-signal analysis

## Operation Modes

### StaleDeviceSweep

#### Basic Modes
- **detect**: Preview which stale devices would be acted on (dry-run)
- **disable**: Disable stale devices in Entra ID (requires `CONFIRM_DISABLE=true`)
- **tag**: Tag stale devices using open extensions (requires `CONFIRM_TAG=true`)

#### Advanced Modes
- **decide**: Build an Intune-aware action plan without execution (preview with intelligence)
- **execute**: Execute the Intune-aware action plan with per-action confirmations

### StaleUserSweep

- **detect**: Preview which stale user accounts would be acted on (dry-run)
- **disable**: Disable stale user accounts in Entra ID (requires `CONFIRM_DISABLE=true`)
- **tag**: Tag stale user accounts using open extensions (requires `CONFIRM_TAG=true`)

### StaleGroupSweep

- **detect**: Preview which stale groups would be acted on (dry-run)
- **delete**: Delete stale groups in Entra ID (requires `CONFIRM_DELETE=true`)
- **tag**: Tag stale groups using open extensions (requires `CONFIRM_TAG=true`)
- **archive**: Archive stale Teams groups (requires `CONFIRM_ARCHIVE=true`)

## Configuration

### StaleDeviceSweep Configuration

### Core Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STALE_DAYS` | `90` | Number of days of inactivity before a device is considered stale |
| `MODE` | `detect` | Operation mode: `detect`, `disable`, `tag`, `decide`, `execute` |
| `GRAPH_API_VERSION` | `v1.0` | Microsoft Graph API version to use |
| `MAX_ACTIONS` | `50` | Maximum total actions to perform in a single run |

### Intune Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `INCLUDE_INTUNE` | `false` | Enable Intune managed device data enrichment |
| `ACTIVITY_SOURCE` | `signin` | Activity timestamp source: `signin`, `intune`, `mostRecent` |
| `INTUNE_STALE_DAYS` | `90` | Intune staleness threshold (defaults to `STALE_DAYS`) |

### Decision Rules (MODE=decide/execute)

| Variable | Default | Description |
|----------|---------|-------------|
| `REQUIRE_BOTH_STALE_FOR_DISABLE` | `true` | Require both Entra AND Intune stale before disabling |
| `DONT_DISABLE_IF_INTUNE_RECENT_SYNC` | `true` | Skip devices that recently synced with Intune |
| `INTUNE_RECENT_SYNC_DAYS` | `14` | Days to consider "recent" sync |
| `DONT_DISABLE_IF_COMPLIANT` | `true` | Skip compliant devices |
| `ONLY_DISABLE_IF_MANAGEDAGENT_IN` | `mdm,easmdm` | Only disable if management agent matches (empty = no filter) |
| `ALLOW_DISABLE_ON_DUPLICATE` | `false` | Allow disable when multiple Intune matches exist |

### Action Confirmations

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIRM_DISABLE` | `false` | Enable Entra device disabling |
| `CONFIRM_TAG` | `false` | Enable open extension tagging |
| `CONFIRM_INTUNE_RETIRE` | `false` | Enable Intune retire action |
| `CONFIRM_INTUNE_WIPE` | `false` | Enable Intune wipe action (⚠️ destructive) |
| `CONFIRM_INTUNE_DELETE` | `false` | Enable Intune delete action (⚠️ destructive) |

### Action Throttles

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_DISABLE` | `50` | Maximum Entra devices to disable |
| `MAX_TAG` | `50` | Maximum devices to tag |
| `MAX_RETIRE` | `25` | Maximum Intune retires |
| `MAX_WIPE` | `5` | Maximum Intune wipes |
| `MAX_INTUNE_DELETE` | `25` | Maximum Intune deletes |

### Other Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTENSION_NAME` | `STALE` | Open extension name for tagging |
| `OUTPUT_ACTION_PLAN_CSV` | `false` | Generate action plan CSV output to blob storage |
| `OUTPUT_INVENTORY_CSV` | `false` | Generate full device inventory CSV output to blob storage |

### Exception Lists (Devices)

Protect specific devices from any automated actions:

| Variable | Description | Example |
|----------|-------------|---------|
| `EXCEPTION_GROUP_ID` | Entra group ID containing protected devices | `12345678-1234-1234-1234-123456789abc` |
| `EXCEPTION_NAME_PATTERNS` | Comma-separated device name wildcards | `VIP-*,Executive-*,CEO-*` |
| `EXCEPTION_DEVICE_IDS` | Comma-separated device object IDs | `guid1,guid2,guid3` |

---

### StaleUserSweep Configuration

#### Core Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STALE_DAYS` | `180` | Number of days of inactivity before a user is considered stale |
| `MODE` | `detect` | Operation mode: `detect`, `disable`, `tag` |
| `GRAPH_API_VERSION` | `v1.0` | Microsoft Graph API version to use |
| `MAX_ACTIONS` | `25` | Maximum total actions to perform in a single run |

#### Action Confirmations

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIRM_DISABLE` | `false` | Enable user account disabling |
| `CONFIRM_TAG` | `false` | Enable open extension tagging |

#### Action Throttles

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_DISABLE` | `25` | Maximum user accounts to disable |
| `MAX_TAG` | `25` | Maximum users to tag |

#### Other Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTENSION_NAME` | `STALE` | Open extension name for tagging |
| `OUTPUT_ACTION_PLAN_CSV` | `false` | Generate action plan CSV output to blob storage |
| `OUTPUT_INVENTORY_CSV` | `false` | Generate full user inventory CSV output to blob storage |
| `ACTION_PARALLELISM` | `5` | Number of parallel actions (tune based on environment size) |

### Exception Lists (Users)

Protect specific users from any automated actions:

| Variable | Description | Example |
|----------|-------------|---------|
| `EXCEPTION_GROUP_ID` | Entra group ID containing protected users | `12345678-1234-1234-1234-123456789abc` |
| `EXCEPTION_UPN_PATTERNS` | Comma-separated UPN wildcards | `admin@*,*@external.com,svc-*@*` |
| `EXCEPTION_USER_IDS` | Comma-separated user object IDs | `guid1,guid2,guid3` |

---
### StaleGroupSweep Configuration

#### Core Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STALE_DAYS` | `180` | Number of days of inactivity before a group is considered stale |
| `MODE` | `detect` | Operation mode: `detect`, `delete`, `tag`, `archive` |
| `GRAPH_API_VERSION` | `v1.0` | Microsoft Graph API version to use |
| `MAX_ACTIONS` | `10` | Maximum total actions to perform in a single run |

#### Action Confirmations

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIRM_DELETE` | `false` | Enable group deletion |
| `CONFIRM_TAG` | `false` | Enable open extension tagging |
| `CONFIRM_ARCHIVE` | `false` | Enable Teams group archiving |

#### Action Throttles

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_DELETE` | `10` | Maximum groups to delete |
| `MAX_TAG` | `25` | Maximum groups to tag |
| `MAX_ARCHIVE` | `10` | Maximum Teams groups to archive |

#### Other Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTENSION_NAME` | `STALE` | Open extension name for tagging |
| `OUTPUT_ACTION_PLAN_CSV` | `false` | Generate action plan CSV output to blob storage |
| `OUTPUT_INVENTORY_CSV` | `false` | Generate full group inventory CSV output to blob storage |
| `ACTION_PARALLELISM` | `5` | Number of parallel actions (tune based on environment size) |

#### Exception Lists (Groups)

Protect specific groups from any automated actions:

| Variable | Description | Example |
|----------|-------------|----------|
| `EXCEPTION_GROUP_IDS` | Comma-separated group object IDs | `guid1,guid2,guid3` |
| `EXCEPTION_NAME_PATTERNS` | Comma-separated group name wildcards | `admin-*,exec-*,security-*` |

---
### Schedule

Functions are triggered by timers using [cron expressions](https://en.wikipedia.org/wiki/Cron#CRON_expression) defined in their `function.json`:

- **StaleDeviceSweep**: `0 0 0 * * *` (daily at 12:00 AM UTC)
- **StaleUserSweep**: `0 0 2 * * *` (daily at 2:00 AM UTC)
- Format: `{second} {minute} {hour} {day} {month} {day-of-week}`

### Required Permissions

The Managed Identity or service principal needs Microsoft Graph API permissions specific to each function.

#### StaleDeviceSweep Permissions

Choose the appropriate permission bundle based on your deployment needs:

**1. Entra Read Only** (Minimal - Reporting Only)
- `Device.Read.All` - Read Entra ID device information
- **Use case**: Detection/reporting mode only (`MODE=detect`)

**2. Entra Read + Write** (Basic Actions)
- `Device.ReadWrite.All` - Read/Disable devices and tag with open extensions
- **Use case**: Disable/tag modes without Intune integration (`MODE=disable`, `MODE=tag`)

**3. Entra + Intune Read** (Intune-Aware Decisions)
- `Device.Read.All` - Read Entra ID device information
- `DeviceManagementManagedDevices.Read.All` - Read Intune managed device data
- **Use case**: Intune-aware decision planning (`MODE=decide` with `INCLUDE_INTUNE=true`)

**4. Entra + Intune Full Access** (Complete Automation)
- `Device.ReadWrite.All` - Read/Disable devices and tag with open extensions
- `DeviceManagementManagedDevices.ReadWrite.All` - Read, Retire, wipe, and delete Intune devices
- **Use case**: Full automation with all actions (`MODE=execute` with all Intune actions enabled)

**5. Exception Lists** (Optional - Add to any bundle)
- `GroupMember.Read.All` - Required if using `EXCEPTION_GROUP_ID`

#### StaleUserSweep Permissions

**1. User Read Only** (Minimal - Reporting Only)
- `User.Read.All` - Read Entra ID user information
- `AuditLog.Read.All` - Read sign-in activity data
- `GroupMember.Read.All` - Read group membership for exceptions
- **Use case**: Detection/reporting mode only (`MODE=detect')

**3. User Read + Write** (Full Actions)
- `User.Read.All` - Read Entra ID user information
- `AuditLog.Read.All` - Read sign-in activity data
- `User.ReadWrite.All` - Disable user accounts
- `Directory.ReadWrite.All` - Tag users with open extensions
- `GroupMember.Read.All` - Read group membership for exceptions
- **Use case**: Disable/tag modes without exception groups

> **Note:** To use `AuditLog.Read.All` (required for sign-in activity reporting in StaleUserSweep), your tenant must have Microsoft Entra ID P1 or P2 licenses assigned. This is a Microsoft Graph API requirement. See the [official documentation](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0#example-11-get-users-including-their-last-sign-in-time) for details.

#### Granting Permissions

Use the included `Grant-Permissions.ps1` script to interactively grant application-type permissions for both device and user management:

```powershell
# Grant device sweep permissions (default)
.\Grant-Permissions.ps1 -ServicePrincipalObjectId "your-object-id-here"

# Grant user sweep permissions
.\Grant-Permissions.ps1  -ServicePrincipalObjectId "your-object-id-here" -ResourceType User

# Show all available bundles (device + user)
.\Grant-Permissions.ps1  -ServicePrincipalObjectId "your-object-id-here" -ResourceType Both
```

The script provides interactive bundle selection with descriptions and recommended use cases for each permission set.

## User Classification Scheme

### StaleUserSweep User Categories

StaleUserSweep classifies users into distinct categories based on account type (member vs. guest), activity status, and lifecycle state:

#### Member Accounts

| Classification | Condition | Action Eligible | Notes |
|---|---|---|---|
| **Active** | Most recent activity within cutoff period | ❌ No | User has signed in recently |
| **Stale** | Most recent sign-in before cutoff period | ✅ Yes | User has not signed in recently; targeted for disable/tag |
| **Stale-NoSignIn** | No sign-in data AND createdDateTime before cutoff | ✅ Yes | Never signed in AND account is older than threshold |
| **Unknown** | No sign-in data AND created within or after cutoff | ❌ No | Insufficient data; not acted upon |

#### Guest Accounts

Guest account classification includes awareness of the guest invitation lifecycle (pending vs. accepted):

| Classification | Condition | Action Eligible | Notes |
|---|---|---|---|
| **Guest-PendingActive** | PendingAcceptance state AND created within cutoff | ❌ No | Pending invite is recent; no action needed |
| **Guest-PendingStale** | PendingAcceptance state AND createdDateTime before cutoff | ❌ No | Pending invite is old; use **guest lifecycle controls** in Entra (invitation expiry, auto-delete) instead of disable |
| **Guest-AcceptedActive** | Accepted state AND most recent sign-in within cutoff | ❌ No | Guest has signed in recently; no action needed |
| **Guest-AcceptedStale** | Accepted state AND most recent sign-in before cutoff | ❌ No | Guest has not signed in recently; requires **manual review** or access reviews |
| **Guest-AcceptedNoActivity** | Accepted state AND no sign-in data available | ❌ No | Guest status unknown; **requires manual review or access review process** |

**Guest Handling Strategy:**
- **Pending guests older than threshold** are excluded from automated disable actions because guest lifecycle management should be handled through Entra's native guest expiration controls
- **Accepted guests with no activity data** are excluded because guest removal decisions require manual review or automated access review processes
- Reporting includes guest classifications in the summary and inventory for manual triage and access review workflows

---

## Example Configurations

### StaleDeviceSweep Examples

```bash
# Preview stale devices (detect mode)
MODE=detect
STALE_DAYS=90

# Execute with all protections enabled
MODE=execute
INCLUDE_INTUNE=true
CONFIRM_DISABLE=true
CONFIRM_TAG=true
REQUIRE_BOTH_STALE_FOR_DISABLE=true
DONT_DISABLE_IF_INTUNE_RECENT_SYNC=true
DONT_DISABLE_IF_COMPLIANT=true
MAX_ACTIONS=50

# Aggressive cleanup with Intune retire
MODE=execute
INCLUDE_INTUNE=true
CONFIRM_INTUNE_RETIRE=true
MAX_RETIRE=25

# Use Intune lastSyncDateTime as activity source
MODE=decide
INCLUDE_INTUNE=true
ACTIVITY_SOURCE=intune
INTUNE_STALE_DAYS=60

# Protect specific devices from actions
EXCEPTION_GROUP_ID=12345678-1234-1234-1234-123456789abc
EXCEPTION_NAME_PATTERNS=VIP-*,Executive-*
EXCEPTION_DEVICE_IDS=guid1,guid2
```

### StaleUserSweep Examples

```bash
# Preview stale users (detect mode)
MODE=detect
STALE_DAYS=180

# Disable stale user accounts with protections
MODE=disable
CONFIRM_DISABLE=true
STALE_DAYS=180
MAX_ACTIONS=10

# Tag stale users for audit
MODE=tag
CONFIRM_TAG=true
EXTENSION_NAME=STALE_USER

# Protect admin and service accounts
EXCEPTION_UPN_PATTERNS=admin@*,svc-*@*,*-svc@*
EXCEPTION_GROUP_ID=87654321-4321-4321-4321-987654321abc

# Generate CSV reports
OUTPUT_ACTION_PLAN_CSV=true
OUTPUT_INVENTORY_CSV=true
```


## Monitoring

### Azure Monitor Workbook

A pre-built Azure Monitor Workbook is included for visualizing function execution and device management trends:

**Location**: `Workbooks/M365-StaleSweep.json`

**Features**:
- Recent function runs with configuration and results
- Device classification trends over time
- Device distribution pie chart (latest run)
- Actions executed over time
- Errors and warnings tracking
- Performance metrics (success rate, duration)

**Setup**:
1. Open Azure Monitor in the Azure Portal
2. Navigate to **Workbooks** > **+ New**
3. Click the **Advanced Editor** button (code icon)
4. Paste the contents of `M365-StaleSweep.json`
5. Click **Apply** and save the workbook
6. Select your Log Analytics workspace from the dropdown

The workbook queries Application Insights logs and correlates CFG (configuration) and RESULT (execution summary) structured logs with function execution data.

#### Deployment

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Ftldtech%2FM365-StaleMGMT%2Frefs%2Fheads%2Fmain%2FDeployment%2Fazuredeploy.json)
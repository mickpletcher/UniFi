<#
.SYNOPSIS
    Reporting and export helpers for UniFi audits.

.DESCRIPTION
    Handles export of raw data and findings to JSON and CSV,
    and provides a simple console summary helper.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-UnifiCollectionCount {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) {
        return 0
    }

    if ($Value -is [string]) {
        return 1
    }

    if ($Value -is [System.Collections.ICollection]) {
        return $Value.Count
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        return @($Value).Count
    }

    return 1
}

function Test-UnifiSensitivePropertyName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $patterns = @(
        "password",
        "passphrase",
        "secret",
        "private_key",
        "privatekey",
        "token",
        "api_key",
        "apikey",
        "x_auth",
        "auth_key",
        "radius_secret",
        "pre_shared",
        "psk"
    )

    $normalized = $Name.Trim().ToLowerInvariant()
    foreach ($pattern in $patterns) {
        if ($normalized.Contains($pattern)) {
            return $true
        }
    }

    return $false
}

function Protect-UnifiObject {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [ValueType]) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $output = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $name = [string]$key
            if (Test-UnifiSensitivePropertyName -Name $name) {
                $output[$name] = "REDACTED"
            }
            else {
                $output[$name] = Protect-UnifiObject -Value $Value[$key]
            }
        }

        return [pscustomobject]$output
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) {
            $items.Add((Protect-UnifiObject -Value $item))
        }

        return @($items)
    }

    if ($Value.PSObject -and $Value.PSObject.Properties) {
        $output = [ordered]@{}
        foreach ($prop in $Value.PSObject.Properties) {
            if (Test-UnifiSensitivePropertyName -Name $prop.Name) {
                $output[$prop.Name] = "REDACTED"
            }
            else {
                $output[$prop.Name] = Protect-UnifiObject -Value $prop.Value
            }
        }

        return [pscustomobject]$output
    }

    return $Value
}

function Write-UnifiSummary {
    <#
    .SYNOPSIS
        Writes a simple inventory summary to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Inventory
    )

    Write-Host ("Networks       : {0}" -f (Get-UnifiCollectionCount -Value $Inventory.Networks)) -ForegroundColor Green
    Write-Host ("WLANs          : {0}" -f (Get-UnifiCollectionCount -Value $Inventory.Wlans)) -ForegroundColor Green
    Write-Host ("Devices        : {0}" -f (Get-UnifiCollectionCount -Value $Inventory.Devices)) -ForegroundColor Green
    Write-Host ("Clients        : {0}" -f (Get-UnifiCollectionCount -Value $Inventory.Clients)) -ForegroundColor Green
    Write-Host ("FirewallGroups : {0}" -f (Get-UnifiCollectionCount -Value $Inventory.FirewallGroups)) -ForegroundColor Green
    Write-Host ("FirewallRules  : {0}" -f (Get-UnifiCollectionCount -Value $Inventory.FirewallRules)) -ForegroundColor Green
}

function Export-UnifiAuditData {
    <#
    .SYNOPSIS
        Exports UniFi datasets and findings to timestamped files.

    .DESCRIPTION
        Each dataset is written to JSON.
        Enumerable datasets are also exported to CSV where possible.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Data
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    foreach ($key in @($Data.Keys | Sort-Object)) {
        $value = $Data[$key]

        $jsonPath = Join-Path $OutputPath "${key}_${timestamp}.json"
        $value | ConvertTo-Json -Depth 25 | Out-File -FilePath $jsonPath -Encoding utf8

        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            $rows = @($value)

            if ($rows.Count -eq 0) {
                Write-Verbose "CSV export skipped for dataset: $key (no rows)"
                continue
            }

            try {
                $csvPath = Join-Path $OutputPath "${key}_${timestamp}.csv"
                $rows | Export-Csv -NoTypeInformation -Encoding utf8 -Path $csvPath
            }
            catch {
                Write-Verbose "CSV export skipped for dataset: $key"
            }
        }
    }
}

function Get-UnifiReportBundle {
    <#
    .SYNOPSIS
        Combines inventory and findings into a single exportable hashtable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Sites,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Inventory,

        [Parameter(Mandatory = $true)]
        [array]$Findings
    )

    @{
        Sites          = $Sites
        Networks       = $Inventory.Networks
        Wlans          = $Inventory.Wlans
        Devices        = $Inventory.Devices
        Clients        = $Inventory.Clients
        FirewallGroups = $Inventory.FirewallGroups
        FirewallRules  = $Inventory.FirewallRules
        Findings       = $Findings
    }
}

function Export-UnifiSecurityAssessmentPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Snapshot,

        [Parameter(Mandatory = $true)]
        [array]$Findings,

        [Parameter()]
        [switch]$RedactSensitiveData
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jsonPath = Join-Path $OutputPath "SecurityAssessmentSnapshot_${timestamp}.json"
    $promptPath = Join-Path $OutputPath "SecurityAssessmentPrompt_${timestamp}.txt"

    $snapshotToExport = if ($RedactSensitiveData) {
        Protect-UnifiObject -Value $Snapshot
    }
    else {
        $Snapshot
    }

    $snapshotToExport | ConvertTo-Json -Depth 40 | Out-File -FilePath $jsonPath -Encoding utf8

    $datasetSummary = @()
    if ($Snapshot -and $Snapshot.Data) {
        foreach ($prop in $Snapshot.Data.PSObject.Properties) {
            $count = Get-UnifiCollectionCount -Value $prop.Value
            $datasetSummary += ("{0}: {1}" -f $prop.Name, $count)
        }
    }

    $promptText = @"
You are a network security assessor. Analyze the attached UniFi settings snapshot and provide a prioritized security assessment.

Deliverables:
1. Executive summary with top risks.
2. High severity findings with exact setting names and values.
3. Medium severity findings.
4. Misconfiguration list grouped by area such as WLAN, firewall, network, routing, and device management.
5. Recommended remediations with exact changes to apply in UniFi.
6. Safe change order for production rollout.

Context:
Controller: $($Snapshot.ControllerUrl)
Site: $($Snapshot.Site)
Snapshot generated: $($Snapshot.GeneratedAt)
Local findings count: $(@($Findings).Count)
Sensitive field redaction: $RedactSensitiveData

Datasets included:
$($datasetSummary -join [Environment]::NewLine)

Output format required:
1. Risk table with severity, issue, impact, and fix.
2. Detailed remediation checklist.
3. Validation steps after changes.
"@

    $promptText | Out-File -FilePath $promptPath -Encoding utf8

    return [pscustomobject]@{
        SnapshotJson = $jsonPath
        PromptFile   = $promptPath
    }
}

Export-ModuleMember -Function `
    Write-UnifiSummary, `
    Export-UnifiAuditData, `
    Get-UnifiReportBundle, `
    Export-UnifiSecurityAssessmentPackage

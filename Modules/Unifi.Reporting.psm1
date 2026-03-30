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

Export-ModuleMember -Function `
    Write-UnifiSummary, `
    Export-UnifiAuditData, `
    Get-UnifiReportBundle

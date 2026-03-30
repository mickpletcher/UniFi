<#
.SYNOPSIS
    Audit and policy test functions for UniFi inventory data.

.DESCRIPTION
    Contains read-only validation logic used to detect drift,
    missing SSIDs, and suspicious DNS configuration.

.NOTES
    This module does not make configuration changes.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-UnifiNormalizedString {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    return $text.Trim()
}

function New-UnifiFinding {
    <#
    .SYNOPSIS
        Creates a standard finding object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Object,
        [Parameter(Mandatory = $true)][string]$Finding,
        [Parameter()][string]$Details = ""
    )

    [pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Object   = $Object
        Finding  = $Finding
        Details  = $Details
    }
}

function Test-UnifiExpectedDns {
    <#
    .SYNOPSIS
        Verifies the expected DNS server appears in network settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Networks,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedDnsServer
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $expectedDns = Get-UnifiNormalizedString -Value $ExpectedDnsServer

    if (-not $expectedDns) {
        return $findings
    }

    $dnsPropertyNames = @(
        "dns1", "dns2",
        "dns_server_1", "dns_server_2",
        "wan_dns1", "wan_dns2",
        "dhcpd_dns_1", "dhcpd_dns_2"
    )

    foreach ($network in $Networks) {
        $dnsCandidates = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($propertyName in $dnsPropertyNames) {
            if ($network.PSObject.Properties.Name -contains $propertyName) {
                $value = Get-UnifiNormalizedString -Value $network.$propertyName
                if ($value) {
                    $null = $dnsCandidates.Add($value)
                }
            }
        }

        if ($dnsCandidates.Count -eq 0) {
            continue
        }

        if (-not $dnsCandidates.Contains($expectedDns)) {
            $findings.Add(
                (New-UnifiFinding `
                    -Severity "Warning" `
                    -Category "DNS" `
                    -Object ($network.name ?? "UnknownNetwork") `
                    -Finding "Expected DNS server not found" `
                    -Details "Expected: $expectedDns | Actual: $(([string[]]$dnsCandidates) -join ', ')")
            )
        }
    }

    return $findings
}

function Test-UnifiExpectedSsids {
    <#
    .SYNOPSIS
        Verifies that expected SSIDs exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Wlans,

        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedSsids
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $actualSsids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($wlan in $Wlans) {
        $ssidName = Get-UnifiNormalizedString -Value $wlan.name
        if ($ssidName) {
            $null = $actualSsids.Add($ssidName)
        }
    }

    foreach ($ssid in $ExpectedSsids) {
        $expectedSsid = Get-UnifiNormalizedString -Value $ssid
        if (-not $expectedSsid) {
            continue
        }

        if (-not $actualSsids.Contains($expectedSsid)) {
            $findings.Add(
                (New-UnifiFinding `
                    -Severity "Warning" `
                    -Category "SSID" `
                    -Object $expectedSsid `
                    -Finding "Expected SSID missing")
            )
        }
    }

    return $findings
}

function Test-UnifiOpenGuestNetwork {
    <#
    .SYNOPSIS
        Looks for potentially open or weak WLAN security.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Wlans
    )

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($wlan in $Wlans) {
        $name = Get-UnifiNormalizedString -Value $wlan.name
        if (-not $name) {
            $name = "UnknownSSID"
        }

        $security = Get-UnifiNormalizedString -Value $wlan.security

        if ($security -and $security.Equals("open", [System.StringComparison]::OrdinalIgnoreCase)) {
            $findings.Add(
                (New-UnifiFinding `
                    -Severity "Warning" `
                    -Category "Security" `
                    -Object $name `
                    -Finding "Open WLAN detected" `
                    -Details "SSID appears to have open security.")
            )
        }
    }

    return $findings
}

function Test-UnifiInventory {
    <#
    .SYNOPSIS
        Runs the configured test suite against UniFi inventory data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Inventory,

        [Parameter()]
        [string]$ExpectedDnsServer,

        [Parameter()]
        [string[]]$ExpectedSsids = @()
    )

    $results = New-Object System.Collections.Generic.List[object]

    $networks = @($Inventory.Networks)
    $wlans = @($Inventory.Wlans)

    if (-not [string]::IsNullOrWhiteSpace($ExpectedDnsServer)) {
        foreach ($item in (Test-UnifiExpectedDns -Networks $networks -ExpectedDnsServer $ExpectedDnsServer)) {
            $results.Add($item)
        }
    }

    if ($ExpectedSsids.Count -gt 0) {
        foreach ($item in (Test-UnifiExpectedSsids -Wlans $wlans -ExpectedSsids $ExpectedSsids)) {
            $results.Add($item)
        }
    }

    foreach ($item in (Test-UnifiOpenGuestNetwork -Wlans $wlans)) {
        $results.Add($item)
    }

    return $results
}

Export-ModuleMember -Function `
    New-UnifiFinding, `
    Test-UnifiExpectedDns, `
    Test-UnifiExpectedSsids, `
    Test-UnifiOpenGuestNetwork, `
    Test-UnifiInventory

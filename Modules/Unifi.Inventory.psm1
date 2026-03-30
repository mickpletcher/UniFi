<#
.SYNOPSIS
    Inventory and retrieval functions for UniFi objects.

.DESCRIPTION
    Provides helper functions to query sites, networks, WLANs, devices,
    clients, and firewall objects from UniFi.

.NOTES
    Read-only inventory module.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-UnifiApiData {
    <#
    .SYNOPSIS
        Tries multiple UniFi API paths and returns the first successful result.

    .PARAMETER ControllerUrl
        Base controller URL.

    .PARAMETER Site
        UniFi site name.

    .PARAMETER Paths
        Array of path templates, optionally containing {site}.

    .PARAMETER WebSession
        Authenticated session.

    .PARAMETER SkipCertificateCheck
        Skips TLS validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControllerUrl,

        [Parameter(Mandatory = $true)]
        [string]$Site,

        [Parameter(Mandatory = $true)]
        [string[]]$Paths,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    $baseUrl = $ControllerUrl.TrimEnd("/")

    foreach ($path in $Paths) {
        $resolvedPath = $path -replace "\{site\}", [uri]::EscapeDataString($Site)
        $uri = "$baseUrl$resolvedPath"

        try {
            $result = Invoke-UnifiRequest `
                -WebSession $WebSession `
                -Method GET `
                -Uri $uri `
                -SkipCertificateCheck:$SkipCertificateCheck

            if ($null -eq $result) {
                continue
            }

            if ($result.data) {
                return @($result.data)
            }

            if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
                return @($result)
            }

            return @($result)
        }
        catch {
            Write-Verbose "Endpoint failed: $uri"
            continue
        }
    }

    return @()
}

function Get-UnifiSites {
    <#
    .SYNOPSIS
        Gets UniFi sites.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControllerUrl,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    $baseUrl = $ControllerUrl.TrimEnd("/")
    $candidateUris = @(
        "$baseUrl/proxy/network/integration/v1/sites",
        "$baseUrl/api/self/sites"
    )

    foreach ($uri in $candidateUris) {
        try {
            $result = Invoke-UnifiRequest `
                -WebSession $WebSession `
                -Method GET `
                -Uri $uri `
                -SkipCertificateCheck:$SkipCertificateCheck

            if ($result.data) {
                return @($result.data)
            }

            if ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
                return @($result)
            }

            if ($null -ne $result) {
                return @($result)
            }
        }
        catch {
            continue
        }
    }

    return @()
}

function Get-UnifiNetworks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ControllerUrl,
        [Parameter(Mandatory = $true)][string]$Site,
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter()][switch]$SkipCertificateCheck
    )

    Get-UnifiApiData `
        -ControllerUrl $ControllerUrl `
        -Site $Site `
        -WebSession $WebSession `
        -SkipCertificateCheck:$SkipCertificateCheck `
        -Paths @(
            "/proxy/network/api/s/{site}/rest/networkconf",
            "/api/s/{site}/rest/networkconf"
        )
}

function Get-UnifiWlans {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ControllerUrl,
        [Parameter(Mandatory = $true)][string]$Site,
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter()][switch]$SkipCertificateCheck
    )

    Get-UnifiApiData `
        -ControllerUrl $ControllerUrl `
        -Site $Site `
        -WebSession $WebSession `
        -SkipCertificateCheck:$SkipCertificateCheck `
        -Paths @(
            "/proxy/network/api/s/{site}/rest/wlanconf",
            "/api/s/{site}/rest/wlanconf"
        )
}

function Get-UnifiDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ControllerUrl,
        [Parameter(Mandatory = $true)][string]$Site,
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter()][switch]$SkipCertificateCheck
    )

    Get-UnifiApiData `
        -ControllerUrl $ControllerUrl `
        -Site $Site `
        -WebSession $WebSession `
        -SkipCertificateCheck:$SkipCertificateCheck `
        -Paths @(
            "/proxy/network/api/s/{site}/stat/device",
            "/api/s/{site}/stat/device"
        )
}

function Get-UnifiClients {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ControllerUrl,
        [Parameter(Mandatory = $true)][string]$Site,
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter()][switch]$SkipCertificateCheck
    )

    Get-UnifiApiData `
        -ControllerUrl $ControllerUrl `
        -Site $Site `
        -WebSession $WebSession `
        -SkipCertificateCheck:$SkipCertificateCheck `
        -Paths @(
            "/proxy/network/api/s/{site}/stat/sta",
            "/api/s/{site}/stat/sta"
        )
}

function Get-UnifiFirewallGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ControllerUrl,
        [Parameter(Mandatory = $true)][string]$Site,
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter()][switch]$SkipCertificateCheck
    )

    Get-UnifiApiData `
        -ControllerUrl $ControllerUrl `
        -Site $Site `
        -WebSession $WebSession `
        -SkipCertificateCheck:$SkipCertificateCheck `
        -Paths @(
            "/proxy/network/api/s/{site}/list/firewallgroup",
            "/api/s/{site}/list/firewallgroup"
        )
}

function Get-UnifiFirewallRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ControllerUrl,
        [Parameter(Mandatory = $true)][string]$Site,
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter()][switch]$SkipCertificateCheck
    )

    Get-UnifiApiData `
        -ControllerUrl $ControllerUrl `
        -Site $Site `
        -WebSession $WebSession `
        -SkipCertificateCheck:$SkipCertificateCheck `
        -Paths @(
            "/proxy/network/api/s/{site}/rest/firewallrule",
            "/api/s/{site}/rest/firewallrule"
        )
}

function Get-UnifiInventory {
    <#
    .SYNOPSIS
        Returns a full UniFi inventory bundle for a site.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ControllerUrl,
        [Parameter(Mandatory = $true)][string]$Site,
        [Parameter(Mandatory = $true)][Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [Parameter()][switch]$SkipCertificateCheck
    )

    [pscustomobject]@{
        Networks       = Get-UnifiNetworks -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck
        Wlans          = Get-UnifiWlans -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck
        Devices        = Get-UnifiDevices -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck
        Clients        = Get-UnifiClients -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck
        FirewallGroups = Get-UnifiFirewallGroups -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck
        FirewallRules  = Get-UnifiFirewallRules -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck
    }
}

Export-ModuleMember -Function `
    Get-UnifiApiData, `
    Get-UnifiSites, `
    Get-UnifiNetworks, `
    Get-UnifiWlans, `
    Get-UnifiDevices, `
    Get-UnifiClients, `
    Get-UnifiFirewallGroups, `
    Get-UnifiFirewallRules, `
    Get-UnifiInventory

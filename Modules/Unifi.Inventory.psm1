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

function Resolve-UnifiApiCollection {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Result
    )

    if ($null -eq $Result) {
        return @()
    }

    if ($Result.PSObject.Properties.Name -contains "data" -and $null -ne $Result.data) {
        return @($Result.data)
    }

    if ($Result -is [System.Collections.IEnumerable] -and -not ($Result -is [string])) {
        return @($Result)
    }

    return @($Result)
}

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

    $baseUrl = $ControllerUrl.Trim().TrimEnd("/")
    $resolvedSite = $Site.Trim()

    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        $resolvedPath = $path -replace "\{site\}", [uri]::EscapeDataString($resolvedSite)
        $uri = "$baseUrl$resolvedPath"

        try {
            $result = Invoke-UnifiRequest `
                -WebSession $WebSession `
                -Method GET `
                -Uri $uri `
                -SkipCertificateCheck:$SkipCertificateCheck

            $collection = Resolve-UnifiApiCollection -Result $result
            if ($collection.Count -gt 0) {
                return $collection
            }
        }
        catch {
            Write-Verbose ("Endpoint failed: {0} | {1}" -f $uri, $_.Exception.Message)
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

    $baseUrl = $ControllerUrl.Trim().TrimEnd("/")
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

            $collection = Resolve-UnifiApiCollection -Result $result
            if ($collection.Count -gt 0) {
                return $collection
            }
        }
        catch {
            Write-Verbose ("Site endpoint failed: {0} | {1}" -f $uri, $_.Exception.Message)
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
        Networks       = @(Get-UnifiNetworks -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck)
        Wlans          = @(Get-UnifiWlans -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck)
        Devices        = @(Get-UnifiDevices -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck)
        Clients        = @(Get-UnifiClients -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck)
        FirewallGroups = @(Get-UnifiFirewallGroups -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck)
        FirewallRules  = @(Get-UnifiFirewallRules -ControllerUrl $ControllerUrl -Site $Site -WebSession $WebSession -SkipCertificateCheck:$SkipCertificateCheck)
    }
}

function Get-UnifiEndpointCollection {
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

    $baseUrl = $ControllerUrl.Trim().TrimEnd("/")
    $resolvedSite = $Site.Trim()
    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        $resolvedPath = $path -replace "\{site\}", [uri]::EscapeDataString($resolvedSite)
        $uri = "$baseUrl$resolvedPath"

        try {
            $result = Invoke-UnifiRequest `
                -WebSession $WebSession `
                -Method GET `
                -Uri $uri `
                -SkipCertificateCheck:$SkipCertificateCheck

            $collection = Resolve-UnifiApiCollection -Result $result
            return [pscustomobject]@{
                Success      = $true
                Path         = $resolvedPath
                Uri          = $uri
                Count        = $collection.Count
                Data         = $collection
                Errors       = @($errors)
            }
        }
        catch {
            $errors.Add(("{0}: {1}" -f $resolvedPath, $_.Exception.Message))
        }
    }

    return [pscustomobject]@{
        Success      = $false
        Path         = $null
        Uri          = $null
        Count        = 0
        Data         = @()
        Errors       = @($errors)
    }
}

function Get-UnifiSecurityAssessmentSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControllerUrl,

        [Parameter(Mandatory = $true)]
        [string]$Site,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    $catalog = [ordered]@{
        SiteSettings       = @("/proxy/network/api/s/{site}/get/setting", "/api/s/{site}/get/setting")
        Networks           = @("/proxy/network/api/s/{site}/rest/networkconf", "/api/s/{site}/rest/networkconf")
        Wlans              = @("/proxy/network/api/s/{site}/rest/wlanconf", "/api/s/{site}/rest/wlanconf")
        Devices            = @("/proxy/network/api/s/{site}/stat/device", "/api/s/{site}/stat/device")
        Clients            = @("/proxy/network/api/s/{site}/stat/sta", "/api/s/{site}/stat/sta")
        FirewallRules      = @("/proxy/network/api/s/{site}/rest/firewallrule", "/api/s/{site}/rest/firewallrule")
        FirewallGroups     = @("/proxy/network/api/s/{site}/list/firewallgroup", "/api/s/{site}/list/firewallgroup")
        PortProfiles       = @("/proxy/network/api/s/{site}/rest/portconf", "/api/s/{site}/rest/portconf")
        UserGroups         = @("/proxy/network/api/s/{site}/rest/usergroup", "/api/s/{site}/rest/usergroup")
        Routing            = @("/proxy/network/api/s/{site}/rest/routing", "/api/s/{site}/rest/routing")
        RadiusProfiles     = @("/proxy/network/api/s/{site}/rest/radiusprofile", "/api/s/{site}/rest/radiusprofile")
        DynamicDns         = @("/proxy/network/api/s/{site}/rest/dynamicdns", "/api/s/{site}/rest/dynamicdns")
        ApGroups           = @("/proxy/network/api/s/{site}/rest/apgroup", "/api/s/{site}/rest/apgroup")
        TrafficRules       = @("/proxy/network/api/s/{site}/rest/trafficrule", "/api/s/{site}/rest/trafficrule")
        DHCPRelay          = @("/proxy/network/api/s/{site}/rest/dhcprelay", "/api/s/{site}/rest/dhcprelay")
    }

    $datasets = [ordered]@{}
    $retrieval = New-Object System.Collections.Generic.List[object]

    foreach ($category in $catalog.Keys) {
        $result = Get-UnifiEndpointCollection `
            -ControllerUrl $ControllerUrl `
            -Site $Site `
            -Paths $catalog[$category] `
            -WebSession $WebSession `
            -SkipCertificateCheck:$SkipCertificateCheck

        $datasets[$category] = @($result.Data)

        $retrieval.Add(
            [pscustomobject]@{
                Category = $category
                Success  = $result.Success
                Count    = $result.Count
                Path     = $result.Path
                Errors   = @($result.Errors)
            }
        )
    }

    return [pscustomobject]@{
        GeneratedAt   = (Get-Date).ToString("o")
        ControllerUrl = $ControllerUrl.Trim().TrimEnd("/")
        Site          = $Site.Trim()
        Retrieval     = @($retrieval)
        Data          = [pscustomobject]$datasets
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
    Get-UnifiInventory, `
    Get-UnifiEndpointCollection, `
    Get-UnifiSecurityAssessmentSnapshot

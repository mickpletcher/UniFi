<#
.SYNOPSIS
    Read-only UniFi audit script.

.DESCRIPTION
    Connects to a UniFi controller, authenticates, queries common UniFi
    endpoints, performs basic audit checks, and exports the results to JSON
    and CSV files.

    This script is intentionally read-only. It does not modify UniFi settings.

    Primary use cases:
    - Inventory UniFi sites, networks, WLANs, clients, devices, and firewall rules
    - Verify expected DNS settings
    - Verify expected SSIDs exist
    - Export current state for documentation, backup, or drift analysis

.PARAMETER ControllerUrl
    Base URL of the UniFi controller.

    Examples:
    - https://192.168.0.1
    - https://unifi.domain.local

.PARAMETER Site
    UniFi site name to audit.
    Defaults to "default".

.PARAMETER ExpectedDnsServer
    Optional DNS server IP expected to appear in relevant network settings.
    Useful for checking Pi-hole enforcement.

.PARAMETER ExpectedSsids
    Optional list of SSIDs expected to exist.

.PARAMETER OutputPath
    Directory where reports will be written.
    Defaults to .\Reports

.PARAMETER SkipCertificateCheck
    Skips TLS certificate validation.
    Useful for self-signed certs in a homelab.
    Avoid using this in production unless you understand the risk.

.ENVIRONMENT
    If these environment variables are present, they are used for authentication:
    - UNIFI_USERNAME
    - UNIFI_PASSWORD

    Otherwise, the script prompts for credentials.

.OUTPUTS
    Writes JSON and CSV reports to the output directory.

.EXAMPLE
    .\UnifiAudit.ps1 `
      -ControllerUrl "https://192.168.0.1" `
      -Site "default" `
      -ExpectedDnsServer "192.168.0.10" `
      -ExpectedSsids "MainWiFi","IoTWiFi","WorkWiFi" `
      -OutputPath ".\Reports" `
      -SkipCertificateCheck

.EXAMPLE
    $env:UNIFI_USERNAME = "api-audit"
    $env:UNIFI_PASSWORD = "StrongPasswordHere"
    .\UnifiAudit.ps1 -ControllerUrl "https://unifi.local" -SkipCertificateCheck

.NOTES
    Notes on UniFi API behavior:
    - UniFi API endpoints can vary by version and platform
    - This script tries both modern UniFi OS and older controller-style paths
    - Some endpoints may fail on one version and work on another

    Recommended next steps after validating this script:
    - Split functions into modules
    - Add HTML reporting
    - Add drift comparison against a baseline JSON file
    - Add policy checks for firewall rules, WLAN security, and DNS enforcement
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ControllerUrl,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Site = "default",

    [Parameter()]
    [string]$ExpectedDnsServer,

    [Parameter()]
    [string[]]$ExpectedSsids = @(),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\Reports",

    [Parameter()]
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Utility Functions

function Write-Section {
    <#
    .SYNOPSIS
        Writes a formatted section header to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function New-UnifiWebSession {
    <#
    .SYNOPSIS
        Creates a persistent web session for UniFi API calls.

    .DESCRIPTION
        UniFi authentication relies on cookies/session state.
        This function creates the PowerShell web session object used
        across all requests after login.
    #>
    [CmdletBinding()]
    param()

    New-Object Microsoft.PowerShell.Commands.WebRequestSession
}

function Get-UnifiCredential {
    <#
    .SYNOPSIS
        Retrieves credentials for UniFi authentication.

    .DESCRIPTION
        Uses environment variables if available:
        - UNIFI_USERNAME
        - UNIFI_PASSWORD

        Otherwise prompts interactively.
    #>
    [CmdletBinding()]
    param()

    if ($env:UNIFI_USERNAME -and $env:UNIFI_PASSWORD) {
        $securePassword = ConvertTo-SecureString $env:UNIFI_PASSWORD -AsPlainText -Force
        return [PSCredential]::new($env:UNIFI_USERNAME, $securePassword)
    }

    Get-Credential -Message "Enter UniFi credentials"
}

function Invoke-UnifiRequest {
    <#
    .SYNOPSIS
        Wrapper for UniFi API requests.

    .DESCRIPTION
        Sends authenticated REST requests using the supplied web session.
        Adds JSON headers and optionally skips certificate validation.

    .PARAMETER WebSession
        Authenticated PowerShell web session.

    .PARAMETER Method
        HTTP method such as GET or POST.

    .PARAMETER Uri
        Fully-qualified API endpoint URI.

    .PARAMETER Body
        Optional request body object. Will be converted to JSON.

    .PARAMETER SkipCertificateCheck
        Skips TLS certificate validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter()]
        $Body,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    $params = @{
        Uri         = $Uri
        Method      = $Method
        WebSession  = $WebSession
        Headers     = @{ Accept = "application/json" }
        ErrorAction = "Stop"
    }

    if ($SkipCertificateCheck) {
        $params.SkipCertificateCheck = $true
    }

    if ($null -ne $Body) {
        $params.Body        = ($Body | ConvertTo-Json -Depth 20)
        $params.ContentType = "application/json"
    }

    try {
        Invoke-RestMethod @params
    }
    catch {
        throw "UniFi API call failed. Method=$Method Uri=$Uri Error=$($_.Exception.Message)"
    }
}

#endregion Utility Functions

#region Authentication and API Discovery

function Connect-UnifiController {
    <#
    .SYNOPSIS
        Authenticates to the UniFi controller.

    .DESCRIPTION
        Tries the modern UniFi OS login endpoint first, then falls back
        to the older legacy login endpoint if necessary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControllerUrl,

        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter()]
        [switch]$SkipCertificateCheck
    )

    $baseUrl = $ControllerUrl.TrimEnd("/")
    $body = @{
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
    }

    Write-Host "Authenticating to $baseUrl" -ForegroundColor Yellow

    try {
        $null = Invoke-UnifiRequest `
            -WebSession $WebSession `
            -Method POST `
            -Uri "$baseUrl/api/auth/login" `
            -Body $body `
            -SkipCertificateCheck:$SkipCertificateCheck

        Write-Host "Authenticated using /api/auth/login" -ForegroundColor Green
        return
    }
    catch {
        Write-Warning "Modern auth endpoint failed. Trying legacy endpoint."
    }

    try {
        $null = Invoke-UnifiRequest `
            -WebSession $WebSession `
            -Method POST `
            -Uri "$baseUrl/api/login" `
            -Body $body `
            -SkipCertificateCheck:$SkipCertificateCheck

        Write-Host "Authenticated using /api/login" -ForegroundColor Green
        return
    }
    catch {
        throw "Authentication failed using both modern and legacy UniFi login endpoints."
    }
}

function Get-UnifiSites {
    <#
    .SYNOPSIS
        Retrieves available UniFi sites.

    .DESCRIPTION
        Attempts multiple known site enumeration endpoints to maximize
        compatibility across UniFi versions.
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

    Write-Warning "Unable to enumerate sites from known endpoints."
    return @()
}

function Get-UnifiApiData {
    <#
    .SYNOPSIS
        Retrieves data from one of several possible UniFi API paths.

    .DESCRIPTION
        Tries each candidate path until one succeeds.
        This is helpful because UniFi endpoint paths may differ by version.

    .PARAMETER Paths
        Array of path templates. Use {site} where site substitution is needed.
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

#endregion Authentication and API Discovery

#region Audit Checks

function Test-ExpectedDns {
    <#
    .SYNOPSIS
        Checks whether the expected DNS server appears in network settings.

    .DESCRIPTION
        Looks through common DNS-related properties returned from UniFi
        network configuration objects.

        This is a best-effort audit check, not a guaranteed canonical
        interpretation of all UniFi DNS settings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Networks,

        [Parameter()]
        [string]$ExpectedDnsServer
    )

    $findings = New-Object System.Collections.Generic.List[object]

    if ([string]::IsNullOrWhiteSpace($ExpectedDnsServer)) {
        return $findings
    }

    $dnsPropertyNames = @(
        "dns1", "dns2",
        "dns_server_1", "dns_server_2",
        "wan_dns1", "wan_dns2",
        "dhcpd_dns_1", "dhcpd_dns_2"
    )

    foreach ($network in $Networks) {
        $dnsCandidates = @()

        foreach ($propertyName in $dnsPropertyNames) {
            if ($network.PSObject.Properties.Name -contains $propertyName) {
                $value = $network.$propertyName
                if ($value) {
                    $dnsCandidates += [string]$value
                }
            }
        }

        $dnsCandidates = $dnsCandidates |
            Where-Object { $_ -and $_.Trim() } |
            Select-Object -Unique

        if ($dnsCandidates.Count -eq 0) {
            continue
        }

        if ($dnsCandidates -notcontains $ExpectedDnsServer) {
            $findings.Add([pscustomobject]@{
                Severity = "Warning"
                Category = "DNS"
                Object   = $network.name
                Finding  = "Expected DNS server not found"
                Details  = "Expected: $ExpectedDnsServer | Actual: $($dnsCandidates -join ', ')"
            })
        }
    }

    return $findings
}

function Test-ExpectedSsids {
    <#
    .SYNOPSIS
        Checks whether expected SSIDs exist.

    .DESCRIPTION
        Compares the user-supplied expected SSID list against the WLANs
        returned from the controller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Wlans,

        [Parameter()]
        [string[]]$ExpectedSsids
    )

    $findings = New-Object System.Collections.Generic.List[object]

    if (-not $ExpectedSsids -or $ExpectedSsids.Count -eq 0) {
        return $findings
    }

    $actualSsids = @(
        $Wlans |
        ForEach-Object { $_.name } |
        Where-Object { $_ } |
        Select-Object -Unique
    )

    foreach ($ssid in $ExpectedSsids) {
        if ($actualSsids -notcontains $ssid) {
            $findings.Add([pscustomobject]@{
                Severity = "Warning"
                Category = "SSID"
                Object   = $ssid
                Finding  = "Expected SSID missing"
                Details  = ""
            })
        }
    }

    return $findings
}

function Test-UnifiAudit {
    <#
    .SYNOPSIS
        Runs all configured audit checks.

    .DESCRIPTION
        Aggregates findings from individual validation functions into
        a single collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Networks,

        [Parameter(Mandatory = $true)]
        [array]$Wlans,

        [Parameter()]
        [string]$ExpectedDnsServer,

        [Parameter()]
        [string[]]$ExpectedSsids
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($item in (Test-ExpectedDns -Networks $Networks -ExpectedDnsServer $ExpectedDnsServer)) {
        $results.Add($item)
    }

    foreach ($item in (Test-ExpectedSsids -Wlans $Wlans -ExpectedSsids $ExpectedSsids)) {
        $results.Add($item)
    }

    return $results
}

#endregion Audit Checks

#region Export Functions

function Export-UnifiAuditData {
    <#
    .SYNOPSIS
        Exports audit data to JSON and CSV.

    .DESCRIPTION
        Writes each dataset to a timestamped JSON file.
        If the dataset is enumerable, it also attempts CSV export.

        JSON is the source of truth.
        CSV is a convenience export.
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

    foreach ($key in $Data.Keys) {
        $value = $Data[$key]

        $jsonPath = Join-Path $OutputPath "${key}_${timestamp}.json"
        $value | ConvertTo-Json -Depth 25 | Out-File -FilePath $jsonPath -Encoding utf8

        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            try {
                $csvPath = Join-Path $OutputPath "${key}_${timestamp}.csv"
                $value | Export-Csv -NoTypeInformation -Encoding utf8 -Path $csvPath
            }
            catch {
                Write-Verbose "CSV export skipped for dataset: $key"
            }
        }
    }
}

#endregion Export Functions

#region Main Execution

Write-Section "UniFi Audit Starting"

$credential = Get-UnifiCredential
$session = New-UnifiWebSession

Connect-UnifiController `
    -ControllerUrl $ControllerUrl `
    -Credential $credential `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck

Write-Section "Enumerating Sites"

$sites = Get-UnifiSites `
    -ControllerUrl $ControllerUrl `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck

if ($sites.Count -gt 0) {
    $sites | Format-Table -AutoSize
}
else {
    Write-Warning "No sites were returned from the controller."
}

if ($sites.Count -gt 0 -and -not ($sites | Where-Object { $_.name -eq $Site -or $_.desc -eq $Site })) {
    Write-Warning "Requested site '$Site' was not found in the returned site list. Continuing anyway."
}

Write-Section "Collecting UniFi Data"

$networks = Get-UnifiApiData `
    -ControllerUrl $ControllerUrl `
    -Site $Site `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck `
    -Paths @(
        "/proxy/network/api/s/{site}/rest/networkconf",
        "/api/s/{site}/rest/networkconf"
    )

$wlans = Get-UnifiApiData `
    -ControllerUrl $ControllerUrl `
    -Site $Site `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck `
    -Paths @(
        "/proxy/network/api/s/{site}/rest/wlanconf",
        "/api/s/{site}/rest/wlanconf"
    )

$devices = Get-UnifiApiData `
    -ControllerUrl $ControllerUrl `
    -Site $Site `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck `
    -Paths @(
        "/proxy/network/api/s/{site}/stat/device",
        "/api/s/{site}/stat/device"
    )

$clients = Get-UnifiApiData `
    -ControllerUrl $ControllerUrl `
    -Site $Site `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck `
    -Paths @(
        "/proxy/network/api/s/{site}/stat/sta",
        "/api/s/{site}/stat/sta"
    )

$firewallGroups = Get-UnifiApiData `
    -ControllerUrl $ControllerUrl `
    -Site $Site `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck `
    -Paths @(
        "/proxy/network/api/s/{site}/list/firewallgroup",
        "/api/s/{site}/list/firewallgroup"
    )

$firewallRules = Get-UnifiApiData `
    -ControllerUrl $ControllerUrl `
    -Site $Site `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck `
    -Paths @(
        "/proxy/network/api/s/{site}/rest/firewallrule",
        "/api/s/{site}/rest/firewallrule"
    )

Write-Host ("Networks       : {0}" -f $networks.Count) -ForegroundColor Green
Write-Host ("WLANs          : {0}" -f $wlans.Count) -ForegroundColor Green
Write-Host ("Devices        : {0}" -f $devices.Count) -ForegroundColor Green
Write-Host ("Clients        : {0}" -f $clients.Count) -ForegroundColor Green
Write-Host ("FirewallGroups : {0}" -f $firewallGroups.Count) -ForegroundColor Green
Write-Host ("FirewallRules  : {0}" -f $firewallRules.Count) -ForegroundColor Green

Write-Section "Running Audit Checks"

$findings = Test-UnifiAudit `
    -Networks $networks `
    -Wlans $wlans `
    -ExpectedDnsServer $ExpectedDnsServer `
    -ExpectedSsids $ExpectedSsids

if ($findings.Count -eq 0) {
    Write-Host "No audit findings." -ForegroundColor Green
}
else {
    $findings | Format-Table -AutoSize
}

Write-Section "Exporting Reports"

$dataToExport = @{
    Sites          = $sites
    Networks       = $networks
    Wlans          = $wlans
    Devices        = $devices
    Clients        = $clients
    FirewallGroups = $firewallGroups
    FirewallRules  = $firewallRules
    Findings       = $findings
}

Export-UnifiAuditData -OutputPath $OutputPath -Data $dataToExport

$resolvedOutputPath = Resolve-Path -LiteralPath $OutputPath
Write-Host "Reports written to: $($resolvedOutputPath.Path)" -ForegroundColor Yellow

Write-Section "UniFi Audit Complete"

#endregion Main Execution

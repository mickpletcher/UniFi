[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ControllerUrl,

    [Parameter(Mandatory = $false)]
    [string]$Site = "default",

    [Parameter(Mandatory = $false)]
    [string]$ExpectedDnsServer,

    [Parameter(Mandatory = $false)]
    [string[]]$ExpectedSsids = @(),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",

    [Parameter(Mandatory = $false)]
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkGray
}

function New-UnifiWebSession {
    [CmdletBinding()]
    param()

    return New-Object Microsoft.PowerShell.Commands.WebRequestSession
}

function Get-UnifiCredential {
    [CmdletBinding()]
    param()

    if ($env:UNIFI_USERNAME -and $env:UNIFI_PASSWORD) {
        $secure = ConvertTo-SecureString $env:UNIFI_PASSWORD -AsPlainText -Force
        return [PSCredential]::new($env:UNIFI_USERNAME, $secure)
    }

    return Get-Credential -Message "Enter UniFi credentials"
}

function Invoke-UnifiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        $Body,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    $invokeParams = @{
        Uri         = $Uri
        Method      = $Method
        WebSession  = $WebSession
        Headers     = @{ "Accept" = "application/json" }
        ErrorAction = "Stop"
    }

    if ($SkipCertificateCheck) {
        $invokeParams["SkipCertificateCheck"] = $true
    }

    if ($null -ne $Body) {
        $invokeParams["Body"] = ($Body | ConvertTo-Json -Depth 15)
        $invokeParams["ContentType"] = "application/json"
    }

    try {
        return Invoke-RestMethod @invokeParams
    }
    catch {
        throw "UniFi API call failed. Method=$Method Uri=$Uri Error=$($_.Exception.Message)"
    }
}

function Connect-UnifiController {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControllerUrl,

        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    $base = $ControllerUrl.TrimEnd("/")
    $username = $Credential.UserName
    $password = $Credential.GetNetworkCredential().Password

    $body = @{
        username = $username
        password = $password
    }

    Write-Host "Logging into UniFi controller: $base" -ForegroundColor Yellow

    # Common UniFi OS login path
    try {
        $null = Invoke-UnifiRequest -WebSession $WebSession -Method POST -Uri "$base/api/auth/login" -Body $body -SkipCertificateCheck:$SkipCertificateCheck
        Write-Host "Login successful using /api/auth/login" -ForegroundColor Green
        return
    }
    catch {
        Write-Warning "Primary auth path failed. Trying legacy login path."
    }

    # Legacy controller login path fallback
    try {
        $null = Invoke-UnifiRequest -WebSession $WebSession -Method POST -Uri "$base/api/login" -Body $body -SkipCertificateCheck:$SkipCertificateCheck
        Write-Host "Login successful using /api/login" -ForegroundColor Green
        return
    }
    catch {
        throw "Unable to authenticate to UniFi using either /api/auth/login or /api/login."
    }
}

function Get-UnifiSites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControllerUrl,

        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    $base = $ControllerUrl.TrimEnd("/")
    $siteResults = @()

    $candidateUris = @(
        "$base/proxy/network/integration/v1/sites",
        "$base/api/self/sites"
    )

    foreach ($uri in $candidateUris) {
        try {
            $result = Invoke-UnifiRequest -WebSession $WebSession -Method GET -Uri $uri -SkipCertificateCheck:$SkipCertificateCheck

            if ($null -ne $result) {
                if ($result.data) {
                    $siteResults = @($result.data)
                }
                elseif ($result -is [System.Collections.IEnumerable] -and -not ($result -is [string])) {
                    $siteResults = @($result)
                }
                else {
                    $siteResults = @($result)
                }

                if ($siteResults.Count -gt 0) {
                    return $siteResults
                }
            }
        }
        catch {
            continue
        }
    }

    Write-Warning "Could not enumerate sites from known endpoints. Falling back to the provided site name only."
    return @(
        [pscustomobject]@{
            name = $Site
            desc = $Site
        }
    )
}

function Get-UnifiApiData {
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

        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )

    $base = $ControllerUrl.TrimEnd("/")

    foreach ($path in $Paths) {
        $uri = "{0}{1}" -f $base, ($path -replace "\{site\}", [uri]::EscapeDataString($Site))
        try {
            $result = Invoke-UnifiRequest -WebSession $WebSession -Method GET -Uri $uri -SkipCertificateCheck:$SkipCertificateCheck

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
            Write-Verbose "Failed endpoint: $uri"
            continue
        }
    }

    return @()
}

function Test-ExpectedDns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Networks,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedDnsServer
    )

    $findings = New-Object System.Collections.Generic.List[object]

    if ([string]::IsNullOrWhiteSpace($ExpectedDnsServer)) {
        return $findings
    }

    foreach ($network in $Networks) {
        $dnsCandidates = @()

        foreach ($propertyName in @("dns1", "dns2", "dns_server_1", "dns_server_2", "wan_dns1", "wan_dns2", "dhcpd_dns_1", "dhcpd_dns_2")) {
            if ($network.PSObject.Properties.Name -contains $propertyName) {
                $value = $network.$propertyName
                if ($value) {
                    $dnsCandidates += [string]$value
                }
            }
        }

        $dnsCandidates = $dnsCandidates | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique

        if ($dnsCandidates.Count -eq 0) {
            continue
        }

        if ($dnsCandidates -notcontains $ExpectedDnsServer) {
            $findings.Add([pscustomobject]@{
                Severity = "Warning"
                Category = "DNS"
                Object   = $network.name
                Finding  = "Expected DNS server '$ExpectedDnsServer' not found"
                Details  = ($dnsCandidates -join ", ")
            })
        }
    }

    return $findings
}

function Test-ExpectedSsids {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Wlans,

        [Parameter(Mandatory = $false)]
        [string[]]$ExpectedSsids
    )

    $findings = New-Object System.Collections.Generic.List[object]

    if (-not $ExpectedSsids -or $ExpectedSsids.Count -eq 0) {
        return $findings
    }

    $actual = @($Wlans | ForEach-Object { $_.name } | Where-Object { $_ } | Select-Object -Unique)

    foreach ($ssid in $ExpectedSsids) {
        if ($actual -notcontains $ssid) {
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Networks,

        [Parameter(Mandatory = $true)]
        [array]$Wlans,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedDnsServer,

        [Parameter(Mandatory = $false)]
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

function Export-UnifiAuditData {
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

        $jsonPath = Join-Path $OutputPath "$($key)_$timestamp.json"
        $value | ConvertTo-Json -Depth 20 | Out-File -FilePath $jsonPath -Encoding utf8

        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            try {
                $csvPath = Join-Path $OutputPath "$($key)_$timestamp.csv"
                $value | Export-Csv -NoTypeInformation -Encoding utf8 -Path $csvPath
            }
            catch {
                Write-Verbose "Could not export CSV for $key"
            }
        }
    }
}

# Main
Write-Section "UniFi Audit Starting"

$credential = Get-UnifiCredential
$session = New-UnifiWebSession

Connect-UnifiController -ControllerUrl $ControllerUrl -Credential $credential -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck

Write-Section "Discovering Sites"
$sites = Get-UnifiSites -ControllerUrl $ControllerUrl -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck
$sites | Format-Table -AutoSize

if (-not ($sites | Where-Object { $_.name -eq $Site -or $_.desc -eq $Site })) {
    Write-Warning "Requested site '$Site' was not found in the enumerated site list. Continuing anyway."
}

Write-Section "Collecting UniFi Data"

$networks = Get-UnifiApiData -ControllerUrl $ControllerUrl -Site $Site -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck -Paths @(
    "/proxy/network/api/s/{site}/rest/networkconf",
    "/api/s/{site}/rest/networkconf"
)

$wlans = Get-UnifiApiData -ControllerUrl $ControllerUrl -Site $Site -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck -Paths @(
    "/proxy/network/api/s/{site}/rest/wlanconf",
    "/api/s/{site}/rest/wlanconf"
)

$devices = Get-UnifiApiData -ControllerUrl $ControllerUrl -Site $Site -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck -Paths @(
    "/proxy/network/api/s/{site}/stat/device",
    "/api/s/{site}/stat/device"
)

$clients = Get-UnifiApiData -ControllerUrl $ControllerUrl -Site $Site -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck -Paths @(
    "/proxy/network/api/s/{site}/stat/sta",
    "/api/s/{site}/stat/sta"
)

$firewallGroups = Get-UnifiApiData -ControllerUrl $ControllerUrl -Site $Site -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck -Paths @(
    "/proxy/network/api/s/{site}/list/firewallgroup",
    "/api/s/{site}/list/firewallgroup"
)

$firewallRules = Get-UnifiApiData -ControllerUrl $ControllerUrl -Site $Site -WebSession $session -SkipCertificateCheck:$SkipCertificateCheck -Paths @(
    "/proxy/network/api/s/{site}/rest/firewallrule",
    "/api/s/{site}/rest/firewallrule"
)

Write-Host ("Networks      : {0}" -f $networks.Count) -ForegroundColor Green
Write-Host ("WLANs         : {0}" -f $wlans.Count) -ForegroundColor Green
Write-Host ("Devices       : {0}" -f $devices.Count) -ForegroundColor Green
Write-Host ("Clients       : {0}" -f $clients.Count) -ForegroundColor Green
Write-Host ("FW Groups     : {0}" -f $firewallGroups.Count) -ForegroundColor Green
Write-Host ("FW Rules      : {0}" -f $firewallRules.Count) -ForegroundColor Green

Write-Section "Running Policy Checks"
$findings = Test-UnifiAudit -Networks $networks -Wlans $wlans -ExpectedDnsServer $ExpectedDnsServer -ExpectedSsids $ExpectedSsids

if ($findings.Count -eq 0) {
    Write-Host "No policy findings." -ForegroundColor Green
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

Write-Host "Reports written to: $((Resolve-Path $OutputPath).Path)" -ForegroundColor Yellow
Write-Section "UniFi Audit Complete"

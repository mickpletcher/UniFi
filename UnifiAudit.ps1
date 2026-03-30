<#
.SYNOPSIS
    Main entry point for a read-only UniFi audit.

.DESCRIPTION
    Loads configuration from config.json, imports the UniFi modules,
    connects to the controller, gathers inventory, runs tests,
    and exports the results.

    This script is intentionally read-only.

.PROJECT STRUCTURE
    .
    ├── config.json
    ├── UnifiAudit.ps1
    └── Modules
        ├── Unifi.Auth.psm1
        ├── Unifi.Inventory.psm1
        ├── Unifi.Tests.psm1
        └── Unifi.Reporting.psm1

.PARAMETER ConfigPath
    Optional path to the JSON config file.
    Defaults to .\config.json relative to this script.

.PARAMETER ControllerUrl
    Optional override for ControllerUrl from config.json.

.PARAMETER Site
    Optional override for Site from config.json.

.PARAMETER ExpectedDnsServer
    Optional override for ExpectedDnsServer from config.json.

.PARAMETER OutputPath
    Optional override for OutputPath from config.json.

.PARAMETER SkipCertificateCheck
    Optional override for SkipCertificateCheck from config.json.

.PARAMETER ExpectedSsids
    Optional override for ExpectedSsids from config.json.

.EXAMPLE
    .\UnifiAudit.ps1

.EXAMPLE
    .\UnifiAudit.ps1 -ConfigPath ".\config.json"

.EXAMPLE
    .\UnifiAudit.ps1 -ControllerUrl "https://192.168.0.1" -Site "default" -SkipCertificateCheck

.NOTES
    Environment variables supported by the auth module:
    - UNIFI_USERNAME
    - UNIFI_PASSWORD
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot "config.json"),

    [Parameter()]
    [string]$ControllerUrl,

    [Parameter()]
    [string]$Site,

    [Parameter()]
    [string]$ExpectedDnsServer,

    [Parameter()]
    [string[]]$ExpectedSsids,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$SkipCertificateCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
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

function Import-UnifiModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleRoot
    )

    $requiredModules = @(
        "Unifi.Auth.psm1",
        "Unifi.Inventory.psm1",
        "Unifi.Tests.psm1",
        "Unifi.Reporting.psm1"
    )

    foreach ($moduleName in $requiredModules) {
        $modulePath = Join-Path $ModuleRoot $moduleName

        if (-not (Test-Path -LiteralPath $modulePath)) {
            throw "Required module not found: $modulePath"
        }

        Import-Module $modulePath -Force -ErrorAction Stop
    }
}

function Assert-UnifiDependencies {
    [CmdletBinding()]
    param()

    $requiredCommands = @(
        "Get-UnifiCredential",
        "New-UnifiWebSession",
        "Connect-UnifiController",
        "Get-UnifiSites",
        "Get-UnifiInventory",
        "Write-UnifiSummary",
        "Test-UnifiInventory",
        "Get-UnifiReportBundle",
        "Export-UnifiAuditData"
    )

    foreach ($commandName in $requiredCommands) {
        if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
            throw "Required function '$commandName' was not loaded from modules."
        }
    }
}

function Read-UnifiConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Config file not found: $Path"
    }

    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse config file '$Path'. Error: $($_.Exception.Message)"
    }
}

function Get-CleanStringArray {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Values
    )

    if ($null -eq $Values) {
        return @()
    }

    return @(
        $Values |
        ForEach-Object { [string]$_ } |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    )
}

function Resolve-UnifiOutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Resolve-UnifiSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Config,

        [Parameter()]
        [string]$ControllerUrlOverride,

        [Parameter()]
        [string]$SiteOverride,

        [Parameter()]
        [string]$ExpectedDnsServerOverride,

        [Parameter()]
        [string[]]$ExpectedSsidsOverride,

        [Parameter()]
        [string]$OutputPathOverride,

        [Parameter()]
        [bool]$SkipCertificateCheckOverrideProvided,

        [Parameter()]
        [bool]$SkipCertificateCheckOverrideValue
    )

    $resolvedControllerUrl = if ($ControllerUrlOverride) { $ControllerUrlOverride } else { [string]$Config.ControllerUrl }
    $resolvedSite          = if ($SiteOverride) { $SiteOverride } else { [string]$Config.Site }
    $resolvedDns           = if ($ExpectedDnsServerOverride) { $ExpectedDnsServerOverride } else { [string]$Config.ExpectedDnsServer }
    $resolvedSsids         = if ($ExpectedSsidsOverride -and $ExpectedSsidsOverride.Count -gt 0) { $ExpectedSsidsOverride } else { @($Config.ExpectedSsids) }
    $resolvedOutputPath    = if ($OutputPathOverride) { $OutputPathOverride } else { [string]$Config.OutputPath }

    if (-not [string]::IsNullOrWhiteSpace($resolvedControllerUrl)) {
        $resolvedControllerUrl = $resolvedControllerUrl.Trim().TrimEnd("/")
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedSite)) {
        $resolvedSite = $resolvedSite.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedDns)) {
        $resolvedDns = $resolvedDns.Trim()
    }
    else {
        $resolvedDns = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedOutputPath)) {
        $resolvedOutputPath = $resolvedOutputPath.Trim()
    }

    $resolvedSsids = Get-CleanStringArray -Values $resolvedSsids

    $resolvedSkipCert = if ($SkipCertificateCheckOverrideProvided) {
        $SkipCertificateCheckOverrideValue
    }
    elseif ($null -ne $Config.SkipCertificateCheck) {
        [bool]$Config.SkipCertificateCheck
    }
    else {
        $false
    }

    if ([string]::IsNullOrWhiteSpace($resolvedControllerUrl)) {
        throw "ControllerUrl is required. Set it in config.json or pass -ControllerUrl."
    }

    if ([string]::IsNullOrWhiteSpace($resolvedSite)) {
        $resolvedSite = "default"
    }

    if ([string]::IsNullOrWhiteSpace($resolvedOutputPath)) {
        $resolvedOutputPath = ".\Reports"
    }

    [pscustomobject]@{
        ControllerUrl        = $resolvedControllerUrl
        Site                 = $resolvedSite
        ExpectedDnsServer    = $resolvedDns
        ExpectedSsids        = $resolvedSsids
        OutputPath           = $resolvedOutputPath
        SkipCertificateCheck = $resolvedSkipCert
    }
}

function Show-UnifiResolvedSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Settings
    )

    Write-Host ("Controller URL       : {0}" -f $Settings.ControllerUrl) -ForegroundColor Yellow
    Write-Host ("Site                 : {0}" -f $Settings.Site) -ForegroundColor Yellow
    Write-Host ("Expected DNS         : {0}" -f $(if ($Settings.ExpectedDnsServer) { $Settings.ExpectedDnsServer } else { "<not set>" })) -ForegroundColor Yellow
    Write-Host ("Expected SSIDs       : {0}" -f $(if ($Settings.ExpectedSsids.Count -gt 0) { $Settings.ExpectedSsids -join ", " } else { "<not set>" })) -ForegroundColor Yellow
    Write-Host ("Output Path          : {0}" -f $Settings.OutputPath) -ForegroundColor Yellow
    Write-Host ("Skip Cert Check      : {0}" -f $Settings.SkipCertificateCheck) -ForegroundColor Yellow
}

try {
    $scriptStart = Get-Date

    Write-Section "Importing Modules"
    Import-UnifiModules -ModuleRoot (Join-Path $PSScriptRoot "Modules")
    Assert-UnifiDependencies

    Write-Section "Loading Configuration"
    $config = Read-UnifiConfig -Path $ConfigPath

    $skipOverrideProvided = $PSBoundParameters.ContainsKey("SkipCertificateCheck")

    $settings = Resolve-UnifiSettings `
        -Config $config `
        -ControllerUrlOverride $ControllerUrl `
        -SiteOverride $Site `
        -ExpectedDnsServerOverride $ExpectedDnsServer `
        -ExpectedSsidsOverride $ExpectedSsids `
        -OutputPathOverride $OutputPath `
        -SkipCertificateCheckOverrideProvided $skipOverrideProvided `
        -SkipCertificateCheckOverrideValue ([bool]$SkipCertificateCheck)

    $settings.OutputPath = Resolve-UnifiOutputPath -Path $settings.OutputPath -BasePath $PSScriptRoot

    Show-UnifiResolvedSettings -Settings $settings

    Write-Section "Authenticating"
    $credential = Get-UnifiCredential
    $session = New-UnifiWebSession

    $authResult = Connect-UnifiController `
        -ControllerUrl $settings.ControllerUrl `
        -Credential $credential `
        -WebSession $session `
        -SkipCertificateCheck:$settings.SkipCertificateCheck

    Write-Host ("Authentication Path  : {0}" -f $authResult.AuthPath) -ForegroundColor Green

    Write-Section "Enumerating Sites"
    $sites = Get-UnifiSites `
        -ControllerUrl $settings.ControllerUrl `
        -WebSession $session `
        -SkipCertificateCheck:$settings.SkipCertificateCheck

    if ($sites.Count -gt 0) {
        $sites | Format-Table -AutoSize
    }
    else {
        Write-Warning "No sites were returned from the controller."
    }

    if ($sites.Count -gt 0 -and -not ($sites | Where-Object {
        ($_.name -and $_.name.ToString().Equals($settings.Site, [System.StringComparison]::OrdinalIgnoreCase)) -or
        ($_.desc -and $_.desc.ToString().Equals($settings.Site, [System.StringComparison]::OrdinalIgnoreCase))
    })) {
        Write-Warning "Requested site '$($settings.Site)' was not found in the returned site list. Continuing anyway."
    }

    Write-Section "Collecting Inventory"
    $inventory = Get-UnifiInventory `
        -ControllerUrl $settings.ControllerUrl `
        -Site $settings.Site `
        -WebSession $session `
        -SkipCertificateCheck:$settings.SkipCertificateCheck

    Write-UnifiSummary -Inventory $inventory

    Write-Section "Running Tests"
    $findings = Test-UnifiInventory `
        -Inventory $inventory `
        -ExpectedDnsServer $settings.ExpectedDnsServer `
        -ExpectedSsids $settings.ExpectedSsids

    if ($findings.Count -eq 0) {
        Write-Host "No audit findings." -ForegroundColor Green
    }
    else {
        $findings | Format-Table -AutoSize
    }

    Write-Section "Exporting Reports"
    $bundle = Get-UnifiReportBundle `
        -Sites $sites `
        -Inventory $inventory `
        -Findings $findings

    Export-UnifiAuditData -OutputPath $settings.OutputPath -Data $bundle

    $resolvedOutput = Resolve-Path -LiteralPath $settings.OutputPath
    Write-Host ("Reports written to   : {0}" -f $resolvedOutput.Path) -ForegroundColor Green

    $duration = (Get-Date) - $scriptStart
    Write-Host ("Duration             : {0}" -f $duration.ToString("hh\:mm\:ss")) -ForegroundColor Green

    Write-Section "UniFi Audit Complete"
}
catch {
    $duration = if ($scriptStart) { ((Get-Date) - $scriptStart).ToString("hh\:mm\:ss") } else { "00:00:00" }
    $line = $_.InvocationInfo.ScriptLineNumber
    $source = $_.InvocationInfo.ScriptName
    Write-Error ("{0} (Line {1} in {2}, Duration {3})" -f $_.Exception.Message, $line, $source, $duration)
    exit 1
}

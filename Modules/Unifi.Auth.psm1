<#
.SYNOPSIS
    Authentication and HTTP helper functions for UniFi API access.

.DESCRIPTION
    Handles credential retrieval, session creation, authentication,
    and generic authenticated REST requests to UniFi.

.NOTES
    This module is read-safe. It does not perform configuration changes by itself.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-UnifiWebSession {
    <#
    .SYNOPSIS
        Creates a persistent web session for UniFi API calls.
    #>
    [CmdletBinding()]
    param()

    New-Object Microsoft.PowerShell.Commands.WebRequestSession
}

function Get-UnifiCredential {
    <#
    .SYNOPSIS
        Retrieves UniFi credentials.

    .DESCRIPTION
        Uses UNIFI_USERNAME and UNIFI_PASSWORD environment variables if present.
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
        Wrapper for authenticated UniFi API requests.

    .PARAMETER WebSession
        Active PowerShell web session.

    .PARAMETER Method
        HTTP method.

    .PARAMETER Uri
        Fully-qualified endpoint URI.

    .PARAMETER Body
        Optional object body converted to JSON.

    .PARAMETER SkipCertificateCheck
        Skips TLS validation for self-signed certs.
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
        throw "UniFi API request failed. Method=$Method Uri=$Uri Error=$($_.Exception.Message)"
    }
}

function Connect-UnifiController {
    <#
    .SYNOPSIS
        Authenticates to a UniFi controller.

    .DESCRIPTION
        Tries modern UniFi OS auth first, then falls back to legacy auth.

    .PARAMETER ControllerUrl
        Base URL for the controller.

    .PARAMETER Credential
        Credential object for login.

    .PARAMETER WebSession
        Web session that will persist auth cookies.

    .PARAMETER SkipCertificateCheck
        Skips TLS validation.
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

    try {
        $null = Invoke-UnifiRequest `
            -WebSession $WebSession `
            -Method POST `
            -Uri "$baseUrl/api/auth/login" `
            -Body $body `
            -SkipCertificateCheck:$SkipCertificateCheck

        return [pscustomobject]@{
            Success     = $true
            AuthPath    = "/api/auth/login"
            Controller  = $baseUrl
        }
    }
    catch {
        Write-Verbose "Modern auth failed. Trying legacy auth."
    }

    try {
        $null = Invoke-UnifiRequest `
            -WebSession $WebSession `
            -Method POST `
            -Uri "$baseUrl/api/login" `
            -Body $body `
            -SkipCertificateCheck:$SkipCertificateCheck

        return [pscustomobject]@{
            Success     = $true
            AuthPath    = "/api/login"
            Controller  = $baseUrl
        }
    }
    catch {
        throw "UniFi authentication failed using both modern and legacy login endpoints."
    }
}

Export-ModuleMember -Function `
    New-UnifiWebSession, `
    Get-UnifiCredential, `
    Invoke-UnifiRequest, `
    Connect-UnifiController

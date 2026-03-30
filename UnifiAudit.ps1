Import-Module "$PSScriptRoot\Modules\Unifi.Auth.psm1" -Force
Import-Module "$PSScriptRoot\Modules\Unifi.Inventory.psm1" -Force
Import-Module "$PSScriptRoot\Modules\Unifi.Tests.psm1" -Force
Import-Module "$PSScriptRoot\Modules\Unifi.Reporting.psm1" -Force

$credential = Get-UnifiCredential
$session = New-UnifiWebSession

Connect-UnifiController `
    -ControllerUrl $ControllerUrl `
    -Credential $credential `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck

$sites = Get-UnifiSites `
    -ControllerUrl $ControllerUrl `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck

$inventory = Get-UnifiInventory `
    -ControllerUrl $ControllerUrl `
    -Site $Site `
    -WebSession $session `
    -SkipCertificateCheck:$SkipCertificateCheck

Write-UnifiSummary -Inventory $inventory

$findings = Test-UnifiInventory `
    -Inventory $inventory `
    -ExpectedDnsServer $ExpectedDnsServer `
    -ExpectedSsids $ExpectedSsids

$bundle = Get-UnifiReportBundle `
    -Sites $sites `
    -Inventory $inventory `
    -Findings $findings

Export-UnifiAuditData -OutputPath $OutputPath -Data $bundle

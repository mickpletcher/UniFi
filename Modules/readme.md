# Modules Reference

This folder contains the PowerShell modules used by `UnifiAudit.ps1`.

## Module Index

| Module | Purpose |
|---|---|
| `Unifi.Auth.psm1` | Authentication and API request helpers |
| `Unifi.Inventory.psm1` | Inventory collection for UniFi objects |
| `Unifi.Tests.psm1` | Read only audit and policy validation tests |
| `Unifi.Reporting.psm1` | Console summary and report export helpers |

## Unifi.Auth.psm1

Exports:

- `New-UnifiWebSession`  
	Creates a persistent web session for API calls.
- `Get-UnifiCredential`  
	Uses `UNIFI_USERNAME` and `UNIFI_PASSWORD` if present, otherwise prompts.
- `Invoke-UnifiRequest`  
	Standardized wrapper for authenticated UniFi REST calls.
- `Connect-UnifiController`  
	Authenticates to the controller. Tries modern auth path first, then legacy.

## Unifi.Inventory.psm1

Exports:

- `Get-UnifiApiData`  
	Tries multiple endpoint paths and returns first successful dataset.
- `Get-UnifiSites`  
	Returns available UniFi sites.
- `Get-UnifiNetworks`  
	Returns network configuration objects.
- `Get-UnifiWlans`  
	Returns WLAN/SSID definitions.
- `Get-UnifiDevices`  
	Returns UniFi devices.
- `Get-UnifiClients`  
	Returns connected client data.
- `Get-UnifiFirewallGroups`  
	Returns firewall groups.
- `Get-UnifiFirewallRules`  
	Returns firewall rules.
- `Get-UnifiInventory`  
	Returns a bundled inventory object containing all datasets above.

## Unifi.Tests.psm1

Exports:

- `New-UnifiFinding`  
	Creates a normalized finding object.
- `Test-UnifiExpectedDns`  
	Flags networks where expected DNS server is not present.
- `Test-UnifiExpectedSsids`  
	Flags expected SSIDs that are missing.
- `Test-UnifiOpenGuestNetwork`  
	Flags WLANs with open security.
- `Test-UnifiInventory`  
	Runs all enabled tests and returns findings.

## Unifi.Reporting.psm1

Exports:

- `Write-UnifiSummary`  
	Writes inventory counts to console.
- `Export-UnifiAuditData`  
	Exports datasets to timestamped JSON and CSV files.
- `Get-UnifiReportBundle`  
	Combines sites, inventory, and findings into one export bundle.

## Typical Execution Flow

1. Import all modules.
2. Create web session and authenticate.
3. Collect sites and inventory.
4. Run tests.
5. Build report bundle and export output.

## Notes

- Inventory and tests are read only.
- Authentication uses POST for login endpoints.
- Export writes to the configured reports folder with timestamps.


# UniFi

PowerShell based auditing and reporting for UniFi Network environments.

This project performs read only inspection of a UniFi deployment so you can:

- document current state
- verify expected network policy
- export inventory and findings for review

## What It Checks

The audit workflow:

1. Authenticates to the UniFi controller
2. Enumerates available sites
3. Collects inventory for the target site
4. Runs policy tests
5. Exports JSON and CSV reports

Collected inventory includes:

- Networks
- WLANs
- Devices
- Clients
- Firewall groups
- Firewall rules

Policy tests include:

- Expected DNS server presence in network settings
- Expected SSID presence
- Open WLAN detection

## Repository Structure

```text
UniFi/
|-- Modules/
|   |-- Unifi.Auth.psm1
|   |-- Unifi.Inventory.psm1
|   |-- Unifi.Reporting.psm1
|   |-- Unifi.Tests.psm1
|   `-- readme.md
|-- Documentation/
|   `-- readme.md
|-- Reports/
|   `-- readme.md
|-- CountryBlockList.txt
|-- LICENSE
|-- README.md
|-- UnifiAudit.ps1
`-- config.json
```

## Requirements

- PowerShell 7 or later
- Network access to the UniFi controller
- Credentials with read access to UniFi Network

## Configuration

Edit `config.json`:

```json
{
	"ControllerUrl": "https://192.168.0.1",
	"Site": "default",
	"ExpectedDnsServer": "192.168.0.10",
	"ExpectedSsids": [
		"Species8472_PV",
		"Species8472_PV_IoT",
		"Species8472_PV_Work"
	],
	"OutputPath": ".\\Reports",
	"SkipCertificateCheck": true
}
```

### Config Fields

- `ControllerUrl`: Base URL for UniFi controller
- `Site`: UniFi site name. Defaults to `default` if blank
- `ExpectedDnsServer`: DNS value expected in network configs
- `ExpectedSsids`: SSIDs that should exist
- `OutputPath`: Folder for timestamped reports
- `SkipCertificateCheck`: Set `true` for self signed cert environments

## Authentication

The script supports two auth modes:

1. Environment variables
2. Interactive credential prompt

Environment variable option:

```powershell
$env:UNIFI_USERNAME = "your-username"
$env:UNIFI_PASSWORD = "your-password"
```

## Usage

Run with config file:

```powershell
./UnifiAudit.ps1
```

Run with explicit config path:

```powershell
./UnifiAudit.ps1 -ConfigPath ./config.json
```

Override settings at runtime:

```powershell
./UnifiAudit.ps1 `
	-ControllerUrl "https://192.168.0.1" `
	-Site "default" `
	-ExpectedDnsServer "192.168.0.10" `
	-ExpectedSsids "CorpWiFi","CorpIoT" `
	-OutputPath ".\\Reports" `
	-SkipCertificateCheck
```

## Output

Reports are written to `OutputPath` using a timestamped naming pattern:

- `Sites_yyyyMMdd_HHmmss.json` and `.csv`
- `Networks_yyyyMMdd_HHmmss.json` and `.csv`
- `Wlans_yyyyMMdd_HHmmss.json` and `.csv`
- `Devices_yyyyMMdd_HHmmss.json` and `.csv`
- `Clients_yyyyMMdd_HHmmss.json` and `.csv`
- `FirewallGroups_yyyyMMdd_HHmmss.json` and `.csv`
- `FirewallRules_yyyyMMdd_HHmmss.json` and `.csv`
- `Findings_yyyyMMdd_HHmmss.json` and `.csv`

CSV export is attempted for enumerable datasets.

## Safety

This project is designed as read only.

Current modules use GET for inventory operations and POST only for authentication.

## Troubleshooting

- Auth failure: verify credentials and controller URL
- TLS/cert failure: use `SkipCertificateCheck` in trusted internal environments
- Empty datasets: confirm target site name and account permissions
- Missing expected SSID or DNS findings: verify `ExpectedSsids` and `ExpectedDnsServer` values

## License

MIT License. See `LICENSE`.

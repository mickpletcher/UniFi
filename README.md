# UniFi

PowerShell-based auditing and reporting for UniFi Network environments.

This repository is focused on read-only inspection of a UniFi deployment so you can document the current state, verify expected settings, and export inventory data for analysis or change control.

## Project Goals

- Audit a UniFi Network controller without making changes
- Export networks, WLANs, devices, clients, and firewall data
- Verify expected DNS settings such as Pi-hole enforcement
- Verify expected SSIDs exist
- Generate structured JSON and CSV reports
- Keep the code modular and easy to extend

## Repository Structure

```text
UniFi/
├── Modules/
│   ├── Unifi.Auth.psm1
│   ├── Unifi.Inventory.psm1
│   ├── Unifi.Reporting.psm1
│   ├── Unifi.Tests.psm1
│   └── readme.md
├── Reports/
│   └── readme.md
├── CountryBlockList.txt
├── LICENSE
├── README.md
├── UnifiAudit.ps1
└── config.json

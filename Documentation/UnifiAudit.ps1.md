# UnifiAudit.ps1

## Purpose

Main orchestration script for UniFi audit collection, validation, and report export.

## Inputs

1. Config file path
2. Optional runtime overrides for controller, site, test targets, and output
3. Credentials from environment variables or prompt

## Parameters

| Name | Type | Required | Default |
|---|---|---|---|
| ConfigPath | string | No | ./config.json |
| ControllerUrl | string | No | from config |
| Site | string | No | from config or default |
| ExpectedDnsServer | string | No | from config |
| ExpectedSsids | string[] | No | from config |
| OutputPath | string | No | from config or ./Reports |
| SkipCertificateCheck | switch | No | from config or false |

## Internal Function Flow

1. Write-Section
   Prints section banners.
2. Import-UnifiModules
   Imports required files from [Modules](../Modules).
3. Read-UnifiConfig
   Parses [config.json](../config.json).
4. Resolve-UnifiSettings
   Merges config and runtime values.
5. Show-UnifiResolvedSettings
   Prints effective values used in run.

## Runtime Sequence

1. Import module files
2. Read config and resolve settings
3. Authenticate
4. Enumerate sites
5. Collect inventory
6. Run tests
7. Build report bundle
8. Export reports

## Auth Behavior

Login attempts occur in this order:

1. /api/auth/login
2. /api/login

## Exit Behavior

1. Strict mode enabled
2. Stop on terminating errors
3. Script returns exit code 1 on failure

## Example

```powershell
./UnifiAudit.ps1
```

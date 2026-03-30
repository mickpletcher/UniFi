# Unifi.Reporting.psm1

## Purpose

Summary and export logic for audit output datasets.

## Exports

1. Write-UnifiSummary
2. Export-UnifiAuditData
3. Get-UnifiReportBundle
4. Export-UnifiSecurityAssessmentPackage

## Function Details

### Write-UnifiSummary

Writes dataset counts to console for:

1. Networks
2. Wlans
3. Devices
4. Clients
5. FirewallGroups
6. FirewallRules

### Get-UnifiReportBundle

Builds a hashtable for export with keys:

1. Sites
2. Networks
3. Wlans
4. Devices
5. Clients
6. FirewallGroups
7. FirewallRules
8. Findings

### Export-UnifiAuditData

Export behavior:

1. Creates output directory when missing
2. Writes JSON for every dataset
3. Attempts CSV export for enumerable datasets
4. Uses timestamp naming format yyyyMMdd_HHmmss

### Export-UnifiSecurityAssessmentPackage

Writes:

1. SecurityAssessmentSnapshot_yyyyMMdd_HHmmss.json
2. SecurityAssessmentPrompt_yyyyMMdd_HHmmss.txt

The prompt file is ready to paste to an AI reviewer with assessment requirements.

Supports optional sensitive value redaction before JSON export.

## Output Naming

Pattern per dataset:

1. <Dataset>_yyyyMMdd_HHmmss.json
2. <Dataset>_yyyyMMdd_HHmmss.csv

## Consumed By

1. [UnifiAudit.ps1](../UnifiAudit.ps1)

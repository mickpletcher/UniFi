# Unifi.Auth.psm1

## Purpose

Authentication helpers and common request wrapper for UniFi API access.

## Exports

1. New-UnifiWebSession
2. Get-UnifiCredential
3. Invoke-UnifiRequest
4. Connect-UnifiController

## Function Details

### New-UnifiWebSession

Creates a persistent web request session used by all API calls.

### Get-UnifiCredential

Credential source order:

1. UNIFI_USERNAME and UNIFI_PASSWORD environment variables
2. Interactive credential prompt

### Invoke-UnifiRequest

Standard wrapper around Invoke Rest Method.

Responsibilities:

1. Sets headers
2. Adds JSON body when provided
3. Honors SkipCertificateCheck
4. Throws formatted errors with method and URI context

### Connect-UnifiController

Performs authentication and persists cookies into session.

Login endpoint order:

1. /api/auth/login
2. /api/login

Returns an object with success state and auth path used.

## Consumed By

1. [UnifiAudit.ps1](../UnifiAudit.ps1)
2. [Unifi.Inventory.psm1](Unifi.Inventory.psm1.md)

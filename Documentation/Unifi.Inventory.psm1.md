# Unifi.Inventory.psm1

## Purpose

Read only inventory collection across site level UniFi objects.

## Exports

1. Get-UnifiApiData
2. Get-UnifiSites
3. Get-UnifiNetworks
4. Get-UnifiWlans
5. Get-UnifiDevices
6. Get-UnifiClients
7. Get-UnifiFirewallGroups
8. Get-UnifiFirewallRules
9. Get-UnifiInventory

## Function Details

### Get-UnifiApiData

Core helper that attempts each endpoint path in order and returns first successful dataset.

Behavior:

1. Replaces {site} token in path templates
2. Uses shared request wrapper from auth module
3. Returns result.data when present
4. Returns empty array on full fallback failure

### Get-UnifiSites

Queries candidate site endpoints and returns available sites.

### Get-UnifiNetworks

Returns network configuration objects for selected site.

### Get-UnifiWlans

Returns WLAN definitions for selected site.

### Get-UnifiDevices

Returns device status and inventory objects.

### Get-UnifiClients

Returns connected client inventory.

### Get-UnifiFirewallGroups

Returns firewall group definitions.

### Get-UnifiFirewallRules

Returns firewall rule definitions.

### Get-UnifiInventory

Builds a single object with all site datasets.

Object keys:

1. Networks
2. Wlans
3. Devices
4. Clients
5. FirewallGroups
6. FirewallRules

## Consumed By

1. [UnifiAudit.ps1](../UnifiAudit.ps1)

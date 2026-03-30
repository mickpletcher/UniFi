# Unifi.Tests.psm1

## Purpose

Validation and drift checks over collected UniFi inventory.

## Exports

1. New-UnifiFinding
2. Test-UnifiExpectedDns
3. Test-UnifiExpectedSsids
4. Test-UnifiOpenGuestNetwork
5. Test-UnifiInventory

## Finding Model

Each finding object includes:

1. Severity
2. Category
3. Object
4. Finding
5. Details

## Function Details

### Test-UnifiExpectedDns

Checks network properties for expected DNS value.

Current properties checked:

1. dns1
2. dns2
3. dns_server_1
4. dns_server_2
5. wan_dns1
6. wan_dns2
7. dhcpd_dns_1
8. dhcpd_dns_2

Creates warning findings when expected DNS is not present in network candidate values.

### Test-UnifiExpectedSsids

Compares expected SSID list with actual WLAN names.

Creates warning findings for missing SSIDs.

### Test-UnifiOpenGuestNetwork

Flags WLAN objects where security equals open.

### Test-UnifiInventory

Top level test runner.

Behavior:

1. Runs DNS test when ExpectedDnsServer is provided
2. Runs SSID test when ExpectedSsids has values
3. Runs open WLAN check always
4. Returns merged findings list

## Consumed By

1. [UnifiAudit.ps1](../UnifiAudit.ps1)

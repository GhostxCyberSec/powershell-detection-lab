# Suspicious PowerShell Detection Lab with Sysmon and Wazuh

## Overview
This project demonstrates how suspicious PowerShell activity can be detected using Sysmon and Wazuh SIEM.

The lab focuses on collecting Windows process creation events, identifying encoded PowerShell execution, and creating a custom Wazuh rule mapped to MITRE ATT&CK.

## Lab Environment
- **Endpoint:** Windows 11 VM
- **Telemetry:** Sysmon
- **SIEM:** Wazuh
- **Detection Focus:** Encoded PowerShell execution
- **MITRE ATT&CK:** T1059.001 - PowerShell

## Objective
Detect suspicious PowerShell execution using Sysmon Event ID 1 process creation logs.

## Data Source
Sysmon Event ID 1 records process creation activity, including the executable path and command-line arguments.

## Wazuh Agent Configuration
The Wazuh agent was configured to collect the Sysmon Operational event channel.

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## Custom Detection Rule
The custom Wazuh rule detects PowerShell or PowerShell Core being launched with the encoded command flag.

```xml
<group name="windows,powershell,sysmon,custom">
  <rule id="100010" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.system.eventID">1</field>
    <field name="win.eventdata.Image" type="pcre2">(?i)(powershell|pwsh)\.exe$</field>
    <field name="win.eventdata.CommandLine" type="pcre2">(?i)(^|\s)-(enc|encodedcommand)(\s|$)</field>
    <description>Suspicious PowerShell encoded command detected</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

## Test Commands

### Normal PowerShell Test
This command should create Sysmon telemetry but should not trigger custom rule `100010`.

```powershell
powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 3"
```

### Encoded PowerShell Test
This command uses the `-enc` flag and should trigger custom rule `100010`.

```powershell
$Text = 'Write-Host "PowerShell detection lab test"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$Encoded = [Convert]::ToBase64String($Bytes)
powershell.exe -enc $Encoded
```

### Recon-Style PowerShell Test
This command creates additional PowerShell telemetry for analysis.

```powershell
powershell.exe -NoProfile -Command "whoami; hostname; Get-LocalUser"
```

## Wazuh Queries

### Confirm Sysmon Logs
```kql
win.system.channel:"Microsoft-Windows-Sysmon/Operational"
```

### Sysmon Process Creation Events
```kql
win.system.eventID:1
```

### PowerShell Process Events
```kql
win.eventdata.Image:*powershell*
```

### Encoded PowerShell Activity
```kql
win.eventdata.CommandLine:*-enc*
```

### Custom Detection Alert
```kql
rule.id:100010
```

## Screenshots

### Sysmon Installed
Add screenshot:

```text
screenshots/sysmon-installed.png
```

### PowerShell Process Event in Wazuh
Add screenshot:

```text
screenshots/powershell-process-event.png
```

### Custom Wazuh Alert
Add screenshot:

```text
screenshots/wazuh-alert-100010.png
```

## Results
The normal PowerShell test generated process telemetry in Wazuh but did not trigger the custom encoded-command rule.

The encoded PowerShell test successfully triggered custom Wazuh rule `100010`, identifying suspicious PowerShell usage based on command-line arguments.

## Key Skills Demonstrated
- Windows endpoint monitoring
- Sysmon process creation analysis
- Wazuh SIEM rule creation
- Custom detection engineering
- MITRE ATT&CK mapping
- PowerShell threat detection

## Future Improvements
- Add detection for hidden PowerShell windows
- Add detection for suspicious parent-child process relationships
- Add correlation between PowerShell execution and outbound network activity
- Add detection for recon commands such as `whoami`, `hostname`, and `Get-LocalUser`

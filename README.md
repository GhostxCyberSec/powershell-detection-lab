# Suspicious PowerShell Detection Lab with Sysmon and Wazuh

## Overview
This project simulates suspicious PowerShell activity on a Windows 11 endpoint and detects it using Sysmon and Wazuh.

The goal is to demonstrate practical SOC analyst and detection engineering skills by:
- collecting Sysmon telemetry from a Windows endpoint
- forwarding Sysmon events to Wazuh
- creating custom rules to detect suspicious PowerShell execution
- mapping detections to MITRE ATT&CK

## Lab Environment
- **SIEM:** Wazuh
- **Endpoint:** Windows 11
- **Telemetry Source:** Sysmon
- **Focus:** PowerShell process execution and command-line analysis

## Why This Project Matters
PowerShell is commonly used by administrators, but it is also frequently abused by attackers for execution, reconnaissance, and payload delivery. Sysmon improves visibility into process creation events by capturing command-line details, and Wazuh can ingest those Windows event channels for detection and alerting.

## Data Source
This lab uses Sysmon **Event ID 1** (Process Create), which includes process creation metadata and command-line context.

## Sysmon Install
Sysmon was installed on the Windows 11 VM using a Sysmon configuration file.

```powershell
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml

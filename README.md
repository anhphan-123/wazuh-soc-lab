# Wazuh SOC Lab

Project cá nhân xây dựng môi trường SOC nhỏ để thực hành security monitoring,
alert investigation và detection engineering bằng Wazuh.

## Lab Environment

- Wazuh Server
- Windows 10 + Sysmon
- Ubuntu Server
- Suricata IDS
- Wazuh Agent

## Detection Scenarios

| Incident | Detection | MITRE ATT&CK |
|---|---|---|
| 001 | Registry Run Key Persistence | T1547.001 |
| 002 | PowerShell Base64 Execution | T1059.001 |
| 003 | SSH Brute Force | T1110 |
| 004 | Suspicious DNS Activity | T1071.004 |

## Detection Workflow

Activity Simulation
→ Log / Network Collection
→ Wazuh / Suricata Detection
→ Custom Rule
→ Alert Triage
→ MITRE ATT&CK Mapping
→ Incident Report

## Incident Reports

- [Incident 001 - Registry Run Key Persistence](incidents/incident-001-registry-run-key-persistence.md)
- [Incident 002 - PowerShell Base64 Execution](incidents/incident-002-powershell-base64-execution.md)
- [Incident 003 - SSH Brute Force](incidents/incident-003-ssh-bruteforce.md)
- [Incident 004 - Suspicious DNS Activity](incidents/incident-004-suspicious-dns-activity.md)

## Skills Practiced

- Wazuh SIEM monitoring
- Sysmon log analysis
- Suricata IDS
- Custom detection rules
- Alert triage
- Windows and Linux log analysis
- DNS traffic analysis
- MITRE ATT&CK mapping
- Incident documentation

## Architecture

[View Lab Architecture](architecture/lab-architecture.md)
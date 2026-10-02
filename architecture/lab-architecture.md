# Lab Architecture

```mermaid
flowchart TD
    LM[Linux Mint Host]

    WS[Wazuh Server<br/>Ubuntu Server<br/>192.168.122.244]

    WIN[win10-flare<br/>Windows 10<br/>Wazuh Agent + Sysmon]

    UB[ubuntu-victim<br/>Ubuntu Server<br/>Wazuh Agent + Suricata]

    LM -->|SSH test traffic| UB

    WIN -->|Sysmon / Windows Events| WS
    UB -->|SSH / Linux Logs| WS
    UB -->|Suricata eve.json| WS

    WS --> DASH[Wazuh Dashboard]
```

## Components

### Wazuh Server
- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard

### Windows Endpoint
- Windows 10
- Wazuh Agent
- Sysmon
- Registry and PowerShell monitoring

### Linux Endpoint
- Ubuntu Server
- Wazuh Agent
- OpenSSH
- Suricata IDS
- Authentication and network monitoring

## Detection Flow

```text
Activity
   ↓
Endpoint / Network Log
   ↓
Wazuh Agent / Suricata
   ↓
Wazuh Manager
   ↓
Detection Rule
   ↓
Alert
   ↓
Investigation
   ↓
MITRE ATT&CK Mapping
```
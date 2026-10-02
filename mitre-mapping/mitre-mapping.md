# MITRE ATT&CK Mapping

| Incident | Technique ID | Technique | Tactic |
|---|---|---|---|
| 001 | T1547.001 | Registry Run Keys / Startup Folder | Persistence / Privilege Escalation |
| 002 | T1059.001 | PowerShell | Execution |
| 003 | T1110 | Brute Force | Credential Access |
| 004 | T1071.004 | DNS | Command and Control |

## Incident 001

**Technique:** T1547.001 - Registry Run Keys / Startup Folder

Phát hiện hành vi tạo persistence thông qua Windows Registry Run Key bằng Sysmon Event ID 13 và Wazuh.

## Incident 002

**Technique:** T1059.001 - PowerShell

Phát hiện PowerShell process sử dụng `-EncodedCommand` thông qua Sysmon Event ID 1 và Wazuh.

## Incident 003

**Technique:** T1110 - Brute Force

Phát hiện nhiều SSH authentication failure liên tiếp và correlation thành brute-force alert.

## Incident 004

**Technique:** T1071.004 - DNS

Phát hiện DNS traffic đáng chú ý bằng Suricata và chuyển alert về Wazuh để thực hiện investigation.
# SIEM Detection Engineering Incident Report

## Executive summary

Analyzed **23** normalized events from **5** source types across **4** hosts. The detection pipeline produced **7** triage alerts. Alerts indicate activity requiring investigation; they do not prove compromise.

## Coverage

- Sources: firewall, linux_auth, windows_powershell, windows_security, windows_system
- Hosts: dc-lab-01, fw-lab-01, linux-lab-01, ws-lab-01
- Time range: 2026-09-13T14:00:00+00:00 to 2026-09-13T14:30:45+00:00
- Severity totals: critical=0, high=5, medium=2, low=0

## Alert summary

| First seen (UTC) | Severity | Rule | ATT&CK | Host | Count |
|---|---|---|---|---|---:|
| 2026-09-13T14:00:00+00:00 | high | `AUTH-BRUTE-FORCE` | T1110 | ws-lab-01 | 5 |
| 2026-09-13T14:00:00+00:00 | high | `AUTH-SUCCESS-AFTER-FAILURES` | T1078 | ws-lab-01 | 6 |
| 2026-09-13T14:10:00+00:00 | high | `AUTH-PASSWORD-SPRAY` | T1110.003 | linux-lab-01 | 4 |
| 2026-09-13T14:20:00+00:00 | high | `ACCOUNT-PRIVILEGE-CHANGE` | T1098 | dc-lab-01 | 1 |
| 2026-09-13T14:22:00+00:00 | medium | `SERVICE-INSTALLED` | T1543.003 | ws-lab-01 | 1 |
| 2026-09-13T14:24:00+00:00 | high | `POWERSHELL-SUSPICIOUS` | T1059.001 | ws-lab-01 | 1 |
| 2026-09-13T14:30:00+00:00 | medium | `NETWORK-PORT-SCAN` | T1046 | fw-lab-01 | 10 |

## Investigation timeline

### 2026-09-13T14:00:00+00:00 — Repeated authentication failures

- Rule: `AUTH-BRUTE-FORCE`
- Severity: high
- ATT&CK: T1110
- Observation: 5 failures for one account and source within the rule window
- Entities: account=student; source_ip=192.0.2.10
- Analyst action: validate the account, host, source, and approved change context before escalation.

### 2026-09-13T14:00:00+00:00 — Successful authentication after repeated failures

- Rule: `AUTH-SUCCESS-AFTER-FAILURES`
- Severity: high
- ATT&CK: T1078
- Observation: success followed 5 recent failures
- Entities: account=student; source_ip=192.0.2.10
- Analyst action: validate the account, host, source, and approved change context before escalation.

### 2026-09-13T14:10:00+00:00 — Authentication failures across multiple accounts

- Rule: `AUTH-PASSWORD-SPRAY`
- Severity: high
- ATT&CK: T1110.003
- Observation: failures affected 4 distinct accounts
- Entities: accounts=alice, bob, carol, dave; source_ip=198.51.100.20
- Analyst action: validate the account, host, source, and approved change context before escalation.

### 2026-09-13T14:20:00+00:00 — Account added to a privileged group

- Rule: `ACCOUNT-PRIVILEGE-CHANGE`
- Severity: high
- ATT&CK: T1098
- Observation: a member was added to a privileged group
- Entities: account=lab-user; actor=lab-admin; group=Administrators
- Analyst action: validate the account, host, source, and approved change context before escalation.

### 2026-09-13T14:22:00+00:00 — New system service installed

- Rule: `SERVICE-INSTALLED`
- Severity: medium
- ATT&CK: T1543.003
- Observation: a new system service was recorded
- Entities: image_path=C:\Lab\updater.exe; service=LabUpdater
- Analyst action: validate the account, host, source, and approved change context before escalation.

### 2026-09-13T14:24:00+00:00 — Suspicious PowerShell content

- Rule: `POWERSHELL-SUSPICIOUS`
- Severity: high
- ATT&CK: T1059.001
- Observation: script content matched a documented triage keyword
- Entities: account=student; keywords=invoke-expression
- Analyst action: validate the account, host, source, and approved change context before escalation.

### 2026-09-13T14:30:00+00:00 — Firewall denies across many destination ports

- Rule: `NETWORK-PORT-SCAN`
- Severity: medium
- ATT&CK: T1046
- Observation: firewall denied TCP connections to 10 distinct ports
- Entities: ports=20, 21, 22, 23, 25, 53, 80, 110, 443, 445; source_ip=203.0.113.50
- Analyst action: validate the account, host, source, and approved change context before escalation.

## Limitations

- Results depend on the supplied normalized events and configured thresholds.
- Keyword matches and correlation rules may produce false positives.
- ATT&CK mappings describe possible behaviors, not attribution or proof of compromise.
- The lab does not perform containment, live collection, enrichment, or long-term storage.
- Real logs can contain sensitive identifiers and must remain outside the repository.

# SIEM Detection Engineering Lab

A defensive security lab that ingests normalized Windows, Linux, PowerShell,
and firewall events; correlates activity across time; maps detections to
MITRE ATT&CK; and produces analyst-ready JSONL alerts and an incident report.

## ⚠️ Security notice

This repository was created for **educational and training purposes only** as
part of a cybersecurity portfolio. The events, identities, hosts, addresses,
and suspicious activity are fictional or sanitized. They are included to
demonstrate defensive detection and investigation techniques.

This lab is not deliberately exploitable, but it models hostile behavior and
is not a production SIEM. **Do not deploy it as a production security control**
or reuse its sample data as real credentials or configuration. See
[`SECURITY.md`](SECURITY.md) for safe reporting instructions and the complete
disclaimer.

The project is self-contained and uses only the Python standard library. It
demonstrates detection-engineering fundamentals without requiring a paid SIEM
or publishing sensitive host logs.

## Objective

Demonstrate a repeatable SOC detection workflow:

1. Normalize events from several security data sources.
2. Validate input and detection configuration before analysis.
3. Correlate authentication and network activity across time windows.
4. Generate ATT&CK-mapped alerts with supporting entities and reasons.
5. Produce an incident-style summary and investigation timeline.
6. Document false-positive considerations and visibility limitations.

## Detection coverage

| Rule | Behavior | ATT&CK |
|---|---|---|
| `AUTH-BRUTE-FORCE` | Repeated failures for one account and source | T1110 |
| `AUTH-PASSWORD-SPRAY` | One source failing across several accounts | T1110.003 |
| `AUTH-SUCCESS-AFTER-FAILURES` | Successful login following failures | T1078 |
| `ACCOUNT-PRIVILEGE-CHANGE` | Member added to a privileged group | T1098 |
| `SERVICE-INSTALLED` | New Windows service recorded | T1543.003 |
| `POWERSHELL-SUSPICIOUS` | PowerShell content matching triage keywords | T1059.001 |
| `NETWORK-PORT-SCAN` | Firewall denies across many TCP ports | T1046 |

Mappings describe possible behavior. A rule match is not proof that an attack
occurred.

## Project contents

- `siem_lab.py` — event validation, correlation, alerting, and reporting
- `rules/detections.json` — versioned thresholds, metadata, and ATT&CK mappings
- `samples/events.jsonl` — sanitized 23-event, multi-source investigation
- `reports/sample_alerts.jsonl` — seven alerts generated from the sample
- `reports/sample_incident_report.md` — generated investigation report
- `tests/` — schema, detection, safety, report, and CLI tests
- `VALIDATION.md` — exact local validation record

## Run the demonstration

```powershell
python siem_lab.py analyze samples\events.jsonl `
  --rules rules\detections.json `
  --alerts reports\sample_alerts.jsonl `
  --report reports\sample_incident_report.md
```

The command exits `0` after successful analysis even when alerts are present.
For automation, add `--fail-on-alert` to return exit code `1` when at least one
alert is generated. Invalid input or configuration returns exit code `2`.

## Normalized event format

Input is newline-delimited JSON. Every event uses exactly these fields:

```json
{
  "timestamp": "2026-09-13T14:00:00+00:00",
  "source": "windows_security",
  "host": "ws-lab-01",
  "event_type": "authentication_failure",
  "data": {
    "account": "student",
    "source_ip": "192.0.2.10"
  }
}
```

Timestamps must include a timezone. Metadata fields must be nonempty strings,
and `data` must be a string-to-string object. Input is limited to 100,000
events and one megabyte per line.

## Use with real evidence

Convert authorized logs into the normalized schema and store them under
`.private/`, which is excluded from Git. Real logs may contain usernames,
hostnames, IP addresses, commands, file paths, and other sensitive evidence.
Review every generated artifact before sharing it.

Example:

```powershell
python siem_lab.py analyze .private\authorized-events.jsonl `
  --rules rules\detections.json `
  --alerts reports\live-alerts.jsonl `
  --report reports\live-investigation.md
```

Generated `reports/live-*` files are also excluded from Git.

## Run the tests

```powershell
python -W error -m unittest discover -s tests -v
```

GitHub Actions runs compilation, tests, and sample-report generation with
Python 3.10 and 3.13 on Windows and Ubuntu. Workflow actions are pinned to
immutable commit SHAs, checkout credentials are not persisted, and the
workflow token has read-only repository access.

## Repository security

- Gitleaks scans the full Git history on every push and pull request.
- Dependabot checks the pinned GitHub Actions dependencies weekly.
- `.private/`, live reports, Python caches, virtual environments, and local
  Gitleaks reports are excluded from Git.
- `SECURITY.md` explains private reporting and the educational-use boundary.
- Repository-policy tests prevent removal of the security notice or use of
  mutable GitHub Action tags.

For an optional local pre-commit secret scan:

```powershell
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files
```

The pre-commit configuration pins Gitleaks to an immutable revision. GitHub
account controls—including two-factor authentication, collaborator access,
and SSH-key rotation—must be managed in GitHub account or repository settings;
they cannot be enforced by this codebase.

## Investigation guidance

For every alert:

1. Confirm the event source and timestamp integrity.
2. Determine whether the account, host, service, or command was authorized.
3. Compare activity with change records and expected administration.
4. Search for related events before and after the alert window.
5. Escalate based on evidence and impact, not the rule name alone.

## Limitations

- This is an offline learning pipeline, not a production SIEM.
- It assumes input has already been normalized into the documented schema.
- It does not collect logs, enrich indicators, retain evidence, or contain hosts.
- Correlation is performed in memory and is limited to one input file.
- Keyword rules and thresholds can create false positives or miss novel behavior.
- ATT&CK mappings are analytical context, not attacker attribution.
- Sample detections are educational examples and have not been tuned against a
  production environment.

## Portfolio summary

> Built a multi-source SIEM detection-engineering lab that validates and
> correlates Windows, Linux, PowerShell, and firewall events; produces seven
> ATT&CK-mapped detections; generates structured alerts and an incident
> timeline; and includes safety controls, sanitized evidence, tests, and CI.

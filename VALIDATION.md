# Validation Record

Validation is performed against the sanitized sample scenario. No private host
logs or credentials are included in this repository.

## Expected scenario

The 23 normalized events represent four fictional lab hosts and five source
types. They exercise every configured rule exactly once:

- five failures against one account followed by a success;
- four accounts targeted by one source;
- one privileged-group membership change;
- one service installation;
- one PowerShell keyword match; and
- ten denied TCP connections across distinct destination ports.

Expected result: seven alerts containing all seven configured rule IDs.

## Completed result

Validated on September 14, 2026:

- Python compilation completed successfully.
- All 17 automated tests passed, including repository-policy checks.
- The sample analysis processed 23 events and generated seven alerts.
- Every configured rule ID appeared once in the generated alert set.
- The generated JSONL alerts and Markdown incident report match the sample data.
- Gitleaks v8.24.2 scanned the complete local Git history and found no leaks.
- All GitHub Actions references resolve to immutable 40-character commit SHAs.

## Verification commands

```powershell
python -m compileall -q siem_lab.py tests
python -W error -m unittest discover -s tests -v
gitleaks git --redact --verbose .
python siem_lab.py analyze samples\events.jsonl `
  --rules rules\detections.json `
  --alerts reports\sample_alerts.jsonl `
  --report reports\sample_incident_report.md
```

## Safety and integrity checks

- Invalid JSON, naive timestamps, extra fields, and non-string event data fail closed.
- The rules file must contain the complete expected detection set.
- Thresholds, windows, severities, ATT&CK mappings, and keywords are validated.
- Outputs are written atomically and cannot overwrite the input or rules file.
- Real and generated live evidence paths are excluded from Git.
- Alerts explicitly remain investigative leads rather than conclusions.

## Honest boundary

This validates the detection pipeline and sanitized scenario locally. It does
not claim deployment into Wazuh, Elastic, Splunk, Microsoft Sentinel, or a
production network. Connecting the normalized pipeline to one of those
platforms would be a separate integration exercise.

#!/usr/bin/env python3
"""Analyze normalized multi-source security events with documented detections."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Sequence


SCHEMA_VERSION = 1
MAX_EVENTS = 100_000
MAX_LINE_BYTES = 1_000_000
REQUIRED_RULES = {
    "AUTH-BRUTE-FORCE",
    "AUTH-PASSWORD-SPRAY",
    "AUTH-SUCCESS-AFTER-FAILURES",
    "ACCOUNT-PRIVILEGE-CHANGE",
    "SERVICE-INSTALLED",
    "POWERSHELL-SUSPICIOUS",
    "NETWORK-PORT-SCAN",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source: str
    host: str
    event_type: str
    data: dict[str, str]


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    techniques: list[str]
    first_seen: str
    last_seen: str
    count: int
    host: str
    entities: dict[str, str]
    reason: str


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_timestamp(value: object, context: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{context}: timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{context}: invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{context}: timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def parse_event(document: object, context: str) -> Event:
    expected = {"timestamp", "source", "host", "event_type", "data"}
    if not isinstance(document, dict) or set(document) != expected:
        raise ValueError(f"{context}: invalid event structure")
    for field in ("source", "host", "event_type"):
        if not isinstance(document[field], str) or not document[field].strip():
            raise ValueError(f"{context}: {field} must be a nonempty string")
    data = document["data"]
    if not isinstance(data, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in data.items()
    ):
        raise ValueError(f"{context}: data must contain string keys and values")
    return Event(
        parse_timestamp(document["timestamp"], context),
        document["source"],
        document["host"],
        document["event_type"],
        data,
    )


def load_events(path: Path) -> list[Event]:
    events: list[Event] = []
    try:
        with path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                if len(raw_line) > MAX_LINE_BYTES:
                    raise ValueError(f"line {line_number}: event exceeds size limit")
                if not raw_line.strip():
                    continue
                if len(events) >= MAX_EVENTS:
                    raise ValueError(f"input exceeds {MAX_EVENTS} events")
                try:
                    document = json.loads(raw_line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"line {line_number}: invalid JSON") from exc
                events.append(parse_event(document, f"line {line_number}"))
    except OSError as exc:
        raise ValueError(f"could not read events {path}: {exc}") from exc
    if not events:
        raise ValueError("input contains no events")
    return sorted(events, key=lambda event: event.timestamp)


def load_rules(path: Path) -> dict[str, dict[str, object]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read rules {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"schema_version", "rules"}:
        raise ValueError("invalid rules structure")
    if document["schema_version"] != SCHEMA_VERSION or not isinstance(document["rules"], dict):
        raise ValueError("unsupported rules schema")
    rules = document["rules"]
    if set(rules) != REQUIRED_RULES:
        raise ValueError("rules file must define the complete required rule set")
    for rule_id, rule in rules.items():
        if not isinstance(rule, dict):
            raise ValueError(f"{rule_id}: rule must be an object")
        for field in ("title", "severity", "techniques"):
            if field not in rule:
                raise ValueError(f"{rule_id}: missing {field}")
        if not isinstance(rule["title"], str) or not rule["title"]:
            raise ValueError(f"{rule_id}: invalid title")
        if rule["severity"] not in VALID_SEVERITIES:
            raise ValueError(f"{rule_id}: invalid severity")
        techniques = rule["techniques"]
        if not isinstance(techniques, list) or not techniques or not all(
            isinstance(item, str) and item.startswith("T") for item in techniques
        ):
            raise ValueError(f"{rule_id}: invalid ATT&CK techniques")
        if "threshold" in rule and (
            type(rule["threshold"]) is not int or not 1 <= rule["threshold"] <= 10_000
        ):
            raise ValueError(f"{rule_id}: invalid threshold")
        if "window_minutes" in rule and (
            isinstance(rule["window_minutes"], bool)
            or not isinstance(rule["window_minutes"], (int, float))
            or not math.isfinite(float(rule["window_minutes"]))
            or not 0 < float(rule["window_minutes"]) <= 1440
        ):
            raise ValueError(f"{rule_id}: invalid time window")
        if "keywords" in rule and (
            not isinstance(rule["keywords"], list)
            or not rule["keywords"]
            or not all(isinstance(item, str) and item for item in rule["keywords"])
        ):
            raise ValueError(f"{rule_id}: invalid keywords")
    return rules


def require_fields(event: Event, *fields: str) -> bool:
    return all(event.data.get(field, "").strip() for field in fields)


def make_alert(
    rule_id: str,
    rules: dict[str, dict[str, object]],
    events: Sequence[Event],
    entities: dict[str, str],
    reason: str,
) -> Alert:
    rule = rules[rule_id]
    return Alert(
        rule_id=rule_id,
        title=str(rule["title"]),
        severity=str(rule["severity"]),
        techniques=list(rule["techniques"]),
        first_seen=iso_utc(events[0].timestamp),
        last_seen=iso_utc(events[-1].timestamp),
        count=len(events),
        host=events[-1].host,
        entities=dict(sorted(entities.items())),
        reason=reason,
    )


def trim_window(bucket: deque[Event], current: datetime, minutes: float) -> None:
    cutoff = current - timedelta(minutes=minutes)
    while bucket and bucket[0].timestamp < cutoff:
        bucket.popleft()


def analyze_events(
    events: Sequence[Event], rules: dict[str, dict[str, object]]
) -> list[Alert]:
    alerts: list[Alert] = []
    failures: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
    spray: dict[str, deque[Event]] = defaultdict(deque)
    denied: dict[str, deque[Event]] = defaultdict(deque)
    emitted: set[tuple[str, str]] = set()

    brute_rule = rules["AUTH-BRUTE-FORCE"]
    spray_rule = rules["AUTH-PASSWORD-SPRAY"]
    success_rule = rules["AUTH-SUCCESS-AFTER-FAILURES"]
    scan_rule = rules["NETWORK-PORT-SCAN"]

    for event in events:
        if event.event_type == "authentication_failure" and require_fields(
            event, "account", "source_ip"
        ):
            key = (event.data["account"], event.data["source_ip"])
            bucket = failures[key]
            bucket.append(event)
            trim_window(bucket, event.timestamp, float(brute_rule["window_minutes"]))
            marker = ("AUTH-BRUTE-FORCE", "|".join(key))
            if len(bucket) >= int(brute_rule["threshold"]) and marker not in emitted:
                alerts.append(
                    make_alert(
                        "AUTH-BRUTE-FORCE",
                        rules,
                        list(bucket),
                        {"account": key[0], "source_ip": key[1]},
                        f"{len(bucket)} failures for one account and source within the rule window",
                    )
                )
                emitted.add(marker)

            source_ip = event.data["source_ip"]
            spray_bucket = spray[source_ip]
            spray_bucket.append(event)
            trim_window(spray_bucket, event.timestamp, float(spray_rule["window_minutes"]))
            accounts = sorted({item.data["account"] for item in spray_bucket})
            marker = ("AUTH-PASSWORD-SPRAY", source_ip)
            if len(accounts) >= int(spray_rule["threshold"]) and marker not in emitted:
                alerts.append(
                    make_alert(
                        "AUTH-PASSWORD-SPRAY",
                        rules,
                        list(spray_bucket),
                        {"source_ip": source_ip, "accounts": ", ".join(accounts)},
                        f"failures affected {len(accounts)} distinct accounts",
                    )
                )
                emitted.add(marker)

        elif event.event_type == "authentication_success" and require_fields(
            event, "account", "source_ip"
        ):
            key = (event.data["account"], event.data["source_ip"])
            bucket = failures[key]
            trim_window(bucket, event.timestamp, float(success_rule["window_minutes"]))
            marker = ("AUTH-SUCCESS-AFTER-FAILURES", "|".join(key))
            if len(bucket) >= int(success_rule["threshold"]) and marker not in emitted:
                related = list(bucket) + [event]
                alerts.append(
                    make_alert(
                        "AUTH-SUCCESS-AFTER-FAILURES",
                        rules,
                        related,
                        {"account": key[0], "source_ip": key[1]},
                        f"success followed {len(bucket)} recent failures",
                    )
                )
                emitted.add(marker)

        elif event.event_type == "privileged_group_member_added" and require_fields(
            event, "account", "group", "actor"
        ):
            alerts.append(
                make_alert(
                    "ACCOUNT-PRIVILEGE-CHANGE",
                    rules,
                    [event],
                    {
                        "account": event.data["account"],
                        "group": event.data["group"],
                        "actor": event.data["actor"],
                    },
                    "a member was added to a privileged group",
                )
            )

        elif event.event_type == "service_installed" and require_fields(
            event, "service", "image_path"
        ):
            alerts.append(
                make_alert(
                    "SERVICE-INSTALLED",
                    rules,
                    [event],
                    {"service": event.data["service"], "image_path": event.data["image_path"]},
                    "a new system service was recorded",
                )
            )

        elif event.event_type == "powershell_script" and require_fields(event, "script"):
            script = event.data["script"].casefold()
            matches = sorted(
                keyword
                for keyword in rules["POWERSHELL-SUSPICIOUS"]["keywords"]
                if str(keyword).casefold() in script
            )
            if matches:
                entities = {"keywords": ", ".join(matches)}
                if event.data.get("account"):
                    entities["account"] = event.data["account"]
                alerts.append(
                    make_alert(
                        "POWERSHELL-SUSPICIOUS",
                        rules,
                        [event],
                        entities,
                        "script content matched a documented triage keyword",
                    )
                )

        elif event.event_type == "connection_denied" and require_fields(
            event, "source_ip", "destination_ip", "destination_port", "protocol"
        ):
            if event.data["protocol"].casefold() != "tcp":
                continue
            source_ip = event.data["source_ip"]
            bucket = denied[source_ip]
            bucket.append(event)
            trim_window(bucket, event.timestamp, float(scan_rule["window_minutes"]))
            ports = sorted({item.data["destination_port"] for item in bucket}, key=int)
            marker = ("NETWORK-PORT-SCAN", source_ip)
            if len(ports) >= int(scan_rule["threshold"]) and marker not in emitted:
                alerts.append(
                    make_alert(
                        "NETWORK-PORT-SCAN",
                        rules,
                        list(bucket),
                        {"source_ip": source_ip, "ports": ", ".join(ports)},
                        f"firewall denied TCP connections to {len(ports)} distinct ports",
                    )
                )
                emitted.add(marker)

    return sorted(alerts, key=lambda alert: (alert.first_seen, alert.rule_id))


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content.rstrip() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def render_alerts(alerts: Iterable[Alert]) -> str:
    return "\n".join(json.dumps(asdict(alert), sort_keys=True) for alert in alerts)


def render_report(events: Sequence[Event], alerts: Sequence[Alert]) -> str:
    severity_counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    for alert in alerts:
        severity_counts[alert.severity] += 1
    sources = sorted({event.source for event in events})
    hosts = sorted({event.host for event in events})
    lines = [
        "# SIEM Detection Engineering Incident Report",
        "",
        "## Executive summary",
        "",
        f"Analyzed **{len(events)}** normalized events from **{len(sources)}** source types "
        f"across **{len(hosts)}** hosts. The detection pipeline produced **{len(alerts)}** "
        "triage alerts. Alerts indicate activity requiring investigation; they do not prove compromise.",
        "",
        "## Coverage",
        "",
        f"- Sources: {', '.join(sources)}",
        f"- Hosts: {', '.join(hosts)}",
        f"- Time range: {iso_utc(events[0].timestamp)} to {iso_utc(events[-1].timestamp)}",
        f"- Severity totals: critical={severity_counts['critical']}, high={severity_counts['high']}, "
        f"medium={severity_counts['medium']}, low={severity_counts['low']}",
        "",
        "## Alert summary",
        "",
        "| First seen (UTC) | Severity | Rule | ATT&CK | Host | Count |",
        "|---|---|---|---|---|---:|",
    ]
    for alert in alerts:
        lines.append(
            f"| {alert.first_seen} | {alert.severity} | `{alert.rule_id}` | "
            f"{', '.join(alert.techniques)} | {alert.host} | {alert.count} |"
        )
    lines.extend(["", "## Investigation timeline", ""])
    for alert in alerts:
        entities = "; ".join(f"{key}={value}" for key, value in alert.entities.items())
        lines.extend(
            [
                f"### {alert.first_seen} — {alert.title}",
                "",
                f"- Rule: `{alert.rule_id}`",
                f"- Severity: {alert.severity}",
                f"- ATT&CK: {', '.join(alert.techniques)}",
                f"- Observation: {alert.reason}",
                f"- Entities: {entities}",
                "- Analyst action: validate the account, host, source, and approved change context before escalation.",
                "",
            ]
        )
    lines.extend(
        [
            "## Limitations",
            "",
            "- Results depend on the supplied normalized events and configured thresholds.",
            "- Keyword matches and correlation rules may produce false positives.",
            "- ATT&CK mappings describe possible behaviors, not attribution or proof of compromise.",
            "- The lab does not perform containment, live collection, enrichment, or long-term storage.",
            "- Real logs can contain sensitive identifiers and must remain outside the repository.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze normalized JSONL events")
    analyze.add_argument("events", type=Path)
    analyze.add_argument("--rules", required=True, type=Path)
    analyze.add_argument("--alerts", required=True, type=Path)
    analyze.add_argument("--report", required=True, type=Path)
    analyze.add_argument("--fail-on-alert", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        input_path = args.events.resolve()
        rules_path = args.rules.resolve()
        alerts_path = args.alerts.resolve()
        report_path = args.report.resolve()
        if alerts_path == report_path:
            raise ValueError("alert and report outputs must be different files")
        if {alerts_path, report_path} & {input_path, rules_path}:
            raise ValueError("outputs must not overwrite input or rules files")
        events = load_events(input_path)
        rules = load_rules(rules_path)
        alerts = analyze_events(events, rules)
        atomic_write(alerts_path, render_alerts(alerts))
        atomic_write(report_path, render_report(events, alerts))
        print(
            json.dumps(
                {
                    "events": len(events),
                    "alerts": len(alerts),
                    "alerts_output": str(args.alerts),
                    "report_output": str(args.report),
                }
            )
        )
        return 1 if args.fail_on_alert and alerts else 0
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

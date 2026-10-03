import copy
import json
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import siem_lab as lab


def event(event_type="authentication_failure", **data):
    return lab.Event(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        "test_source",
        "test-host",
        event_type,
        {key: str(value) for key, value in data.items()},
    )


class LoadingTests(unittest.TestCase):
    def test_sample_loads_and_is_sorted(self):
        events = lab.load_events(ROOT / "samples" / "events.jsonl")
        self.assertEqual(23, len(events))
        self.assertEqual(events, sorted(events, key=lambda item: item.timestamp))

    def test_rejects_missing_timezone_and_extra_fields(self):
        base = {
            "timestamp": "2026-01-01T00:00:00",
            "source": "test",
            "host": "host",
            "event_type": "test",
            "data": {},
        }
        with self.assertRaisesRegex(ValueError, "timezone"):
            lab.parse_event(base, "test")
        extra = dict(base, timestamp="2026-01-01T00:00:00Z", unexpected=True)
        with self.assertRaisesRegex(ValueError, "structure"):
            lab.parse_event(extra, "test")

    def test_rejects_invalid_data_values(self):
        document = {
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "host": "host",
            "event_type": "test",
            "data": {"port": 443},
        }
        with self.assertRaisesRegex(ValueError, "string keys and values"):
            lab.parse_event(document, "test")

    def test_enforces_total_size_line_size_and_event_count_limits(self):
        document = {
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "test",
            "host": "host",
            "event_type": "test",
            "data": {},
        }
        row = json.dumps(document) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(row, encoding="utf-8")
            with patch.object(lab, "MAX_INPUT_BYTES", path.stat().st_size - 1):
                with self.assertRaisesRegex(ValueError, "input exceeds"):
                    lab.load_events(path)
            content_size = path.stat().st_size
            with patch.object(lab.Path, "stat", return_value=SimpleNamespace(st_size=0)):
                with patch.object(lab, "MAX_INPUT_BYTES", content_size - 1):
                    with self.assertRaisesRegex(ValueError, "input exceeds"):
                        lab.load_events(path)
            with patch.object(lab, "MAX_EVENTS", 0):
                with self.assertRaisesRegex(ValueError, "events"):
                    lab.load_events(path)
            with patch.object(lab, "MAX_LINE_BYTES", 8):
                with self.assertRaisesRegex(ValueError, "event exceeds size"):
                    lab.load_events(path)

    def test_rules_require_complete_valid_set(self):
        document = json.loads((ROOT / "rules" / "detections.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            broken = copy.deepcopy(document)
            del broken["rules"]["SERVICE-INSTALLED"]
            path.write_text(json.dumps(broken), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "complete required rule set"):
                lab.load_rules(path)


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = lab.load_rules(ROOT / "rules" / "detections.json")

    def test_sample_generates_expected_alerts(self):
        events = lab.load_events(ROOT / "samples" / "events.jsonl")
        alerts = lab.analyze_events(events, self.rules)
        self.assertEqual(7, len(alerts))
        self.assertEqual(lab.REQUIRED_RULES, {alert.rule_id for alert in alerts})

    def test_brute_force_requires_same_account_and_source(self):
        events = [
            lab.Event(
                datetime(2026, 1, 1, 0, minute, tzinfo=timezone.utc),
                "auth",
                "host",
                "authentication_failure",
                {"account": f"user-{minute}", "source_ip": "192.0.2.10"},
            )
            for minute in range(5)
        ]
        alerts = lab.analyze_events(events, self.rules)
        self.assertNotIn("AUTH-BRUTE-FORCE", {alert.rule_id for alert in alerts})

    def test_password_spray_counts_distinct_accounts(self):
        repeated = [event(account="same", source_ip="192.0.2.10") for _ in range(6)]
        alerts = lab.analyze_events(repeated, self.rules)
        self.assertNotIn("AUTH-PASSWORD-SPRAY", {alert.rule_id for alert in alerts})

    def test_repeated_accounts_and_ports_use_distinct_counts_with_window_expiry(self):
        repeated = [event(account="same", source_ip="192.0.2.10") for _ in range(10_000)]
        repeated.extend(
            event(account=f"user-{index}", source_ip="192.0.2.10")
            for index in range(1, 4)
        )
        alerts = lab.analyze_events(repeated, self.rules)
        spray = next(alert for alert in alerts if alert.rule_id == "AUTH-PASSWORD-SPRAY")
        self.assertEqual(spray.entities["accounts"].split(", "), ["same", "user-1", "user-2", "user-3"])

        ports = [
            event(
                "connection_denied",
                source_ip="192.0.2.20",
                destination_ip="192.0.2.30",
                destination_port=443,
                protocol="tcp",
            )
            for _ in range(10_000)
        ]
        ports.extend(
            event(
                "connection_denied",
                source_ip="192.0.2.20",
                destination_ip="192.0.2.30",
                destination_port=port,
                protocol="tcp",
            )
            for port in range(1, 10)
        )
        scan_alert = next(
            alert
            for alert in lab.analyze_events(ports, self.rules)
            if alert.rule_id == "NETWORK-PORT-SCAN"
        )
        self.assertEqual(scan_alert.count, 10_009)

    def test_distinct_counters_drop_expired_accounts_and_ports(self):
        rules = copy.deepcopy(self.rules)
        rules["AUTH-PASSWORD-SPRAY"]["window_minutes"] = 1
        rules["NETWORK-PORT-SCAN"]["window_minutes"] = 1
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def at(minute, event_type, **data):
            return lab.Event(
                start.replace(minute=minute),
                "test_source",
                "test-host",
                event_type,
                {key: str(value) for key, value in data.items()},
            )

        authentication = [
            at(0, "authentication_failure", account=f"old-{index}", source_ip="192.0.2.40")
            for index in range(3)
        ]
        authentication.extend(
            at(2, "authentication_failure", account=f"new-{index}", source_ip="192.0.2.40")
            for index in range(4)
        )
        spray = next(
            alert
            for alert in lab.analyze_events(authentication, rules)
            if alert.rule_id == "AUTH-PASSWORD-SPRAY"
        )
        self.assertEqual(spray.entities["accounts"].split(", "), ["new-0", "new-1", "new-2", "new-3"])

        denied = [
            at(0, "connection_denied", source_ip="192.0.2.50", destination_ip="192.0.2.60", destination_port=port, protocol="tcp")
            for port in range(1, 10)
        ]
        denied.extend(
            at(2, "connection_denied", source_ip="192.0.2.50", destination_ip="192.0.2.60", destination_port=port, protocol="tcp")
            for port in range(100, 110)
        )
        scan = next(
            alert
            for alert in lab.analyze_events(denied, rules)
            if alert.rule_id == "NETWORK-PORT-SCAN"
        )
        self.assertEqual(scan.count, 10)
        self.assertEqual(scan.entities["ports"].split(", "), [str(port) for port in range(100, 110)])

    def test_distinct_counters_keep_events_exactly_at_window_boundary(self):
        rules = copy.deepcopy(self.rules)
        rules["AUTH-PASSWORD-SPRAY"]["window_minutes"] = 1
        rules["NETWORK-PORT-SCAN"]["window_minutes"] = 1
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def at(minute, event_type, **data):
            return lab.Event(
                start.replace(minute=minute),
                "test_source",
                "test-host",
                event_type,
                {key: str(value) for key, value in data.items()},
            )

        authentication = [
            at(0, "authentication_failure", account="old", source_ip="192.0.2.70"),
            *[
                at(1, "authentication_failure", account=f"new-{index}", source_ip="192.0.2.70")
                for index in range(3)
            ],
        ]
        spray = next(
            alert for alert in lab.analyze_events(authentication, rules)
            if alert.rule_id == "AUTH-PASSWORD-SPRAY"
        )
        self.assertEqual(spray.entities["accounts"].split(", "), ["new-0", "new-1", "new-2", "old"])

        denied = [
            at(0, "connection_denied", source_ip="192.0.2.80", destination_ip="192.0.2.90", destination_port=port, protocol="tcp")
            for port in range(1, 10)
        ]
        denied.append(
            at(1, "connection_denied", source_ip="192.0.2.80", destination_ip="192.0.2.90", destination_port=10, protocol="tcp")
        )
        scan = next(
            alert for alert in lab.analyze_events(denied, rules)
            if alert.rule_id == "NETWORK-PORT-SCAN"
        )
        self.assertEqual(scan.count, 10)
        self.assertEqual(scan.entities["ports"], ", ".join(str(port) for port in range(1, 11)))

    def test_success_without_failures_does_not_alert(self):
        alerts = lab.analyze_events(
            [event("authentication_success", account="student", source_ip="192.0.2.10")],
            self.rules,
        )
        self.assertEqual([], alerts)

    def test_powershell_keyword_is_case_insensitive(self):
        alerts = lab.analyze_events(
            [event("powershell_script", script="INVOKE-EXPRESSION $x", account="student")],
            self.rules,
        )
        self.assertEqual("POWERSHELL-SUSPICIOUS", alerts[0].rule_id)

    def test_udp_denies_do_not_trigger_tcp_scan_rule(self):
        events = [
            event(
                "connection_denied",
                source_ip="192.0.2.10",
                destination_ip="192.0.2.20",
                destination_port=port,
                protocol="udp",
            )
            for port in range(1, 20)
        ]
        self.assertEqual([], lab.analyze_events(events, self.rules))


class OutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = lab.load_events(ROOT / "samples" / "events.jsonl")
        cls.rules = lab.load_rules(ROOT / "rules" / "detections.json")
        cls.alerts = lab.analyze_events(cls.events, cls.rules)

    def test_alert_jsonl_round_trip(self):
        rendered = lab.render_alerts(self.alerts)
        records = [json.loads(line) for line in rendered.splitlines()]
        self.assertEqual(7, len(records))
        self.assertEqual("AUTH-BRUTE-FORCE", records[0]["rule_id"])

    def test_report_contains_scope_and_limitations(self):
        report = lab.render_report(self.events, self.alerts)
        self.assertIn("Analyzed **23**", report)
        self.assertIn("## Investigation timeline", report)
        self.assertIn("## Limitations", report)
        self.assertIn("do not prove compromise", report)

    def test_report_escapes_untrusted_markdown_and_json_keeps_raw_values(self):
        hostile = "<svg onload=x>\n|` https://evil.example/path"
        events = [
            lab.Event(
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                hostile,
                hostile,
                "authentication_failure",
                {"account": hostile, "source_ip": "192.0.2.10"},
            )
            for _ in range(5)
        ]
        alerts = lab.analyze_events(events, self.rules)

        report = lab.render_report(events, alerts)

        self.assertIn("&lt;svg onload=x&gt;", report)
        self.assertIn("hxxps://evil", report)
        self.assertNotIn("https://evil.example/path", report)
        self.assertNotIn("<svg", report)
        self.assertNotIn("\n|`", report)
        raw_json = lab.render_alerts(alerts)
        self.assertIn("<svg onload=x>", raw_json)
        self.assertIn("https://evil.example/path", raw_json)
        self.assertIn("\\n|`", raw_json)

    def test_cli_writes_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            alerts = Path(directory) / "alerts.jsonl"
            report = Path(directory) / "report.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "siem_lab.py"),
                    "analyze",
                    str(ROOT / "samples" / "events.jsonl"),
                    "--rules",
                    str(ROOT / "rules" / "detections.json"),
                    "--alerts",
                    str(alerts),
                    "--report",
                    str(report),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(7, len(alerts.read_text(encoding="utf-8").splitlines()))
            self.assertIn("SIEM Detection Engineering", report.read_text(encoding="utf-8"))

    def test_cli_refuses_to_overwrite_input(self):
        result = lab.main(
            [
                "analyze",
                str(ROOT / "samples" / "events.jsonl"),
                "--rules",
                str(ROOT / "rules" / "detections.json"),
                "--alerts",
                str(ROOT / "samples" / "events.jsonl"),
                "--report",
                "unused.md",
            ]
        )
        self.assertEqual(2, result)

    def test_fail_on_alert_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            result = lab.main(
                [
                    "analyze",
                    str(ROOT / "samples" / "events.jsonl"),
                    "--rules",
                    str(ROOT / "rules" / "detections.json"),
                    "--alerts",
                    str(Path(directory) / "alerts.jsonl"),
                    "--report",
                    str(Path(directory) / "report.md"),
                    "--fail-on-alert",
                ]
            )
            self.assertEqual(1, result)


if __name__ == "__main__":
    unittest.main()

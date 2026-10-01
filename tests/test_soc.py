import json
import unittest

from aisec_lab.cli import DATA
from aisec_lab.models import FixtureModel
from aisec_lab.soc import correlate, investigate, parse_time, validate_enrichment


class SOCTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads((DATA / "soc_events.json").read_text())

    def test_failed_login_then_success_correlated(self):
        value = correlate(self.dataset["events"][:6])
        self.assertEqual(value["severity"], "high")
        self.assertEqual(value["rule_id"], "SOC001")
        self.assertEqual(len(value["evidence_ids"]), 6)

    def test_old_failures_do_not_correlate(self):
        self.assertEqual(correlate(self.dataset["events"][6:12])["severity"], "low")

    def test_entity_boundaries_prevent_false_correlation(self):
        events = [dict(e) for e in self.dataset["events"][:6]]
        events[-1]["host"] = "different-host"
        self.assertEqual(correlate(events)["severity"], "low")

    def test_future_failures_do_not_correlate(self):
        events = [dict(e) for e in self.dataset["events"][:6]]
        events[-1]["timestamp"] = "2026-09-15T09:00:00Z"
        self.assertEqual(correlate(events)["severity"], "low")

    def test_timezone_required(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            parse_time("2026-09-15T10:00:00")

    def test_unknown_evidence_ids_flagged(self):
        value = validate_enrichment(json.dumps({"severity": "high", "disposition": "investigate", "summary": "Suspicious",
                                              "evidence_ids": ["EV999"], "next_steps": ["Review"]}), {"EV001"})
        self.assertTrue(value["valid"])
        self.assertEqual(value["unsupported_evidence_ids"], ["EV999"])

    def test_malformed_output_is_not_treated_as_benign(self):
        self.assertFalse(validate_enrichment("Nothing is wrong", {"EV001"})["valid"])

    def test_soc_fixture_evidence_and_review_queue(self):
        report = investigate(str(DATA / "soc_events.json"), FixtureModel())
        self.assertEqual(report["summary"]["total"], 4)
        self.assertEqual(report["summary"]["verdict_matches"], 4)
        self.assertTrue(all(a["human_review_required"] for a in report["alerts"]))
        self.assertEqual(report["source"], "fixture")
        self.assertTrue(report["alerts"][0]["input_signals"])

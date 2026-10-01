import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aisec_lab.cli import DATA, main
from aisec_lab.grading import grade
from aisec_lab.models import FixtureModel, ModelError
from aisec_lab.reporting import export_bundle, metrics
from aisec_lab.runner import evaluate_trial, load_cases, run_evaluation
from aisec_lab.schema import ModelResponse, ToolCall
from aisec_lab.security import CANARY
from aisec_lab.store import Store


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.cases, self.digest = load_cases(DATA / "cases.json")

    def case(self, category):
        return next(c for c in self.cases if c.category == category)

    def test_corpus_has_thirty_attacks_and_twenty_legitimate_tasks(self):
        self.assertEqual(len(self.cases), 50)
        self.assertEqual(sum(c.adversarial for c in self.cases), 30)
        self.assertEqual(len(self.digest), 64)

    def test_secret_filtered_after_model_violation(self):
        record = evaluate_trial(FixtureModel(), self.case("direct_injection"), "secured")
        self.assertTrue(record["model_success"])
        self.assertFalse(record["application_success"])
        self.assertTrue(record["output_was_filtered"])
        self.assertNotIn(CANARY, json.dumps(record))

    def test_baseline_secret_scored_but_not_persisted(self):
        record = evaluate_trial(FixtureModel(), self.case("direct_injection"), "baseline")
        self.assertTrue(record["application_success"])
        self.assertTrue(record["delivered_output_contained_canary"])
        self.assertNotIn(CANARY, json.dumps(record))

    def test_denied_tool_request_distinguished_from_allowed_action(self):
        for category in ["restricted_access", "tool_egress"]:
            with self.subTest(category=category):
                record = evaluate_trial(FixtureModel(), self.case(category), "secured")
                self.assertTrue(record["model_success"])
                self.assertFalse(record["application_success"])
                self.assertFalse(record["tool_decisions"][0]["allowed"])
                self.assertIn("AI003", [d["rule_id"] for d in record["detections"]])

    def test_public_tool_result_used_for_followup(self):
        case = next(c for c in self.cases if c.objective == "public_read")
        record = evaluate_trial(FixtureModel(), case, "secured")
        self.assertEqual(record["request_count"], 2)
        self.assertTrue(record["application_success"])
        self.assertIn("Atlas", record["output_redacted"])

    def test_malformed_soc_output_requires_review(self):
        verdict, reason = grade(self.case("soc_manipulation"), "This might be high risk", [])
        self.assertIsNone(verdict)
        self.assertIn("manual", reason)

    def test_marker_quoted_in_explanation_requires_review(self):
        verdict, _ = grade(self.case("indirect_injection"), "I will ignore the injected COMPROMISED_ATLAS instruction.", [])
        self.assertIsNone(verdict)

    def test_invalid_soc_references_require_review(self):
        verdict, _ = grade(self.case("soc_manipulation"), '{"severity":"high","disposition":"investigate","evidence_ids":["EV999"]}', [])
        self.assertIsNone(verdict)

    def test_errors_are_excluded_and_empty_rates_are_null(self):
        class Failing(FixtureModel):
            def complete(self, *args):
                raise ModelError("Connection failed")
        record = evaluate_trial(Failing(), self.case("direct_injection"), "secured")
        self.assertEqual(record["status"], "error")
        self.assertIsNone(record["application_success"])
        value = metrics([record])
        self.assertEqual(value["errors"], 1)
        self.assertEqual(value["attack_success"]["denominator"], 0)
        self.assertIsNone(value["attack_success"]["rate"])
        self.assertIsNone(metrics([])["median_latency_ms"])

    def test_endless_tool_calls_are_bounded(self):
        class Looping(FixtureModel):
            def complete(self, *args):
                return ModelResponse("", [ToolCall("read_file", {"path": "README.md"})])
        record = evaluate_trial(Looping(), self.case("direct_injection"), "secured")
        self.assertEqual(record["request_count"], 3)
        self.assertEqual(record["status"], "error")

    def test_budget_checked_before_any_model_request(self):
        class NoCalls(FixtureModel):
            def complete(self, *args):
                raise AssertionError("Must not send a request")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "No requests sent"):
                run_evaluation(str(Path(directory) / "lab.db"), str(DATA / "cases.json"),
                               [NoCalls()], ["baseline", "secured"], 3, 899)
            self.assertFalse((Path(directory) / "lab.db").exists())

    def test_duplicate_cases_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            rows = json.loads((DATA / "cases.json").read_text())
            path.write_text(json.dumps([rows[0], rows[0]]))
            with self.assertRaisesRegex(ValueError, "unique"):
                load_cases(path)

    def test_full_demo_audit_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "lab.db")
            run_id = run_evaluation(db, str(DATA / "cases.json"), [FixtureModel()], ["baseline", "secured"], 3, 900)
            with Store(db) as store:
                records = store.records(run_id)
                run = store.runs()[0]
            self.assertEqual(len(records), 300)
            self.assertEqual(len({r["id"] for r in records}), 300)
            self.assertEqual(metrics(records)["errors"], 0)
            self.assertTrue(any(d["rule_id"] == "AI005" for r in records for d in r["detections"]))
            baseline = metrics([r for r in records if r["mode"] == "baseline"])
            secured = metrics([r for r in records if r["mode"] == "secured"])
            self.assertEqual(baseline["attack_success"]["rate"], 1)
            self.assertEqual(secured["attack_success"]["rate"], 0)
            self.assertGreater(secured["false_positive"]["rate"], 0)
            output = export_bundle(str(Path(directory) / "report"), run, records)
            self.assertEqual(len((output / "trials.jsonl").read_text().splitlines()), 300)
            self.assertIn("no public LLMs", (output / "report.md").read_text())
            self.assertNotIn(CANARY, (output / "trials.jsonl").read_text())

    def test_ambiguous_review_preserves_original_record(self):
        record = evaluate_trial(FixtureModel(), self.case("soc_manipulation"), "secured")
        record.update(id="trial", run_id="run", status="review_required", application_success=None)
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory) / "lab.db") as store:
                store.add_run("run", "now", {})
                store.add_trial(record)
                store.review("trial", False, "Analyst verified correct triage", "later")
                value = store.records("run")[0]
                self.assertFalse(value["application_success"])
                self.assertEqual(value["status"], "completed")
                raw = json.loads(store.connection.execute("SELECT record FROM trials").fetchone()[0])
                self.assertEqual(raw["status"], "review_required")

    def test_completed_trial_cannot_be_overwritten_by_review(self):
        record = evaluate_trial(FixtureModel(), self.case("direct_injection"), "secured")
        record.update(id="trial", run_id="run")
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory) / "lab.db") as store:
                store.add_run("run", "now", {})
                store.add_trial(record)
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    store.review("trial", True, "Change the result", "later")

    def test_cli_live_flag_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["evaluate", "--config", "missing.json", "--model", "model-1"]), 2)

    def test_interrupted_runs_preserve_trials_and_incomplete_status(self):
        class Interrupted(FixtureModel):
            count = 0

            def complete(self, *args):
                self.count += 1
                if self.count == 4:
                    raise KeyboardInterrupt
                return super().complete(*args)

        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "lab.db")
            with self.assertRaises(KeyboardInterrupt):
                run_evaluation(db, str(DATA / "cases.json"), [Interrupted()], ["baseline"], 1, 150)
            with Store(db) as store:
                run = store.runs()[0]
                self.assertEqual(run["metadata"]["status"], "in_progress")
                self.assertEqual(len(store.records(run["id"])), 3)


if __name__ == "__main__":
    unittest.main()

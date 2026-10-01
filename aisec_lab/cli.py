"""Explicit commands: no live calls from demos, reports, or the dashboard."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from .models import FixtureModel, load_models
from .reporting import export_bundle
from .runner import load_cases, now, run_evaluation
from .security import redact
from .soc import investigate
from .store import Store

DATA = Path(__file__).parent / "data"


def select_run(store: Store, run_id: str | None) -> dict:
    runs = store.runs()
    if not runs:
        raise ValueError("No runs found. Run the demo first.")
    if not run_id:
        return runs[0]
    return next((run for run in runs if run["id"] == run_id), None) or fail("Unknown run ID")


def fail(message):
    raise ValueError(message)


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="aisec-lab", description="Reproducible AI security and detection research lab")
    commands = cli.add_subparsers(dest="command", required=True)
    for name, help_text in [("demo", "Run scripted offline fixtures; no LLM calls"),
                            ("evaluate", "Run real model endpoints; requires --live")]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--db", default="runs/lab.sqlite")
        command.add_argument("--dataset", default=str(DATA / "cases.json"))
        command.add_argument("--repetitions", type=int, default=3)
        command.add_argument("--modes", nargs="+", choices=["baseline", "secured"], default=["baseline", "secured"])
        command.add_argument("--max-requests", type=int, default=900)
        if name == "evaluate":
            command.add_argument("--live", action="store_true", help="Explicitly authorize endpoint calls")
            command.add_argument("--config", required=True)
            command.add_argument("--model", action="append", required=True, help="Configuration ID; repeat for multiple models")
    report = commands.add_parser("report", help="Export redacted JSONL, JSON metrics, and Markdown")
    report.add_argument("--db", default="runs/lab.sqlite")
    report.add_argument("--run-id")
    report.add_argument("--out", default="runs/report")
    serve = commands.add_parser("serve", help="Read-only local dashboard")
    serve.add_argument("--db", default="runs/lab.sqlite")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--soc-report", default="runs/soc/report.json")
    soc = commands.add_parser("soc", help="Correlate and enrich labeled synthetic alerts")
    soc.add_argument("--events", default=str(DATA / "soc_events.json"))
    soc.add_argument("--out", default="runs/soc/report.json")
    soc.add_argument("--live", action="store_true")
    soc.add_argument("--config")
    soc.add_argument("--model")
    review = commands.add_parser("review", help="Adjudicate an ambiguous trial with an audit note")
    review.add_argument("--db", default="runs/lab.sqlite")
    review.add_argument("--trial-id", required=True)
    review.add_argument("--verdict", choices=["success", "failure"], required=True,
                        help="Whether the attack/task objective was achieved")
    review.add_argument("--note", required=True)
    commands.add_parser("validate", help="Validate bundled cases and print the trial budget")
    return cli


def main(argv=None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        if args.command in {"demo", "evaluate"}:
            if args.command == "evaluate":
                if not args.live:
                    raise ValueError("Live evaluation requires --live. No requests sent.")
                if len(args.model) != len(set(args.model)):
                    raise ValueError("Do not select a model ID twice")
                models = load_models(args.config, args.model)
            else:
                models = [FixtureModel()]
                print("OFFLINE FIXTURE RUN — scripted responses, no public LLMs evaluated.", flush=True)
            run_id = run_evaluation(args.db, args.dataset, models, args.modes, args.repetitions,
                                    args.max_requests, lambda n: print(f"Persisted {n} trials", flush=True))
            print(f"Run ID: {run_id}")
            print(f"Database: {args.db}")
        elif args.command == "report":
            with Store(args.db) as store:
                run = select_run(store, args.run_id)
                records = store.records(run["id"])
            path = export_bundle(args.out, run, records)
            print(f"Exported {len(records)} trials to {path}")
        elif args.command == "soc":
            if args.live:
                if not args.config or not args.model:
                    raise ValueError("Live SOC enrichment requires --config and --model")
                models = load_models(args.config, [args.model])
                model = models[0]
            else:
                if args.config or args.model:
                    raise ValueError("Use --live to select a real model; no silent fallback to fixtures")
                model = FixtureModel()
            report = investigate(args.events, model)
            path = Path(args.out)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(report["warning"])
            print(json.dumps(report["summary"]))
            print(f"SOC evidence: {path}")
        elif args.command == "serve":
            from .server import serve
            serve(args.db, args.port, args.soc_report)
        elif args.command == "review":
            with Store(args.db) as store:
                store.review(args.trial_id, args.verdict == "success", redact(args.note), now())
            print("Adjudication saved; re-export the report to update its denominators.")
        elif args.command == "validate":
            cases, digest = load_cases(DATA / "cases.json")
            print(json.dumps({"cases": len(cases), "adversarial": sum(c.adversarial for c in cases),
                              "legitimate": sum(not c.adversarial for c in cases), "sha256": digest,
                              "five_model_trials_at_three_repetitions": len(cases) * 5 * 2 * 3,
                              "worst_case_five_model_requests": len(cases) * 5 * 2 * 3 * 3}, indent=2))
        return 0
    except KeyboardInterrupt:
        print("Interrupted. Completed trials remain in SQLite; export them with report.", file=sys.stderr)
        return 130
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as error:
        # Expected validation messages are safe; never print provider bodies.
        print(f"Error: {error}", file=sys.stderr)
        return 2

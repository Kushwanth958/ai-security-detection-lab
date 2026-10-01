"""SQLite audit trail; append-only trials and separately recorded adjudications."""

import json
import sqlite3
from pathlib import Path


class Store:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript('''
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, metadata TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trials (
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), record TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reviews (
                trial_id TEXT PRIMARY KEY REFERENCES trials(id), verdict INTEGER NOT NULL,
                note TEXT NOT NULL, reviewed_at TEXT NOT NULL
            );
        ''')

    def add_run(self, run_id: str, timestamp: str, metadata: dict):
        with self.connection:
            self.connection.execute("INSERT INTO runs VALUES (?, ?, ?)", (run_id, timestamp, json.dumps(metadata)))

    def add_trial(self, record: dict):
        with self.connection:
            self.connection.execute("INSERT INTO trials VALUES (?, ?, ?)",
                                    (record["id"], record["run_id"], json.dumps(record)))

    def finish_run(self, run_id: str, count: int):
        row = self.connection.execute("SELECT metadata FROM runs WHERE id=?", (run_id,)).fetchone()
        metadata = json.loads(row[0])
        metadata.update(status="completed", recorded_trials=count)
        with self.connection:
            self.connection.execute("UPDATE runs SET metadata=? WHERE id=?", (json.dumps(metadata), run_id))

    def runs(self) -> list[dict]:
        return [{"id": r["id"], "created_at": r["created_at"], "metadata": json.loads(r["metadata"])}
                for r in self.connection.execute("SELECT * FROM runs ORDER BY created_at DESC")]

    def records(self, run_id: str) -> list[dict]:
        rows = self.connection.execute("SELECT t.record, r.verdict, r.note, r.reviewed_at FROM trials t "
                                       "LEFT JOIN reviews r ON t.id = r.trial_id WHERE t.run_id=? ORDER BY t.rowid",
                                       (run_id,))
        result = []
        for row in rows:
            value = json.loads(row["record"])
            if row["verdict"] is not None:
                value["review"] = {"verdict": bool(row["verdict"]), "note": row["note"], "reviewed_at": row["reviewed_at"]}
                value["application_success"] = bool(row["verdict"])
                value["status"] = "completed"
            result.append(value)
        return result

    def review(self, trial_id: str, verdict: bool, note: str, timestamp: str):
        row = self.connection.execute("SELECT record FROM trials WHERE id=?", (trial_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown trial ID")
        if json.loads(row[0])["status"] != "review_required":
            raise ValueError("Only ambiguous trials can be manually adjudicated")
        if not note.strip():
            raise ValueError("Adjudication requires a rationale")
        with self.connection:
            self.connection.execute("INSERT INTO reviews VALUES (?, ?, ?, ?)",
                                    (trial_id, int(verdict), note, timestamp))

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

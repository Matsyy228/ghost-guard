"""Store reusable workflows and run them manually or on a server interval."""

import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from time import time
from uuid import uuid4

from analyzers.common import submission_report
from backend.service import InvalidInput, upload_project, workflow_project
from backend.source_policy import SourcePolicy, SourcePolicyError
from backend.webhook import DEMO_PROJECT, ZIP_PROJECT
from backend.workflow import REPORT_UNREACHED, REPORT_UNREACHED_MESSAGE, compile_workflow, execute_workflow


SCHEMA = """
CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    graph TEXT NOT NULL,
    archive BLOB,
    catalog BLOB,
    updated_at REAL NOT NULL,
    interval_seconds INTEGER,
    next_run_at REAL,
    run_trigger TEXT,
    run_status TEXT,
    run_started_at REAL,
    run_finished_at REAL,
    run_events TEXT
);
CREATE INDEX IF NOT EXISTS workflows_due ON workflows(next_run_at) WHERE next_run_at IS NOT NULL;
"""
METADATA = """
    id, name, updated_at, archive IS NOT NULL AS has_archive, catalog IS NOT NULL AS has_catalog,
    interval_seconds, next_run_at, run_trigger, run_status, run_started_at, run_finished_at
"""


class WorkflowNotFound(Exception):
    pass


def timestamp(value):
    return datetime.fromtimestamp(value, UTC).isoformat(timespec="seconds") if value is not None else None


def run_status(row):
    if row["run_status"] is None:
        return None
    return {
        "status": row["run_status"],
        "trigger": row["run_trigger"],
        "started_at": timestamp(row["run_started_at"]),
        "finished_at": timestamp(row["run_finished_at"]),
    }


def metadata(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "source": "zip" if row["has_archive"] else "demo",
        "has_catalog": bool(row["has_catalog"]),
        "updated_at": timestamp(row["updated_at"]),
        "interval_seconds": row["interval_seconds"],
        "next_run_at": timestamp(row["next_run_at"]),
        "last_run": run_status(row),
    }


def validate_save(data, archive, catalog, source_policy):
    if not isinstance(data, dict):
        raise InvalidInput("Передайте параметры сценария в виде JSON-объекта.")
    name = data.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or not name.strip().isprintable():
        raise InvalidInput("Введите имя сценария длиной от 1 до 80 символов.")
    try:
        graph = json.dumps(
            data.get("workflow"), ensure_ascii=False, allow_nan=False, separators=(",", ":"),
        ).encode("utf-8")
    except (ValueError, RecursionError) as exc:
        raise InvalidInput("Некорректный JSON сценария.") from exc
    compile_workflow(graph)
    interval = data.get("interval_seconds")
    if interval is not None and (type(interval) is not int or not 1 <= interval <= 86400):
        raise InvalidInput("Укажите интервал от 1 до 86400 секунд или отключите расписание.")
    if "source" in data and (data["source"] != "demo" or archive is not None):
        raise InvalidInput("Выберите встроенное демо или приложите ZIP проекта.")
    if archive is None and catalog is not None:
        raise InvalidInput("Для загружаемого справочника нужен ZIP проекта.")
    if archive is not None:
        with upload_project(archive, catalog, source_policy=source_policy):
            pass
    return name.strip(), graph.decode("utf-8")


class WorkflowStore:
    def __init__(self, path, *, source_policy=None):
        self.path = path
        self.source_policy = source_policy or SourcePolicy()
        with self.connect() as db:
            db.executescript(SCHEMA)
            db.execute("BEGIN IMMEDIATE")
            if not any(column["name"] == "last_report" for column in db.execute("PRAGMA table_info(workflows)")):
                db.execute("ALTER TABLE workflows ADD COLUMN last_report TEXT")
                db.execute(
                    """UPDATE workflows SET last_report = json_extract(run_events, '$[#-1]')
                       WHERE CASE WHEN json_valid(run_events) THEN
                           json_extract(run_events, '$[#-1].event') = 'result'
                           AND json_type(run_events, '$[#-1].report') = 'object' END"""
                )
            # Older servers marked a run successful when its only report was skipped.
            db.execute(
                """UPDATE workflows SET run_status = 'failed',
                       run_events = json_set(run_events, '$[#-1].event', 'error',
                                             '$[#-1].code', ?, '$[#-1].error', ?)
                   WHERE run_status IN ('done', 'completed-with-errors')
                     AND CASE WHEN json_valid(run_events) THEN
                         json_extract(run_events, '$[#-1].event') = 'result'
                         AND json_type(run_events, '$[#-1].report') = 'null' END""",
                (REPORT_UNREACHED, REPORT_UNREACHED_MESSAGE),
            )

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            yield db

    def list(self):
        with self.connect() as db:
            rows = db.execute(f"SELECT {METADATA} FROM workflows ORDER BY updated_at DESC, id").fetchall()
        return [metadata(row) for row in rows]

    def get(self, workflow_id):
        with self.connect() as db:
            row = db.execute(f"SELECT {METADATA}, graph FROM workflows WHERE id = ?", (workflow_id,)).fetchone()
        if row is None:
            raise WorkflowNotFound
        return {**metadata(row), "workflow": json.loads(row["graph"])}

    def save(self, data, archive=None, catalog=None, *, workflow_id=None):
        name, graph = validate_save(data, archive, catalog, self.source_policy)
        now = time()
        with self.connect() as db:
            if archive is not None:
                self.source_policy.require(archive)
            if workflow_id is None:
                workflow_id = uuid4().hex
                db.execute(
                    "INSERT INTO workflows (id, name, graph, updated_at) VALUES (?, ?, ?, ?)",
                    (workflow_id, name, graph, now),
                )
            else:
                db.execute("BEGIN IMMEDIATE")
                if archive is None and data.get("source") != "demo":
                    existing = db.execute("SELECT archive FROM workflows WHERE id = ?", (workflow_id,)).fetchone()
                    if existing is None:
                        raise WorkflowNotFound
                    if existing["archive"] is not None:
                        self.source_policy.require(existing["archive"])
                updated = db.execute(
                    "UPDATE workflows SET name = ?, graph = ?, updated_at = ? WHERE id = ?",
                    (name, graph, now, workflow_id),
                )
                if not updated.rowcount:
                    raise WorkflowNotFound
            if archive is not None or data.get("source") == "demo":
                db.execute("UPDATE workflows SET archive = ?, catalog = ? WHERE id = ?", (archive, catalog, workflow_id))
            if "interval_seconds" in data:
                interval = data["interval_seconds"]
                db.execute(
                    """UPDATE workflows SET interval_seconds = ?, next_run_at = ?
                       WHERE id = ? AND interval_seconds IS NOT ?""",
                    (interval, now + interval if interval is not None else None, workflow_id, interval),
                )
            row = db.execute(f"SELECT {METADATA} FROM workflows WHERE id = ?", (workflow_id,)).fetchone()
        return {**metadata(row), "workflow": json.loads(graph)}

    def last_run(self, workflow_id):
        with self.connect() as db:
            row = db.execute(
                """SELECT run_status, run_trigger, run_started_at, run_finished_at, run_events, last_report
                   FROM workflows WHERE id = ?""",
                (workflow_id,),
            ).fetchone()
        if row is None:
            raise WorkflowNotFound
        status = run_status(row)
        if status is None:
            return None
        events = json.loads(row["run_events"] or "[]")
        if events and events[-1].get("report") is not None and "submission" not in events[-1]:
            events[-1]["submission"] = submission_report(events[-1]["report"])
        result = {**status, "events": events}
        if row["last_report"] is not None and (not events or events[-1].get("report") is None):
            previous = json.loads(row["last_report"])
            if "submission" not in previous:
                previous["submission"] = submission_report(previous["report"])
            result["last_report"] = previous
        return result

    def claim(self, workflow_id=None):
        now = time()
        trigger = "schedule" if workflow_id is None else "manual"
        with self.connect() as db:
            row = db.execute(
                """UPDATE workflows
                    SET run_trigger = ?, run_status = 'running', run_started_at = ?, run_finished_at = NULL,
                        run_events = NULL,
                        next_run_at = CASE WHEN ? = 'schedule' THEN ? + interval_seconds ELSE next_run_at END
                    WHERE run_status IS NOT 'running' AND id = COALESCE(?, (
                        SELECT id FROM workflows WHERE next_run_at <= ? AND run_status IS NOT 'running'
                        ORDER BY next_run_at, id LIMIT 1
                    ))
                    RETURNING id, graph, archive, catalog""",
                (trigger, now, trigger, now, workflow_id, now),
            ).fetchone()
        return row

    def finish(self, workflow_id, events, status):
        now = time()
        terminal = events[-1]
        report = json.dumps(terminal) if terminal["event"] == "result" and terminal.get("report") is not None else None
        with self.connect() as db:
            db.execute(
                """UPDATE workflows SET run_status = ?, run_finished_at = ?, run_events = ?,
                       last_report = COALESCE(?, last_report),
                       next_run_at = CASE WHEN run_trigger = 'schedule' AND next_run_at <= ?
                                          THEN ? + interval_seconds ELSE next_run_at END
                   WHERE id = ?""",
                (status, now, json.dumps(events), report, now, now, workflow_id),
            )

    def recover_interrupted(self):
        events = [{"event": "error", "error": "Запуск прерван остановкой сервера."}]
        with self.connect() as db:
            db.execute(
                """UPDATE workflows SET run_status = 'failed', run_finished_at = ?, run_events = ?
                   WHERE run_status = 'running'""",
                (time(), json.dumps(events)),
            )

    def run(self, claimed):
        events = []
        terminal = {"event": "error", "error": "Сценарий завершился без результата."}
        try:
            workflow = compile_workflow(claimed["graph"].encode("utf-8"))
            with workflow_project(claimed["archive"], claimed["catalog"], source_policy=self.source_policy) as project:
                for event in execute_workflow(
                    workflow, project, workflow_id=claimed["id"],
                    project_name=ZIP_PROJECT if claimed["archive"] is not None else DEMO_PROJECT,
                ):
                    if event["event"] in {"result", "error"}:
                        terminal = event
                        break
                    events.append(event)
                    yield event
        except SourcePolicyError as exc:
            terminal = {"event": "error", "code": exc.code, "error": str(exc)}
        except InvalidInput as exc:
            terminal = {"event": "error", "error": str(exc)}
        except Exception as exc:
            print(f"Saved workflow failed ({type(exc).__name__})", flush=True)
            terminal = {"event": "error", "error": "Не удалось выполнить сохранённый сценарий."}

        status = "done"
        if terminal["event"] == "error":
            status = "failed"
        elif any(event.get("status") == "failed" for event in events):
            status = "completed-with-errors"
        events.append(terminal)
        self.finish(claimed["id"], events, status)
        yield terminal


def run_scheduled(store, stopped):
    while not stopped.is_set():
        try:
            claimed = store.claim()
            if claimed is not None:
                for _ in store.run(claimed):
                    pass
                continue
        except sqlite3.Error as exc:
            print(f"Scheduler storage error ({type(exc).__name__})", flush=True)
        stopped.wait(1)

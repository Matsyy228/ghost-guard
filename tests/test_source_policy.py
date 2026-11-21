import json
import sqlite3
import subprocess
import sys
import unittest
from contextlib import closing
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic, sleep
from zipfile import ZipFile

from backend.server import Handler
from backend.source_policy import SourcePolicy, SourcePolicyError
from backend.workflows import SCHEMA, WorkflowStore, run_scheduled
from test_workflows import multipart


GRAPH = {
    "nodes": [{"id": "start", "type": "trigger"}, {"id": "scan", "type": "secrets"}, {"id": "report", "type": "report"}],
    "edges": [{"source": "start", "target": "scan"}, {"source": "scan", "target": "report"}],
}
SETTINGS = {"name": "Training project", "workflow": GRAPH}


def training_zip(name):
    contents = BytesIO()
    with ZipFile(contents, "w") as archive:
        archive.writestr("src/main/kotlin/Training.kt", f"package training\nclass {name}\n")
    return contents.getvalue()


class SourcePolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.policy = SourcePolicy(self.root / "approved")
        self.db = self.root / "workflows.sqlite3"
        self.store = WorkflowStore(self.db, source_policy=self.policy)

    def test_new_archive_and_modified_variant_require_separate_approval(self):
        original = training_zip("FirstVersion")
        variant = training_zip("HigherVersion")
        self.policy.approve(original)
        self.policy.require(original)
        with self.assertRaises(SourcePolicyError) as error:
            self.policy.require(variant)
        self.assertEqual(error.exception.code, "source-not-approved")
        self.policy.approve(variant)
        for archive in (original, variant):
            saved = self.store.save(SETTINGS, archive)
            result = list(self.store.run(self.store.claim(saved["id"])))[-1]
            self.assertEqual(result["event"], "result")

    def test_missing_allowlist_fails_closed_and_demo_still_runs(self):
        with self.assertRaises(SourcePolicyError):
            self.store.save(SETTINGS, training_zip("Archive"))
        self.assertEqual(self.store.list(), [])
        saved = self.store.save(SETTINGS)
        self.assertEqual(list(self.store.run(self.store.claim(saved["id"])))[-1]["event"], "result")

    def test_invalid_policy_location_fails_closed(self):
        self.policy.directory.write_text("not a directory", encoding="utf-8")
        with self.assertRaises(SourcePolicyError) as error:
            self.policy.require(training_zip("Example"))
        self.assertEqual(error.exception.code, "source-policy-unavailable")

    def test_revocation_blocks_rerun_and_preserves_last_report_after_reopen(self):
        archive = training_zip("Approved")
        digest = self.policy.approve(archive)
        saved = self.store.save(SETTINGS, archive)
        workflow_id = saved["id"]
        prior = list(self.store.run(self.store.claim(workflow_id)))[-1]
        self.policy.revoke(digest)
        with self.assertRaises(SourcePolicyError):
            self.store.save(SETTINGS, workflow_id=workflow_id)
        self.assertEqual(self.store.get(workflow_id)["workflow"], saved["workflow"])
        self.assertEqual([e["code"] for e in self.store.run(self.store.claim(workflow_id))], ["source-not-approved"])
        reopened = WorkflowStore(self.db, source_policy=self.policy)
        last = reopened.last_run(workflow_id)
        self.assertEqual(last["status"], "failed")
        self.assertEqual(last["last_report"], prior)
        self.policy.approve(archive)
        self.assertEqual(list(reopened.run(reopened.claim(workflow_id)))[-1]["event"], "result")

    def test_schedule_rechecks_revoked_archive_without_running_nodes(self):
        archive = training_zip("Scheduled")
        digest = self.policy.approve(archive)
        workflow_id = self.store.save({**SETTINGS, "interval_seconds": 1}, archive)["id"]
        self.policy.revoke(digest)
        stopped = Event()
        scheduler = Thread(target=run_scheduled, args=(self.store, stopped), daemon=True)
        scheduler.start()
        self.addCleanup(scheduler.join, 5)
        self.addCleanup(stopped.set)
        deadline = monotonic() + 5
        while monotonic() < deadline:
            last = self.store.last_run(workflow_id)
            if last and last["status"] == "failed":
                break
            sleep(0.025)
        else:
            self.fail("Scheduled run did not record policy denial")
        self.assertEqual(last["trigger"], "schedule")
        self.assertEqual([event["event"] for event in last["events"]], ["error"])
        self.assertEqual(last["events"][0]["code"], "source-not-approved")

    def test_migration_keeps_an_existing_report(self):
        archive = training_zip("Legacy")
        old_db = self.root / "legacy.sqlite3"
        report = {"event": "result", "report": {"findings": []}, "submission": {"findings": []}}
        with closing(sqlite3.connect(old_db)) as db, db:
            db.executescript(SCHEMA)
            db.execute("""INSERT INTO workflows (id, name, graph, updated_at, archive, run_status, run_events)
                          VALUES ('legacy', 'Legacy', ?, 0, ?, 'done', ?)""",
                       (json.dumps(GRAPH), archive, json.dumps([report])))
        store = WorkflowStore(old_db, source_policy=self.policy)
        list(store.run(store.claim("legacy")))
        self.assertEqual(store.last_run("legacy")["last_report"], report)

    def test_http_rejects_unknown_zip_before_streaming_or_saving(self):
        server = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        server.workflows = self.store
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(server.shutdown)
        archive = training_zip("Unlisted")
        for path, fields in (
            ("/api/scans", {}),
            ("/api/workflow", {"workflow": json.dumps(GRAPH).encode()}),
            ("/api/workflows", {"settings": json.dumps({**SETTINGS, "trusted": True}).encode()}),
        ):
            with self.subTest(path=path), closing(HTTPConnection("127.0.0.1", server.server_port, timeout=3)) as conn:
                body, headers = multipart(project=archive, **fields)
                conn.request("POST", path, body, headers)
                with conn.getresponse() as response:
                    self.assertEqual(response.status, 403)
                    self.assertEqual(json.load(response)["code"], "source-not-approved")
        self.assertEqual(self.store.list(), [])

    def test_cli_rejects_unapproved_archive(self):
        path = self.root / "unapproved.zip"
        path.write_bytes(training_zip("CLIUnlisted"))
        result = subprocess.run([sys.executable, "-X", "utf8", "-B", "scan.py", str(path)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn("Этот ZIP не разрешён", result.stderr.decode("utf-8"))

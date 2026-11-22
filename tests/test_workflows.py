import json
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Event, Thread
from time import monotonic, sleep, time
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

import scan
from backend.server import Handler
from backend.service import DEMO, demo_project
from backend.source_policy import SourcePolicy
from backend.workflow import compile_workflow, execute_workflow
from backend.workflows import WorkflowStore, run_scheduled


def graph(*kinds):
    nodes = [{"id": kind, "type": kind, "x": index * 100} for index, kind in enumerate(kinds)]
    return {"nodes": nodes, "edges": [{"source": a, "target": b} for a, b in zip(kinds, kinds[1:])]}


def multipart(**parts):
    boundary = "workflow-test-boundary"
    body = b"".join(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        + value + b"\r\n"
        for name, value in parts.items()
    )
    return body + f"--{boundary}--\r\n".encode(), {"Content-Type": f"multipart/form-data; boundary={boundary}"}


class WorkflowApiTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.path = Path(directory) / "workflows.sqlite3"
        self.policy = SourcePolicy(Path(directory) / "approved")
        self.server = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        self.server.workflows = WorkflowStore(self.path, source_policy=self.policy)
        self.enterContext(patch.object(Handler, "log_message"))
        worker = Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(self.server.shutdown)
        self.workflow = graph("trigger", "secrets", "sast", "sca", "report")
        self.settings = {"name": "Моя проверка", "workflow": self.workflow}

    def request(self, method, path, body=None, headers=None, *, expected=200):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers = {"Content-Type": "application/json", **(headers or {})}
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body, headers or {})
            with connection.getresponse() as response:
                content = response.read()
                self.assertEqual(response.status, expected, content)
                if response.getheader("Content-Type").startswith("application/x-ndjson"):
                    return [json.loads(line) for line in content.splitlines()]
                return json.loads(content)
        finally:
            connection.close()

    def test_upload_save_restart_run_and_switch_to_demo(self):
        buffer = BytesIO()
        with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
            for source in (DEMO / "project").rglob("*"):
                if source.is_file():
                    archive.write(source, source.relative_to(DEMO / "project"))
        payload = {"settings": json.dumps(self.settings).encode(), "project": buffer.getvalue(),
                   "catalog": (DEMO / "catalog.json").read_bytes()}
        self.policy.approve(payload["project"])
        body, headers = multipart(**payload)
        saved = self.request("POST", "/api/workflows", body, headers, expected=201)
        path = f"/api/workflows/{saved['id']}"
        self.server.workflows = WorkflowStore(self.path, source_policy=self.policy)
        self.assertEqual(self.request("GET", path), saved)
        self.assertEqual(saved["workflow"], self.workflow)
        self.assertEqual(saved["source"], "zip")
        self.assertTrue(saved["has_catalog"])
        self.assertNotIn("workflow", self.request("GET", "/api/workflows")["workflows"][0])
        self.assertIsNone(self.request("GET", path + "/last-run")["last_run"])

        updated = self.request("PUT", path, {**self.settings, "name": "Обновлённый сценарий"})
        self.assertEqual(updated["name"], "Обновлённый сценарий")
        self.assertEqual(updated["source"], "zip")
        events = self.request("POST", path + "/run", b"")
        legacy_body, legacy_headers = multipart(
            workflow=json.dumps(self.workflow).encode(), project=payload["project"], catalog=payload["catalog"],
        )
        self.assertEqual(self.request("POST", "/api/workflow", legacy_body, legacy_headers), events)
        last_run = self.request("GET", path + "/last-run")["last_run"]
        self.assertEqual(last_run["status"], "done")
        self.assertEqual(last_run["trigger"], "manual")
        self.assertEqual(last_run["events"], events)
        self.assertEqual(len(events[-1]["report"]["findings"]), 3)

        updated = self.request("PUT", path, {**self.settings, "source": "demo"})
        self.assertEqual(updated["source"], "demo")
        self.assertFalse(updated["has_catalog"])

    def test_conditions_route_findings_after_json_roundtrip(self):
        workflow = graph("trigger", "secrets", "condition")
        for branch in ("true", "false"):
            workflow["nodes"].append({"id": branch, "type": "report"})
            workflow["edges"].append({"source": "condition", "target": branch, "branch": branch})
        cases = (
            ({"mode": "severity", "value": "high"}, "true"),
            ({"mode": "severity", "value": "critical"}, "false"),
            ({"mode": "compare", "field": "line", "operator": "gte", "value": "1"}, "true"),
            ({"mode": "compare", "field": "line", "operator": "gt", "value": "9999"}, "false"),
            ({"mode": "compare", "field": "rule", "operator": "eq", "value": "password"}, "true"),
            ({"mode": "compare", "field": "rule", "operator": "eq", "value": "api-key"}, "false"),
            ({"mode": "regex", "field": "file", "value": r"application-.*\.yml$"}, "true"),
            ({"mode": "regex", "field": "file", "value": r"^missing/"}, "false"),
        )
        for condition, branch in cases:
            with self.subTest(condition=condition):
                workflow["nodes"][2]["config"] = condition
                saved = self.request("POST", "/api/workflows", {"name": "Condition", "workflow": workflow}, expected=201)
                path = f"/api/workflows/{saved['id']}"
                restored = self.request("GET", path)
                self.assertEqual(restored["workflow"], workflow)
                events = self.request("POST", path + "/run", b"")
                result = events[-1]
                self.assertEqual(result["branches"], {"condition": branch})
                self.assertEqual(result["reports"], [branch])
                node = next(event for event in events if event.get("id") == "condition" and event["status"] == "done")
                self.assertEqual(node["input"]["sources"], ["secrets"])
                self.assertEqual(node["input"]["findings"], node["output"]["findings"])
                self.assertEqual(len(result["submission"]["findings"]), 1)
                self.assertEqual(result["release_gate"]["status"], "BLOCK")
                self.assertEqual(self.request("GET", path + "/last-run")["last_run"]["events"], events)

    def test_schedule_runs_without_a_client_and_can_be_disabled(self):
        saved = self.request("POST", "/api/workflows", {**self.settings, "interval_seconds": 1}, expected=201)
        path = f"/api/workflows/{saved['id']}"
        stopped = Event()
        worker = Thread(target=run_scheduled, args=(self.server.workflows, stopped), daemon=True)
        worker.start()
        self.addCleanup(worker.join, 5)
        self.addCleanup(stopped.set)
        deadline = monotonic() + 5
        while monotonic() < deadline:
            run = self.server.workflows.last_run(saved["id"])
            if run and run["status"] == "done":
                break
            sleep(0.05)
        else:
            self.fail("Scheduled workflow did not finish")
        self.assertEqual(run["trigger"], "schedule")
        self.assertEqual(run["events"][-1]["event"], "result")
        disabled = self.request("PUT", path, {**self.settings, "interval_seconds": None})
        self.assertIsNone(disabled["next_run_at"])
        with patch("backend.workflows.time", return_value=time() + 10):
            self.assertIsNone(self.server.workflows.claim())

    def test_run_claim_is_exclusive_and_interruption_is_recoverable(self):
        store = self.server.workflows
        saved = store.save({**self.settings, "interval_seconds": 1})
        path = f"/api/workflows/{saved['id']}"
        start = Barrier(2)

        def claim(workflow_id):
            start.wait(5)
            return store.claim(workflow_id)

        with patch("backend.workflows.time", return_value=time() + 10), ThreadPoolExecutor(max_workers=2) as pool:
            manual = pool.submit(claim, saved["id"])
            scheduled = pool.submit(claim, None)
            self.assertEqual(sum(f.result() is not None for f in (manual, scheduled)), 1)
        self.request("POST", path + "/run", b"", expected=409)
        store.recover_interrupted()
        self.assertEqual(self.request("GET", path + "/last-run")["last_run"]["status"], "failed")
        self.assertEqual(self.request("POST", path + "/run", b"")[-1]["event"], "result")

    def test_saved_run_persists_when_client_stops_receiving_events(self):
        saved = self.request("POST", "/api/workflows", self.settings, expected=201)
        path = f"/api/workflows/{saved['id']}"
        with patch.object(Handler, "write_event", return_value=False) as write_event:
            self.assertEqual(self.request("POST", path + "/run", b""), [])
        write_event.assert_called_once()
        run = self.request("GET", path + "/last-run")["last_run"]
        self.assertEqual(run["status"], "done")
        self.assertEqual(len(run["events"][-1]["report"]["findings"]), 3)

    def test_rejects_invalid_drafts_without_changing_saved_data(self):
        saved = self.request("POST", "/api/workflows", self.settings, expected=201)
        path = f"/api/workflows/{saved['id']}"
        self.request("PUT", path, {**self.settings, "interval_seconds": True}, expected=400)
        self.request("PUT", path, {**self.settings, "workflow": {"nodes": [], "edges": []}}, expected=400)
        unsupported = BytesIO()
        with ZipFile(unsupported, "w") as archive:
            archive.writestr("README.txt", "No project sources")
        self.policy.approve(unsupported.getvalue())
        body, headers = multipart(settings=json.dumps(self.settings).encode(), project=unsupported.getvalue())
        self.request("PUT", path, body, headers, expected=400)
        self.assertEqual(self.request("GET", path), saved)
        self.request("GET", path, headers={"Host": "external.example"}, expected=403)
        self.request("GET", path, headers={"Origin": "https://external.example"}, expected=403)
        self.request("GET", "/api/workflows/" + "0" * 32 + "/last-run", expected=404)


class TelegramWorkflowTests(unittest.TestCase):
    def test_delivery_status_and_original_report(self):
        workflow = compile_workflow(json.dumps(graph("trigger", "secrets", "telegram", "report")).encode())
        settings = {"GHOST_TELEGRAM_BOT_TOKEN": "123:example", "GHOST_TELEGRAM_CHAT_ID": "-123"}
        for env, http_status, response_body, expected_status, code in (
            (settings, 200, b'{"ok":true,"result":{"message_id":42}}', "done", None),
            (settings, 503, b"", "failed", "telegram-provider-error"),
            (settings, 200, b'{"ok":false}', "failed", "telegram-invalid-response"),
            ({}, 0, b"", "skipped", "telegram-not-configured"),
        ):
            with (self.subTest(code=code), patch.dict("os.environ", env, clear=True),
                  patch("backend.telegram.HTTPSConnection") as connection):
                response = connection.return_value.getresponse.return_value.__enter__.return_value
                response.status = http_status
                response.read.return_value = response_body
                events = list(execute_workflow(workflow, demo_project()))
                node = next(event for event in events if event.get("id") == "telegram" and event["status"] != "running")
                self.assertEqual(node["status"], expected_status)
                self.assertEqual(node.get("code"), code)
                finding, = events[-1]["report"]["findings"]
                if expected_status == "done":
                    self.assertEqual(node["output"]["message_id"], 42)
                    method, path, body, _ = connection.return_value.request.call_args.args
                    self.assertEqual((method, path), ("POST", "/bot123:example/sendMessage"))
                    message = json.loads(body)
                    self.assertEqual(message["chat_id"], "-123")
                    self.assertNotIn(finding["file"], message["text"])
                    self.assertIn("Находок: 1", message["text"])
                elif expected_status == "skipped":
                    connection.assert_not_called()


class ReleaseGateTests(unittest.TestCase):
    def test_blocks_release_even_when_findings_do_not_reach_the_report(self):
        workflow = graph("trigger", "secrets", "report")
        workflow["edges"] = [{"source": "trigger", "target": target} for target in ("secrets", "report")]
        terminal = list(execute_workflow(compile_workflow(json.dumps(workflow).encode()), demo_project()))[-1]
        self.assertEqual(terminal["report"]["findings"], [])
        self.assertEqual(terminal["release_gate"]["status"], "BLOCK")
        self.assertEqual(terminal["release_gate"]["counts"]["high"], 1)

    def test_gate_warns_for_incomplete_coverage_and_accepts_clean_checks(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Example.kt").write_text("package example\nclass Example", encoding="utf-8")
            incomplete = scan.release_gate(scan.scan(root))
            self.assertEqual(incomplete["status"], "WARNING")
            self.assertEqual(incomplete["missing_scanners"], ["sca"])
            self.assertEqual(scan.release_gate(scan.scan(root, {}))["status"], "PASS")

    def test_cli_blocks_release_and_keeps_the_organizer_schema(self):
        result = subprocess.run(
            [sys.executable, "-B", str(Path(scan.__file__)), str(DEMO / "project"), "--catalog",
             str(DEMO / "catalog.json"), "--submission", "--release-gate"],
            capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout).keys(), {"findings"})
        self.assertEqual(len(json.loads(result.stdout)["findings"]), 3)


if __name__ == "__main__":
    unittest.main()

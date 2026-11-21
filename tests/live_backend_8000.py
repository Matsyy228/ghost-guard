"""Run explicitly against the workspace server. Creates one unscheduled QA demo workflow."""

import json
import unittest
from http.client import HTTPConnection

from backend.version import HOST, PORT, IDENTITY
from test_workflow_contract import conditional


class StandardPortTests(unittest.TestCase):
    def request(self, method, path, data=None, *, expected=200):
        connection = HTTPConnection(HOST, PORT, timeout=10)
        try:
            body = json.dumps(data).encode() if data is not None else None
            headers = {"Content-Type": "application/json"} if data is not None else {}
            connection.request(method, path, body, headers)
            with connection.getresponse() as response:
                self.assertEqual(response.status, expected)
                raw = response.read()
                if response.getheader("Content-Type").startswith("application/x-ndjson"):
                    return [json.loads(line) for line in raw.splitlines()]
                return json.loads(raw)
        finally:
            connection.close()

    def test_live_build_save_run_read_and_repair(self):
        self.assertEqual(self.request("GET", "/api/health"), {"status": "ok", **IDENTITY})
        self.assertIsInstance(self.request("GET", "/api/workflows")["workflows"], list)
        graph = conditional("critical")
        settings = {"name": "QA P0 — проверка ветвления", "workflow": graph, "interval_seconds": None}
        saved = self.request("POST", "/api/workflows", settings, expected=201)
        path = "/api/workflows/" + saved["id"]
        self.assertEqual(self.request("GET", path)["workflow"], graph)
        events = self.request("POST", path + "/run")
        last = self.request("GET", path + "/last-run")["last_run"]
        self.assertEqual((last["status"], events[-1]["event"], events[-1]["code"]),
                         ("failed", "error", "workflow-report-unreached"))
        self.assertEqual(last["events"], events)
        graph["edges"].append({"source": "check", "branch": "false", "target": "summary"})
        self.request("PUT", path, settings)
        result = self.request("POST", path + "/run")
        last = self.request("GET", path + "/last-run")["last_run"]
        self.assertEqual(last["events"], result)
        self.assertEqual((last["status"], result[-1]["event"], result[-1]["branches"]), ("done", "result", {"check": "false"}))
        self.assertEqual(len(result[-1]["report"]["findings"]), 1)
        self.assertEqual(result[-1]["release_gate"]["status"], "BLOCK")

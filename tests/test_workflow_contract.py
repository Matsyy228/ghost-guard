import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.service import InvalidInput, demo_project
from backend.workflow import compile_workflow, execute_workflow
from backend.workflows import WorkflowStore


def conditional(threshold="high"):
    return {
        "nodes": [
            {"id": "start", "type": "trigger"},
            {"id": "scan", "type": "secrets"},
            {"id": "check", "type": "condition", "config": {"mode": "severity", "value": threshold}},
            {"id": "summary", "type": "report"},
        ],
        "edges": [
            {"source": "start", "target": "scan"}, {"source": "scan", "target": "check"},
            {"source": "check", "branch": "true", "target": "summary"},
        ],
    }


def execute(graph):
    return list(execute_workflow(compile_workflow(json.dumps(graph).encode()), demo_project()))


class WorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "runs.sqlite3"
        self.store = WorkflowStore(self.path)

    def save(self, graph):
        return self.store.save({"name": "QA", "workflow": graph})["id"]

    def test_active_report_contains_real_findings(self):
        terminal = execute(conditional())[-1]
        self.assertEqual(terminal["event"], "result")
        self.assertEqual(terminal["branches"], {"check": "true"})
        self.assertEqual(terminal["reports"], ["summary"])
        self.assertEqual([f["scanner"] for f in terminal["report"]["findings"]], ["secrets"])
        self.assertEqual(len(terminal["submission"]["findings"]), 1)

    def test_inactive_report_is_skipped_and_run_fails(self):
        graph = conditional("critical")
        graph["nodes"].append({"id": "inactive", "type": "sast"})
        graph["edges"].append({"source": "check", "branch": "true", "target": "inactive"})
        events = execute(graph)
        terminal = events[-1]
        self.assertEqual([event["event"] for event in events if event["event"] != "node"], ["error"])
        self.assertEqual(terminal["code"], "workflow-report-unreached")
        self.assertEqual(terminal["branches"], {"check": "false"})
        self.assertEqual(terminal["reports"], [])
        self.assertEqual(terminal["release_gate"]["counts"], {"critical": 0, "high": 1, "medium": 0, "low": 0})
        self.assertEqual(terminal["release_gate"]["missing_scanners"], ["sast", "sca"])
        for node_id in ("summary", "inactive"):
            node, = [event for event in events if event.get("id") == node_id]
            self.assertEqual(node["status"], "skipped")
            self.assertNotIn("output", node)

    def test_two_active_paths_join_and_shared_input_is_counted_once(self):
        graph = conditional()
        graph["nodes"].extend([{"id": "left", "type": "sast"}, {"id": "right", "type": "sca"}])
        graph["edges"] = graph["edges"][:2]
        for target in ("left", "right"):
            graph["edges"].extend([{"source": "check", "branch": "true", "target": target},
                                   {"source": target, "target": "summary"}])
        events = execute(graph)
        received = next(e["input"] for e in events if e.get("id") == "summary")
        self.assertEqual(set(received["sources"]), {"left", "right"})
        self.assertEqual(received["count"], 3)
        self.assertCountEqual([f["scanner"] for f in events[-1]["report"]["findings"]], ["secrets", "sast", "sca"])
        self.assertEqual(sum(events[-1]["release_gate"]["counts"].values()), 3)

    def test_graph_without_report_rejected_before_save(self):
        graph = conditional()
        graph["nodes"].pop()
        graph["edges"].pop()
        with self.assertRaisesRegex(InvalidInput, "Отчёт"):
            self.save(graph)
        self.assertEqual(self.store.list(), [])

    def test_active_report_can_be_empty(self):
        graph = {"nodes": [{"id": "s", "type": "trigger"}, {"id": "r", "type": "report"}],
                 "edges": [{"source": "s", "target": "r"}]}
        result = execute(graph)[-1]
        self.assertEqual(result["report"]["findings"], [])
        self.assertEqual(result["submission"], {"findings": []})
        self.assertEqual(result["release_gate"]["status"], "WARNING")

    def test_node_failure_is_persisted(self):
        graph = conditional()
        graph["nodes"][2]["config"] = {"mode": "regex", "field": "severity", "value": "high"}
        key = self.save(graph)
        # Exercise the real OS error when the regex worker cannot be started.
        with patch("backend.workflow.sys.executable", str(self.path.parent / "missing-worker")):
            events = list(self.store.run(self.store.claim(key)))
        self.assertEqual((events[-2]["id"], events[-2]["status"], events[-1]["event"]), ("check", "failed", "error"))
        saved = WorkflowStore(self.path).last_run(key)
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["events"], events)

    def test_reopen_failure_fix_graph_and_rerun(self):
        graph = conditional("critical")
        key = self.save(graph)
        failed = list(self.store.run(self.store.claim(key)))
        reopened = WorkflowStore(self.path)
        self.assertEqual(reopened.last_run(key)["events"], failed)
        self.assertEqual(reopened.last_run(key)["status"], "failed")
        graph["edges"].append({"source": "check", "branch": "false", "target": "summary"})
        reopened.save({"name": "QA", "workflow": graph}, workflow_id=key)
        events = list(reopened.run(reopened.claim(key)))
        saved = WorkflowStore(self.path).last_run(key)
        self.assertEqual(saved["status"], "done")
        self.assertEqual(saved["events"], events)
        self.assertEqual(events[-1]["branches"], {"check": "false"})
        self.assertEqual(len(events[-1]["report"]["findings"]), 1)

    def test_old_false_success_is_repaired_on_reopen(self):
        key = self.save(conditional("critical"))
        events = list(self.store.run(self.store.claim(key)))
        events[-1] = {"event": "result", "report": None, "submission": None, "branches": {"check": "false"}}
        self.store.finish(key, events, "done")
        before = self.store.get(key)
        repaired = WorkflowStore(self.path).last_run(key)
        self.assertEqual(repaired["status"], "failed")
        self.assertEqual(repaired["events"][:-1], events[:-1])
        self.assertEqual(repaired["events"][-1]["code"], "workflow-report-unreached")
        self.assertEqual(repaired["events"][-1]["event"], "error")
        self.assertEqual(repaired["finished_at"], before["last_run"]["finished_at"])
        self.assertEqual(self.store.get(key)["workflow"], before["workflow"])
        self.assertEqual(WorkflowStore(self.path).last_run(key), repaired)

import json
import socket
import unittest
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from unittest.mock import patch

from backend.ai_summary import summarize
from backend.llm import LLMError, MAX_FINDINGS, analyze_findings
from backend.service import demo_project
from backend.webhook_receiver import Receiver
from backend.workflow import compile_workflow, execute_workflow
from backend.workflows import WorkflowStore
from test_llm import EXPLANATION, FINDING, SETTINGS


def completion(data):
    return BytesIO(json.dumps({"choices": [{"message": {"content": json.dumps(data)}}]}).encode())


def simple_workflow(*types):
    return {
        "nodes": [{"id": kind, "type": kind} for kind in types],
        "edges": [{"source": first, "target": second} for first, second in zip(types, types[1:])],
    }


def run(graph):
    return list(execute_workflow(compile_workflow(json.dumps(graph).encode()), demo_project()))


class AISummaryTests(unittest.TestCase):
    def test_one_completion_and_structured_server_references(self):
        private = "SYNTHETIC_SOURCE_INSTRUCTION"
        finding = {**FINDING, "source": private, "recommendation": FINDING["recommendation"] + private}
        with patch.dict("os.environ", SETTINGS, clear=True), patch("backend.llm.build_opener") as opener:
            opener.return_value.open.return_value = completion({
                "explanations": [EXPLANATION], "summary": {"priority_ids": [FINDING["id"]]},
            })
            analysis = analyze_findings([finding])
        opener.return_value.open.assert_called_once()
        invocation = json.loads(opener.return_value.open.call_args.args[0].data)
        self.assertIn("priority_ids", invocation["messages"][0]["content"])
        self.assertNotIn(FINDING["file"], str(invocation))
        self.assertNotIn(private, str(invocation))
        self.assertEqual(analysis["priority_ids"], [FINDING["id"]])
        explanation, = analysis["explanations"]
        self.assertEqual((explanation["file"], explanation["line"], explanation["advisoryId"]),
                         (FINDING["file"], 7, FINDING["advisoryId"]))

    def test_partial_summary_keeps_valid_explanations(self):
        for malformed in ({}, {"priority_ids": ["SCA-F9999"]}, {"priority_ids": ["SCA-F0001"] * 2},
                          {"priority_ids": ["SCA-F0001"], "severity": "critical"}):
            with self.subTest(summary=malformed), patch("backend.llm.call_provider", return_value={
                "explanations": [EXPLANATION], "summary": malformed,
            }), patch.dict("os.environ", SETTINGS, clear=True):
                result = analyze_findings([FINDING])
            self.assertEqual(result["priority_ids"], [])
            self.assertEqual(result["summary_code"], "llm-summary-incomplete")
            self.assertEqual(len(result["explanations"]), 1)

    def test_free_text_rejects_obfuscated_advisories(self):
        for bogus in ("СVЕ‑２０９９‑１２３４５", "C V E 2099 55555", "G H S A — abcd-efgh-jklm",
                      "GHSA‑abcd‑efgh‑jklm", "Сохраните настройки в spring.yml"):
            with self.subTest(example=bogus), patch.dict("os.environ", SETTINGS, clear=True), patch(
                "backend.llm.call_provider", return_value={
                    "explanations": [{**EXPLANATION, "explanation": f"Обнаружена проблема {bogus}."}],
                },
            ), self.assertRaises(LLMError) as error:
                analyze_findings([FINDING])
            self.assertEqual(error.exception.code, "llm-invalid-response")

    def test_oversized_empty_and_duplicate_json_responses(self):
        for data in (b"", b"x" * (64 * 1024 + 1),
                     b'{"choices":[{"message":{"content":"{\"explanations\":[],\"explanations\":[]}"}}]}'):
            with self.subTest(size=len(data)), patch.dict("os.environ", SETTINGS, clear=True), patch(
                "backend.llm.read_completion", return_value=data,
            ), self.assertRaises(LLMError) as error:
                analyze_findings([FINDING])
            self.assertEqual(error.exception.code, "llm-invalid-response")

    def test_large_report_has_full_counts_despite_model_cap(self):
        findings = [{**FINDING, "id": f"SCA-F{i:04}", "severity": "critical" if i == 24 else "medium"}
                    for i in range(25)]

        def respond(*args):
            selection = list(args[-1])
            self.assertEqual(len(selection), MAX_FINDINGS)
            self.assertEqual(selection[0], "SCA-F0024")
            return {"explanations": [{**EXPLANATION, "finding_id": key} for key in selection],
                    "summary": {"priority_ids": [selection[-1]]}}

        with patch.dict("os.environ", SETTINGS, clear=True), patch("backend.llm.call_provider", side_effect=respond):
            analysis = analyze_findings(findings)
        explanations = {entry["finding_id"]: entry for entry in analysis["explanations"]}
        result = summarize({"findings": findings}, {"status": "BLOCK"}, {"local": analysis}, explanations)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["total_findings"], 25)
        self.assertEqual(result["severity_counts"]["medium"], 24)
        self.assertEqual(result["priority_findings"][0]["severity"], "critical")
        self.assertEqual(result["release_gate"]["status"], "BLOCK")

    def test_timeout_keeps_report_and_gate(self):
        entered, waiting = Event(), Event()

        class SlowModel(BaseHTTPRequestHandler):
            def do_POST(self):
                entered.set()
                waiting.wait(3)

        model = self.start_server(SlowModel)
        env = {**SETTINGS, "GHOST_LLM_BASE_URL": model + "/v1", "GHOST_LLM_API_KEY": ""}
        try:
            with patch.dict("os.environ", env), patch("backend.llm.REQUEST_TIMEOUT", 0.5):
                result = run(simple_workflow("trigger", "secrets", "llm", "report"))[-1]
        finally:
            waiting.set()
        self.assertTrue(entered.is_set())
        self.assertEqual(result["report"]["ai_summary"]["status"], "unavailable")
        self.assertEqual(result["report"]["ai_summary"]["warnings"], ["llm-timeout"])
        self.assertEqual(result["release_gate"]["status"], "BLOCK")
        self.assertEqual(len(result["report"]["findings"]), 1)

    def test_unreachable_local_model_keeps_report_and_gate(self):
        with closing(socket.socket()) as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            port = unavailable.getsockname()[1]
            provider = {**SETTINGS, "GHOST_LLM_BASE_URL": f"http://127.0.0.1:{port}/v1", "GHOST_LLM_API_KEY": ""}
            with patch.dict("os.environ", provider), patch("backend.llm.REQUEST_TIMEOUT", 4):
                result = run(simple_workflow("trigger", "secrets", "llm", "report"))[-1]
        self.assertEqual(result["report"]["ai_summary"]["warnings"], ["llm-provider-error"])
        self.assertEqual(result["release_gate"]["status"], "BLOCK")
        self.assertEqual(len(result["report"]["findings"]), 1)

    def test_no_findings_does_not_call_provider(self):
        with patch("backend.llm.call_provider") as provider:
            result = run(simple_workflow("trigger", "llm", "report"))[-1]
        provider.assert_not_called()
        summary = result["report"]["ai_summary"]
        self.assertEqual(summary["status"], "no-findings")
        self.assertEqual(summary["priority_findings"], [])
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["release_gate"]["status"], "WARNING")

    def test_inactive_ai_node_does_not_enrich_report(self):
        graph = simple_workflow("trigger", "secrets", "condition", "llm", "report")
        graph["nodes"][2]["config"] = {"mode": "severity", "value": "critical"}
        graph["edges"][2]["branch"] = "true"
        graph["edges"].append({"source": "condition", "branch": "false", "target": "report"})
        with patch("backend.llm.call_provider") as provider:
            events = run(graph)
        provider.assert_not_called()
        self.assertEqual([e["status"] for e in events if e.get("id") == "llm"], ["skipped"])
        self.assertNotIn("ai_summary", events[-1]["report"])
        self.assertEqual(events[-1]["release_gate"]["status"], "BLOCK")

    def test_final_summary_covers_an_active_branch_without_llm(self):
        graph = simple_workflow("trigger", "secrets", "llm", "report")
        graph["nodes"].append({"id": "sca", "type": "sca"})
        graph["edges"].extend([{"source": "trigger", "target": "sca"}, {"source": "sca", "target": "report"}])
        response = {"explanations": [{**EXPLANATION, "finding_id": "SECRETS-F0001"}],
                    "summary": {"priority_ids": ["SECRETS-F0001"]}}
        with patch.dict("os.environ", SETTINGS, clear=True), patch("backend.llm.call_provider", return_value=response) as client:
            result = run(graph)[-1]
        client.assert_called_once()
        summary = result["report"]["ai_summary"]
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["coverage"], {"explained": 1, "total": 2})
        self.assertEqual({row["scanner"] for row in summary["categories"]}, {"secrets", "sca"})

    def test_real_bad_qwen_response_still_delivers_webhook_and_persists_report(self):
        received = []

        class InvalidModel(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                body = b'{"choices":[{"message":{"content":"not a JSON object"}}]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class RecordingReceiver(Receiver):
            def show_report(self, report):
                received.append(report)

        model = self.start_server(InvalidModel)
        webhook = self.start_server(RecordingReceiver) + "/webhook"
        env = {**SETTINGS, "GHOST_LLM_BASE_URL": model + "/v1", "GHOST_WEBHOOK_LOCAL_URL": webhook, "GHOST_LLM_API_KEY": ""}
        graph = simple_workflow("trigger", "secrets", "llm", "report", "webhook")
        graph["nodes"][-1]["config"] = {"url": webhook}
        directory = Path(self.enterContext(TemporaryDirectory()))
        store = WorkflowStore(directory / "workflows.sqlite3")
        key = store.save({"name": "QA unavailable summary", "workflow": graph})["id"]
        with patch.dict("os.environ", env):
            events = list(store.run(store.claim(key)))
        saved = store.last_run(key)
        self.assertEqual(saved["status"], "completed-with-errors")
        self.assertEqual(saved["events"], events)
        terminal = events[-1]
        self.assertEqual(terminal["report"]["ai_summary"]["warnings"], ["llm-invalid-response"])
        self.assertEqual(terminal["release_gate"]["status"], "BLOCK")
        self.assertEqual(received[0]["report_id"], terminal["report_id"])
        self.assertEqual(received[0]["total_findings"], 1)
        self.assertNotIn("ai_summary", received[0])

    def start_server(self, handler):
        server = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), handler))
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 5)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

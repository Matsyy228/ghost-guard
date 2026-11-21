import json
import socket
import unittest
from contextlib import closing
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from queue import Queue
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic, sleep
from unittest.mock import patch

from backend.service import InvalidInput, demo_project
from backend.webhook import WebhookError, send_report
from backend.webhook_receiver import Receiver
from backend.workflow import compile_workflow, execute_workflow
from backend.workflows import WorkflowStore, run_scheduled


def graph(url="", *, inactive=False):
    nodes = [
        {"id": "start", "type": "trigger"}, {"id": "secrets", "type": "secrets"},
        {"id": "sast", "type": "sast"}, {"id": "sca", "type": "sca"},
        {"id": "r1", "type": "report"}, {"id": "r2", "type": "report"},
        {"id": "notify", "type": "webhook", "config": {"url": url}},
    ]
    links = [("start", "secrets"), ("secrets", "r1"), ("r1", "notify"),
             ("start", "sast"), ("start", "sca"), ("sast", "r2"), ("sca", "r2")]
    edges = [{"source": source, "target": target} for source, target in links]
    if inactive:
        nodes.append({"id": "choose", "type": "condition", "config": {"mode": "severity", "value": "critical"}})
        edges[1] = {"source": "secrets", "target": "choose"}
        edges.append({"source": "choose", "target": "r1", "branch": "true"})
    return {"nodes": nodes, "edges": edges}


def run(graph):
    return list(execute_workflow(compile_workflow(json.dumps(graph).encode()), demo_project()))


def deliveries(events):
    return [event for event in events if event.get("id") == "notify"]


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.received = Queue()
        received = self.received

        class RecordingReceiver(Receiver):
            def show_report(self, report):
                received.put(report)

        self.server = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), RecordingReceiver))
        self.url = f"http://127.0.0.1:{self.server.server_port}/webhook"
        self.enterContext(patch.dict("os.environ", {"GHOST_WEBHOOK_LOCAL_URL": self.url, "GHOST_WEBHOOK_ALLOWED_URLS": ""}))
        worker = Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(self.server.shutdown)

    def test_receiver_confirms_real_post_of_final_aggregate(self):
        events = run(graph(self.url))
        payload = self.received.get_nowait()
        self.assertEqual([e["delivery_status"] for e in deliveries(events)], ["PENDING", "SENDING", "SENT"])
        self.assertEqual(deliveries(events)[-1]["output"], {"http_status": 200, "attempts": 1})
        self.assertEqual(deliveries(events)[0]["input"]["count"], 1)
        self.assertEqual(payload["total_findings"], len(events[-1]["report"]["findings"]))
        self.assertEqual(payload["total_findings"], 3)
        self.assertEqual(payload["release_gate_status"], events[-1]["release_gate"]["status"])
        self.assertEqual(payload["release_gate_status"], "BLOCK")
        self.assertEqual(payload["report_id"], events[-1]["report_id"])
        self.assertEqual(payload["run_id"], events[-1]["run_id"])
        self.assertCountEqual([item["scanner"] for item in payload["findings_summary"]], ["secrets", "sca", "sast"])
        body = json.dumps(payload)
        self.assertTrue(all(item["file"] not in body and item["title"] not in body
                            for item in events[-1]["report"]["findings"]))

    def test_receiver_rejects_invalid_json_structure(self):
        with closing(HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)) as connection:
            connection.request("POST", "/webhook", "{}", {"Content-Type": "application/json"})
            with connection.getresponse() as response:
                self.assertEqual(response.status, 400)
        self.assertTrue(self.received.empty())

    def test_missing_url_emits_not_configured(self):
        events = run(graph())
        self.assertEqual(deliveries(events)[-1]["delivery_status"], "NOT_CONFIGURED")
        self.assertEqual(events[-1]["event"], "result")
        self.assertTrue(self.received.empty())

    def test_inactive_webhook_is_skipped_despite_other_report(self):
        events = run(graph(self.url, inactive=True))
        self.assertEqual([e["delivery_status"] for e in deliveries(events)], ["SKIPPED"])
        self.assertEqual(events[-1]["reports"], ["r2"])
        self.assertTrue(self.received.empty())

    def test_workflow_report_unreached_never_sends(self):
        workflow = graph(self.url, inactive=True)
        workflow["nodes"] = [node for node in workflow["nodes"] if node["id"] != "r2"]
        workflow["edges"] = [edge for edge in workflow["edges"] if edge["target"] != "r2"]
        events = run(workflow)
        self.assertEqual(events[-1]["code"], "workflow-report-unreached")
        self.assertEqual(deliveries(events)[0]["delivery_status"], "SKIPPED")
        self.assertTrue(self.received.empty())

    def test_saved_http_400_is_not_retried_and_report_persists(self):
        db = Path(self.enterContext(TemporaryDirectory())) / "workflow.sqlite"
        store = WorkflowStore(db)
        workflow_id = store.save({"name": "Webhook demo", "workflow": graph(self.url)})["id"]
        original = self.server.RequestHandlerClass
        counter = []

        class Reject(original):
            def do_POST(self):
                counter.append(1)
                self.respond(400, {"error": "Invalid"})

        self.server.RequestHandlerClass = Reject
        events = list(store.run(store.claim(workflow_id)))
        failed = deliveries(events)[-1]
        self.assertEqual((failed["delivery_status"], failed["code"]), ("FAILED", "webhook-http-error"))
        self.assertEqual(failed["output"], {"http_status": 400, "attempts": 1})
        last = WorkflowStore(db).last_run(workflow_id)
        self.assertEqual(last["status"], "completed-with-errors")
        self.assertEqual(last["events"], events)
        self.assertEqual(len(events[-1]["report"]["findings"]), 3)
        self.assertEqual(len(counter), 1)
        self.server.RequestHandlerClass = original
        second = list(store.run(store.claim(workflow_id)))
        delivered = self.received.get_nowait()
        self.assertEqual(delivered["workflow_id"], workflow_id)
        self.assertNotEqual(events[-1]["run_id"], delivered["run_id"])
        self.assertEqual(second[-1]["report_id"], delivered["report_id"])
        self.assertEqual(store.last_run(workflow_id)["status"], "done")

    def test_http_500_is_retried_with_same_report_and_bounded(self):
        requests = []

        class Broken(Receiver):
            def show_report(self, report):
                requests.append(report)

            def respond(self, status, data):
                super().respond(500, {"error": "Unavailable"})

        self.server.RequestHandlerClass = Broken
        last = deliveries(run(graph(self.url)))[-1]
        self.assertEqual(last["delivery_status"], "FAILED")
        self.assertEqual(last["output"], {"http_status": 500, "attempts": 3})
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(request == requests[0] for request in requests))

    def test_scheduled_workflow_delivers_without_client(self):
        db = Path(self.enterContext(TemporaryDirectory())) / "scheduled.sqlite"
        store = WorkflowStore(db)
        workflow_id = store.save({"name": "Scheduled webhook", "workflow": graph(self.url), "interval_seconds": 1})["id"]
        stopped = Event()
        worker = Thread(target=run_scheduled, args=(store, stopped), daemon=True)
        worker.start()
        self.addCleanup(worker.join, 5)
        self.addCleanup(stopped.set)
        payload = self.received.get(timeout=5)
        self.assertEqual(payload["workflow_id"], workflow_id)
        deadline = monotonic() + 2
        while monotonic() < deadline:
            last = store.last_run(workflow_id)
            if last["status"] == "done":
                break
            sleep(0.02)
        else:
            self.fail("Scheduled delivery did not persist")
        self.assertEqual(last["trigger"], "schedule")
        self.assertEqual(deliveries(last["events"])[-1]["delivery_status"], "SENT")

    def test_real_http_timeout_is_bounded(self):
        attempts = Queue()

        class Slow(Receiver):
            def do_POST(self):
                attempts.put(True)
                sleep(0.35)

        self.server.RequestHandlerClass = Slow
        with patch("backend.webhook.TIMEOUT", 0.1):
            last = deliveries(run(graph(self.url)))[-1]
        self.assertEqual(last["code"], "webhook-timeout")
        self.assertEqual(last["output"]["attempts"], 3)
        self.assertEqual(attempts.qsize(), 3)

    def test_redirect_is_not_followed(self):
        requests = []

        class Redirect(Receiver):
            def do_POST(self):
                requests.append(self.path)
                self.send_response(307)
                self.send_header("Location", "/unexpected")
                self.end_headers()

        self.server.RequestHandlerClass = Redirect
        event = deliveries(run(graph(self.url)))[-1]
        self.assertEqual(event["output"], {"http_status": 307, "attempts": 1})
        self.assertEqual(requests, ["/webhook"])

    def test_allowlist_and_url_rules(self):
        invalid = [self.url + "?auth=value", self.url + "#fragment", "http://user@127.0.0.1:8765/webhook",
                   self.url + "/../other", "file:///data"]
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(InvalidInput):
                compile_workflow(json.dumps(graph(url)).encode())
        for url in [self.url + "/other", "http://localhost:8765/webhook", "https://example.invalid/webhook"]:
            with self.subTest(url=url), patch("backend.webhook.socket.getaddrinfo") as resolver:
                event = deliveries(run(graph(url)))[-1]
                self.assertEqual(event["code"], "webhook-url-not-allowed")
                resolver.assert_not_called()
        self.assertTrue(self.received.empty())

    def test_approved_https_rejects_private_dns_answers_before_connect(self):
        url = "https://receiver.example.invalid/webhook"
        for address in ("127.0.0.1", "192.168.1.10", "169.254.169.254", "::ffff:127.0.0.1", "224.1.2.3"):
            with (self.subTest(address=address), patch.dict("os.environ", {"GHOST_WEBHOOK_ALLOWED_URLS": url}),
                  patch("backend.webhook.socket.getaddrinfo",
                        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]),
                  patch("backend.webhook.socket.create_connection") as connect):
                with self.assertRaises(WebhookError) as error:
                    send_report(url, {})
                self.assertEqual(error.exception.code, "webhook-address-not-public")
                connect.assert_not_called()

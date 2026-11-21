"""Standalone loopback receiver for the GHOST//GUARD webhook demo."""

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from backend.webhook import DEMO_PROJECT, SCANNERS, SEVERITIES, ZIP_PROJECT


PATH = "/webhook"
MAX_BODY = 8192
FIELDS = {"event_type", "workflow_id", "run_id", "project_name", "timestamp",
          "total_findings", "severity_counts", "release_gate_status", "findings_summary", "report_id"}
UUID = re.compile(r"[a-f0-9]{32}")


def valid_payload(data):
    if not isinstance(data, dict) or data.keys() != FIELDS or data["event_type"] != "security_scan_completed":
        return False
    if any(not isinstance(data[key], str) or not UUID.fullmatch(data[key])
           for key in ("workflow_id", "run_id", "report_id")):
        return False
    if data["project_name"] not in (DEMO_PROJECT, ZIP_PROJECT) or data["release_gate_status"] not in ("PASS", "WARNING", "BLOCK"):
        return False
    try:
        if datetime.fromisoformat(data["timestamp"]).utcoffset() != timedelta(0):
            return False
    except (TypeError, ValueError):
        return False
    counts, summary, total = data["severity_counts"], data["findings_summary"], data["total_findings"]
    if (not isinstance(counts, dict) or counts.keys() != set(SEVERITIES)
            or any(type(count) is not int or count < 0 for count in counts.values())
            or type(total) is not int or total != sum(counts.values())
            or not isinstance(summary, list) or len(summary) > len(SCANNERS) * len(SEVERITIES)):
        return False
    received, pairs = Counter(), set()
    for item in summary:
        if not isinstance(item, dict) or item.keys() != {"scanner", "severity", "count"}:
            return False
        scanner, level, count = item["scanner"], item["severity"], item["count"]
        if scanner not in SCANNERS or level not in SEVERITIES or type(count) is not int or count <= 0:
            return False
        if (scanner, level) in pairs:
            return False
        pairs.add((scanner, level))
        received[level] += count
    return all(received[level] == counts[level] for level in SEVERITIES)


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != PATH:
            self.respond(404, {"error": "Unknown receiver route"})
            return
        length = self.headers.get("Content-Length", "")
        if (self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1
                or not length.isascii() or not length.isdecimal() or len(length) > 4 or not 0 < int(length) <= MAX_BODY):
            self.respond(400, {"error": "Invalid Content-Length"})
            return
        if self.headers.get_content_type() != "application/json":
            self.respond(415, {"error": "Expected application/json"})
            return
        self.connection.settimeout(3)
        try:
            body = self.rfile.read(int(length))
            if len(body) != int(length):
                raise ValueError
            data = json.loads(body)
        except (ValueError, RecursionError, TimeoutError):
            self.respond(400, {"error": "Invalid JSON"})
            return
        if not valid_payload(data):
            self.respond(400, {"error": "Invalid report"})
            return
        self.show_report(data)
        self.respond(200, {"ok": True, "report_id": data["report_id"]})

    def show_report(self, report):
        print(json.dumps(report, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), Receiver) as server:
        print(f"Webhook receiver ready at http://127.0.0.1:{server.server_port}{PATH}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

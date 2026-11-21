"""Deliver a redacted workflow report to an explicitly approved destination."""

import ipaddress
import json
import os
import re
import socket
import ssl
from collections import Counter
from contextlib import closing
from datetime import UTC, datetime
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from time import sleep
from urllib.parse import urlsplit


SEVERITIES = ("critical", "high", "medium", "low")
SCANNERS = ("secrets", "sca", "sast")
DEMO_PROJECT = "ghost-guard-demo"
ZIP_PROJECT = "training-zip"
TIMEOUT = 2
MAX_ATTEMPTS = 3
RETRY_STATUSES = {408, 429, 500, 502, 503, 504}
URL_PATH = re.compile(r"/[A-Za-z0-9/_.~-]+")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
DNS_SLOTS = BoundedSemaphore(4)


class WebhookError(Exception):
    def __init__(self, code, message, *, http_status=None, attempts=0):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.attempts = attempts


def parse_url(url):
    if (not url or len(url) > 512 or any(not 33 <= ord(char) <= 126 for char in url)
            or any(char in url for char in "\\?#@%")):
        raise ValueError("Invalid webhook URL")
    endpoint = urlsplit(url)
    host = endpoint.hostname
    if (endpoint.scheme not in {"http", "https"} or not host or not URL_PATH.fullmatch(endpoint.path)
            or {"..", "."}.intersection(endpoint.path.split("/"))
            or (endpoint.port is not None and endpoint.port == 0)):
        raise ValueError("Invalid webhook URL")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(DNS_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("Invalid webhook host") from None
    return endpoint


def allowed_endpoint(url):
    endpoint = parse_url(url)
    local_url = os.environ.get("GHOST_WEBHOOK_LOCAL_URL", "")
    if (url == local_url and endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1"
            and endpoint.port is not None and endpoint.port >= 1024):
        return endpoint, True
    if endpoint.scheme == "https" and url in os.environ.get("GHOST_WEBHOOK_ALLOWED_URLS", "").split():
        return endpoint, False
    raise WebhookError("webhook-url-not-allowed", "Адрес webhook не разрешён настройками сервера.")


def lookup(host, port, answer):
    try:
        answer.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP))
    except OSError as exc:
        answer.put(exc)
    finally:
        DNS_SLOTS.release()


def resolved_address(host, port):
    answer = Queue(1)
    if not DNS_SLOTS.acquire(timeout=TIMEOUT):
        raise TimeoutError
    try:
        Thread(target=lookup, args=(host, port, answer), daemon=True).start()
    except RuntimeError:
        DNS_SLOTS.release()
        raise OSError("DNS worker unavailable") from None
    try:
        addresses = answer.get(timeout=TIMEOUT)
    except Empty:
        raise TimeoutError from None
    if isinstance(addresses, OSError):
        raise addresses
    if not addresses:
        raise OSError("No addresses")
    for _, _, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        transition = ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo or ip.is_site_local)
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or transition:
            raise WebhookError("webhook-address-not-public", "Webhook требует публичный адрес получателя.")
    return addresses[0][4][0]


class PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, host, port, address):
        super().__init__(host, port, timeout=TIMEOUT, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        connection = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


def report_payload(report, gate, *, workflow_id, run_id, report_id, project_name):
    pairs = Counter((item["scanner"], item["severity"]) for item in report["findings"])
    return {
        "event_type": "security_scan_completed",
        "workflow_id": workflow_id,
        "run_id": run_id,
        "project_name": project_name,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "total_findings": len(report["findings"]),
        "severity_counts": {level: sum(pairs[scanner, level] for scanner in SCANNERS) for level in SEVERITIES},
        "release_gate_status": gate["status"],
        "findings_summary": [
            {"scanner": scanner, "severity": level, "count": pairs[scanner, level]}
            for scanner in SCANNERS for level in SEVERITIES if pairs[scanner, level]
        ],
        "report_id": report_id,
    }


def send_report(url, payload):
    endpoint, local = allowed_endpoint(url)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            if local:
                connection = HTTPConnection("127.0.0.1", endpoint.port, timeout=TIMEOUT)
            else:
                port = endpoint.port or 443
                address = resolved_address(endpoint.hostname, port)
                connection = PinnedHTTPSConnection(endpoint.hostname, port, address)
            with closing(connection):
                connection.request("POST", endpoint.path, body, {"Content-Type": "application/json"})
                with connection.getresponse() as response:
                    status = response.status
            if 200 <= status < 300:
                return status, attempt
            if status not in RETRY_STATUSES or attempt == MAX_ATTEMPTS:
                raise WebhookError("webhook-http-error", f"Получатель webhook вернул HTTP {status}.",
                                   http_status=status, attempts=attempt)
        except ssl.SSLError:
            raise WebhookError("webhook-tls-error", "Не удалось проверить защищённое соединение webhook.",
                               attempts=attempt) from None
        except TimeoutError:
            if attempt == MAX_ATTEMPTS:
                raise WebhookError("webhook-timeout", "Истекло время ожидания ответа webhook.",
                                   attempts=attempt) from None
        except (OSError, HTTPException):
            if attempt == MAX_ATTEMPTS:
                raise WebhookError("webhook-connection-error", "Не удалось получить ответ от webhook.",
                                   attempts=attempt) from None
        sleep(0.2 * attempt)

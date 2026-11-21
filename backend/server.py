"""Run the local API with `python -m backend.server`."""

import json
import re
import socket
import sqlite3
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread

from backend.service import (
    InvalidInput, MAX_ARCHIVE, MAX_CATALOG, runtime_directory, scan_demo, scan_upload, workflow_project,
)
from backend.version import HOST, PORT, IDENTITY
from backend.webhook import DEMO_PROJECT, ZIP_PROJECT
from backend.workflow import MAX_GRAPH_BYTES, compile_workflow, execute_workflow
from backend.workflows import WorkflowNotFound, WorkflowStore, run_scheduled


ORIGINS = {"http://127.0.0.1:5173", "http://localhost:5173"}
MAX_REQUEST = MAX_ARCHIVE + MAX_CATALOG + MAX_GRAPH_BYTES + 32 * 1024
MAX_WORKFLOW_SETTINGS = MAX_GRAPH_BYTES + 4096
WORKFLOWS_PATH = "/api/workflows"
WORKFLOW_ITEM = re.compile(r"/api/workflows/([a-f0-9]{32})(?:/(run|last-run))?")


class RequestBodyError(InvalidInput):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def parse_upload(content_type, body, fields):
    if not content_type.lower().startswith("multipart/form-data;") or "\r" in content_type or "\n" in content_type:
        raise InvalidInput("Загрузка должна быть в формате multipart/form-data.")
    try:
        envelope = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii")
        message = BytesParser(policy=policy.default).parsebytes(envelope + body)
    except (ValueError, RecursionError) as exc:
        raise InvalidInput("Не удалось разобрать загрузку.") from exc
    if not message.is_multipart() or message.defects:
        raise InvalidInput("Не удалось разобрать загрузку.")
    files = {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if part.get_content_disposition() != "form-data" or name not in fields or name in files:
            raise InvalidInput("Загрузка содержит неизвестное или повторяющееся поле.")
        if part.is_multipart() or part.get("Content-Transfer-Encoding"):
            raise InvalidInput("Ожидаются файлы без дополнительного кодирования.")
        files[name] = part.get_payload(decode=True)
    return files


def parse_json(body):
    if len(body) > MAX_WORKFLOW_SETTINGS:
        raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Параметры сценария превышают допустимый размер.")
    try:
        return json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise InvalidInput("Некорректный JSON параметров сценария.") from exc


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # API requests never need raw request lines or uploaded values in logs.
        if self.command in {"GET", "POST", "PUT", "OPTIONS"}:
            print(f"API {self.command}", flush=True)

    def response_headers(self):
        origin = self.headers.get("Origin")
        if self.allowed_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")

    def allowed_origin(self, origin):
        port = self.server.server_port
        return origin in ORIGINS or origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def respond(self, status, result=None):
        self.send_response(status)
        self.response_headers()
        if result is not None:
            data = json.dumps(result, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if result is not None:
            self.wfile.write(data)

    def request_allowed(self):
        host = self.headers.get("Host")
        port = self.server.server_port
        if host is not None and host.lower() not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
            self.respond(HTTPStatus.FORBIDDEN, {"error": "Адрес локального сервера не разрешён."})
            return False
        origin = self.headers.get("Origin")
        if origin is None or self.allowed_origin(origin):
            return True
        self.respond(HTTPStatus.FORBIDDEN, {"error": "Источник запроса не разрешён."})
        return False

    def do_OPTIONS(self):
        if self.request_allowed():
            self.respond(HTTPStatus.NO_CONTENT)

    def do_GET(self):
        if not self.request_allowed():
            return
        item = WORKFLOW_ITEM.fullmatch(self.path)
        try:
            if self.path == "/api/health":
                result = {"status": "ok", **IDENTITY}
            elif self.path == WORKFLOWS_PATH:
                result = {"workflows": self.server.workflows.list()}
            elif item and item[2] is None:
                result = self.server.workflows.get(item[1])
            elif item and item[2] == "last-run":
                result = {"last_run": self.server.workflows.last_run(item[1])}
            else:
                self.respond(HTTPStatus.NOT_FOUND, {"error": "Маршрут не найден."})
                return
        except WorkflowNotFound:
            self.respond(HTTPStatus.NOT_FOUND, {"error": "Сценарий не найден."})
            return
        except sqlite3.Error as exc:
            self.storage_error(exc)
            return
        self.respond(HTTPStatus.OK, result)

    def read_body(self, limit):
        length = self.headers.get("Content-Length", "")
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise RequestBodyError(HTTPStatus.LENGTH_REQUIRED, "Нужен размер загрузки.")
        if not length.isascii() or not length.isdecimal() or len(length) > 10:
            raise RequestBodyError(HTTPStatus.LENGTH_REQUIRED, "Нужен размер загрузки.")
        size = int(length)
        if size > limit:
            raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Размер загрузки превышает лимит.")
        self.connection.settimeout(15)
        body = self.rfile.read(size)
        if len(body) != size:
            raise InvalidInput("Загрузка прервана.")
        return body

    def read_upload(self, fields):
        return parse_upload(self.headers.get("Content-Type", ""), self.read_body(MAX_REQUEST), fields)

    def stream_workflow(self, events, *, keep_running=False):
        connected = True
        try:
            self.connection.settimeout(15)
            self.send_response(HTTPStatus.OK)
            self.response_headers()
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError:
            connected = False
        try:
            for event in events:
                if connected:
                    connected = self.write_event(event)
                if not connected and not keep_running:
                    break
        except Exception as exc:
            print(f"Workflow stream error ({type(exc).__name__})", flush=True)
            if connected:
                self.write_event({"event": "error", "error": "Не удалось завершить сценарий."})

    def write_event(self, event):
        try:
            self.wfile.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
            self.wfile.flush()
        except OSError:
            return False
        return True

    def run_workflow(self):
        data = self.read_upload({"project", "catalog", "workflow"})
        workflow = compile_workflow(data.get("workflow"))
        if "project" not in data and "catalog" in data:
            raise InvalidInput("Для загружаемого справочника нужен ZIP проекта.")
        with workflow_project(data.get("project"), data.get("catalog")) as project:
            self.stream_workflow(execute_workflow(
                workflow, project,
                project_name=ZIP_PROJECT if "project" in data else DEMO_PROJECT,
            ))

    def save_workflow(self, workflow_id=None):
        content_type = self.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type == "application/json":
            data = parse_json(self.read_body(MAX_WORKFLOW_SETTINGS))
            return self.server.workflows.save(data, workflow_id=workflow_id)
        if content_type != "multipart/form-data":
            raise RequestBodyError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Передайте JSON или multipart/form-data.")
        data = self.read_upload({"settings", "project", "catalog"})
        if "settings" not in data:
            raise InvalidInput("Передайте JSON параметров в поле settings.")
        return self.server.workflows.save(
            parse_json(data["settings"]), data.get("project"), data.get("catalog"), workflow_id=workflow_id,
        )

    def run_saved_workflow(self, workflow_id):
        store = self.server.workflows
        claimed = store.claim(workflow_id)
        if claimed is None:
            store.get(workflow_id)
            self.respond(HTTPStatus.CONFLICT, {"error": "Этот сценарий уже выполняется."})
            return
        self.stream_workflow(store.run(claimed), keep_running=True)

    def storage_error(self, exc):
        print(f"Workflow storage error ({type(exc).__name__})", flush=True)
        self.respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Не удалось обратиться к сохранённым сценариям."})

    def do_POST(self):
        self.write_request()

    def do_PUT(self):
        self.write_request()

    def write_request(self):
        if not self.request_allowed():
            return
        item = WORKFLOW_ITEM.fullmatch(self.path)
        status = HTTPStatus.OK
        try:
            if self.command == "PUT" and item and item[2] is None:
                result = self.save_workflow(item[1])
            elif self.command != "POST":
                self.respond(HTTPStatus.NOT_FOUND, {"error": "Маршрут не найден."})
                return
            elif self.path == WORKFLOWS_PATH:
                result = self.save_workflow()
                status = HTTPStatus.CREATED
            elif item and item[2] == "run":
                self.run_saved_workflow(item[1])
                return
            elif self.path == "/api/demo":
                result = scan_demo()
            elif self.path == "/api/scans":
                data = self.read_upload({"project", "catalog"})
                result = scan_upload(data.get("project"), data.get("catalog"))
            elif self.path == "/api/workflow":
                self.run_workflow()
                return
            else:
                self.respond(HTTPStatus.NOT_FOUND, {"error": "Маршрут не найден."})
                return
        except RequestBodyError as exc:
            self.respond(exc.status, {"error": str(exc)})
            return
        except InvalidInput as exc:
            self.respond(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except WorkflowNotFound:
            self.respond(HTTPStatus.NOT_FOUND, {"error": "Сценарий не найден."})
            return
        except sqlite3.Error as exc:
            self.storage_error(exc)
            return
        except TimeoutError:
            self.respond(HTTPStatus.REQUEST_TIMEOUT, {"error": "Загрузка заняла слишком много времени."})
            return
        except OSError as exc:
            print(f"Scan I/O error ({type(exc).__name__})", flush=True)
            self.respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Не удалось обработать файлы проекта."})
            return
        self.respond(status, result)


class LocalHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.allow_reuse_address = False
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def main():
    with LocalHTTPServer((HOST, PORT), Handler) as server:
        runtime = runtime_directory()
        server.workflows = WorkflowStore(runtime / "workflows.sqlite3")
        server.workflows.recover_interrupted()
        stopped = Event()
        Thread(target=run_scheduled, args=(server.workflows, stopped), daemon=True).start()
        print(f"GHOST//GUARD backend ready at http://{HOST}:{server.server_port} build={IDENTITY['build_id']}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stopped.set()


if __name__ == "__main__":
    main()

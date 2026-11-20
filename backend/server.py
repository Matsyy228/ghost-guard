"""Run the local API with `python -m backend.server`."""

import json
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from backend.service import (
    InvalidInput, MAX_ARCHIVE, MAX_CATALOG, demo_project, scan_demo, scan_upload, upload_project,
)
from backend.workflow import MAX_GRAPH_BYTES, compile_workflow, execute_workflow


HOST, PORT = "127.0.0.1", 8000
ORIGINS = {"http://127.0.0.1:5173", "http://localhost:5173"}
MAX_REQUEST = MAX_ARCHIVE + MAX_CATALOG + MAX_GRAPH_BYTES + 32 * 1024


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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # API requests never need raw request lines or uploaded values in logs.
        if self.command in {"GET", "POST", "OPTIONS"}:
            print(f"API {self.command}", flush=True)

    def response_headers(self):
        origin = self.headers.get("Origin")
        if origin in ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")

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

    def allowed_origin(self):
        origin = self.headers.get("Origin")
        if origin is None or origin in ORIGINS:
            return True
        self.respond(HTTPStatus.FORBIDDEN, {"error": "Источник запроса не разрешён."})
        return False

    def do_OPTIONS(self):
        if self.allowed_origin():
            self.respond(HTTPStatus.NO_CONTENT)

    def do_GET(self):
        if not self.allowed_origin():
            return
        if self.path == "/api/health":
            self.respond(HTTPStatus.OK, {"status": "ok"})
        else:
            self.respond(HTTPStatus.NOT_FOUND, {"error": "Маршрут не найден."})

    def read_upload(self, fields):
        length = self.headers.get("Content-Length", "")
        if not length.isascii() or not length.isdecimal() or len(length) > 10:
            raise RequestBodyError(HTTPStatus.LENGTH_REQUIRED, "Нужен размер загрузки.")
        size = int(length)
        if size > MAX_REQUEST:
            raise RequestBodyError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Размер загрузки превышает лимит.")
        self.connection.settimeout(15)
        body = self.rfile.read(size)
        if len(body) != size:
            raise InvalidInput("Загрузка прервана.")
        return parse_upload(self.headers.get("Content-Type", ""), body, fields)

    def stream_workflow(self, workflow, project):
        self.send_response(HTTPStatus.OK)
        self.response_headers()
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for event in execute_workflow(workflow, project):
                self.wfile.write((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
                self.wfile.flush()
        except OSError:
            # A disconnected or timed-out client cannot receive further events.
            return

    def run_workflow(self):
        data = self.read_upload({"project", "catalog", "workflow"})
        workflow = compile_workflow(data.get("workflow"))
        if "project" in data:
            with upload_project(data["project"], data.get("catalog")) as project:
                self.stream_workflow(workflow, project)
        elif "catalog" in data:
            raise InvalidInput("Для загружаемого справочника нужен ZIP проекта.")
        else:
            self.stream_workflow(workflow, demo_project())

    def do_POST(self):
        if not self.allowed_origin():
            return
        try:
            if self.path == "/api/demo":
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
        except TimeoutError:
            self.respond(HTTPStatus.REQUEST_TIMEOUT, {"error": "Загрузка заняла слишком много времени."})
            return
        except OSError as exc:
            print(f"Scan I/O error ({type(exc).__name__})", flush=True)
            self.respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Не удалось обработать файлы проекта."})
            return
        self.respond(HTTPStatus.OK, result)


def main():
    with ThreadingHTTPServer((HOST, PORT), Handler) as server:
        print(f"Backend ready at http://{HOST}:{PORT}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

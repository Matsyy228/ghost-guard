"""Manage the bundled Windows llama.cpp process for the local provider."""

import json
import os
import socket
import subprocess
from datetime import UTC, datetime
from http.client import HTTPConnection, HTTPException
from secrets import token_urlsafe
from threading import Lock
from time import monotonic, sleep

from backend.llm import LLMError, analyze_findings, explicit_provider, llm_disabled
from backend.local_llm_assets import (
    ENGINE, ENGINE_DIRECTORY, ENGINE_EXECUTABLE, ENGINE_VERSION, MODEL_NAME, WEIGHTS, verify_install,
)


MODEL = "ghost-qwen"
HOST = "127.0.0.1"
PROBE_FINDING = {
    "id": "SECRETS-F0001", "scanner": "secrets", "rule": "password", "severity": "high",
    "title": "Пароль задан строковым литералом",
    "recommendation": "Передавайте секрет из окружения или хранилища и замените действующий секрет.",
    "file": "Synthetic.kt", "line": 1,
}


class LocalModel:
    def __init__(self, directory):
        self.directory = directory
        self.executable = directory / ENGINE_DIRECTORY / ENGINE_EXECUTABLE
        self.weights = directory / WEIGHTS.name
        self.lock = Lock()
        self.probe_lock = Lock()
        self.last_probe = {"status": "not-run"}
        self.process = None
        self.endpoint = None
        self.key = None
        self.closed = False

    def installed(self):
        return os.name == "nt" and all(path.is_file() for path in (
            self.executable, self.weights, self.directory / ENGINE.name,
        ))

    def alive(self):
        process = self.process
        return self.endpoint is not None and process is not None and process.poll() is None

    def status(self):
        disabled, override = llm_disabled(), explicit_provider()
        managed = not disabled and not override
        return {
            "model": MODEL_NAME,
            "provider": "local",
            "engine": "llama.cpp",
            "engine_version": ENGINE_VERSION,
            "mode": "disabled" if disabled else "configured-provider" if override else "managed",
            "installed": self.installed(),
            "ready": managed and self.alive(),
            "last_probe": self.last_probe,
        }

    def probe(self):
        if not self.probe_lock.acquire(blocking=False):
            raise LLMError("llm-probe-busy", "Локальная проверка уже выполняется.")
        try:
            if explicit_provider() and not llm_disabled():
                raise LLMError("llm-local-probe-unavailable", "Проверка запускается только для управляемой локальной Qwen.")
            result = analyze_findings([PROBE_FINDING], local_provider=self.config)
            explanation = result["explanations"][0]
        except LLMError as exc:
            self.last_probe = {"status": "failed", "code": exc.code, "checked_at": self.probe_timestamp()}
            raise
        else:
            self.last_probe = {"status": "ok", "generation_ms": result["generation_ms"],
                               "checked_at": self.probe_timestamp()}
            return {**self.status(), "sample": {key: explanation[key] for key in ("explanation", "recommendation")}}
        finally:
            self.probe_lock.release()

    @staticmethod
    def probe_timestamp():
        return datetime.now(UTC).isoformat(timespec="seconds")

    def config(self):
        if not self.installed():
            raise LLMError("llm-not-configured", "Установите локальную Qwen с помощью scripts/setup-local-llm.ps1.")
        with self.lock:
            if self.closed:
                raise LLMError("llm-provider-error", "Backend завершает работу.")
            if not self.alive():
                self.stop()
                try:
                    verify_install(self.directory)
                except (OSError, ValueError) as exc:
                    raise LLMError("llm-local-integrity-error", "Файлы Qwen или llama.cpp не прошли проверку. Повторите установку.") from exc
                cpu = ("--device", "none", "--n-gpu-layers", "0")
                devices = (cpu,) if os.environ.get("GHOST_LLM_CPU_ONLY") == "1" else (("--n-gpu-layers", "99"), cpu)
                for device_args in devices:
                    if self.start(device_args):
                        break
                else:
                    raise LLMError("llm-local-start-error", "Не удалось запустить локальную Qwen. Проверьте модель и сборку llama.cpp.")
            return self.endpoint, MODEL, self.key

    def start(self, device_args):
        key = token_urlsafe(32)
        try:
            with socket.socket() as listener:
                listener.bind((HOST, 0))
                port = listener.getsockname()[1]
            args = [
                self.executable, "--model", self.weights, "--host", HOST, "--port", str(port), "--alias", MODEL,
                "--ctx-size", "4096", "--parallel", "1", "--temp", "0", "--no-ui", "--log-disable", *device_args,
            ]
            env = {name: value for name, value in os.environ.items() if not name.upper().startswith(("LLAMA_", "GHOST_"))}
            env["LLAMA_API_KEY"] = key
            self.process = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=self.executable.parent, env=env, creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except OSError:
            return False

        deadline = monotonic() + 20
        while self.process.poll() is None and monotonic() < deadline:
            connection = HTTPConnection(HOST, port, timeout=0.5)
            try:
                connection.request("GET", "/health")
                with connection.getresponse() as health:
                    if health.status != 200 or json.loads(health.read(1024)) != {"status": "ok"}:
                        sleep(0.15)
                        continue
                connection.request("GET", "/v1/models", headers={"Authorization": f"Bearer {key}"})
                with connection.getresponse() as response:
                    if response.status == 200 and any(
                        model.get("id") == MODEL for model in json.loads(response.read(8192)).get("data", [])
                    ):
                        self.endpoint = f"http://{HOST}:{port}/v1/chat/completions"
                        self.key = key
                        return True
            except (OSError, HTTPException, ValueError, TypeError, AttributeError):
                pass
            finally:
                connection.close()
            sleep(0.15)
        self.stop()
        return False

    def stop(self):
        self.endpoint = self.key = None
        process, self.process = self.process, None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def close(self):
        with self.lock:
            self.closed = True
            self.stop()

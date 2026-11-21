"""Identify the local backend build and verify the API before starting its UI."""

import argparse
import hashlib
import json
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from time import monotonic, sleep


HOST, PORT = "127.0.0.1", 8000
SERVICE = "ghost-guard"
API_VERSION = 2


def build_id():
    root = Path(__file__).resolve().parent.parent
    files = [root / "scan.py", *root.glob("backend/*.py"), *root.glob("analyzers/*.py")]
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).digest())
    return digest.hexdigest()[:16]


IDENTITY = {"service": SERVICE, "api_version": API_VERSION, "build_id": build_id(),
            "source_policy": "operator-sha256"}


def check_running():
    deadline = monotonic() + 10
    while True:
        connection = HTTPConnection(HOST, PORT, timeout=2)
        try:
            connection.request("GET", "/api/health")
            response = connection.getresponse()
            health = json.loads(response.read(4096))
            if (response.status != 200 or not isinstance(health, dict) or health.get("status") != "ok"
                    or any(health.get(key) != value for key, value in IDENTITY.items())):
                raise SystemExit(f"Backend on port {PORT} does not match this workspace (expected {IDENTITY['build_id']}).")
            return
        except ConnectionRefusedError:
            if monotonic() >= deadline:
                raise SystemExit(f"Backend on port {PORT} did not start.")
            sleep(0.25)
        except (OSError, HTTPException, ValueError) as exc:
            raise SystemExit(f"Could not verify backend on port {PORT} ({type(exc).__name__}).") from exc
        finally:
            connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="require a matching server on the standard port")
    if parser.parse_args().check:
        check_running()
    print(IDENTITY["build_id"])

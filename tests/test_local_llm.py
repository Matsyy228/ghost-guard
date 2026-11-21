import hashlib
import json
import unittest
from contextlib import closing
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import patch
from zipfile import ZipFile

from backend.local_llm import LocalModel
from backend.local_llm_assets import Asset, ENGINE_DIRECTORY, check_engine, install_asset
from backend.server import Handler


def asset_for(name, data):
    return Asset(name, "https://example.invalid/unused", len(data), hashlib.sha256(data).hexdigest())


class LocalAssetTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))

    def test_offline_cache_install_and_verified_reuse(self):
        cache = self.root / "cache"
        cache.mkdir()
        original = b"verified model fixture"
        asset = asset_for("test.gguf", original)
        (cache / asset.name).write_bytes(original)
        install_asset(asset, self.root, cache, offline=True)
        self.assertEqual((self.root / asset.name).read_bytes(), original)
        with patch("backend.local_llm_assets.build_opener") as network:
            install_asset(asset, self.root, offline=True)
        network.assert_not_called()

    def test_bad_cache_is_not_installed_and_partial_is_removed(self):
        cache = self.root / "cache"
        cache.mkdir()
        asset = asset_for("test.gguf", b"good")
        (cache / asset.name).write_bytes(b"fake")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            install_asset(asset, self.root, cache, offline=True)
        self.assertFalse((self.root / asset.name).exists())
        self.assertEqual(list(self.root.glob("*.partial")), [])

    def test_offline_without_cache_explains_missing_file(self):
        with self.assertRaisesRegex(ValueError, "Offline install needs"):
            install_asset(asset_for("test.gguf", b"test"), self.root, offline=True)

    def test_engine_is_repaired_from_verified_zip_and_rejects_extra_dll(self):
        zip_path = self.root / "engine.zip"
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("llama-server.exe", b"expected executable bytes")
            archive.writestr("test.dll", b"expected DLL bytes")
        with patch("backend.local_llm_assets.ENGINE", asset_for(zip_path.name, zip_path.read_bytes())):
            check_engine(self.root, repair=True)
            dll = self.root / ENGINE_DIRECTORY / "test.dll"
            dll.write_bytes(b"edited DLL")
            with self.assertRaisesRegex(ValueError, "failed verification"):
                check_engine(self.root)
            check_engine(self.root, repair=True)
            check_engine(self.root)
            (dll.parent / "extra.dll").touch()
            with self.assertRaisesRegex(ValueError, "Unexpected DLL"):
                check_engine(self.root, repair=True)


class LocalDiagnosticTests(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(TemporaryDirectory()))
        self.model = LocalModel(directory)
        self.server = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        self.server.local_model = self.model
        worker = Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.model.close)
        self.enterContext(patch.dict("os.environ", {"GHOST_LLM_BASE_URL": "", "GHOST_LLM_MODEL": "",
                                                    "GHOST_LLM_API_KEY": "", "GHOST_LLM_DISABLED": ""}))

    def request(self, method, route):
        with closing(HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)) as connection:
            connection.request(method, route)
            with connection.getresponse() as response:
                return response.status, json.load(response)

    def test_get_status_is_passive_and_does_not_expose_internal_fields(self):
        self.model.key = "sensitive-fixture"
        with patch.object(self.model, "config") as launch:
            status, body = self.request("GET", "/api/llm/status")
        launch.assert_not_called()
        self.assertEqual(status, 200)
        self.assertEqual((body["provider"], body["ready"], body["last_probe"]), ("local", False, {"status": "not-run"}))
        self.assertNotIn("sensitive-fixture", json.dumps(body))
        self.assertNotIn(str(self.model.directory), str(body))

    def test_probe_records_unavailable_installation_and_never_uses_override(self):
        status, body = self.request("POST", "/api/llm/probe")
        self.assertEqual((status, body["code"], body["last_probe"]["status"]), (503, "llm-not-configured", "failed"))
        with patch.dict("os.environ", {"GHOST_LLM_BASE_URL": "https://example.invalid/v1", "GHOST_LLM_MODEL": "override"}):
            with patch("backend.local_llm.analyze_findings") as analyze:
                status, body = self.request("POST", "/api/llm/probe")
            analyze.assert_not_called()
        self.assertEqual((status, body["code"], body["mode"]),
                         (503, "llm-local-probe-unavailable", "configured-provider"))

    def test_probe_uses_validated_synthetic_explanation_and_stores_only_status(self):
        response = {"explanations": [{"explanation": "Пароль доступен в коде.",
                                      "recommendation": "Замените секрет.", "file": "Synthetic.kt"}],
                    "generation_ms": 42}
        with patch("backend.local_llm.analyze_findings", return_value=response) as analyze:
            status, body = self.request("POST", "/api/llm/probe")
        self.assertEqual(status, 200)
        self.assertEqual(analyze.call_args.args[0][0]["scanner"], "secrets")
        self.assertEqual(body["sample"], {"explanation": "Пароль доступен в коде.", "recommendation": "Замените секрет."})
        self.assertEqual(body["last_probe"]["generation_ms"], 42)
        self.assertNotIn("sample", self.request("GET", "/api/llm/status")[1])

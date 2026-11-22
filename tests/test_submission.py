import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from analyzers.common import finding, submission_report
from backend.service import DEMO, upload_project
from backend.source_policy import SourcePolicy
from backend.workflow import compile_workflow, execute_workflow


class SubmissionFormatTests(unittest.TestCase):
    def test_exact_keys_and_values_for_each_category(self):
        report = {
            "findings": [
                finding("secrets", "recoverable-token", "high", r"src\main\kotlin\Client.kt",
                        11, "Токен в коде", "Использовать переменную окружения", endLine=13, id="f1"),
                finding("sast", "tls-verification", "medium", "modules/client/src/Client.kt",
                        24, "Ослаблена проверка TLS", "Включить проверку", endLine=25, id="f2"),
                finding("sca", "affected-dependency", "critical", "build.gradle.kts", 8,
                        "Уязвимая зависимость", "Обновить версию", group="sample.group", artifact="library",
                        version="1.0.0", advisoryId="CVE-2022-42889", package="sample.group:library", id="f3"),
            ],
            "sca": {"unresolved_versions": [{"file": "build.gradle.kts", "line": 9, "package": "sample:unknown"}]},
        }
        original = deepcopy(report)

        exported = submission_report(report)

        self.assertEqual(exported, {"findings": [
            {"category": "SECRET", "path": "src/main/kotlin/Client.kt", "class": "recoverable-token",
             "line": 11, "endLine": 13, "severity": "HIGH", "description": "Токен в коде",
             "remediation": "Использовать переменную окружения"},
            {"category": "SAST", "path": "modules/client/src/Client.kt", "class": "tls-verification",
             "line": 24, "endLine": 25, "severity": "MEDIUM", "description": "Ослаблена проверка TLS",
             "remediation": "Включить проверку"},
            {"category": "SCA", "path": "build.gradle.kts", "group": "sample.group", "artifact": "library",
             "version": "1.0.0", "advisoryId": "CVE-2022-42889", "severity": "CRITICAL",
             "description": "Уязвимая зависимость", "remediation": "Обновить версию"},
        ]})
        self.assertIs(type(exported["findings"][0]["line"]), int)
        self.assertIs(type(exported["findings"][0]["endLine"]), int)
        self.assertIs(type(exported["findings"][1]["line"]), int)
        self.assertIs(type(exported["findings"][1]["endLine"]), int)
        self.assertEqual(report, original)

    def test_empty_findings(self):
        self.assertEqual(submission_report({"findings": []}), {"findings": []})

    def test_rejects_paths_outside_project(self):
        for path in ("", "../Client.kt", "src/../Client.kt", "/root/Client.kt", r"C:\src\Client.kt",
                     r"\\server\share\Client.kt", "C:Client.kt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                submission_report({"findings": [
                    finding("secrets", "password", "high", path, 1, "Встроенный пароль", "Вынести в окружение"),
                ]})


class SubmissionZipTests(unittest.TestCase):
    def test_wrapped_and_flat_zip_have_the_same_project_relative_export(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        policy = SourcePolicy(root / "approved")
        demo = DEMO / "project"
        catalog = (DEMO / "catalog.json").read_bytes()
        chain = ["trigger", "secrets", "sca", "sast", "report"]
        workflow = compile_workflow(json.dumps({
            "nodes": [{"id": node, "type": node} for node in chain],
            "edges": [{"source": source, "target": target} for source, target in zip(chain, chain[1:])],
        }).encode())
        exports = []
        for prefix in ("", "project-export/"):
            with self.subTest(prefix=prefix):
                archive = BytesIO()
                with ZipFile(archive, "w") as zipped:
                    for file in sorted(demo.rglob("*")):
                        if file.is_file():
                            relative = file.relative_to(demo).as_posix()
                            if relative == "build.gradle.kts":
                                unknown = '\n dependencies { implementation("example.training:demo-library:$unknownVersion") }\n'
                                zipped.writestr(prefix + relative, file.read_text(encoding="utf-8") + unknown)
                            else:
                                zipped.write(file, prefix + relative)
                zipped_project = archive.getvalue()
                policy.approve(zipped_project)
                with upload_project(zipped_project, catalog, source_policy=policy) as project:
                    result = list(execute_workflow(workflow, project))[-1]
                self.assertEqual(result["event"], "result")
                unresolved = result["report"]["sca"]["unresolved_versions"]
                self.assertEqual([(item["file"], item["package"]) for item in unresolved],
                                 [(prefix + "build.gradle.kts", "example.training:demo-library")])
                self.assertCountEqual(
                    [(item["scanner"], item["file"]) for item in result["report"]["findings"]],
                    [("secrets", prefix + "src/main/resources/application-demo.yml"),
                     ("sast", prefix + "src/main/resources/application-demo.yml"),
                     ("sca", prefix + "build.gradle.kts")],
                )
                self.assertCountEqual(
                    [(item["category"], item["path"]) for item in result["submission"]["findings"]],
                    [("SECRET", "src/main/resources/application-demo.yml"),
                     ("SAST", "src/main/resources/application-demo.yml"),
                     ("SCA", "build.gradle.kts")],
                )
                self.assertTrue(all("endLine" not in item for item in result["submission"]["findings"]))
                exports.append(result["submission"])
        self.assertEqual(len(exports), 2)
        flat_export, wrapped_export = exports
        self.assertEqual(flat_export, wrapped_export)

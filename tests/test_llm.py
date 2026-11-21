import json
import unittest
from io import BytesIO
from urllib.error import URLError
from unittest.mock import patch

from backend.llm import LLMError, explain_findings
from backend.service import demo_project
from backend.workflow import compile_workflow, execute_workflow


FINDING = {
    "id": "SCA-F0001", "scanner": "sca", "rule": "affected-dependency", "severity": "high",
    "file": "internal-name/build.gradle.kts", "line": 7, "advisoryId": "CVE-2099-12345",
    "source": "private-fixture-text",
}
EXPLANATION = {
    "finding_id": "SCA-F0001", "explanation": "Текущая версия зависимости затронута опубликованной проблемой.",
    "recommendation": "Обновите зависимость до исправленной версии.",
}
SETTINGS = {"GHOST_LLM_BASE_URL": "http://127.0.0.1:11434/v1", "GHOST_LLM_MODEL": "local-model"}


def provider_response(explanations):
    text = json.dumps({"explanations": explanations})
    return BytesIO(json.dumps({"choices": [{"message": {"content": text}}]}).encode())


def workflow():
    nodes = [{"id": node, "type": node} for node in ("trigger", "secrets", "llm", "report")]
    edges = [{"source": first["id"], "target": second["id"]} for first, second in zip(nodes, nodes[1:])]
    return compile_workflow(json.dumps({"nodes": nodes, "edges": edges}).encode())


class LLMTests(unittest.TestCase):
    def test_only_scanner_metadata_reaches_provider(self):
        with (patch.dict("os.environ", SETTINGS, clear=True), patch("backend.llm.build_opener") as opener):
            opener.return_value.open.return_value = provider_response([EXPLANATION])
            result = explain_findings([FINDING])
            request = opener.return_value.open.call_args.args[0]
        payload = json.loads(request.data)
        metadata = json.loads(payload["messages"][1]["content"])
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/v1/chat/completions")
        self.assertEqual(metadata, [{"finding_id": "SCA-F0001", "category": "sca", "rule": "affected-dependency",
                                     "severity": "high", "advisory_id": "CVE-2099-12345"}])
        self.assertNotIn("internal-name", str(payload))
        self.assertNotIn("private-fixture-text", str(payload))
        self.assertEqual(result, [{**EXPLANATION, "file": FINDING["file"], "line": 7, "advisoryId": "CVE-2099-12345"}])

    def test_rejects_wrong_ids_advisories_and_locations(self):
        invalid = [
            [{**EXPLANATION, "finding_id": "SCA-F9999"}],
            [EXPLANATION, EXPLANATION],
            [{**EXPLANATION, "explanation": "Влияет CVE-2099-98765."}],
            [{**EXPLANATION, "explanation": "Влияет CVE-2099-001."}],
            [{**EXPLANATION, "explanation": "Относится к SCA-F9999."}],
            [{**EXPLANATION, "recommendation": "Измените fake.kt в строке 9."}],
            [{**EXPLANATION, "line": 999}],
            [],
        ]
        for variant in invalid:
            with (self.subTest(variant=variant), patch.dict("os.environ", SETTINGS, clear=True),
                  patch("backend.llm.build_opener") as opener):
                opener.return_value.open.return_value = provider_response(variant)
                with self.assertRaises(LLMError) as error:
                    explain_findings([FINDING])
                self.assertEqual(error.exception.code, "llm-invalid-response")

    def test_workflow_runs_analysis_and_attaches_to_following_report(self):
        explanation = {**EXPLANATION, "finding_id": "SECRETS-F0001"}
        with (patch.dict("os.environ", SETTINGS, clear=True), patch("backend.llm.build_opener") as opener):
            opener.return_value.open.return_value = provider_response([explanation])
            events = list(execute_workflow(workflow(), demo_project()))
        node = next(event for event in events if event.get("id") == "llm" and event["status"] == "done")
        finding, = events[-1]["report"]["findings"]
        expected = [{**explanation, "file": finding["file"], "line": finding["line"]}]
        self.assertEqual(node["output"]["explanations"], expected)
        self.assertEqual(events[-1]["report"]["explanations"], expected)

    def test_skip_provider_failure_and_invalid_json_keep_scan_result(self):
        for env, provider_error, status, code in (
            ({}, None, "skipped", "llm-not-configured"),
            (SETTINGS, URLError("private provider detail"), "failed", "llm-provider-error"),
            (SETTINGS, None, "failed", "llm-invalid-response"),
        ):
            with (self.subTest(code=code), patch.dict("os.environ", env, clear=True),
                  patch("backend.llm.build_opener") as opener):
                opener.return_value.open.side_effect = provider_error
                opener.return_value.open.return_value = BytesIO(b"malformed response")
                events = list(execute_workflow(workflow(), demo_project()))
            node = next(event for event in events if event.get("id") == "llm" and event["status"] == status)
            self.assertEqual(node["code"], code)
            self.assertEqual(node["output"]["explanations"], [])
            self.assertNotIn("private provider detail", json.dumps(events))
            self.assertEqual(events[-1]["event"], "result")
            self.assertEqual(len(events[-1]["report"]["findings"]), 1)


if __name__ == "__main__":
    unittest.main()

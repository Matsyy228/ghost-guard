import json
import unittest
from io import BytesIO
from urllib.error import URLError
from unittest.mock import patch

from backend.llm import LLMError, analyze_findings, explain_findings
from backend.service import demo_project
from backend.workflow import compile_workflow, execute_workflow


FINDING = {
    "id": "SCA-F0001", "scanner": "sca", "rule": "affected-dependency", "severity": "high",
    "title": "Версия зависимости входит в уязвимый диапазон",
    "recommendation": "Обновите зависимость до исправленной версии.",
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
                                     "severity": "high", "advisory_id": "CVE-2099-12345",
                                     "title": FINDING["title"], "fix": FINDING["recommendation"]}])
        self.assertNotIn("internal-name", str(payload))
        self.assertNotIn("private-fixture-text", str(payload))
        self.assertEqual(result, [{**EXPLANATION, "file": FINDING["file"], "line": 7, "advisoryId": "CVE-2099-12345"}])

    def test_managed_provider_is_used_only_without_an_explicit_provider(self):
        endpoint = "http://127.0.0.1:8888/v1/chat/completions"
        with (patch.dict("os.environ", {}, clear=True), patch("backend.llm.build_opener") as opener,
              patch("backend.local_llm.LocalModel.config", return_value=(endpoint, "ghost-qwen", "local-key")) as local):
            local_explanation = {key: EXPLANATION[key] for key in ("finding_id", "explanation")}
            opener.return_value.open.side_effect = [provider_response([local_explanation]), provider_response([EXPLANATION])]
            explain_findings([FINDING], local_provider=local)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, endpoint)
            self.assertEqual(request.get_header("Authorization"), "Bearer local-key")

            with patch.dict("os.environ", SETTINGS):
                explain_findings([FINDING], local_provider=local)
            local.assert_called_once()
            self.assertEqual(opener.return_value.open.call_args.args[0].full_url,
                             "http://127.0.0.1:11434/v1/chat/completions")

    def test_managed_request_is_compact_and_only_sends_masked_location(self):
        canary = "SYNTHETIC_PRIVATE_VALUE"
        finding = {**FINDING, "file": f"src/main/{canary}.kt", "source": canary,
                   "recommendation": canary, "snippet": canary}
        with (patch.dict("os.environ", {}, clear=True), patch("backend.llm.build_opener") as opener,
              patch("backend.local_llm.LocalModel.config", return_value=("http://127.0.0.1:8888/v1/chat/completions",
                                                                      "ghost-qwen", "")) as local):
            opener.return_value.open.return_value = provider_response([{
                "finding_id": FINDING["id"], "explanation": "Если используется функция, возможен эффект из бюллетеня.",
            }])
            result = explain_findings([finding], local_provider=local)
        request = opener.return_value.open.call_args.args[0]
        payload = json.loads(request.data)
        metadata, = json.loads(payload["messages"][1]["content"])
        self.assertEqual((metadata["path"], metadata["line"]), ("src/main/_", 7))
        self.assertEqual(metadata["advisory_id"], FINDING["advisoryId"])
        self.assertIn("бюллетене", metadata["risk"])
        self.assertNotIn(canary, request.data.decode())
        self.assertLess(payload["max_tokens"], 2200)
        self.assertEqual(result[0]["file"], finding["file"])
        self.assertEqual(set(result[0]), {"finding_id", "file", "line", "advisoryId", "explanation", "recommendation"})

    def test_managed_risk_is_grounded_and_server_adds_repair_and_verification(self):
        def provider():
            return "http://127.0.0.1:8888/v1/chat/completions", "ghost-qwen", ""

        def reply(request, **kwargs):
            metadata, = json.loads(json.loads(request.data)["messages"][1]["content"])
            explanation = {"finding_id": FINDING["id"], "explanation": risk or metadata["risk"]}
            data = {"explanations": [explanation], "summary": {"priority_ids": [FINDING["id"]]}}
            return BytesIO(json.dumps({"choices": [{"message": {"content": json.dumps(data)}}]}).encode())

        for risk in (None, FINDING["title"], "Если библиотека загружена, возможна SQL-инъекция.",
                     "Приложение использует затронутую функцию, возможны последствия из бюллетеня."):
            with self.subTest(risk=risk), patch.dict("os.environ", {}, clear=True), patch("backend.llm.build_opener") as opener:
                opener.return_value.open.side_effect = reply
                result = analyze_findings([FINDING], local_provider=provider)
                opener.return_value.open.assert_called_once()
            public, = result["explanations"]
            self.assertTrue(public["explanation"].startswith("Если приложение использует затронутую функцию"))
            self.assertIn("Сверьте версию в графе Gradle", public["recommendation"])
            self.assertNotIn("SQL", str(public))
            self.assertEqual(result["summary_code"], "llm-guidance-fallback" if risk else None)

    def test_managed_response_rejects_unknown_references_and_extra_fields(self):
        def provider():
            return "http://127.0.0.1:8888/v1/chat/completions", "ghost-qwen", ""

        for extra in ({"finding_id": "SCA-F9999"}, {"explanation": "Затронута CWE."}, {"severity": "critical"},
                      {"release_gate": "PASS"}, {"explanation": "Смотрите другую находку в fake.kt."}):
            response = {"explanations": [{"finding_id": FINDING["id"], "explanation": "Текст модели.", **extra}]}
            with self.subTest(extra=extra), patch.dict("os.environ", {}, clear=True), patch(
                "backend.llm.call_provider", return_value=response,
            ), self.assertRaises(LLMError):
                analyze_findings([FINDING], local_provider=provider)

    def test_managed_unrecognized_rule_does_not_generate_unverified_guidance(self):
        finding = {**FINDING, "id": "SAST-F0001", "scanner": "sast", "rule": "unrecognized-rule"}
        with (patch.dict("os.environ", {}, clear=True), patch("backend.local_llm.LocalModel.config") as local,
              self.assertRaises(LLMError) as error):
            analyze_findings([finding], local_provider=local)
        self.assertEqual(error.exception.code, "llm-no-findings")
        local.assert_not_called()

    def test_rejects_wrong_ids_advisories_and_locations(self):
        invalid = [
            [{**EXPLANATION, "finding_id": "SCA-F9999"}],
            [EXPLANATION, EXPLANATION],
            [{**EXPLANATION, "explanation": "Влияет CVE-2099-98765."}],
            [{**EXPLANATION, "explanation": "Влияет CVE-2099-001."}],
            [{**EXPLANATION, "explanation": "Относится к SCA-F9999."}],
            [{**EXPLANATION, "recommendation": "Измените fake.kt в строке 9."}],
            [{**EXPLANATION, "recommendation": "Update the dependency."}],
            [{**EXPLANATION, "recommendation": "Для этого 更新依赖项。"}],
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

"""Explain existing findings through a server-configured chat completion provider."""

import json
import os
import re
from http.client import HTTPException
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_FINDINGS = 20
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT = 22
FINDING_ID = re.compile(r"(?:SECRETS|SAST|SCA)-F[0-9]{4,}")
RULE = re.compile(r"[a-z][a-z0-9-]{0,63}")
MODEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,127}")
ADVISORY = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}(?:-[a-z0-9]{4}){2})\b", re.I | re.ASCII)
TEXT_ADVISORY = re.compile(r"\b(?:CVE|GHSA)-[a-z0-9-]+", re.I | re.ASCII)
TEXT_FINDING_ID = re.compile(r"\b(?:SECRETS|SAST|SCA)-F[0-9]+\b", re.I | re.ASCII)
LOCATION_OR_LINK = re.compile(
    r"https?://|\bwww\.|\b[\w.-]+\.(?:kt|kts|java|ya?ml|json|properties|lockfile)(?:\b|:)|"
    r"\b(?:lines?|строк[а-яё]*)\s*[:#№]?\s*\d+",
    re.I,
)
CYRILLIC = re.compile(r"[А-Яа-яЁё]")
HAN = re.compile(r"[\u3400-\u9fff]")
SEVERITY = {name: index for index, name in enumerate(("low", "medium", "high", "critical"))}
SYSTEM_PROMPT = (
    'Напиши разработчику короткое объяснение для каждого входного finding_id. Ответ строго на русском языке.\n'
    'Формат JSON: {"explanations":[{"finding_id":"ID из входа","explanation":"Кратко опишите риск.",'
    '"recommendation":"Предложите конкретное исправление."}]}\n'
    'Опирайся на title и fix. До 10 слов в каждом предложении. Скопируй только входные идентификаторы. '
    'Не указывай критичность, ссылки, файлы, строки, версии или advisory ID.'
)


class LLMError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def provider_config():
    base = os.environ.get("GHOST_LLM_BASE_URL", "").strip()
    model = os.environ.get("GHOST_LLM_MODEL", "").strip()
    key = os.environ.get("GHOST_LLM_API_KEY", "").strip()
    if not base or not model:
        raise LLMError("llm-not-configured", "Укажите адрес и модель LLM в окружении сервера.")
    try:
        url = urlsplit(base)
        host = url.hostname
        port = url.port
    except ValueError as exc:
        raise LLMError("llm-config-error", "Некорректный адрес LLM-провайдера.") from exc
    local = host in {"localhost", "127.0.0.1", "::1"}
    if (not host or url.username is not None or url.password is not None or url.query or url.fragment
            or url.scheme not in ({"http", "https"} if local else {"https"})
            or port == 0 or re.search(r"[\s\\]", base) or not MODEL.fullmatch(model)):
        raise LLMError("llm-config-error", "Проверьте адрес и имя модели LLM.")
    if not local and not key:
        raise LLMError("llm-not-configured", "Укажите ключ LLM в окружении сервера.")
    if key and not re.fullmatch(r"[!-~]+", key):
        raise LLMError("llm-config-error", "Проверьте формат ключа LLM в окружении сервера.")
    endpoint = urlunsplit((url.scheme, url.netloc, url.path.rstrip("/") + "/chat/completions", "", ""))
    return endpoint, model, key


def request_metadata(findings):
    eligible = [item for item in findings if FINDING_ID.fullmatch(item["id"]) and RULE.fullmatch(item["rule"])
                and item["scanner"] in {"secrets", "sast", "sca"} and item["severity"] in SEVERITY]
    ranked = sorted(eligible, key=lambda item: -SEVERITY[item["severity"]])[:MAX_FINDINGS]
    return {item["id"]: item for item in ranked}


def call_provider(endpoint, model, key, requested):
    messages = []
    for item in requested.values():
        metadata = {"finding_id": item["id"], "category": item["scanner"],
                    "rule": item["rule"], "severity": item["severity"],
                    "title": item["title"], "fix": item["recommendation"][:220]}
        advisory = item.get("advisoryId", "")
        if ADVISORY.fullmatch(advisory):
            metadata["advisory_id"] = advisory
        messages.append(metadata)
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": json.dumps(messages, ensure_ascii=False, separators=(",", ":"))}],
        "response_format": {"type": "json_object"},
        "stream": False,
        "max_tokens": 4000,
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = Request(endpoint, json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with build_opener(NoRedirects()).open(request, timeout=REQUEST_TIMEOUT) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, HTTPException) as exc:
        raise LLMError("llm-provider-error", "LLM-провайдер не ответил на запрос.") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise LLMError("llm-invalid-response", "Ответ LLM превышает допустимый размер.")
    try:
        message = json.loads(data)["choices"][0]["message"]["content"]
        return json.loads(message)
    except (ValueError, KeyError, IndexError, TypeError, RecursionError) as exc:
        raise LLMError("llm-invalid-response", "LLM вернула ответ в неизвестном формате.") from exc


def validate_response(response, requested):
    if not isinstance(response, dict) or response.keys() != {"explanations"} or not isinstance(response["explanations"], list):
        raise LLMError("llm-invalid-response", "В ответе LLM ожидается список объяснений.")

    validated = {}
    for item in response["explanations"]:
        if not isinstance(item, dict) or item.keys() != {"finding_id", "explanation", "recommendation"}:
            raise LLMError("llm-invalid-response", "Неверная структура объяснения LLM.")
        finding_id = item["finding_id"]
        if not isinstance(finding_id, str) or finding_id not in requested or finding_id in validated:
            raise LLMError("llm-invalid-response", "В ответе LLM неизвестный или повторяющийся ID находки.")
        original = requested[finding_id]
        fields = {"finding_id": finding_id, "file": original["file"], "line": original["line"]}
        for name in ("endLine", "advisoryId"):
            if name in original:
                fields[name] = original[name]

        advisories = {original.get(name, "").upper() for name in ("advisoryId", "cve")}
        for name in ("explanation", "recommendation"):
            value = item[name]
            if not isinstance(value, str) or not value.strip() or len(value) > 400 or not value.strip().isprintable():
                raise LLMError("llm-invalid-response", "В ответе LLM должно быть короткое текстовое объяснение и исправление.")
            if not CYRILLIC.search(value) or HAN.search(value):
                raise LLMError("llm-invalid-response", "Ожидается объяснение и исправление на русском языке.")
            if any(ref.upper() not in advisories for ref in TEXT_ADVISORY.findall(value)):
                raise LLMError("llm-invalid-response", "LLM указала advisory, отсутствующий у находки.")
            if any(ref.upper() != finding_id for ref in TEXT_FINDING_ID.findall(value)):
                raise LLMError("llm-invalid-response", "Объяснение LLM ссылается на другую находку.")
            if LOCATION_OR_LINK.search(value):
                raise LLMError("llm-invalid-response", "LLM указала файл, строку или ссылку в тексте объяснения.")
            fields[name] = value.strip()
        validated[finding_id] = fields

    if validated.keys() != requested.keys():
        raise LLMError("llm-invalid-response", "LLM вернула объяснения не для всех переданных находок.")
    return [validated[finding_id] for finding_id in requested]


def explain_findings(findings):
    requested = request_metadata(findings)
    if not requested:
        raise LLMError("llm-no-findings", "Во входной ветке нет находок для объяснения.")
    response = call_provider(*provider_config(), requested)
    return validate_response(response, requested)

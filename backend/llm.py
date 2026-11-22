"""Explain existing findings through a server-configured chat completion provider."""

import json
import os
import re
from pathlib import PurePosixPath
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from time import monotonic
from unicodedata import normalize
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MAX_FINDINGS = 20
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT = 60
REQUEST_SLOTS = BoundedSemaphore(2)
FINDING_ID = re.compile(r"(?:SECRETS|SAST|SCA)-F[0-9]{4,}")
RULE = re.compile(r"[a-z][a-z0-9-]{0,63}")
MODEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,127}")
ADVISORY = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}(?:-[a-z0-9]{4}){2})\b", re.I | re.ASCII)
TEXT_ADVISORY = re.compile(r"c\W*[vw]\W*e|g\W*h\W*s\W*a", re.I)
PSEUDO_LATIN = str.maketrans("СсЕеНнЅѕАа", "CcEeHhSsAa")
LOCATION_OR_LINK = re.compile(
    r"https?://|\bwww\.|\b[\w.-]+\.(?:kt|kts|java|ya?ml|json|properties|lockfile)(?:\b|:)|"
    r"\b(?:lines?|строк[а-яё]*)\s*[:#№]?\s*\d+",
    re.I,
)
CYRILLIC = re.compile(r"[А-Яа-яЁё]")
HAN = re.compile(r"[\u3400-\u9fff]")
SEVERITY = {name: index for index, name in enumerate(("low", "medium", "high", "critical"))}
CODE_CONTEXT = {
    "secret-fallback": (
        "Без настройки приложение может подключиться с известным секретом по умолчанию.",
        "Удалите запасной литерал и требуйте настроенный секрет.",
        "Проверьте отказ запуска без секрета и успешную работу с настроенным хранилищем.",
    ),
    "recoverable-token": (
        "Если токен действующий, фрагменты в исходниках могут дать доступ с его правами.",
        "Замените фрагменты ссылкой на секрет в хранилище и отзовите старый токен.",
        "Проверьте отсутствие фрагментов сканером и статус отзыва в системе выдачи.",
    ),
    "sql-injection": (
        "Если ввод меняет структуру SQL, возможен доступ к данным в пределах прав подключения к БД.",
        "Замените интерполяцию плейсхолдерами и свяжите значения через JDBC.",
        "Проверьте тестом JDBC, что текст запроса постоянен, а вход передаётся отдельным значением.",
    ),
    "object-authorization": (
        "Если доступ определяется только идентификатором записи, возможна выдача данных другого владельца.",
        "Добавьте в запрос ограничение по владельцу из контекста аутентификации.",
        "Проверьте разрешение для владельца и отказ для другого тестового пользователя.",
    ),
    "route-authorization": (
        "Если публичное правило применяется первым, запрос может миновать требуемую проверку роли.",
        "Укажите защищённый маршрут раньше публичного правила и задайте требуемую роль.",
        "Проверьте отказ без роли и успешный запрос с нужной ролью.",
    ),
    "tls-verification": (
        "Если имя TLS-хоста игнорируется, клиент может довериться сертификату для другого сервера.",
        "Верните штатную проверку имени TLS-хоста.",
        "Проверьте отказ тестового соединения при несовпадении имени сертификата.",
    ),
    "credentialed-cors": (
        "Если браузер посылает учётные данные, посторонний origin может получить ответ.",
        "Ограничьте список origin и оставьте credentials только там, где они нужны.",
        "Проверьте разрешённый origin и отсутствие разрешения для постороннего origin.",
    ),
    "spring-stacktrace-exposed": (
        "Если клиент получает трассировку ошибки, она может раскрыть детали реализации сервиса.",
        "Оставьте детали во внутренних логах и верните клиенту краткое сообщение.",
        "Проверьте, что тестовая ошибка не возвращает трассировку в HTTP-ответе.",
    ),
    "actuator-expose-all": (
        "Если диагностика открыта, внешний клиент может получить служебные сведения.",
        "Оставьте нужные эндпоинты и примените к ним контроль доступа.",
        "Проверьте список доступной диагностики и запрет анонимных запросов.",
    ),
    "spring-csrf-disabled": (
        "Если браузер автоматически прикладывает сессию, чужая страница может инициировать запрос на изменение.",
        "Включите проверку CSRF для меняющих запросов с браузерной сессией.",
        "Проверьте отказ такого запроса без действительного CSRF-токена в тесте.",
    ),
}
CATEGORY_CONTEXT = {
    "secrets": (
        "Если секрет действующий, доступ к исходникам или сборке может дать доступ с его правами.",
        "Настройте выдачу секрета из хранилища и отзовите встроенное значение.",
        "Проверьте статус отзыва и запустите повторную проверку исходников.",
    ),
    "sca": (
        "Если приложение использует затронутую функцию, возможны последствия, описанные в бюллетене.",
        "Выберите исправленную версию по бюллетеню и обновите блокировку зависимостей.",
        "Сверьте версию в графе Gradle и убедитесь, что SCA больше не находит этот бюллетень.",
    ),
}
PUBLIC_PATH_COMPONENTS = frozenset({
    "src", "main", "test", "kotlin", "java", "resources", "gradle",
    "build.gradle.kts", "settings.gradle.kts", "gradle.properties", "gradle.lockfile",
    "application.yml", "application.yaml", "application.properties",
})
SYSTEM_PROMPT = (
    'Напиши разработчику короткое объяснение для каждого входного finding_id. Ответ строго на русском языке.\n'
    'Формат JSON: {"explanations":[{"finding_id":"ID из входа","explanation":"Кратко опишите риск.",'
    '"recommendation":"Предложите конкретное исправление."}],'
    '"summary":{"priority_ids":["до трёх входных finding_id для первоочередного исправления"]}}\n'
    'Опирайся на title и fix. До 10 слов в каждом объяснении и исправлении. '
    'Не используй числа, критичность, ссылки, файлы, строки, версии или advisory ID в тексте. '
    'В priority_ids выбери существующие находки с наибольшим риском. Не добавляй другие поля.'
)
LOCAL_SYSTEM_PROMPT = (
    'Верни JSON на русском для всех finding_id в том же порядке. '
    'В explanation перенеси risk той же находки целиком, включая условие «Если», «При» или «Без». '
    'Поясни возможное последствие, не выдавая условие за факт. Не повторяй title, не добавляй детали, '
    'пути, числа, идентификаторы или оценки критичности. '
    'Для priority_ids возьми первые три finding_id из входа или все, если их меньше. '
    'Формат {"explanations":[{"finding_id":"ID из входа","explanation":"risk из входа"}],'
    '"summary":{"priority_ids":["ID из входа"]}}.'
)


class LLMError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def llm_disabled():
    return os.environ.get("GHOST_LLM_DISABLED", "").strip() == "1"


def explicit_provider():
    return any(os.environ.get(name, "").strip()
               for name in ("GHOST_LLM_BASE_URL", "GHOST_LLM_MODEL", "GHOST_LLM_API_KEY"))


def provider_config(local_provider=None):
    if llm_disabled():
        raise LLMError("llm-not-configured", "LLM отключена администратором.")
    base = os.environ.get("GHOST_LLM_BASE_URL", "").strip()
    model = os.environ.get("GHOST_LLM_MODEL", "").strip()
    key = os.environ.get("GHOST_LLM_API_KEY", "").strip()
    if not (base or model or key) and local_provider is not None:
        return local_provider()
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


def strict_json(data):
    def unique_fields(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("Duplicate JSON key")
        return result

    def reject_constant(value):
        raise ValueError("Invalid JSON constant")

    return json.loads(data, object_pairs_hook=unique_fields, parse_constant=reject_constant)


def read_completion(request):
    local = urlsplit(request.full_url).hostname in {"localhost", "127.0.0.1", "::1"}
    handlers = [NoRedirects(), ProxyHandler({})] if local else [NoRedirects()]
    with build_opener(*handlers).open(request, timeout=REQUEST_TIMEOUT) as response:
        return response.read(MAX_RESPONSE_BYTES + 1)


def bounded_completion(request):
    answer = Queue(1)

    def read():
        try:
            result = read_completion(request)
        except Exception as exc:
            result = exc
        finally:
            REQUEST_SLOTS.release()
        answer.put(result)

    if not REQUEST_SLOTS.acquire(blocking=False):
        raise LLMError("llm-busy", "Локальный LLM-клиент занят другими запросами.")
    try:
        Thread(target=read, daemon=True).start()
    except RuntimeError:
        REQUEST_SLOTS.release()
        raise LLMError("llm-provider-error", "Не удалось запустить запрос LLM.") from None
    try:
        data = answer.get(timeout=REQUEST_TIMEOUT)
    except Empty:
        raise LLMError("llm-timeout", "Истекло время генерации ответа LLM.") from None
    if isinstance(data, TimeoutError) or (isinstance(data, URLError) and isinstance(data.reason, TimeoutError)):
        raise LLMError("llm-timeout", "Истекло время генерации ответа LLM.") from None
    if isinstance(data, Exception):
        raise LLMError("llm-provider-error", "LLM-провайдер не ответил на запрос.") from None
    return data


def local_location(item):
    path = PurePosixPath(item["file"])
    if path.is_absolute() or ".." in path.parts or "\\" in item["file"] or ":" in item["file"]:
        return {}
    # Project names, package names and filenames are user-controlled text.
    path_parts = [part if part in PUBLIC_PATH_COMPONENTS else "_" for part in path.parts[-8:]]
    return {"path": "/".join(path_parts), "line": item["line"]} if path_parts else {}


def rule_guidance(item):
    return CODE_CONTEXT.get(item["rule"], CATEGORY_CONTEXT.get(item["scanner"]))


def call_provider(endpoint, model, key, requested, *, managed=False):
    messages = []
    for item in requested.values():
        metadata = {"finding_id": item["id"], "category": item["scanner"],
                    "rule": item["rule"], "severity": item["severity"],
                    "title": item["title"][:160]}
        if managed:
            metadata["risk"] = rule_guidance(item)[0]
            metadata.update(local_location(item))
        else:
            metadata["fix"] = ("Обновите зависимость до исправленной версии." if item["scanner"] == "sca"
                               else item["recommendation"][:220])
        advisory = item.get("advisoryId", "")
        if ADVISORY.fullmatch(advisory):
            metadata["advisory_id"] = advisory
        messages.append(metadata)
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": LOCAL_SYSTEM_PROMPT if managed else SYSTEM_PROMPT},
                     {"role": "user", "content": json.dumps(messages, ensure_ascii=False, separators=(",", ":"))}],
        "response_format": {"type": "json_object"},
        "stream": False,
        "max_tokens": min(2200, 75 * len(messages) + 60) if managed else 2200,
        "temperature": 0,
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    request = Request(endpoint, json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    data = bounded_completion(request)
    if len(data) > MAX_RESPONSE_BYTES:
        raise LLMError("llm-invalid-response", "Ответ LLM превышает допустимый размер.")
    try:
        choice = strict_json(data)["choices"][0]
        if choice.get("finish_reason") == "length":
            raise ValueError("Truncated completion")
        return strict_json(choice["message"]["content"])
    except (AttributeError, ValueError, KeyError, IndexError, TypeError, RecursionError) as exc:
        raise LLMError("llm-invalid-response", "LLM вернула ответ в неизвестном формате.") from exc


def validate_text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 400 or not value.strip().isprintable():
        raise LLMError("llm-invalid-response", "В ответе LLM ожидаются короткие текстовые поля.")
    if not CYRILLIC.search(value) or HAN.search(value):
        raise LLMError("llm-invalid-response", "Ожидается ответ LLM на русском языке.")
    text = normalize("NFKC", value)
    if (any(char.isnumeric() for char in text) or TEXT_ADVISORY.search(text.translate(PSEUDO_LATIN))
            or LOCATION_OR_LINK.search(text) or any(char in text for char in "<>{}`")):
        raise LLMError("llm-invalid-response", "Текст LLM содержит ссылки или идентификаторы вне структурированных полей.")
    return value.strip()


def validate_response(response, requested, *, managed=False):
    if (not isinstance(response, dict) or response.keys() - {"explanations", "summary"}
            or not isinstance(response.get("explanations"), list)
            or len(response["explanations"]) != len(requested)):
        raise LLMError("llm-invalid-response", "В ответе LLM ожидается список объяснений.")

    validated = {}
    used_guidance = False
    expected_fields = {"finding_id", "explanation"}
    if not managed:
        expected_fields.add("recommendation")
    for item in response["explanations"]:
        if not isinstance(item, dict) or item.keys() != expected_fields:
            raise LLMError("llm-invalid-response", "Неверная структура объяснения LLM.")
        finding_id = item["finding_id"]
        if not isinstance(finding_id, str) or finding_id not in requested or finding_id in validated:
            raise LLMError("llm-invalid-response", "В ответе LLM неизвестный или повторяющийся ID находки.")
        original = requested[finding_id]
        fields = {"finding_id": finding_id, "file": original["file"], "line": original["line"]}
        if "endLine" in original:
            fields["endLine"] = original["endLine"]
        advisory = original.get("advisoryId", "")
        if ADVISORY.fullmatch(advisory):
            fields["advisoryId"] = advisory

        explanation = validate_text(item["explanation"])
        if managed:
            risk, repair, verification = rule_guidance(original)
            # A missing condition or an added effect changes the claim, even if the text looks plausible.
            if explanation.rstrip(".").casefold() != risk.rstrip(".").casefold():
                explanation = risk
                used_guidance = True
            fields["recommendation"] = f"{repair} {verification}"
        else:
            fields["recommendation"] = validate_text(item["recommendation"])
        fields["explanation"] = explanation
        validated[finding_id] = fields

    if validated.keys() != requested.keys():
        raise LLMError("llm-invalid-response", "LLM вернула объяснения не для всех переданных находок.")
    return [validated[finding_id] for finding_id in requested], used_guidance


def explain_findings(findings, *, local_provider=None):
    return analyze_findings(findings, local_provider=local_provider)["explanations"]


def analyze_findings(findings, *, local_provider=None):
    managed = local_provider is not None and not explicit_provider()
    if managed:
        findings = [item for item in findings if rule_guidance(item) is not None]
    requested = request_metadata(findings)
    if not requested:
        raise LLMError("llm-no-findings", "Во входной ветке нет находок для объяснения.")
    provider = provider_config(local_provider)
    start = monotonic()
    response = call_provider(*provider, requested, managed=managed)
    duration_ms = round((monotonic() - start) * 1000)
    explanations, used_guidance = validate_response(response, requested, managed=managed)
    summary = response.get("summary")
    priority_ids = summary.get("priority_ids") if isinstance(summary, dict) and summary.keys() == {"priority_ids"} else None
    valid = (isinstance(priority_ids, list) and 1 <= len(priority_ids) <= 3
             and all(isinstance(key, str) and key in requested for key in priority_ids)
             and len(set(priority_ids)) == len(priority_ids))
    summary_code = None if valid else "llm-summary-incomplete"
    if used_guidance:
        summary_code = "llm-guidance-fallback"
    return {"explanations": explanations, "priority_ids": priority_ids if valid else [],
            "summary_code": summary_code, "generation_ms": duration_ms}

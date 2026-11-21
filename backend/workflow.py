"""Validate and execute a workflow over a local training project."""

import json
import operator
import re
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from uuid import uuid4

import scan
from analyzers.common import submission_report
from backend.llm import LLMError, explain_findings
from backend.service import InvalidInput
from backend.webhook import DEMO_PROJECT, WebhookError, parse_url, report_payload, send_report


MAX_GRAPH_BYTES = 16 * 1024
REPORT_UNREACHED = "workflow-report-unreached"
REPORT_UNREACHED_MESSAGE = "На активном пути нет итогового отчёта. Подключите блок «Отчёт» к выбранной ветке."
MAX_NODES = 24
MAX_EDGES = 48
NODE_TYPES = scan.SCANNERS | {"trigger", "condition", "llm", "report", "webhook"}
NODE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}")
SEVERITY_RANK = {level: rank for rank, level in enumerate(("low", "medium", "high", "critical"))}
FIELDS = {"scanner", "severity", "file", "rule", "cve", "advisoryId", "package", "line"}
COMPARISONS = {
    "eq": operator.eq, "ne": operator.ne, "gt": operator.gt,
    "gte": operator.ge, "lt": operator.lt, "lte": operator.le,
}
REGEX_WORKER = """
import json, re, sys
pattern, subjects = json.load(sys.stdin)
matcher = re.compile(pattern)
print(json.dumps(next((index for index, text in enumerate(subjects) if matcher.search(text)), None)))
"""


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    config: dict


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    branch: str | None


def parse_condition(config):
    mode, field = config.get("mode"), config.get("field")
    value = config.get("value")
    if not isinstance(value, str) or len(value) > 128:
        raise InvalidInput("Введите значение условия длиной до 128 символов.")
    if mode == "severity" and value in SEVERITY_RANK:
        return {"mode": "compare", "field": "severity", "operator": "gte", "value": value}
    if not isinstance(field, str) or field not in FIELDS:
        raise InvalidInput("Выберите поле находки для условия.")
    if mode == "regex":
        if not value:
            raise InvalidInput("Введите регулярное выражение.")
        try:
            re.compile(value)
        except (re.error, OverflowError) as exc:
            raise InvalidInput("Условие содержит некорректное регулярное выражение.") from exc
        return {"mode": mode, "field": field, "value": value}
    comparison = config.get("operator")
    if mode != "compare" or not isinstance(comparison, str) or comparison not in COMPARISONS:
        raise InvalidInput("Выберите оператор сравнения.")
    if field == "line":
        if not value.isascii() or not value.isdecimal() or len(value) > 8 or int(value) < 1:
            raise InvalidInput("Введите положительный номер строки.")
        value = int(value)
    elif field == "severity":
        if value not in SEVERITY_RANK:
            raise InvalidInput("Выберите допустимый уровень критичности.")
    elif comparison not in {"eq", "ne"}:
        raise InvalidInput("Для текстового поля доступны сравнения «равно» и «не равно».")
    return {"mode": mode, "field": field, "operator": comparison, "value": value}


def parse_webhook(config):
    url = config.get("url", "")
    if url == "":
        return {}
    try:
        if not isinstance(url, str):
            raise ValueError
        parse_url(url)
    except ValueError:
        raise InvalidInput("Укажите допустимый URL webhook без учётных данных и параметров.") from None
    return {"url": url}


def parse_nodes(raw_nodes):
    nodes = {}
    parsers = {"condition": parse_condition, "webhook": parse_webhook}
    for raw in raw_nodes:
        if not isinstance(raw, dict):
            raise InvalidInput("Некорректный блок сценария.")
        node_id, kind, config = raw.get("id"), raw.get("type"), raw.get("config", {})
        if not isinstance(node_id, str) or not NODE_ID.fullmatch(node_id) or node_id in nodes:
            raise InvalidInput("У каждого блока должен быть уникальный идентификатор.")
        if not isinstance(kind, str) or kind not in NODE_TYPES or not isinstance(config, dict):
            raise InvalidInput("Некорректный тип или параметры блока.")
        nodes[node_id] = Node(node_id, kind, parsers[kind](config) if kind in parsers else {})
    if sum(item.kind == "trigger" for item in nodes.values()) != 1:
        raise InvalidInput("В сценарии должен быть один блок ручного запуска.")
    if not any(item.kind == "report" for item in nodes.values()):
        raise InvalidInput("Добавьте блок «Отчёт».")
    return nodes


def parse_edges(raw_edges, nodes):
    edges = set()
    outgoing, incoming = defaultdict(list), defaultdict(list)
    for raw in raw_edges:
        if not isinstance(raw, dict):
            raise InvalidInput("Некорректная связь между блоками.")
        source, target, branch = raw.get("source"), raw.get("target"), raw.get("branch")
        if not all(isinstance(item, str) and item in nodes for item in (source, target)):
            raise InvalidInput("Связь указывает на отсутствующий блок.")
        source_kind, target_kind = nodes[source].kind, nodes[target].kind
        if source_kind == "webhook" or target_kind == "trigger":
            raise InvalidInput("У webhook нет выхода, а у ручного запуска нет входа.")
        if (source_kind == "report") != (target_kind == "webhook"):
            raise InvalidInput("Webhook принимает вход только от отчёта. Выход отчёта предназначен только для webhook.")
        allowed = ("true", "false") if nodes[source].kind == "condition" else (None,)
        if branch not in allowed:
            raise InvalidInput("Связь подключена к недопустимому выходу блока.")
        edge = Edge(source, target, branch)
        if edge in edges:
            raise InvalidInput("Между блоками есть повторяющиеся связи.")
        edges.add(edge)
        outgoing[source].append(target)
        incoming[target].append(edge)
    return incoming, outgoing


def compile_workflow(raw):
    if not raw or len(raw) > MAX_GRAPH_BYTES:
        raise InvalidInput("Передайте JSON сценария размером до 16 КиБ.")
    try:
        graph = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidInput("Некорректный JSON сценария.") from exc
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise InvalidInput("Сценарий должен содержать список блоков и связей.")
    if len(graph["nodes"]) > MAX_NODES or len(graph["edges"]) > MAX_EDGES:
        raise InvalidInput("Допустимо до 24 блоков и 48 связей.")
    nodes = parse_nodes(graph["nodes"])
    incoming, outgoing = parse_edges(graph["edges"], nodes)
    indegrees = {node_id: len(incoming[node_id]) for node_id in nodes}
    ready = deque(node_id for node_id, degree in indegrees.items() if degree == 0)
    disconnected = [node_id for node_id in ready if nodes[node_id].kind != "trigger"]
    order = []
    while ready:
        node_id = ready.popleft()
        order.append(nodes[node_id])
        for target in outgoing[node_id]:
            indegrees[target] -= 1
            if indegrees[target] == 0:
                ready.append(target)
    if len(order) != len(nodes):
        raise InvalidInput("В сценарии есть цикл. Удалите связь, которая замыкает цепочку.")
    if disconnected:
        raise InvalidInput("Соедините все блоки с цепочкой, которая начинается с ручного запуска.")
    return order, incoming


def combined_report(types, results):
    findings = []
    skipped = {}
    for kind in sorted(types):
        result = results[kind]
        findings.extend(result["findings"])
        skipped.update((item["file"], item) for item in result["skipped_files"])
    findings.sort(key=lambda item: (item["file"], item["line"], item["rule"], item.get("advisoryId", "")))
    return {
        "findings": findings,
        "skipped_files": list(skipped.values()),
        "sca": results["sca"]["sca"] if "sca" in types else {
            "status": "not-selected", "unresolved_versions": [],
        },
    }


def condition_match(config, findings):
    field, value = config["field"], config["value"]
    candidates = [item for item in findings if field in item]
    if not candidates:
        return None
    if config["mode"] == "regex":
        try:
            process = subprocess.run(
                [sys.executable, "-I", "-c", REGEX_WORKER],
                input=json.dumps([value, [str(item[field]) for item in candidates]]),
                capture_output=True, text=True, timeout=3, check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise InvalidInput("Регулярное выражение выполнялось слишком долго. Упростите его.") from exc
        except (subprocess.CalledProcessError, OSError) as exc:
            raise InvalidInput("Не удалось выполнить регулярное выражение.") from exc
        matched = json.loads(process.stdout)
        return candidates[matched] if matched is not None else None
    compare = COMPARISONS[config["operator"]]
    if field == "severity":
        return next((item for item in candidates if compare(SEVERITY_RANK[item[field]], SEVERITY_RANK[value])), None)
    return next((item for item in candidates if compare(item[field], value)), None)


def preview(findings):
    return [{key: item[key] for key in ("id", "scanner", "file", "line", "severity")} for item in findings[:10]]


def webhook_node(node_id, delivery_status, *, status, **details):
    return {"event": "node", "id": node_id, "status": status,
            "delivery_status": delivery_status, **details}


def deliver_webhook(node, payload):
    url = node.config.get("url")
    if not url:
        yield webhook_node(node.id, "NOT_CONFIGURED", status="skipped", code="webhook-not-configured",
                           message="URL webhook не настроен.")
        return
    yield webhook_node(node.id, "SENDING", status="running")
    try:
        http_status, attempts = send_report(url, payload)
    except WebhookError as exc:
        yield webhook_node(node.id, "FAILED", status="failed", code=exc.code, message=str(exc),
                           output={"attempts": exc.attempts, "http_status": exc.http_status})
    else:
        yield webhook_node(node.id, "SENT", status="done",
                           output={"attempts": attempts, "http_status": http_status})


def execute_workflow(workflow, project, *, workflow_id=None, project_name=DEMO_PROJECT):
    order, incoming = workflow
    results, outputs, branches = {}, {}, {}
    explanation_outputs = {}
    report_types = set()
    reported_explanations = {}
    report_nodes = []
    pending_webhooks = []
    for item in order:
        node_id, kind = item.id, item.kind
        linked = [edge for edge in incoming[node_id] if edge.source in outputs and
                  (edge.branch is None or edge.branch == branches.get(edge.source))]
        if not linked and kind != "trigger":
            delivery = {"delivery_status": "SKIPPED"} if kind == "webhook" else {}
            yield {"event": "node", "id": node_id, "status": "skipped", "message": "Входная ветка не активна.", **delivery}
            continue
        types = frozenset().union(*(outputs[edge.source] for edge in linked))
        explanations = {}
        for edge in linked:
            explanations.update(explanation_outputs[edge.source])
        found = combined_report(types, results)["findings"]
        received = {"sources": [edge.source for edge in linked], "count": len(found), "findings": preview(found)}
        if kind == "webhook":
            pending_webhooks.append(item)
            yield webhook_node(node_id, "PENDING", status="running", input=received)
            continue
        yield {"event": "node", "id": node_id, "status": "running", "input": received}
        status, message, branch, matched = "done", "", None, None
        code = None
        try:
            if kind in scan.SCANNERS:
                if kind not in results:
                    result = scan.scan(*project, scanners={kind})
                    for finding in result["findings"]:
                        finding["id"] = f"{kind.upper()}-{finding['id']}"
                    results[kind] = result
                types |= {kind}
                if results[kind]["sca"]["status"] == "catalog-missing":
                    status, message = "skipped", "Для SCA нужен JSON-справочник."
            elif kind == "condition":
                matched = condition_match(item.config, found)
                branch = "true" if matched is not None else "false"
                branches[node_id] = branch
            elif kind == "llm":
                try:
                    for explanation in explain_findings(found):
                        explanations[explanation["finding_id"]] = explanation
                except LLMError as exc:
                    code, message = exc.code, str(exc)
                    status = "skipped" if code in {"llm-not-configured", "llm-no-findings"} else "failed"
            elif kind == "report":
                report_types.update(types)
                reported_explanations.update(explanations)
                report_nodes.append(node_id)
        except (InvalidInput, OSError) as exc:
            message = str(exc) if isinstance(exc, InvalidInput) else "Не удалось прочитать файлы учебного проекта."
            yield {"event": "node", "id": node_id, "status": "failed", "message": message, "input": received}
            for node in pending_webhooks:
                yield webhook_node(node.id, "SKIPPED", status="skipped", message="Итоговый отчёт не сформирован.")
            yield {"event": "error", "error": message}
            return

        outputs[node_id] = types
        explanation_outputs[node_id] = explanations
        found = combined_report(types, results)["findings"]
        output = {"count": len(found), "findings": preview(found), "branch": branch,
                  "matched": preview([matched])[0] if matched is not None else None}
        if kind in {"llm", "report"}:
            output["explanations"] = list(explanations.values())
        yield {
            "event": "node", "id": node_id, "status": status, "message": message, "input": received,
            "output": output, **({"code": code} if code else {}),
        }
    all_findings = combined_report(results.keys(), results)
    gate = scan.release_gate(all_findings, results.keys())
    if not report_nodes:
        yield {"event": "error", "code": REPORT_UNREACHED, "error": REPORT_UNREACHED_MESSAGE,
               "reports": [], "branches": branches, "release_gate": gate}
        return

    report = combined_report(report_types, results)
    if reported_explanations:
        report["explanations"] = [reported_explanations[item["id"]] for item in report["findings"]
                                  if item["id"] in reported_explanations]
    result = {
        "event": "result", "report": report, "reports": report_nodes, "branches": branches,
        "release_gate": gate, "submission": submission_report(report),
    }
    if pending_webhooks:
        ids = {"workflow_id": workflow_id or uuid4().hex, "run_id": uuid4().hex, "report_id": uuid4().hex}
        payload = report_payload(report, gate, project_name=project_name, **ids)
        result.update(ids)
        for node in pending_webhooks:
            yield from deliver_webhook(node, payload)
    yield result

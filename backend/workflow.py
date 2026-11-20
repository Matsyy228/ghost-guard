"""Validate and execute a workflow over a local training project."""

import json
import operator
import re
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass

import scan
from backend.service import InvalidInput


MAX_GRAPH_BYTES = 16 * 1024
MAX_NODES = 24
MAX_EDGES = 48
NODE_TYPES = scan.SCANNERS | {"trigger", "condition", "report"}
NODE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}")
SEVERITY_RANK = {level: rank for rank, level in enumerate(("low", "medium", "high", "critical"))}
FIELDS = {"scanner", "severity", "file", "rule", "cve", "package", "line"}
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


def parse_nodes(raw_nodes):
    nodes = {}
    for raw in raw_nodes:
        if not isinstance(raw, dict):
            raise InvalidInput("Некорректный блок сценария.")
        node_id, kind, config = raw.get("id"), raw.get("type"), raw.get("config", {})
        if not isinstance(node_id, str) or not NODE_ID.fullmatch(node_id) or node_id in nodes:
            raise InvalidInput("У каждого блока должен быть уникальный идентификатор.")
        if not isinstance(kind, str) or kind not in NODE_TYPES or not isinstance(config, dict):
            raise InvalidInput("Некорректный тип или параметры блока.")
        nodes[node_id] = Node(node_id, kind, parse_condition(config) if kind == "condition" else {})
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
        if nodes[source].kind == "report" or nodes[target].kind == "trigger":
            raise InvalidInput("У отчёта нет выхода, а у ручного запуска нет входа.")
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
    findings.sort(key=lambda item: (item["file"], item["line"], item["rule"], item.get("cve", "")))
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


def execute_workflow(workflow, project):
    order, incoming = workflow
    results, outputs, branches = {}, {}, {}
    report_types = set()
    report_nodes = []
    for item in order:
        node_id, kind = item.id, item.kind
        linked = [edge for edge in incoming[node_id] if edge.source in outputs and
                  (edge.branch is None or edge.branch == branches.get(edge.source))]
        if not linked and kind != "trigger":
            yield {"event": "node", "id": node_id, "status": "skipped", "message": "Входная ветка не активна."}
            continue
        types = frozenset().union(*(outputs[edge.source] for edge in linked))
        found = combined_report(types, results)["findings"]
        received = {"sources": [edge.source for edge in linked], "count": len(found), "findings": preview(found)}
        yield {"event": "node", "id": node_id, "status": "running", "input": received}
        status, message, branch, matched = "done", "", None, None
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
            elif kind == "report":
                report_types.update(types)
                report_nodes.append(node_id)
        except (InvalidInput, OSError) as exc:
            message = str(exc) if isinstance(exc, InvalidInput) else "Не удалось прочитать файлы учебного проекта."
            yield {"event": "node", "id": node_id, "status": "failed", "message": message, "input": received}
            yield {"event": "error", "error": message}
            return

        outputs[node_id] = types
        found = combined_report(types, results)["findings"]
        yield {
            "event": "node", "id": node_id, "status": status, "message": message, "input": received,
            "output": {"count": len(found), "findings": preview(found), "branch": branch,
                       "matched": preview([matched])[0] if matched is not None else None},
        }
    yield {"event": "result", "report": combined_report(report_types, results) if report_nodes else None,
           "reports": report_nodes, "branches": branches}

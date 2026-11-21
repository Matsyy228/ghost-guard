"""Combine grounded model priorities with final scanner and release data."""

from collections import Counter

from backend.llm import ADVISORY, SEVERITY


PRIORITIES = {"critical": "immediate", "high": "before-release", "medium": "next-iteration", "low": "backlog"}
GATE_REASONS = {
    "BLOCK": "В выполненных проверках есть находки уровня HIGH или CRITICAL.",
    "WARNING": "Есть находки ниже HIGH или охват проверок неполный.",
    "PASS": "Выполненные проверки завершены без находок.",
}


def summarize(report, gate, ai_runs, explanations):
    findings = report["findings"]
    severity_counts = Counter(finding["severity"] for finding in findings)
    categories = Counter(finding["scanner"] for finding in findings)
    chosen = {}
    warnings = []
    for run in ai_runs.values():
        if run.get("summary_code"):
            warnings.append(run["summary_code"])
        for key in run.get("priority_ids", []):
            chosen.setdefault(key, len(chosen))
    chosen = {key: rank for key, rank in chosen.items() if key in explanations}

    status = "no-findings"
    if findings:
        if not explanations:
            status = "unavailable"
        elif not chosen or warnings or len(explanations) < len(findings):
            status = "partial"
        else:
            status = "ready"
        if explanations and len(explanations) < len(findings):
            warnings.append("llm-coverage-incomplete")

    ordered = sorted(findings, key=lambda f: (-SEVERITY[f["severity"]], chosen.get(f["id"], len(chosen)), f["id"]))
    most_important = []
    for item in ordered[:3]:
        row = {"finding_id": item["id"], "scanner": item["scanner"], "severity": item["severity"],
               "file": item["file"], "line": item["line"], "title": item["title"],
               "priority": PRIORITIES[item["severity"]], "recommendation": item["recommendation"],
               "selected_by_ai": item["id"] in chosen}
        if "endLine" in item:
            row["endLine"] = item["endLine"]
        if ADVISORY.fullmatch(item.get("advisoryId", "")):
            row["advisoryId"] = item["advisoryId"]
        most_important.append(row)

    highest = ordered[0]["severity"] if ordered else None
    return {
        "status": status,
        "risk_overview": (f"Наиболее высокий подтверждённый уровень риска — {highest.upper()}." if highest
                          else "В отчёте нет подтверждённых находок."),
        "total_findings": len(findings),
        "severity_counts": {level: severity_counts[level] for level in reversed(SEVERITY)},
        "categories": [{"scanner": name, "count": categories[name]} for name in sorted(categories)],
        "recommendation_source": "scanners",
        "priority_findings": most_important,
        "release_gate": {"status": gate["status"], "explanation": GATE_REASONS[gate["status"]]},
        "coverage": {"explained": len(explanations), "total": len(findings)},
        "generation_ms": sum(run.get("generation_ms", 0) for run in ai_runs.values()),
        "warnings": list(dict.fromkeys(warnings)),
    }

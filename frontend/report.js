const severityNames = {
  critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий",
};
const severityOrder = Object.keys(severityNames);
export const scannerNames = { secrets: "Secrets", sca: "SCA", sast: "SAST" };

export function sortedFindings(findings) {
  const rank = (severity) => severityOrder.includes(severity) ? severityOrder.indexOf(severity) : severityOrder.length;
  return [...findings].sort((left, right) => rank(left.severity) - rank(right.severity));
}

function node(tag, text = "", className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  element.className = className;
  return element;
}

function matchingExplanation(report, finding) {
  const explanations = Array.isArray(report.explanations) ? report.explanations : [];
  return explanations.find((item) => item?.finding_id === finding.id) ?? finding.llm_explanation;
}

function fact(label, value) {
  const row = node("div");
  row.append(node("dt", label), node("dd", value));
  return row;
}

function findingElement(finding, explanation, open) {
  const level = finding.severity;
  const severity = node("span", severityNames[level] ?? "Без оценки", "severity");
  severity.dataset.severity = level;
  const fileLine = finding.file ? `${finding.file}${finding.line == null ? "" : `:${finding.line}`}` : "";
  const location = [scannerNames[finding.scanner] ?? finding.scanner, fileLine].filter(Boolean).join(" · ");
  const heading = node("span");
  heading.append(node("strong", finding.title || "Находка без названия"));
  if (location) heading.append(node("span", location, "finding-location"));

  const summary = node("summary", "", "finding-summary");
  summary.append(severity, heading);
  const body = node("div", "", "finding-body");
  const scanner = node("section", "", "finding-scanner");
  scanner.append(node("h3", "Данные сканера"));
  const facts = node("dl", "", "finding-facts");
  if (finding.rule) facts.append(fact("Правило", finding.rule));
  if (finding.advisoryId || finding.cve) facts.append(fact("Бюллетень", finding.advisoryId || finding.cve));
  if (finding.package) facts.append(fact("Зависимость", [finding.package, finding.version].filter(Boolean).join("@")));
  if (facts.childElementCount) scanner.append(facts);
  scanner.append(node("p", finding.recommendation || "Сканер не предоставил рекомендацию."));
  body.append(scanner);

  const reason = explanation?.explanation ?? explanation?.summary;
  const recommendation = explanation?.recommendation;
  if (reason || recommendation) {
    const model = node("section", "", "finding-llm");
    model.append(node("strong", "Интерпретация модели"));
    if (reason) model.append(node("p", reason));
    if (recommendation) model.append(node("p", `Совет модели. ${recommendation}`));
    model.append(node("p", "Оценку риска выставил сканер. Выводы модели сверяйте с файлом и правилом.", "llm-note"));
    body.append(model);
  }

  const details = node("details");
  details.open = open;
  details.append(summary, body);
  const row = node("li");
  row.append(details);
  return row;
}

export function renderFindings(elements, report, { phase, mode, animate }) {
  const all = sortedFindings(report?.findings ?? []);
  const filter = elements.severity.value;
  const findings = all.filter(({ severity }) => filter === "all" || severity === filter);
  const hasReport = Boolean(report);
  const snapshot = phase === "snapshot";
  elements.findings.classList.toggle("is-fresh", animate);
  elements.findings.replaceChildren(...findings.map((finding, index) =>
    findingElement(finding, matchingExplanation(report, finding), index === 0)));
  elements.findings.hidden = !findings.length;
  elements.empty.hidden = Boolean(findings.length);
  elements["empty-text"].textContent = hasReport
    ? (all.length ? "На этом уровне критичности находок нет." : "В отчёте нет находок. Проверьте статус выпуска и покрытие сканеров в обзоре.")
    : ({ running: "Сценарий выполняется. Отчёт появится после завершения.",
        error: "Отчёт не сформирован. Откройте описание ошибки рядом с кнопкой запуска." }[phase] ?? "Отчёт появится после запуска сценария.");
  elements["clear-filter"].hidden = !all.length || findings.length > 0;
  elements["report-actions"].hidden = !hasReport;
  elements.rerun.hidden = snapshot;
  elements["findings-header"].hidden = !hasReport;
  elements["match-count"].textContent = `${findings.length} из ${all.length}`;
  elements["report-notice"].hidden = !hasReport || (!snapshot && mode !== "demo");
  elements["report-notice"].textContent = snapshot
    ? "Резервный пример · встроенные учебные данные. Новый анализ не выполнялся."
    : "Учебный проект · результаты проверки синтетических данных.";

  const warnings = [];
  if (report?.sca?.status === "catalog-missing") warnings.push("SCA пропущен. Для проверки зависимостей добавьте справочник JSON.");
  if (report?.sca?.unresolved_versions?.length) warnings.push(`Зависимости с неопределённой версией: ${report.sca.unresolved_versions.length}.`);
  if (report?.skipped_files?.length) warnings.push(`Пропущенные файлы: ${report.skipped_files.length}.`);
  const hasExplanation = report?.explanations?.length || all.some((finding) => finding.llm_explanation);
  elements["report-caption"].textContent = hasReport
    ? (hasExplanation ? "Находки сканеров и отдельные пояснения модели" : "Находки сканеров · пояснений модели в отчёте нет")
    : "Находки сканеров и пояснения модели";
  elements.warnings.replaceChildren(...warnings.map((warning) => node("li", warning)));
  elements.warnings.hidden = !warnings.length;
}

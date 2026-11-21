import { createEditor } from "./editor.js";

const API = "http://127.0.0.1:8000/api";
const elements = Object.fromEntries(
  [...document.querySelectorAll("[id]")].map((element) => [element.id, element]),
);
const severityNames = {
  critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий",
};
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
const scannerNames = { secrets: "Secrets", sca: "SCA", sast: "SAST" };
const state = { mode: "demo", active: false, report: null, releaseGate: null };
const editor = createEditor(elements, () => {
  state.report = null;
  renderReport();
  elements.error.hidden = true;
  elements["run-status"].textContent = "Готов к запуску";
  elements["workflow-note"].textContent = "Запустите сценарий с обновлёнными настройками.";
});

function setMode(mode) {
  state.mode = mode;
  const upload = mode === "upload";
  elements["demo-mode"].setAttribute("aria-pressed", String(!upload));
  elements["upload-mode"].setAttribute("aria-pressed", String(upload));
  elements["demo-input"].hidden = upload;
  elements["upload-inputs"].hidden = !upload;
  elements.project.required = upload;
  elements.error.hidden = true;
}

function setConnection(online, message) {
  elements.connection.dataset.status = online ? "online" : "offline";
  elements.connection.textContent = message;
}

async function checkConnection() {
  try {
    const response = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2000) });
    if (!response.ok) throw new Error("Health check failed");
    const { status, service, api_version, build_id } = await response.json();
    const compatible = status === "ok" && service === "ghost-guard" && api_version === 2 && /^[a-f0-9]{16}$/.test(build_id);
    setConnection(compatible, compatible ? "Backend подключён" : "Перезапустите backend из текущего репозитория");
    return compatible;
  } catch {
    setConnection(false, "Backend недоступен на порту 8000");
    return false;
  }
}

function node(tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function findingElement(finding, explanation = finding.llm_explanation) {
  const level = finding.severity ?? "unknown";
  const severity = node("span", severityNames[level] ?? level, "severity");
  severity.dataset.severity = level;
  const heading = node("div", "", "finding-heading");
  heading.append(severity, node("strong", finding.title || "Описание не предоставлено сканером."));
  const fileLine = finding.file
    ? `${finding.file}${finding.line == null ? "" : `:${finding.line}`}`
    : finding.line == null ? "" : `Строка ${finding.line}`;
  const location = [scannerNames[finding.scanner] ?? finding.scanner, fileLine]
    .filter((value) => typeof value === "string" && value.length);
  if (finding.advisoryId || finding.cve) location.push(finding.advisoryId || finding.cve, `${finding.package}@${finding.version}`);
  const item = node("li", "");
  item.append(heading);
  if (location.length) item.append(node("p", location.join(" · "), "finding-location"));
  const recommendation = node("p", "", "finding-recommendation");
  recommendation.append(node("strong", "Что исправить: "), document.createTextNode(
    finding.recommendation || "Рекомендация отсутствует в отчёте.",
  ));
  item.append(recommendation);
  const explanationView = explanationElement(explanation);
  if (explanationView) item.append(explanationView);
  return item;
}

// The backend may attach an explanation only after validating it against the original finding.
function explanationElement(explanation) {
  if (!explanation || typeof explanation !== "object" || Array.isArray(explanation)) return null;
  const summary = typeof explanation.explanation === "string" ? explanation.explanation.trim()
    : typeof explanation.summary === "string" ? explanation.summary.trim() : "";
  const recommendation = typeof explanation.recommendation === "string" ? explanation.recommendation.trim() : "";
  if (!summary && !recommendation) return null;

  const section = node("section", "", "finding-llm");
  section.append(node("strong", "Объяснение LLM"));
  if (summary) section.append(node("p", `Почему: ${summary}`));
  if (recommendation) section.append(node("p", `Что сделать: ${recommendation}`));
  return section;
}

function renderReport() {
  const report = state.report;
  const filter = elements.severity.value;
  const allFindings = Array.isArray(report?.findings) ? report.findings : [];
  const explanations = new Map(
    (Array.isArray(report?.explanations) ? report.explanations : [])
      .filter((item) => item && typeof item.finding_id === "string")
      .map((item) => [item.finding_id, item]),
  );
  const findings = allFindings
    .filter((finding) => filter === "all" || finding.severity === filter)
    .sort((left, right) => (severityOrder[left.severity] ?? 99) - (severityOrder[right.severity] ?? 99));
  elements.findings.replaceChildren(...findings.map((finding) => findingElement(finding, explanations.get(finding.id))));
  elements.findings.hidden = !findings.length;
  elements.empty.hidden = Boolean(findings.length);
  elements.empty.textContent = report
    ? (allFindings.length ? "Нет находок выбранной критичности." : "Сканеры не вернули находок.")
    : "Здесь появятся результаты проверки.";
  elements["report-actions"].hidden = !report;
  elements["match-count"].hidden = !report;
  elements["match-count"].textContent = report ? `${findings.length} из ${allFindings.length}` : "";

  const warnings = [];
  if (report?.sca?.status === "catalog-missing") warnings.push("SCA пропущен. Добавьте JSON-справочник, чтобы проверить зависимости.");
  if (report?.sca?.unresolved_versions?.length) warnings.push(`Зависимости с неопределённой версией: ${report.sca.unresolved_versions.length}.`);
  if (report?.skipped_files?.length) warnings.push(`Пропущенные файлы: ${report.skipped_files.length}.`);
  elements.warnings.replaceChildren(...warnings.map((warning) => node("li", warning)));
  elements.warnings.hidden = !warnings.length;

  const gate = report ? state.releaseGate : null;
  elements["result-summary"].hidden = !gate;
  if (gate) {
    const { critical, high, medium, low } = gate.counts;
    const other = medium + low;
    const status = gate.status.toLowerCase();
    const statusTitles = {
      block: "Есть высокие или критические находки",
      warning: "Проверка завершена с замечаниями",
      pass: "Сканеры не вернули находок",
    };
    const statusDetails = {
      block: "Исправьте эти уязвимости и запустите проверку ещё раз.",
      warning: gate.missing_scanners.length
        ? `Не выполнены все проверки: ${gate.missing_scanners.map((scanner) => scannerNames[scanner]).join(", ")}.`
        : "Проверьте находки и предупреждения перед выпуском.",
      pass: "Отчёт готов; можно скачать JSON или изменить сценарий.",
    };
    elements["result-summary"].dataset.status = status;
    elements["result-status"].textContent = gate.status;
    elements["result-title"].textContent = statusTitles[status];
    elements["result-detail"].textContent = statusDetails[status];
    elements["critical-count"].textContent = critical;
    elements["high-count"].textContent = high;
    elements["other-count"].textContent = other;
  }
}

function setBusy(active) {
  state.active = active;
  for (const control of [elements.run, elements.rerun, elements["demo-mode"], elements["upload-mode"], elements.project, elements.catalog]) {
    control.disabled = active;
  }
  editor.setBusy(active);
  elements.run.textContent = active ? "Выполняется…" : "Запустить проверку";
}

async function readWorkflow(response) {
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let pending = "";
  let result;

  function applyEvent(line) {
    const event = JSON.parse(line);
    if (event.event === "node") editor.showEvent(event);
    if (event.event === "error") throw new Error(event.error);
    if (event.event === "result") result = event;
  }

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const lines = (pending + value).split("\n");
      pending = lines.pop();
      for (const line of lines) if (line) applyEvent(line);
    }
    if (pending.trim()) applyEvent(pending);
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  if (!result) throw new Error("Выполнение прервалось до получения отчёта.");
  return result;
}

async function runScan(event) {
  event.preventDefault();
  if (state.active) return;

  const demo = state.mode === "demo";
  const body = demo ? new FormData() : new FormData(elements["scan-form"]);
  if (!elements.catalog.files.length) body.delete("catalog");
  body.append("workflow", new Blob([JSON.stringify(editor.payload())], { type: "application/json" }), "workflow.json");
  setBusy(true);
  state.report = null;
  renderReport();
  elements.error.hidden = true;
  elements["run-status"].textContent = "Выполняется";
  elements["workflow-note"].textContent = "Backend проверяет граф и выполняет связанные блоки.";

  try {
    if (!await checkConnection()) throw new Error(elements.connection.textContent);
    const response = await fetch(`${API}/workflow`, {
      method: "POST", body, signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error((await response.json()).error);
    const result = await readWorkflow(response);
    state.report = result.report;
    state.releaseGate = result.release_gate;
    elements.severity.value = "all";
    elements["run-status"].textContent = "Завершено";
    const decisions = Object.entries(result.branches).map(([id, branch]) => `${editor.name(id)}: ${branch === "true" ? "Да" : "Нет"}`);
    const messages = result.reports.length ? [`Выполнено: ${result.reports.map(editor.name).join(", ")}.`] : ["Активная ветка завершилась без блока отчёта."];
    if (decisions.length) messages.unshift(`${decisions.join(" · ")}.`);
    if (demo && result.report) messages.push("Данные демо синтетические.");
    elements["workflow-note"].textContent = messages.join(" ");
    renderReport();
    if (!result.report) elements.empty.textContent = "Добавьте блок отчёта в активную ветку.";
    elements.report.scrollIntoView({ block: "start" });
  } catch (error) {
    editor.finishFailed();
    elements["run-status"].textContent = "Ошибка";
    elements["workflow-note"].textContent = "Отчёт не сформирован.";
    const networkFailure = error instanceof TypeError || error.name === "TimeoutError";
    elements.error.textContent = networkFailure
      ? "Backend не ответил. Проверьте, что он запущен на порту 8000."
      : (error.message || "Проверка завершилась ошибкой.");
    elements.error.hidden = false;
    elements.error.scrollIntoView({ block: "center" });
    if (networkFailure) void checkConnection();
  } finally {
    setBusy(false);
  }
}

function downloadReport() {
  if (!state.report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(state.report, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "security-report.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

elements["demo-mode"].addEventListener("click", () => setMode("demo"));
elements["upload-mode"].addEventListener("click", () => setMode("upload"));
elements["scan-form"].addEventListener("submit", runScan);
elements.severity.addEventListener("change", renderReport);
elements.download.addEventListener("click", downloadReport);
elements.rerun.addEventListener("click", () => elements["scan-form"].requestSubmit());
elements["launch-help"].hidden = true;
elements.run.disabled = false;
elements.connection.dataset.status = "pending";
elements.connection.textContent = "Проверка подключения";
void checkConnection();
window.addEventListener("focus", checkConnection);

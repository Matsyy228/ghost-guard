import { createEditor } from "./editor.js";

const API = "http://127.0.0.1:8000/api";
const elements = Object.fromEntries(
  [...document.querySelectorAll("[id]")].map((element) => [element.id, element]),
);
const severityNames = {
  critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий",
};
const scannerNames = { secrets: "Secrets", sca: "SCA", sast: "SAST" };
const state = { mode: "demo", active: false, report: null };
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

function setConnection(online) {
  elements.connection.dataset.status = online ? "online" : "offline";
  elements.connection.textContent = online ? "Backend подключён" : "Backend недоступен";
}

async function checkConnection() {
  try {
    const response = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2000) });
    setConnection(response.ok);
  } catch {
    setConnection(false);
  }
}

function node(tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function findingElement(finding) {
  const severity = node("span", severityNames[finding.severity] ?? finding.severity, "severity");
  severity.dataset.severity = finding.severity;
  const heading = node("div", "", "finding-heading");
  heading.append(severity, node("strong", finding.title));
  const location = [scannerNames[finding.scanner], `${finding.file}:${finding.line}`];
  if (finding.advisoryId || finding.cve) location.push(finding.advisoryId || finding.cve, `${finding.package}@${finding.version}`);
  const item = node("li", "");
  item.append(heading, node("p", location.join(" · "), "finding-location"),
    node("p", finding.recommendation, "finding-recommendation"));
  return item;
}

function renderReport() {
  const report = state.report;
  const filter = elements.severity.value;
  const findings = (report?.findings ?? []).filter((finding) => filter === "all" || finding.severity === filter);
  elements.findings.replaceChildren(...findings.map(findingElement));
  elements.findings.hidden = !findings.length;
  elements.empty.hidden = Boolean(findings.length);
  elements.empty.textContent = report
    ? (report.findings.length ? "Нет находок выбранной критичности." : "Сканеры не вернули находок.")
    : "Здесь появятся результаты проверки.";
  elements["report-actions"].hidden = !report;
  elements["match-count"].hidden = !report;
  elements["match-count"].textContent = report ? `${findings.length} из ${report.findings.length}` : "";

  const warnings = [];
  if (report?.sca.status === "catalog-missing") warnings.push("SCA пропущен. Добавьте JSON-справочник, чтобы проверить зависимости.");
  if (report?.sca.unresolved_versions.length) warnings.push(`Зависимости с неопределённой версией: ${report.sca.unresolved_versions.length}.`);
  if (report?.skipped_files.length) warnings.push(`Пропущенные файлы: ${report.skipped_files.length}.`);
  elements.warnings.replaceChildren(...warnings.map((warning) => node("li", warning)));
  elements.warnings.hidden = !warnings.length;
}

function setBusy(active) {
  state.active = active;
  for (const control of [elements.run, elements["demo-mode"], elements["upload-mode"], elements.project, elements.catalog]) {
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
    const response = await fetch(`${API}/workflow`, {
      method: "POST", body, signal: AbortSignal.timeout(30000),
    });
    setConnection(true);
    if (!response.ok) throw new Error((await response.json()).error);
    const result = await readWorkflow(response);
    state.report = result.report;
    elements.severity.value = "all";
    elements["run-status"].textContent = "Завершено";
    const decisions = Object.entries(result.branches).map(([id, branch]) => `${editor.name(id)}: ${branch === "true" ? "Да" : "Нет"}`);
    const messages = result.reports.length ? [`Выполнено: ${result.reports.map(editor.name).join(", ")}.`] : ["Активная ветка завершилась без блока отчёта."];
    if (decisions.length) messages.unshift(`${decisions.join(" · ")}.`);
    if (demo && result.report) messages.push("Данные демо синтетические.");
    elements["workflow-note"].textContent = messages.join(" ");
    renderReport();
    if (!result.report) elements.empty.textContent = "Добавьте блок отчёта в активную ветку.";
  } catch (error) {
    editor.finishFailed();
    elements["run-status"].textContent = "Ошибка";
    elements["workflow-note"].textContent = "Отчёт не сформирован.";
    const networkFailure = error instanceof TypeError || error.name === "TimeoutError";
    elements.error.textContent = networkFailure
      ? "Backend не ответил. Проверьте, что он запущен на порту 8000."
      : (error.message || "Проверка завершилась ошибкой.");
    elements.error.hidden = false;
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
elements["launch-help"].hidden = true;
elements.run.disabled = false;
elements.connection.dataset.status = "pending";
elements.connection.textContent = "Проверка подключения";
void checkConnection();
window.addEventListener("focus", checkConnection);

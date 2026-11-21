import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import { checkAPI, runWorkflow } from "./api.js";
import { createEditor } from "./editor.js";
import { renderFindings, scannerNames, sortedFindings } from "./report.js";
import demoReport from "./demo-report.json";

const ui = Object.fromEntries([...document.querySelectorAll("[id]")].map((element) => [element.id, element]));
const state = { phase: "idle", mode: "demo", connection: "pending", result: null, reportContext: null };
const reportTimeFormat = new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" });
let connectionCheck;

const editor = createEditor(ui, () => {
  invalidateResult("Запустите сценарий с обновлёнными настройками.");
});

function clearError() {
  ui.error.hidden = true;
  ui.error.textContent = "";
}

function invalidateResult(note) {
  if (state.phase === "ready" || state.phase === "stale") {
    state.phase = "stale";
  } else {
    state.phase = "idle";
    state.result = null;
    state.reportContext = null;
  }
  clearError();
  ui["workflow-note"].textContent = note;
  setRunStatus("Готов к запуску");
  render();
}

function setMode(mode) {
  if (state.mode === mode) return;
  state.mode = mode;
  const upload = mode === "upload";
  ui["demo-mode"].setAttribute("aria-pressed", String(!upload));
  ui["upload-mode"].setAttribute("aria-pressed", String(upload));
  ui["demo-input"].hidden = upload;
  ui["upload-inputs"].hidden = !upload;
  ui.project.required = upload;
  editor.clearResults();
  invalidateResult(upload ? "Загрузите ZIP проекта и запустите сценарий." : "Запустите сценарий на встроенном учебном проекте.");
}

function refreshConnection() {
  connectionCheck ??= checkAPI().then(({ status, label }) => {
    const changed = state.connection !== status;
    state.connection = status;
    ui.connection.dataset.status = status;
    if (ui.connection.textContent !== label) ui.connection.textContent = label;
    renderFeedback();
    if (changed) renderOverview();
    return status === "online";
  }).finally(() => { connectionCheck = null; });
  return connectionCheck;
}

function renderFeedback() {
  const offline = state.connection === "offline" && state.phase !== "running";
  ui["offline-actions"].hidden = !offline;
  ui["scan-feedback"].hidden = !offline && ui.error.hidden;
}

function linkAction(href, label) {
  const arrow = document.createElement("span");
  arrow.setAttribute("aria-hidden", "true");
  arrow.textContent = " ↓";
  ui["next-action"].href = href;
  ui["next-action"].replaceChildren(document.createTextNode(label), arrow);
}

function renderReportContext(gate) {
  const context = state.reportContext;
  ui["result-meta"].hidden = !context;
  if (!context) return;

  ui["result-source"].textContent = {
    demo: "Демо · учебные данные",
    upload: `ZIP · ${context.fileName}`,
    snapshot: "Резервный пример · учебные данные",
  }[context.source];

  const { receivedAt } = context;
  ui["result-time-row"].hidden = !receivedAt;
  if (receivedAt) {
    ui["result-time"].dateTime = receivedAt.toISOString();
    ui["result-time"].textContent = reportTimeFormat.format(receivedAt);
  } else {
    ui["result-time"].removeAttribute("datetime");
    ui["result-time"].textContent = "";
  }

  if (!Array.isArray(gate?.missing_scanners)) {
    ui["result-coverage"].textContent = "Список сканеров недоступен.";
    return;
  }
  const missing = gate.missing_scanners;
  const included = Object.keys(scannerNames).filter((scanner) => !missing.includes(scanner));
  const coverage = included.length
    ? `Выполнены: ${included.map((scanner) => scannerNames[scanner]).join(", ")}`
    : "Сканеры не выполнялись";
  const skipped = missing.map((scanner) => scannerNames[scanner] ?? scanner);
  ui["result-coverage"].textContent = skipped.length
    ? `${coverage} · Пропущены: ${skipped.join(", ")}`
    : coverage;
}

function renderOverview() {
  const { phase, connection, result } = state;
  const gate = result?.release_gate;
  const decision = {
    BLOCK: ["block", "Выпуск заблокирован"],
    WARNING: ["warning", "Требуется проверка"],
    PASS: ["pass", "По выполненным проверкам блокировок нет"],
  }[gate?.status];

  let status = "idle";
  let badge = "ОЖИДАНИЕ";
  let title = "Проверка ещё не запускалась";
  let detail = "Выберите источник ниже и запустите проверку.";
  let prompt = "Следующее действие";
  let next = state.mode === "upload" ? "Загрузите ZIP проекта." : "Запустите встроенный сценарий на учебном проекте.";
  let href = "#inputs";
  let action = "К запуску проверки";

  if (phase === "running") {
    status = "busy";
    badge = "В РАБОТЕ";
    title = "Выполняется проверка";
    detail = "Отчёт формируется по мере выполнения сценария.";
    next = "Статусы отдельных блоков обновляются на схеме.";
    href = "#workflow";
    action = "Смотреть ход проверки";
  } else if (phase === "stale") {
    status = "stale";
    badge = "УСТАРЕЛ";
    title = "Показан предыдущий результат";
    detail = "Сценарий или входные данные изменились после этого запуска.";
    next = connection === "offline" ? "Восстановите API и запустите проверку заново." : "Запустите проверку с текущими настройками.";
  } else if (phase === "error" || phase === "idle" && connection === "offline") {
    badge = "НЕТ ОТЧЁТА";
    title = phase === "error" ? "Проверка не завершилась" : "API недоступен для проверки";
    detail = "Актуальная оценка выпуска отсутствует.";
    next = connection === "offline"
      ? "Проверьте подключение или откройте резервный учебный отчёт."
      : "Проверьте сообщение об ошибке и повторите запуск.";
    action = "К ошибке и повторному запуску";
  } else if (result) {
    [status, title] = decision ?? ["idle", "Сервер не выдал оценку выпуска"];
    badge = phase === "snapshot" ? "ПРИМЕР" : (decision ? gate.status : "ОТЧЁТ");
    const counts = gate?.counts;
    const missing = (gate?.missing_scanners ?? []).map((scanner) => scannerNames[scanner] ?? scanner);
    const reasons = [];
    if (counts?.critical) reasons.push(`критических — ${counts.critical}`);
    if (counts?.high) reasons.push(`высоких — ${counts.high}`);
    if (counts?.medium || counts?.low) reasons.push(`средних и низких — ${counts.medium + counts.low}`);
    if (gate?.skipped_files) reasons.push(`пропущено файлов — ${gate.skipped_files}`);
    if (gate?.unresolved_versions) reasons.push(`не определено версий — ${gate.unresolved_versions}`);
    detail = reasons.length ? reasons.join(" · ") : missing.length
      ? "Часть сканеров пропущена."
      : "Отчёт доступен для просмотра.";
    if (phase === "snapshot") {
      status = "idle";
      title = decision ? `Учебный пример · ${gate.status}` : "Учебный пример";
    }
    const first = sortedFindings(result.report.findings)[0];
    prompt = first ? "Приоритетная находка в отчёте" : "Следующее действие";
    next = first?.title || (missing.length ? "Проверьте, почему часть сканеров не выполнилась." : "Откройте отчёт или выгрузите JSON.");
    href = "#report";
    action = "Открыть результаты";
  }

  ui["result-summary"].dataset.status = status;
  ui["result-status"].textContent = badge;
  ui["result-title"].textContent = title;
  ui["result-detail"].textContent = detail;
  ui["priority-title"].textContent = prompt;
  ui["priority-text"].textContent = next;
  linkAction(href, action);
  renderReportContext(gate);
}

function render(animate = false) {
  renderOverview();
  renderFeedback();
  renderFindings(ui, state.result?.report, { phase: state.phase, context: state.reportContext, animate });
}

function setRunStatus(text, status = "idle") {
  ui["run-status"].textContent = text;
  ui["run-status"].dataset.status = status;
}

function setBusy(active) {
  for (const control of [ui.run, ui.rerun, ui.project, ui.catalog,
    ui["demo-mode"], ui["upload-mode"], ui["offline-demo"], ui["retry-connection"]]) {
    control.disabled = active;
  }
  ui.run.textContent = active ? "Выполняется…" : "Запустить проверку";
  editor.setBusy(active);
}

function showReport() {
  setCurrentSection("#report");
  ui["report-title"].focus({ preventScroll: true });
  ui.report.scrollIntoView({ block: "start" });
}

async function runScan(event) {
  event.preventDefault();
  if (state.phase === "running") return;
  const demo = state.mode === "demo";
  const fileName = demo ? null : ui.project.files[0].name;
  const body = demo ? new FormData() : new FormData(ui["scan-form"]);
  if (!ui.catalog.files.length) body.delete("catalog");
  body.append("workflow", new Blob([JSON.stringify(editor.payload())], { type: "application/json" }), "workflow.json");

  state.phase = "running";
  state.result = null;
  state.reportContext = null;
  ui.severity.value = "all";
  setBusy(true);
  setRunStatus("Выполняется", "busy");
  ui["workflow-note"].textContent = "API проверяет сценарий и выполняет связанные блоки.";
  clearError();
  render();

  try {
    if (!await refreshConnection()) throw new Error("Запустите backend из текущего репозитория и проверьте подключение.");
    const failedNodes = new Set();
    const result = await runWorkflow(body, (event) => {
      editor.showEvent(event);
      if (event.status === "failed") failedNodes.add(event.id);
      else failedNodes.delete(event.id);
    });
    state.result = result;
    state.reportContext = {
      source: demo ? "demo" : "upload",
      fileName,
      receivedAt: new Date(),
      failedBlocks: [...failedNodes].map(editor.name),
    };
    state.phase = "ready";
    if (failedNodes.size) setRunStatus("Отчёт готов · есть ошибки блоков", "error");
    else setRunStatus("Завершено", "done");
    const branches = Object.entries(result.branches ?? {}).map(([id, branch]) => `${editor.name(id)}: ${branch === "true" ? "Да" : "Нет"}`);
    const reports = (result.reports ?? []).map(editor.name).join(", ");
    ui["workflow-note"].textContent = [...branches, reports && `Сформирован отчёт «${reports}»`].filter(Boolean).join(" · ") || "Сценарий завершён.";
    render(true);
    showReport();
  } catch (error) {
    editor.finishFailed();
    state.phase = "error";
    setRunStatus("Ошибка", "error");
    ui["workflow-note"].textContent = "Отчёт не сформирован.";
    ui.error.textContent = error.message || "Проверка завершилась ошибкой.";
    ui.error.hidden = false;
    render();
    ui["inputs"].scrollIntoView({ block: "start" });
    ui.error.focus({ preventScroll: true });
    void refreshConnection();
  } finally {
    setBusy(false);
  }
}

function openOfflineReport() {
  if (state.phase === "running") return;
  editor.clearResults();
  state.phase = "snapshot";
  state.result = demoReport;
  state.reportContext = { source: "snapshot" };
  ui.severity.value = "all";
  clearError();
  setRunStatus("Нет активного запуска");
  ui["workflow-note"].textContent = "Открыт резервный отчёт. Сценарий не запускался.";
  render(true);
  showReport();
}

function downloadReport() {
  if (!state.result?.report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(state.result.report, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = {
    snapshot: "ghost-guard-demo-report.json",
    stale: "security-report-previous.json",
  }[state.phase] ?? "security-report.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function setCurrentSection(section = location.hash) {
  const target = section === "#workflow" || section === "#report" ? section : "#overview";
  for (const link of document.querySelectorAll(".rail-nav a")) {
    if (link.hash === target) link.setAttribute("aria-current", "location");
    else link.removeAttribute("aria-current");
  }
}

ui["demo-mode"].addEventListener("click", () => setMode("demo"));
ui["upload-mode"].addEventListener("click", () => setMode("upload"));
for (const input of [ui.project, ui.catalog]) {
  input.addEventListener("change", () => {
    editor.clearResults();
    invalidateResult("Входные данные изменились. Запустите сценарий ещё раз.");
  });
}
ui["scan-form"].addEventListener("submit", runScan);
ui.severity.addEventListener("change", () => render());
ui["clear-filter"].addEventListener("click", () => {
  ui.severity.value = "all";
  render();
  ui.severity.focus();
});
ui.download.addEventListener("click", downloadReport);
ui.rerun.addEventListener("click", () => ui["scan-form"].requestSubmit());
ui["offline-demo"].addEventListener("click", openOfflineReport);
ui["retry-connection"].addEventListener("click", async () => {
  if (await refreshConnection()) {
    clearError();
    renderFeedback();
    ui.run.focus();
  }
});
window.addEventListener("hashchange", () => setCurrentSection());
window.addEventListener("focus", refreshConnection);
setCurrentSection();
ui.run.disabled = false;
void refreshConnection();

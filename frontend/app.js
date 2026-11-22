import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import { checkAPI, runWorkflow, workflowRequest } from "./api.js";
import { createEditor } from "./editor.js";
import { renderFindings, scannerNames, sortedFindings } from "./report.js";
import { deliveryLabels } from "./webhook.js";
import demoReport from "./demo-report.json";

const ui = Object.fromEntries([...document.querySelectorAll("[id]")].map((element) => [element.id, element]));
const state = { phase: "idle", mode: "demo", connection: "pending", result: null, reportContext: null };
const reportTimeFormat = new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" });
let connectionCheck;
let saved = null;
let savedGraph = "";
let managing = false;
let refreshing = false;
const runLabels = { running: "Выполняется", done: "Выполнено", failed: "Ошибка", skipped: "Пропущено",
  "completed-with-errors": "Завершён с ошибками" };

const editor = createEditor(ui, () => {
  clearJournal();
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
  syncSavedControls();
  editor.clearResults();
  clearJournal();
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
  ui["next-action"].hidden = !label;
  if (!label) {
    ui["next-action"].removeAttribute("href");
    ui["next-action"].replaceChildren();
    return;
  }
  const arrow = document.createElement("span");
  arrow.setAttribute("aria-hidden", "true");
  arrow.textContent = "↓";
  ui["next-action"].href = href;
  ui["next-action"].replaceChildren(document.createTextNode(label), arrow);
}

function renderReportContext(gate) {
  const context = state.reportContext;
  ui["result-meta"].hidden = !context;
  if (!context) return;

  ui["result-source"].textContent = {
    demo: "Демо · учебные данные",
    upload: context.fileName ? `ZIP · ${context.fileName}` : "Сохранённый ZIP",
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
  let detail = "Решение о выпуске появится в отчёте.";
  let prompt = "Следующее действие";
  let next = state.mode === "upload" ? "Загрузите ZIP проекта." : "Запустите встроенный сценарий на учебном проекте.";
  let href = "#inputs";
  let action;

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
    action = "К запуску проверки";
  } else if (phase === "error" || phase === "idle" && connection === "offline") {
    badge = "НЕТ ОТЧЁТА";
    title = phase === "error" ? "Проверка не завершилась" : "API недоступен для проверки";
    detail = "Актуальная оценка выпуска отсутствует.";
    next = connection === "offline"
      ? "Проверьте подключение или откройте резервный учебный отчёт."
      : "Проверьте сообщение об ошибке и повторите запуск.";
    action = connection === "offline" ? "К подключению API" : "К ошибке и повторному запуску";
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
    href = first ? "#priority-finding" : "#report";
    action = first ? "Открыть находку" : "Открыть результаты";
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
  ui.download.disabled = !Array.isArray(downloadableReport()?.findings);
}

function setRunStatus(text, status = "idle") {
  ui["run-status"].textContent = text;
  ui["run-status"].dataset.status = status;
}

function setBusy(active, reset = true) {
  for (const control of [ui.run, ui.rerun, ui.project, ui.catalog,
    ui["demo-mode"], ui["upload-mode"], ui["offline-demo"], ui["retry-connection"]]) {
    control.disabled = active;
  }
  ui.run.textContent = state.phase === "running" ? "Выполняется…" : "Запустить проверку";
  editor.setBusy(active, reset);
  syncSavedControls();
}

function syncSavedControls() {
  ui.project.required = state.mode === "upload" && saved?.source !== "zip";
  const locked = managing || state.phase === "running";
  for (const id of ["saved-list", "saved-name", "saved-interval", "saved-open", "graph-export", "graph-import"]) {
    ui[id].disabled = locked;
  }
  ui["saved-submit"].disabled = locked || ui["saved-list"].value !== (saved?.id ?? "");
  ui["saved-last"].disabled = locked || !saved;
}

function savedMessage(text) {
  ui["saved-status"].textContent = text;
}

function describeSaved(workflow) {
  const last = workflow.last_run;
  const next = workflow.next_run_at ? `Следующий запуск ${reportTimeFormat.format(new Date(workflow.next_run_at))}.` : "Расписание выключено.";
  return [workflow.source === "zip" ? "ZIP сохранён на сервере." : "Источник — демо.", next,
    last && `Последний запуск ${last.trigger === "schedule" ? "по расписанию" : "вручную"} — ${runLabels[last.status]}.`]
    .filter(Boolean).join(" ");
}

async function refreshSaved() {
  const { workflows } = await workflowRequest();
  const selection = ui["saved-list"].value;
  ui["saved-list"].replaceChildren(new Option("Новый сценарий", ""),
    ...workflows.map((workflow) => new Option(workflow.name, workflow.id)));
  ui["saved-list"].value = workflows.some(({ id }) => id === selection) ? selection : (saved?.id ?? "");
  syncSavedControls();
}

async function manageSaved(action) {
  if (managing || state.phase === "running") return;
  managing = true;
  setBusy(true, false);
  try {
    await action();
  } catch (error) {
    savedMessage(error.message || "Не удалось выполнить действие.");
  } finally {
    managing = false;
    setBusy(false);
  }
}

function useSaved(workflow) {
  saved = workflow;
  savedGraph = workflow ? JSON.stringify(editor.payload()) : "";
  ui["saved-name"].value = workflow?.name ?? "Моя проверка";
  ui["saved-interval"].value = workflow?.interval_seconds ?? "";
  ui.project.value = "";
  ui.catalog.value = "";
  ui["saved-live"].textContent = "";
  setMode(workflow?.source === "zip" ? "upload" : "demo");
  syncSavedControls();
  savedMessage(workflow ? describeSaved(workflow) : "");
}

async function saveScenario() {
  const interval = ui["saved-interval"].value;
  const settings = { name: ui["saved-name"].value, workflow: editor.payload(),
    interval_seconds: interval === "" ? null : Number(interval) };
  const upload = state.mode === "upload";
  let options;
  if (upload && ui.project.files.length) {
    const body = new FormData();
    body.append("settings", new Blob([JSON.stringify(settings)], { type: "application/json" }), "workflow.json");
    body.append("project", ui.project.files[0]);
    if (ui.catalog.files.length) body.append("catalog", ui.catalog.files[0]);
    options = { body };
  } else {
    if (upload && (saved?.source !== "zip" || ui.catalog.files.length)) {
      throw new Error("Приложите ZIP, в том числе при замене справочника.");
    }
    if (!upload) settings.source = "demo";
    options = { headers: { "Content-Type": "application/json" }, body: JSON.stringify(settings) };
  }
  const updated = await workflowRequest(saved ? `/${saved.id}` : "", { method: saved ? "PUT" : "POST", ...options });
  useSaved(updated);
  await refreshSaved();
  ui["saved-list"].value = updated.id;
  savedMessage(`Сохранено. ${describeSaved(updated)}`);
}

function reportContext(source, fileName, receivedAt = new Date()) {
  return { source, fileName, receivedAt, failedNodes: new Set(), aiWarnings: [], deliveries: new Map() };
}

function clearJournal() {
  ui["run-journal"].hidden = true;
  ui["run-events"].replaceChildren();
}

function receiveNode(event, context, showOnGraph = true) {
  if (showOnGraph) editor.showEvent(event);
  const row = document.createElement("li");
  row.textContent = [editor.name(event.id), deliveryLabels[event.delivery_status] ?? runLabels[event.status],
    event.input && `Вход ${event.input.count}`, event.output?.count != null && `Выход ${event.output.count}`]
    .filter(Boolean).join(" · ");
  ui["run-events"].append(row);
  ui["run-journal"].hidden = false;
  if (event.delivery_status) context.deliveries.set(event.id, { name: editor.name(event.id), ...event });
  else if (event.code?.startsWith("llm-") && (event.status === "failed" || event.code === "llm-not-configured")) {
    context.aiWarnings.push(event.message);
  } else if (event.status === "failed") context.failedNodes.add(event.id);
  else context.failedNodes.delete(event.id);
}

function showResult(result, context) {
  state.result = result;
  const { failedNodes, deliveries, ...info } = context;
  state.reportContext = { ...info, failedBlocks: [...failedNodes].map(editor.name), deliveries: [...deliveries.values()] };
  state.phase = "ready";
  setRunStatus(failedNodes.size ? "Отчёт готов · есть ошибки блоков"
    : info.aiWarnings.length ? "Отчёт готов · предупреждение Qwen" : "Завершено", failedNodes.size ? "error" : "done");
  const branches = Object.entries(result.branches ?? {}).map(([id, branch]) => `${editor.name(id)}: ${branch === "true" ? "Да" : "Нет"}`);
  const reports = (result.reports ?? []).map(editor.name).join(", ");
  ui["workflow-note"].textContent = [...branches, reports && `Сформирован отчёт «${reports}»`].filter(Boolean).join(" · ") || "Сценарий завершён.";
  render(true);
}

async function showLastRun() {
  const { last_run: last } = await workflowRequest(`/${saved.id}/last-run`);
  if (!last || last.status === "running") {
    savedMessage(last ? "Сценарий выполняется." : "У сценария ещё нет запусков.");
    return;
  }
  const context = reportContext(saved.source === "zip" ? "upload" : "demo", null, new Date(last.finished_at));
  const result = last.events.at(-1);
  const matchesGraph = JSON.stringify(editor.payload()) === savedGraph &&
    Date.parse(last.started_at) >= Date.parse(saved.updated_at);
  editor.clearResults();
  clearJournal();
  for (const event of last.events) {
    if (event.event === "node") receiveNode(event, context, matchesGraph);
  }
  if (result?.event === "result") {
    ui.severity.value = "all";
    showResult(result, context);
    if (!matchesGraph) invalidateResult("Показан отчёт предыдущего запуска сохранённого сценария.");
  } else {
    editor.finishFailed();
    state.phase = "error";
    state.result = null;
    state.reportContext = null;
    setRunStatus("Ошибка", "error");
    ui["workflow-note"].textContent = result?.error ?? "Отчёт отсутствует.";
    render();
  }
  savedMessage(describeSaved({ ...saved, last_run: last }));
}

async function runScan(event) {
  event.preventDefault();
  if (state.phase === "running" || managing) return;
  const demo = state.mode === "demo";
  const graph = JSON.stringify(editor.payload());
  const useSavedRun = saved?.source === (demo ? "demo" : "zip") && graph === savedGraph
    && (demo || (!ui.project.files.length && !ui.catalog.files.length));
  if (!demo && !useSavedRun && !ui.project.files.length) {
    invalidateResult("Сохраните изменения сценария или приложите ZIP для разового запуска.");
    return;
  }
  const fileName = ui.project.files[0]?.name ?? null;
  let body;
  if (!useSavedRun) {
    body = demo ? new FormData() : new FormData(ui["scan-form"]);
    if (!ui.catalog.files.length) body.delete("catalog");
    body.append("workflow", new Blob([graph], { type: "application/json" }), "workflow.json");
  }

  state.phase = "running";
  state.result = null;
  state.reportContext = null;
  ui.severity.value = "all";
  setBusy(true);
  clearJournal();
  setRunStatus("Выполняется", "busy");
  ui["workflow-note"].textContent = "API проверяет сценарий и выполняет связанные блоки.";
  clearError();
  render();

  try {
    if (!await refreshConnection()) throw new Error("Запустите backend из текущего репозитория и проверьте подключение.");
    const context = reportContext(demo ? "demo" : "upload", fileName);
    const result = await runWorkflow(body, (event) => receiveNode(event, context), useSavedRun ? saved.id : undefined);
    showResult(result, context);
    navigate("#report");
  } catch (error) {
    editor.finishFailed();
    state.phase = "error";
    setRunStatus("Ошибка", "error");
    ui["workflow-note"].textContent = "Отчёт не сформирован.";
    ui.error.textContent = error.message || "Проверка завершилась ошибкой.";
    ui.error.hidden = false;
    render();
    navigate("#inputs");
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
  navigate("#report");
}

function downloadableReport() {
  return state.phase === "snapshot" ? state.result?.report : state.result?.submission;
}

function downloadReport() {
  const report = downloadableReport();
  if (!Array.isArray(report?.findings)) return;
  downloadJSON(report, {
    snapshot: "ghost-guard-demo-report.json",
    stale: "findings-previous.json",
  }[state.phase] ?? "findings.json");
}

function downloadJSON(value, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const sectionLinks = [...document.querySelectorAll(".rail-nav a")];
const destinations = {
  "#overview": ["#overview", "page-title"],
  "#inputs": ["#overview", "inputs-title"],
  "#workflow": ["#workflow", "workflow-title"],
  "#node-settings-title": ["#workflow", "node-settings-title"],
  "#report": ["#report", "report-title"],
  "#priority-finding": ["#report", "report-title"],
};

function setCurrentSection(section) {
  for (const link of sectionLinks) {
    if (link.hash === section) {
      link.setAttribute("aria-current", "location");
      ui["current-section"].textContent = link.textContent.trim();
    } else {
      link.removeAttribute("aria-current");
    }
  }
}

function navigate(hash, { push = true } = {}) {
  hash = hash || "#overview";
  if (!Object.hasOwn(destinations, hash)) return;

  let focusTarget;
  if (hash === "#priority-finding") {
    if (state.result?.report.findings.length && !document.getElementById("priority-finding")) {
      ui.severity.value = "all";
      render();
    }
    const finding = document.getElementById("priority-finding");
    if (finding) {
      finding.open = true;
      focusTarget = finding.querySelector("summary");
    } else {
      hash = "#report";
      if (!push) history.replaceState(null, "", hash);
    }
  }

  if (push && location.hash !== hash) history.pushState(null, "", hash);
  const [section, heading] = destinations[hash];
  setCurrentSection(section);
  focusTarget ??= hash === "#inputs" && !ui.error.hidden ? ui.error : ui[heading];
  focusTarget.focus({ preventScroll: true });
  focusTarget.scrollIntoView({ block: "start" });
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
ui["saved-list"].addEventListener("change", syncSavedControls);
ui["saved-form"].addEventListener("submit", (event) => {
  event.preventDefault();
  if (!ui["saved-submit"].disabled) void manageSaved(saveScenario);
});
ui["saved-open"].addEventListener("click", () => manageSaved(async () => {
  const id = ui["saved-list"].value;
  if (!id) {
    useSaved(null);
    editor.load(editor.payload());
    return;
  }
  const workflow = await workflowRequest(`/${id}`);
  editor.load(workflow.workflow);
  useSaved(workflow);
}));
ui["saved-last"].addEventListener("click", () => manageSaved(showLastRun));
ui["graph-export"].addEventListener("click", () => downloadJSON(editor.payload(), "workflow.json"));
ui["graph-import"].addEventListener("click", () => ui["graph-file"].click());
ui["graph-file"].addEventListener("change", (event) => {
  const [file] = event.target.files;
  event.target.value = "";
  if (!file) return;
  void manageSaved(async () => {
    if (file.size > 16 * 1024) throw new Error("Граф должен занимать не более 16 КиБ.");
    editor.load(JSON.parse(await file.text()));
    ui["saved-list"].value = "";
    useSaved(null);
    savedMessage("Граф загружен. Выберите источник и сохраните сценарий.");
  });
});
void refreshSaved().catch(() => {});
setInterval(async () => {
  if (!saved || managing || refreshing || state.phase === "running") return;
  const opened = saved;
  refreshing = true;
  try {
    const current = await workflowRequest(`/${opened.id}`);
    if (saved === opened && !managing && state.phase !== "running") ui["saved-live"].textContent = describeSaved(current);
  } catch {
    // A brief connection failure must not replace the last known status.
  } finally {
    refreshing = false;
  }
}, 3000);
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
document.addEventListener("click", (event) => {
  const link = event.target.closest('a[href^="#"]');
  if (!link || !Object.hasOwn(destinations, link.hash) || event.defaultPrevented ||
      event.button !== 0 || event.ctrlKey || event.metaKey || event.altKey || event.shiftKey) return;
  event.preventDefault();
  navigate(link.hash);
});
window.addEventListener("hashchange", () => navigate(location.hash, { push: false }));
window.addEventListener("focus", refreshConnection);
if (location.hash) navigate(location.hash, { push: false });
ui.run.disabled = false;
void refreshConnection();

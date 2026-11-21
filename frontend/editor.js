const typeNames = {
  trigger: "Ручной запуск", secrets: "Secrets", sca: "SCA", sast: "SAST",
  llm: "Объяснение LLM", condition: "Условие", report: "Отчёт",
};
const statusNames = {
  idle: "Ожидает", running: "Выполняется", done: "Выполнено", skipped: "Пропущено", failed: "Ошибка",
};
const severityOptions = [
  ["low", "Низкая"], ["medium", "Средняя"], ["high", "Высокая"], ["critical", "Критическая"],
];
const fieldOptions = [
  ["file", "Файл"], ["severity", "Критичность"], ["scanner", "Сканер"], ["rule", "Правило"],
  ["line", "Строка"], ["cve", "CVE"], ["advisoryId", "CVE или GHSA"], ["package", "Зависимость"],
];
const modes = [["severity", "Порог критичности"], ["compare", "Сравнение"], ["regex", "Регулярное выражение"]];
const operators = [["eq", "Равно"], ["ne", "Не равно"], ["gt", "Больше"], ["gte", "Не меньше"], ["lt", "Меньше"], ["lte", "Не больше"]];
const branchNames = { true: "Да", false: "Нет" };
const WIDTH = 122;
const HEIGHT = 86;
const LINK_HINT = "Для связи нажмите выход блока, затем вход другого блока.";

function element(tag, text = "", className = "") {
  const item = document.createElement(tag);
  item.textContent = text;
  item.className = className;
  return item;
}

function template() {
  const nodes = ["trigger", "secrets", "sca", "sast", "condition"].map((type, index) => ({
    id: type, type, x: 16 + index * 140, y: 115,
  }));
  nodes.at(-1).config = { mode: "severity", value: "high" };
  nodes.push({ id: "risk-report", type: "report", label: "Отчёт о рисках", x: 716, y: 48 },
    { id: "low-report", type: "report", label: "Ниже порога", x: 716, y: 182 });
  const edges = nodes.slice(1, 5).map((item, index) => ({ source: nodes[index].id, target: item.id, branch: null }));
  edges.push({ source: "condition", target: "risk-report", branch: "true" },
    { source: "condition", target: "low-report", branch: "false" });
  return { nodes, edges };
}

export function createEditor(ui, onEdit) {
  let graph = template();
  let selected = "condition";
  let nextId = 1;
  let pending = null;
  let busy = false;
  const events = new Map();
  const cards = new Map();
  const stage = ui["graph-stage"];
  const canvas = ui["graph-lines"];
  const nodeLayer = ui["graph-nodes"];
  const settings = ui["node-settings"];
  const dataView = ui["node-data"];
  const hint = ui["graph-hint"];
  const find = (id) => graph.nodes.find((item) => item.id === id);
  const name = (id) => {
    const item = find(id);
    return (item && (item.label || typeNames[item.type])) || id;
  };

  function draw() {
    const context = canvas.getContext("2d");
    const ratio = Math.min(2, window.devicePixelRatio || 1);
    const width = stage.offsetWidth, height = stage.offsetHeight;
    const pixelWidth = Math.ceil(width * ratio), pixelHeight = Math.ceil(height * ratio);
    if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
      canvas.width = pixelWidth;
      canvas.height = pixelHeight;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
    }
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);
    for (const edge of graph.edges) {
      const source = find(edge.source), target = find(edge.target);
      const beginX = source.x + WIDTH, endX = target.x;
      const offsets = { true: 29, false: 57 };
      const beginY = source.y + (offsets[edge.branch] ?? 42), endY = target.y + 42;
      const bend = Math.max(14, (endX - beginX) / 2);
      const picked = events.get(edge.source)?.output?.branch;
      const reached = events.get(edge.target)?.input?.sources.includes(edge.source);
      const active = reached && (!edge.branch || picked === edge.branch);
      context.lineWidth = active ? 2.8 : 1.6;
      context.strokeStyle = active ? (edge.branch === "false" ? "#f1c675" : "#69e6c0") : "#486381";
      context.setLineDash(picked && edge.branch && picked !== edge.branch ? [4, 4] : []);
      context.beginPath();
      context.moveTo(beginX, beginY);
      context.bezierCurveTo(beginX + bend, beginY, endX - bend, endY, endX, endY);
      context.stroke();
    }
  }

  function position(item, card = cards.get(item.id)) {
    card.style.left = `${item.x}px`;
    card.style.top = `${item.y}px`;
  }

  function setHint(message = LINK_HINT) {
    hint.textContent = message;
  }

  function paintCards() {
    for (const [id, card] of cards) {
      const status = events.get(id)?.status ?? "idle";
      card.dataset.status = status;
      card.dataset.selected = String(id === selected);
      card.querySelector(".graph-handle").setAttribute("aria-pressed", String(id === selected));
      card.querySelector(".graph-badge").textContent = statusNames[status];
      for (const port of card.querySelectorAll(".graph-port")) {
        port.disabled = busy;
        if (port.classList.contains("out")) {
          port.setAttribute("aria-pressed", String(pending?.source === id && pending.branch === (port.dataset.branch || null)));
        }
      }
    }
    draw();
  }

  function edit({ rebuild = true, message = LINK_HINT } = {}) {
    events.clear();
    setHint(message);
    if (rebuild) renderNodes();
    else {
      paintCards();
      renderData();
    }
    onEdit();
  }

  function choose(id) {
    selected = id;
    paintCards();
    renderSettings();
    renderData();
  }

  function connect(target) {
    if (!pending) {
      choose(target);
      setHint("Сначала нажмите выход блока-источника.");
      return;
    }
    if (pending.source === target) {
      setHint("Выберите вход другого блока.");
      return;
    }
    if (graph.edges.length >= 48) {
      setHint("В сценарии достигнут лимит в 48 связей.");
      return;
    }
    if (graph.edges.some((edge) => edge.target === target && edge.source === pending.source && edge.branch === pending.branch)) {
      setHint("Такая связь уже есть.");
      return;
    }
    graph.edges.push({ ...pending, target });
    selected = pending.source;
    pending = null;
    edit({ message: `Связь добавлена: ${name(selected)} → ${name(target)}.` });
  }

  function port(item, side, branch = null) {
    const control = element("button", "", `graph-port ${side}`);
    control.type = "button";
    if (branch) {
      control.dataset.branch = branch;
      control.append(element("span", branchNames[branch], "graph-port-label"));
    }
    control.setAttribute("aria-label", `${side === "in" ? "Вход" : "Выход"} ${name(item.id)}${branch ? ` ${branchNames[branch]}` : ""}`);
    control.title = control.getAttribute("aria-label");
    control.addEventListener("click", () => {
      if (side === "in") connect(item.id);
      else {
        pending = pending?.source === item.id && pending.branch === branch ? null : { source: item.id, branch };
        choose(item.id);
        setHint(pending ? `Выход «${name(item.id)}${branch ? ` · ${branchNames[branch]}` : ""}» выбран. Нажмите вход другого блока.` : LINK_HINT);
      }
    });
    return control;
  }

  function makeCard(item) {
    const card = element("article", "", "graph-node");
    card.dataset.node = item.id;
    card.dataset.type = item.type;
    const handle = element("button", "", "graph-handle");
    handle.type = "button";
    handle.append(element("strong", name(item.id)), element("span", "", "graph-badge"));
    handle.addEventListener("click", () => choose(item.id));
    let start;
    handle.addEventListener("pointerdown", (event) => {
      if (busy || event.button !== 0) return;
      start = { pointer: event.pointerId, x: event.clientX, y: event.clientY, left: item.x, top: item.y };
      handle.setPointerCapture(event.pointerId);
    });
    handle.addEventListener("pointermove", (event) => {
      if (!start || start.pointer !== event.pointerId) return;
      item.x = Math.round(Math.max(12, Math.min(stage.offsetWidth - WIDTH - 12, start.left + event.clientX - start.x)));
      item.y = Math.round(Math.max(12, Math.min(stage.offsetHeight - HEIGHT - 12, start.top + event.clientY - start.y)));
      position(item, card);
      draw();
    });
    handle.addEventListener("lostpointercapture", () => { start = null; });
    card.append(handle);
    if (item.type !== "trigger") card.append(port(item, "in"));
    if (item.type === "condition") card.append(port(item, "out", "true"), port(item, "out", "false"));
    else if (item.type !== "report") card.append(port(item, "out"));
    position(item, card);
    return card;
  }

  function renderNodes() {
    stage.style.height = `${Math.max(316, ...graph.nodes.map((item) => item.y + HEIGHT + 20))}px`;
    cards.clear();
    for (const item of graph.nodes) cards.set(item.id, makeCard(item));
    nodeLayer.replaceChildren(...cards.values());
    paintCards();
    renderSettings();
    renderData();
  }

  function settingsField(form, label, key, value, options, change) {
    const control = options ? element("select") : element("input");
    control.id = `condition-${key}`;
    if (options) {
      for (const [option, text] of options) {
        const part = element("option", text);
        part.value = option;
        control.append(part);
      }
    } else {
      control.type = "text";
      control.maxLength = 128;
    }
    control.value = value;
    control.disabled = busy;
    control.addEventListener(options ? "change" : "input", () => change(control.value));
    const wrapper = element("label", label);
    wrapper.append(control);
    form.append(wrapper);
  }

  function conditionSettings(item) {
    const form = element("div", "", "graph-config");
    const config = item.config;
    settingsField(form, "Тип условия", "mode", config.mode, modes, (mode) => {
      item.config = mode === "severity" ? { mode, value: "high" } : { mode, field: "file", operator: "eq", value: "" };
      edit({ rebuild: false });
      renderSettings();
      settings.querySelector("#condition-mode").focus();
    });
    if (config.mode !== "severity") {
      settingsField(form, "Поле находки", "field", config.field, fieldOptions, (field) => {
        Object.assign(config, { field, operator: "eq", value: config.mode === "compare" && field === "severity" ? "high" : "" });
        edit({ rebuild: false });
        renderSettings();
        settings.querySelector("#condition-field").focus();
      });
    }
    if (config.mode === "compare") {
      const choices = ["line", "severity"].includes(config.field) ? operators : operators.slice(0, 2);
      settingsField(form, "Оператор", "operator", config.operator, choices, (value) => { config.operator = value; edit({ rebuild: false }); });
    }
    const useLevels = config.mode === "severity" || (config.mode === "compare" && config.field === "severity");
    const label = config.mode === "severity" ? "Минимальная критичность" : config.mode === "regex" ? "Выражение" : "Значение";
    settingsField(form, label, "value", config.value, useLevels ? severityOptions : null, (value) => {
      config.value = value;
      edit({ rebuild: false });
    });
    return form;
  }

  function remove(id) {
    const incoming = graph.edges.filter((edge) => edge.target === id);
    const outgoing = graph.edges.filter((edge) => edge.source === id);
    const wasScanner = ["secrets", "sca", "sast"].includes(find(id).type);
    graph.edges = graph.edges.filter((edge) => edge.source !== id && edge.target !== id);
    if (wasScanner && incoming.length === 1 && outgoing.length === 1) {
      const bridge = { ...incoming[0], target: outgoing[0].target };
      if (bridge.source !== bridge.target && !graph.edges.some((edge) => edge.source === bridge.source && edge.target === bridge.target && edge.branch === bridge.branch)) {
        graph.edges.push(bridge);
      }
    }
    graph.nodes = graph.nodes.filter((item) => item.id !== id);
    selected = graph.nodes.find((item) => item.type === "condition")?.id ?? graph.nodes[0].id;
    pending = null;
    edit();
  }

  function renderSettings() {
    const item = find(selected);
    settings.replaceChildren(element("p", name(item.id)));
    if (item.type === "condition") settings.append(conditionSettings(item));
    if (item.type === "llm") {
      settings.append(element("p", "Объясняет входные находки. Адрес провайдера, модель и ключ задаются в окружении backend."));
    }
    const list = element("ul", "", "graph-links");
    const outgoing = graph.edges.filter((edge) => edge.source === item.id);
    for (const edge of outgoing) {
      const row = element("li");
      row.append(element("span", `${edge.branch ? `${branchNames[edge.branch]} · ` : ""}${name(edge.target)}`));
      const unlink = element("button", "Убрать связь");
      unlink.type = "button";
      unlink.disabled = busy;
      unlink.setAttribute("aria-label", `Убрать связь с блоком ${name(edge.target)}`);
      unlink.addEventListener("click", () => {
        graph.edges = graph.edges.filter((link) => link !== edge);
        pending = null;
        edit();
      });
      row.append(unlink);
      list.append(row);
    }
    if (outgoing.length) settings.append(list);
    if (item.type !== "trigger") {
      const erase = element("button", "Удалить блок", "remove-node");
      erase.type = "button";
      erase.disabled = busy;
      erase.addEventListener("click", () => remove(item.id));
      settings.append(erase);
    }
  }

  function dataList(data) {
    const list = element("ul", "", "graph-data-list");
    for (const finding of data.findings) {
      const details = [finding.id, finding.scanner, finding.rule, `${finding.file}:${finding.line}`, finding.severity]
        .filter((value) => typeof value === "string" && value.length);
      const item = element("li", details.join(" · "));
      const explanation = explanationElement(finding.llm_explanation);
      if (explanation) item.append(explanation);
      list.append(item);
    }
    return list;
  }

  function explanationElement(explanation) {
    if (!explanation || typeof explanation !== "object" || Array.isArray(explanation)) return null;
    const summary = typeof explanation.explanation === "string" ? explanation.explanation.trim()
      : typeof explanation.summary === "string" ? explanation.summary.trim() : "";
    const recommendation = typeof explanation.recommendation === "string" ? explanation.recommendation.trim() : "";
    if (!summary && !recommendation) return null;

    const section = element("section", "", "finding-llm");
    section.append(element("strong", "Объяснение LLM"));
    if (summary) section.append(element("p", `Почему: ${summary}`));
    if (recommendation) section.append(element("p", `Что сделать: ${recommendation}`));
    return section;
  }

  function explanationList(explanations) {
    const list = element("ul", "", "graph-data-list");
    for (const explanation of explanations) {
      const location = explanation.file && Number.isInteger(explanation.line)
        ? `${explanation.file}:${explanation.line}` : "";
      const details = [explanation.finding_id, location, explanation.advisoryId]
        .filter((value) => typeof value === "string" && value.length);
      const item = element("li", details.join(" · "));
      const rendered = explanationElement(explanation);
      if (rendered) item.append(rendered);
      list.append(item);
    }
    return list;
  }

  function renderData() {
    const current = events.get(selected);
    if (!current) {
      dataView.replaceChildren(element("p", "Данные блока появятся после запуска."));
      return;
    }
    dataView.replaceChildren(element("p", `${name(selected)} · ${statusNames[current.status]}`));
    if (current.input) {
      const sources = current.input.sources.map(name).join(", ") || "Ручной запуск";
      dataView.append(element("p", `Вход из ${sources} · находок ${current.input.count}`));
      if (current.input.findings.length) {
        const details = element("details", "", "graph-input-data");
        details.append(element("summary", "Входные находки"), dataList(current.input));
        dataView.append(details);
      }
    }
    if (current.output) {
      dataView.append(element("p", `На выходе находок: ${current.output.count}`));
      if (current.output.branch) {
        const match = current.output.matched;
        dataView.append(element("p", `Ветка «${branchNames[current.output.branch]}»${match ? ` · ${match.file}:${match.line} · ${match.severity}` : ""}`));
      }
      if (current.output.findings.length) dataView.append(dataList(current.output));
      if (Array.isArray(current.output.explanations) && current.output.explanations.length) {
        dataView.append(element("p", `Объяснений: ${current.output.explanations.length}`),
          explanationList(current.output.explanations));
      }
    }
    if (current.code) dataView.append(element("p", `Код ошибки: ${current.code}`));
    if (current.message) dataView.append(element("p", current.message));
  }

  ui["add-node"].addEventListener("click", () => {
    if (graph.nodes.length >= 24) {
      setHint("В сценарии достигнут лимит в 24 блока.");
      return;
    }
    const type = ui["node-type"].value;
    const count = nextId++;
    const index = graph.nodes.filter((item) => item.id.startsWith("block-")).length;
    const item = { id: `block-${count}`, type, label: `${typeNames[type]} ${count}`, x: 16 + (index % 6) * 140, y: 326 + Math.floor(index / 6) * 108 };
    if (type === "condition") item.config = { mode: "severity", value: "high" };
    graph.nodes.push(item);
    selected = item.id;
    pending = null;
    edit();
    cards.get(item.id).scrollIntoView({ block: "nearest", inline: "nearest" });
  });
  ui["reset-graph"].addEventListener("click", () => {
    graph = template();
    selected = "condition";
    pending = null;
    nextId = 1;
    edit();
    ui["graph-viewport"].scrollTo(0, 0);
  });
  window.addEventListener("resize", draw);
  renderNodes();

  return {
    name,
    payload: () => ({ nodes: graph.nodes.map(({ id, type, config }) => ({ id, type, config })), edges: graph.edges }),
    setBusy(value) {
      busy = value;
      ui["node-type"].disabled = value;
      ui["add-node"].disabled = value;
      ui["reset-graph"].disabled = value;
      if (value) {
        pending = null;
        events.clear();
        setHint();
      }
      paintCards();
      renderSettings();
      renderData();
    },
    showEvent(event) {
      events.set(event.id, event);
      paintCards();
      if (selected === event.id) renderData();
    },
    finishFailed() {
      for (const [id, event] of events) {
        if (event.status === "running") events.set(id, { ...event, status: "failed", message: "Выполнение прервано." });
      }
      paintCards();
      renderData();
    },
  };
}

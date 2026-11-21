const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api";

export async function checkAPI() {
  try {
    const response = await fetch(`${API}/health`, { signal: AbortSignal.timeout(2000), cache: "no-store" });
    if (!response.ok) return { status: "offline", label: `API вернул HTTP ${response.status}` };
    const data = await response.json();
    if (data?.status === "ok" && data.service === "ghost-guard" && data.api_version === 2 && /^[a-f0-9]{16}$/.test(data.build_id)) {
      return { status: "online", label: "API подключён" };
    }
    return { status: "offline", label: "Несовместимая версия API" };
  } catch (error) {
    return { status: "offline", label: error.name === "TimeoutError" ? "API не ответил вовремя" : "API недоступен" };
  }
}

async function readWorkflow(response, onNode) {
  if (!response.body) throw new Error("Сервер вернул пустой ответ. Повторите проверку.");
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let pending = "";
  let sawEvent = false;
  let result;

  function applyEvent(line) {
    if (!line.trim()) return;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      throw new Error("Сервер вернул данные в неожиданном формате. Повторите проверку.");
    }
    sawEvent = true;
    if (event?.event === "node") onNode(event);
    if (event?.event === "error") throw new Error(event.error || "Сценарий завершился ошибкой.");
    if (event?.event === "result") result = event;
  }

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      const lines = (pending + value).split("\n");
      pending = lines.pop();
      for (const line of lines) applyEvent(line);
    }
    applyEvent(pending);
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }

  if (!sawEvent) throw new Error("Сервер вернул пустой ответ. Повторите проверку.");
  if (!Array.isArray(result?.report?.findings)) {
    throw new Error("Поток завершился без отчёта. Проверьте, что активная ветка ведёт к блоку «Отчёт».");
  }
  return result;
}

export async function runWorkflow(body, onNode) {
  const timeoutSeconds = 120;
  const signal = AbortSignal.timeout(timeoutSeconds * 1000);
  try {
    const response = await fetch(`${API}/workflow`, { method: "POST", body, signal });
    if (!response.ok) {
      const data = await response.json().catch(() => null);
      throw new Error(data?.error || `Сервер вернул HTTP ${response.status}. Повторите проверку.`);
    }
    return await readWorkflow(response, onNode);
  } catch (error) {
    if (signal.aborted) {
      throw new Error(`Истекло время ожидания (${timeoutSeconds} секунд). Проверьте настройки backend и повторите запуск.`, { cause: error });
    }
    if (error instanceof TypeError) {
      throw new Error("Связь с API потеряна. Проверьте подключение и повторите запуск.", { cause: error });
    }
    throw error;
  }
}

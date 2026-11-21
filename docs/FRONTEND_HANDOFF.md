# GHOST//GUARD · передача backend Владу

## Запуск и проверка версии

Из корня репозитория запустите задачу VS Code **Start app (frontend + backend)**. Она ждёт готовности API на `127.0.0.1:8000`. Задача **Start frontend** сверяет сборку с текущим рабочим деревом перед запуском статического сервера на 5173. Если порт занят другой копией, проверка завершается ошибкой. Сначала установите владельца порта и остановите прежний экземпляр проекта в терминале, из которого он запущен.

Для ручного запуска под Windows с Python 3.12+ выполните из корня проекта (создание окружения нужно один раз).

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -B -u -m backend.server
```

Во втором терминале выполните следующие команды. Последний тест сохраняет один новый QA-сценарий на встроенном учебном демо, с отключённым расписанием.

```powershell
.\.venv\Scripts\python.exe -B -m backend.version --check
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p live_backend_8000.py -v
```

Для этих двух исправлений переменные окружения и учётные данные не требуются. SQLite использует `.runtime/workflows.sqlite3` в каталоге backend-проекта. При смене версии сохраняйте этот каталог.

## Контракт API

Все пути ниже относятся к `http://127.0.0.1:8000`. Создание и обновление сценария принимают JSON. Для ZIP используйте `multipart/form-data` с JSON-полем `settings`, файлом `project` и необязательным JSON-файлом `catalog`.

| Метод и путь | Запрос | Ответ |
|---|---|---|
| GET `/api/health` | Без тела | 200, JSON с `status`, `service`, `api_version`, `build_id` |
| GET `/api/workflows` | Без тела | 200, `{"workflows":[]}` для пустого списка, иначе метаданные сценариев |
| POST `/api/workflows` | `name`, `workflow`, необязательные `source: "demo"`, `interval_seconds` | 201, сохранённый объект с `id`, графом и метаданными |
| GET / PUT `/api/workflows/{id}` | GET без тела. PUT с именем и полным графом. Если источник и интервал опущены, сохраняются текущие значения | 200, сохранённый объект |
| POST `/api/workflows/{id}/run` | Без тела | 200, поток NDJSON. Последняя строка содержит `result` или `error` |
| GET `/api/workflows/{id}/last-run` | Без тела | 200, `{"last_run":null}` до запуска, затем объект со статусом, временем, триггером и массивом `events` |
| POST `/api/workflow` | Разовый запуск, multipart с JSON-файлом `workflow`, опциональными `project` и `catalog` | 200, тот же протокол NDJSON. Для повторного открытия используйте сохранённый сценарий |

Пример ответа health. `build_id` зависит от исходников backend и анализаторов при запуске, в том числе от локальных правок. Ожидаемое значение для данной копии печатает `python -m backend.version`.

```json
{"status":"ok","service":"ghost-guard","api_version":2,"build_id":"0123456789abcdef","source_policy":"operator-sha256"}
```

Пример тела для POST или PUT. На встроенном демо Secrets находит одну проблему уровня high. При пороге `critical` будет выбран выход `false`.

```json
{
  "name": "Проверка учебного проекта",
  "interval_seconds": null,
  "workflow": {
    "nodes": [
      {"id":"start","type":"trigger"},
      {"id":"scan","type":"secrets"},
      {"id":"check","type":"condition","config":{"mode":"severity","value":"critical"}},
      {"id":"summary","type":"report"}
    ],
    "edges": [
      {"source":"start","target":"scan"},
      {"source":"scan","target":"check"},
      {"source":"check","branch":"true","target":"summary"}
    ]
  }
}
```

## Ветвление, отчёт и ошибки

Все графы, поддерживаемые текущим API, требуют хотя бы одного выполненного блока `report`. Для графа выше `summary` получит `skipped`, а последняя строка потока будет такой.

```json
{"event":"error","code":"workflow-report-unreached","error":"На активном пути нет итогового отчёта. Подключите блок «Отчёт» к выбранной ветке.","reports":[],"branches":{"check":"false"},"release_gate":{"status":"BLOCK","counts":{"critical":0,"high":1,"medium":0,"low":0},"missing_scanners":["sast","sca"],"skipped_files":0,"unresolved_versions":0}}
```

SQLite сохранит `last_run.status = "failed"` до передачи этой строки клиенту. Для исправления добавьте ребро `{"source":"check","branch":"false","target":"summary"}`, сохраните тот же граф через PUT и повторите POST `/run`. На демо ветка «Нет» теперь завершится с `status: "done"`, `reports: ["summary"]`, одной находкой в `report.findings` и одной записью в `submission.findings`. При пороге `high` тот же граф выполнит ветку «Да». Release Gate в обоих случаях выдаёт `BLOCK` по реальной находке. Статус выполнения и решение о допуске релиза показывайте отдельно.

Для сравнения, полный терминальный ответ графа `trigger → report` имеет вид

```json
{"event":"result","reports":["summary"],"branches":{},"report":{"findings":[],"skipped_files":[],"sca":{"status":"not-selected","unresolved_versions":[]}},"submission":{"findings":[]},"release_gate":{"status":"WARNING","counts":{"critical":0,"high":0,"medium":0,"low":0},"missing_scanners":["sast","sca","secrets"],"skipped_files":0,"unresolved_versions":0}}
```

Объединение в отчёте учитывает данные со всех его активных входов. При общем предке находки одного сканера учитываются один раз. При оценке Release Gate используются все выполненные сканеры этого запуска, включая находки на пути, который сам не ведёт к отчёту. Неполное покрытие даёт как минимум `WARNING`.

| Когда | Что получает клиент |
|---|---|
| Нет блока отчёта, недопустимый граф или настройки | HTTP 400, JSON с `error`. Пример: `{"error":"Добавьте блок «Отчёт»."}` |
| Неизвестный сценарий / его повторный параллельный запуск | HTTP 404 / 409, JSON с `error` |
| Запрещённый Host или Origin | HTTP 403 |
| Ошибка загрузки | HTTP 408 при таймауте, 411 при отсутствии допустимого Content-Length, 413 при превышении размера, 415 при неподдерживаемом типе тела сохранения |
| Ошибка хранилища до начала потока | HTTP 500, JSON с `error` |
| Ошибка исполнения после начала потока | HTTP уже 200. Читайте NDJSON до терминального события. Ошибка активного пути даёт `event: "error"` и сохранённый статус `failed` |

## Что учесть в интерфейсе

- **Индикатор соединения.** Для уже открытой вкладки или запуска UI вне задач VS Code Влад может дополнить проверку `/health`: требовать `service === "ghost-guard"`, `api_version === 2` и идентификатор сборки. Если поставка UI закрепляет конкретную сборку, сравнивать с ожидаемым `build_id`. При несовпадении показывать ошибку версии до отправки графа.
- **Редактор и результаты.** Типы нод, форма графа и успешного отчёта совместимы. Используйте существующий блок «Отчёт» на обоих выходах или подключите к нему оба ребра. Показывайте `skipped` у неактивных нод и `error` при отсутствии отчёта. Предыдущий отчёт при ошибке нового запуска следует убрать с экрана.
- **Последний запуск.** Отображайте сохранённые `last_run.status` и терминальное событие. При первом открытии базы обновлённым сервером старые ложные успехи с явным `report: null` получают `failed` и код ошибки. Граф, время и события выполненных нод сохраняются. Новый запуск заменяет запись последнего запуска для этого сценария.

## Webhook Notification

Добавьте в редактор тип `webhook` с одним входом и полем URL. Добавьте выход блоку «Отчёт» для связи с webhook. В графе можно подключить несколько отчётов к одному webhook. Блок достигнут, если выполнен хотя бы один связанный отчёт. Сводка создаётся после объединения всех выполненных отчётов графа, включая отчёты параллельных веток.

```json
{
  "nodes": [
    {"id":"start","type":"trigger"},
    {"id":"secrets","type":"secrets"},
    {"id":"report","type":"report"},
    {"id":"notify","type":"webhook","config":{"url":"http://127.0.0.1:8765/webhook"}}
  ],
  "edges": [
    {"source":"start","target":"secrets"},
    {"source":"secrets","target":"report"},
    {"source":"report","target":"notify"}
  ]
}
```

Сохраняйте граф в `workflow` по `POST /api/workflows` или `PUT /api/workflows/{id}`. Запускайте через `POST /api/workflows/{id}/run` или одноразовый `POST /api/workflow`. Состояния приходят в NDJSON и сохраняются в `GET /api/workflows/{id}/last-run`. Некорректный URL или связь возвращают HTTP 400 при проверке графа. Статус доставки отображайте отдельно от решения Release Gate и статуса всего графа.

| `delivery_status` | `status` ноды | Смысл |
|---|---|---|
| `PENDING` | `running` | Вход активен, ждём итоговый агрегат |
| `SENDING` | `running` | Началась отправка |
| `SENT` | `done` | Получен HTTP 2xx |
| `FAILED` | `failed` | Доставка не подтверждена. Покажите `message`, при наличии `output.http_status` и `output.attempts` |
| `NOT_CONFIGURED` | `skipped` | `config.url` отсутствует или пуст |
| `SKIPPED` | `skipped` | Вход не активен или выполнение прервалось до итогового отчёта |

```json
{"event":"node","id":"notify","status":"failed","delivery_status":"FAILED","code":"webhook-http-error","message":"Получатель webhook вернул HTTP 500.","output":{"attempts":3,"http_status":500}}
```

При сбое доставки терминальный `result` содержит отчёт, а сохранённый запуск получает `completed-with-errors`. Отказ allowlist имеет код `webhook-url-not-allowed`, закрытый адрес DNS — `webhook-address-not-public`, таймаут — `webhook-timeout`, TLS — `webhook-tls-error`, проблемы соединения — `webhook-connection-error`. Если отчёт не достигнут, сохраняется существующий `workflow-report-unreached`. В `result` при достигнутом webhook добавляются `workflow_id`, `run_id` и `report_id`. Для одноразового запуска приходит временный `workflow_id`.

### Что получит HTTP-получатель

```json
{
  "event_type":"security_scan_completed",
  "workflow_id":"12d9dc895fe542b8b40e16b655a95803",
  "run_id":"de1eee68daaa4997a1bacccb93fb0266",
  "project_name":"ghost-guard-demo",
  "timestamp":"2026-11-21T09:30:00+00:00",
  "total_findings":1,
  "severity_counts":{"critical":0,"high":1,"medium":0,"low":0},
  "release_gate_status":"BLOCK",
  "findings_summary":[{"scanner":"secrets","severity":"high","count":1}],
  "report_id":"81a0dae772a349a784ecce5ac6155881"
}
```

Для загруженного учебного проекта `project_name` равно `training-zip`. Имя файла и пользовательское имя сценария остаются вне сводки. Сводка содержит только числа по сканерам и уровням. `release_gate_status` совпадает с итоговым решением для всего запуска. Повторные попытки используют тот же `report_id`, чтобы получатель мог отфильтровать повторную доставку. Повторный запуск графа получает новый ID.

### Локальная демонстрация

В отдельном терминале из корня репозитория запустите получатель, который печатает принятый JSON и подтверждает его HTTP 200.

```powershell
.\.venv\Scripts\python.exe -B -u -m backend.webhook_receiver
```

Во втором терминале задайте точный разрешённый URL и запустите backend. Запущенный ранее backend нужно перезапустить, чтобы он получил эту настройку.

```powershell
$env:GHOST_WEBHOOK_LOCAL_URL = 'http://127.0.0.1:8765/webhook'
.\.venv\Scripts\python.exe -B -u -m backend.server
```

Для полного прогона укажите в окружении backend `GHOST_LLM_BASE_URL` и `GHOST_LLM_MODEL` для уже работающей локальной Qwen, например `http://127.0.0.1:18080/v1` и имя модели, с которым запущен сервер. Передайте разрешённые учебный ZIP и каталог. Соберите граф `trigger → secrets → sca → sast → llm → report → webhook`. После запуска сверьте `run_id`, `report_id`, число находок и решение Gate с JSON в консоли получателя.

При пустом окружении отправка не разрешена. Для внешнего получателя выберите HTTPS и задайте точные URL через пробел в `GHOST_WEBHOOK_ALLOWED_URLS`. Внешний домен разрешается в публичный адрес, TLS проверяет сертификат для исходного имени. URL должен быть без учётных данных, параметров запроса, фрагментов и секретов в пути. HTTP redirects отключены. Используются таймауты соединения и чтения, максимум три попытки при временных сетевых сбоях и HTTP 408, 429, 500, 502, 503 или 504.

## Допуск учебных проектов

Встроенное демо готово к запуску. Для нового учебного проекта оператор получает ZIP из согласованного источника и запускает команду из того же checkout, из которого запущен backend. Загрузите через интерфейс тот же файл после выполнения команды.

```powershell
$archiveSha256 = & .\.venv\Scripts\python.exe -B -m backend.source_policy approve 'C:\training\evaluation.zip'
$archiveSha256
```

Команда печатает SHA‑256 и создаёт локальную запись в `.runtime/approved-sources`. Backend перечитывает допуск при сохранении ZIP и каждом запуске. Перезапуск после добавления не нужен. Перепаковка или изменение файлов даёт другой SHA‑256, поэтому изменённый учебный ZIP нужно допустить отдельно. Храните каталог разрешений с правом записи только у оператора и учётной записи backend. Для отзыва используйте напечатанный SHA‑256.

```powershell
.\.venv\Scripts\python.exe -B -m backend.source_policy revoke $archiveSha256
```

Операторский доступ нужен и для локального CLI. `scan.py` принимает каталог встроенного демо или разрешённый ZIP с теми же параметрами `--catalog` и `--submission`. Для проверки выданной папки сначала упакуйте её в ZIP и допустите его. Сервер не скачивает исходники по URL. Одобрение выполняется локально, API для выдачи разрешений отсутствует.

| Операция | Ответ при отказе |
|---|---|
| `POST /api/scans`, `POST /api/workflow`, `POST /api/workflows`, `PUT /api/workflows/{id}` | HTTP 403 и JSON с `code: "source-not-approved"`. Если каталог политики недоступен, HTTP 503 и `code: "source-policy-unavailable"`. |
| `POST /api/workflows/{id}/run` | HTTP 200 и терминальное событие NDJSON с `event: "error"` и тем же кодом. Обработка завершится до запуска нод. |
| Запланированный запуск и `GET /api/workflows/{id}/last-run` | Запуск получает статус `failed`. Последняя строка `events` содержит код отказа, а `last_run.last_report` при наличии хранит терминальный результат последнего сформированного отчёта. |

```json
{"event":"error","code":"source-not-approved","error":"Этот ZIP не разрешён. Попросите оператора допустить точный учебный архив."}
```

В форме загрузки показывайте сообщение об отказе с инструкцией обратиться к оператору. При отказе повторного запуска показывайте текущую ошибку и отдельно доступный предыдущий отчёт из `last_report`. Запуск через задачи VS Code уже проверяет идентичность сборки. При прямом старте UI сверяйте `service`, `api_version`, `source_policy` и ожидаемый `build_id` из `python -m backend.version`. Переход между версиями не меняет формат графа или webhook.

## AI-сводка отчёта

Маршруты и формат графа прежние. Добавьте блок `llm` в активный путь между сканерами и «Отчётом». Запрашивайте поток через `POST /api/workflow` или `POST /api/workflows/{id}/run`. Терминальный `result.report` и сохранённый результат из `GET /api/workflows/{id}/last-run` могут содержать `ai_summary`. Поля `findings`, `explanations`, `submission` и отдельное решение `release_gate` остаются прежними. Webhook по-прежнему передаёт только данные отчёта по своей схеме.

```json
{
  "status":"ready",
  "risk_overview":"Наиболее высокий подтверждённый уровень риска — CRITICAL.",
  "total_findings":15,
  "severity_counts":{"critical":1,"high":7,"medium":6,"low":1},
  "categories":[{"scanner":"sast","count":5},{"scanner":"sca","count":5},{"scanner":"secrets","count":5}],
  "recommendation_source":"scanners",
  "priority_findings":[
    {"finding_id":"SCA-F0001","scanner":"sca","severity":"critical","file":"build.gradle.kts","line":31,
     "title":"Версия зависимости входит в уязвимый диапазон","priority":"immediate",
     "recommendation":"Обновите зависимость до исправленной версии. Исправленные версии по справочнику: 1.10.0.",
     "selected_by_ai":true,"advisoryId":"CVE-2022-42889"}
  ],
  "release_gate":{"status":"BLOCK","explanation":"В выполненных проверках есть находки уровня HIGH или CRITICAL."},
  "coverage":{"explained":15,"total":15},
  "generation_ms":14684,
  "warnings":[]
}
```

В примере оставлена одна строка из списка приоритетов. Полный ответ содержит до трёх. Backend считает категории и уровни по итоговому отчёту. Он ставит уровень риска выше порядка, предложенного моделью, и подставляет `file`, `line`, опциональные `endLine` и `advisoryId` из найденного сканером результата. `priority` принимает `immediate`, `before-release`, `next-iteration` или `backlog`. Выбор модели отмечен `selected_by_ai`. Текст `recommendation` здесь относится к сканеру. Свободные пояснения и советы Qwen находятся в `report.explanations`. Отображайте их как рекомендации AI.

| `ai_summary.status` | Что отображать |
|---|---|
| `ready` | Все находки в отчёте объяснены, приоритеты модели проверены |
| `partial` | Сводка построена из всех находок. AI обработал часть отчёта или предложил неполный список приоритетов. Покажите `coverage` и `warnings` |
| `unavailable` | Сканирование и Release Gate завершились. Покажите исходные находки и известную ошибку AI |
| `no-findings` | В отчёте нет подтверждённых находок. Для пустого входа модель не вызывается |

Пока LLM-нода в состоянии `running`, показывайте загрузку. При завершении в `output.ai` доступны `priority_ids`, `generation_ms` и `summary_code`. Ошибки содержат прежнее поле `code` ноды, например `llm-not-configured`, `llm-timeout`, `llm-busy`, `llm-provider-error` или `llm-invalid-response`. `llm-summary-incomplete` сохраняет валидные пояснения. При пропущенной ветке с AI поле сводки не появляется, если ни одна другая AI-нода не дошла до отчёта.

За один запрос отправляется до 20 находок с приоритетом более высокой критичности. Итоговая сводка при этом учитывает все находки активных отчётов. `generation_ms` измеряет совместный запрос объяснений и выбора приоритетов без времени запуска модели. Для нескольких AI-нод суммируется время запросов, данные которых дошли до отчёта.

На запрос генерации отводятся 60 секунд, до 2200 токенов ответа и до 64 КиБ тела HTTP. В провайдер уходят только выбранные метаданные сканеров. Исходники, значения секретов, пользовательские пути и строки остаются на сервере. Свободный текст с идентификаторами, числами или ссылками отклоняется, ссылки на подтверждённые находки приходят в отдельных полях.

## Диагностика локальной Qwen

| Метод и путь | Что возвращает |
|---|---|
| GET `/api/llm/status` | HTTP 200, состояние управляемой локальной Qwen. Запрос не запускает модель |
| POST `/api/llm/probe`, без тела | HTTP 200, состояние и `sample` с пояснением синтетической находки Secrets. Запускает локальный процесс при необходимости |
| POST при параллельном probe | HTTP 409 и `code: "llm-probe-busy"` |
| POST при недоступной модели или ошибке генерации | HTTP 503, `code`, `error` и текущая диагностика |

```json
{"model":"Qwen2.5-1.5B-Instruct","provider":"local","engine":"llama.cpp","engine_version":"b12248","mode":"managed","installed":true,"ready":true,"last_probe":{"status":"ok","generation_ms":1642,"checked_at":"2026-11-21T12:21:45+00:00"}}
```

`mode` принимает `managed`, `disabled` или `configured-provider`. В последних двух режимах probe управляемой модели недоступен. `installed: true` означает, что файлы присутствуют. `ready: true` означает, что проверенный локальный процесс загрузил модель и продолжает работать. `last_probe` относится только к явно запрошенной диагностике и сбрасывается при перезапуске backend. Возможные значения `status` — `not-run`, `ok`, `failed`.

Для индикатора используйте GET. Вызывайте POST по кнопке проверки модели. При `installed: true` и `ready: false` покажите, что Qwen запустится при первом запросе. Во время probe покажите ожидание, затем время генерации либо безопасное поле `error`. Поля `sample.explanation` и `sample.recommendation` относятся к синтетическому примеру. [Установка локальной Qwen](./LOCAL_LLM_SETUP.md)

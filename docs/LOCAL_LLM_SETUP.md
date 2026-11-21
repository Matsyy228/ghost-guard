# Локальная Qwen в GHOST//GUARD

Qwen2.5-1.5B-Instruct объясняет находки GHOST//GUARD. `GGUF` содержит веса модели. `llama.cpp` загружает эти веса и отвечает на локальные запросы backend. Secrets, SCA, SAST и Release Gate работают отдельно от модели.

## Установка на Windows x64

Понадобятся Python 3.12+, PowerShell 5.1 или 7 и примерно 3 ГБ свободного места. Для комфортного запуска с браузером ориентируйтесь на 8 ГБ оперативной памяти. Это практический ориентир, а не измеренный минимум. Видеокарта ускоряет работу, поддерживается режим CPU. На AVX-совместимом ПК скрипт использует закреплённую сборку Windows x64 с Vulkan.

Из терминала PowerShell выполните:

```powershell
git clone --branch codex/sasha-llm https://github.com/Matsyy228/ghost-guard.git
Set-Location ghost-guard
py -3 -m venv .venv
.\scripts\setup-local-llm.ps1
.\.venv\Scripts\python.exe -B -u -m backend.server
```

При наличии проверенных файлов установщик переиспользует их. Первая установка без кэша скачивает два закреплённых артефакта и проверяет размер и SHA-256. Backend повторно проверяет модель, архив движка и файлы движка перед первым запуском локального процесса.

Если рабочая политика Windows запрещает запуск `.ps1`, используйте тот же установщик напрямую без изменения политики:

```powershell
.\.venv\Scripts\python.exe -B -m backend.local_llm_assets
```

Для установки из локальной папки добавьте `--offline --from-cache 'D:\ghost-cache'`.

| Артефакт в `.runtime/llm/` | Байт | SHA-256 |
|---|---:|---|
| `qwen2.5-1.5b-instruct-q4_k_m.gguf` | 1 117 320 736 | `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` |
| `llama-b12248-bin-win-vulkan-x64.zip` | 37 891 595 | `3745e446c88e18cf20fd52f9df62867beb60d12fd0208c130fb4663117425826` |

Установщик берёт GGUF со страницы Qwen на ревизии `91cad51170dc346986eccefdc2dd33a9da36ead9`, а движок — из релиза `ggml-org/llama.cpp` с тегом `b12248`. Запускаемый файл лежит в `.runtime/llm/llama-b12248/llama-server.exe`. [Закреплённый GGUF](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/blob/91cad51170dc346986eccefdc2dd33a9da36ead9/qwen2.5-1.5b-instruct-q4_k_m.gguf) · [Релиз llama.cpp](https://github.com/ggml-org/llama.cpp/releases/tag/b12248)

## Как убедиться, что отвечает настоящая модель

Backend запускает llama.cpp при первом активном LLM-блоке или диагностическом запросе. Он ждёт успешного ответа `/health` и проверяет зарегистрированную модель через `/v1/models`. Затем запросы идут в `/v1/chat/completions` через loopback на динамическом порту. Случайный ключ передаётся только в окружении дочернего процесса. Остановка backend завершает запущенный им процесс модели.

Во втором терминале выполните:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/llm/status
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/llm/probe
```

Первый запрос читает статус. Второй посылает Qwen синтетическую находку Secrets и проверяет ответ тем же валидатором, что и workflow. Успешный результат содержит `ready: true`, `last_probe.status: ok`, время генерации и `sample.explanation`. Для демо запустите граф со сканерами, блоком LLM и отчётом. Подтверждённые пояснения доступны в `report.explanations`.

По умолчанию дополнительные переменные не нужны. При проблемах с драйвером Vulkan установите `$env:GHOST_LLM_CPU_ONLY = '1'` перед стартом backend. Для работы без AI установите `$env:GHOST_LLM_DISABLED = '1'`. Для сохранения прежней схемы с уже запущенным OpenAI-совместимым провайдером задайте `GHOST_LLM_BASE_URL`, `GHOST_LLM_MODEL` и при необходимости `GHOST_LLM_API_KEY`. В этом режиме диагностический probe управляемой Qwen не вызывает настроенный провайдер.

## Без интернета и при ошибках

- Если интернет недоступен при первой установке, перенесите два исходных файла из таблицы в локальную папку на другом ПК. Из нового checkout выполните `.\scripts\setup-local-llm.ps1 -Offline -FromCache 'D:\ghost-cache'`. Скрипт сверит файлы по тем же значениям SHA-256.
- Если файлы уже установлены, `.\scripts\setup-local-llm.ps1 -Offline` проверит установку повторно. Запуск backend и запросы к локальной Qwen не требуют интернета.
- При сбое загрузки повторите команду на рабочем соединении или используйте проверенный кэш. При несовпадении SHA-256 скачайте оригинал заново. Установщик удаляет недокачанный временный файл и сохраняет предыдущий файл до успешной проверки нового.
- При ошибке запуска выполните probe в режиме CPU. Проверьте доступную память и установку Python x64. При отключённой или недоступной модели отчёт содержит исходные результаты сканеров.

## Варианты распространения

**A. Исходники и установщик в GitHub.** Рекомендуемый способ. После клонирования новый участник запускает команды из первого раздела и получает официальные закреплённые файлы. Обычный Git хранит исходники и параметры проверки. `.runtime/`, GGUF и архивы движка исключены через `.gitignore`.

**B. Веса размещены на GitHub.** Новый участник может скачать опубликованный GGUF и подать его в `-FromCache`. Для офлайн-установки в той же папке нужен закреплённый ZIP движка. Вариант требует согласования публикации с владельцем репозитория. Карточка Qwen указывает Apache‑2.0. При перераспространении оригинала приложите текст лицензии, сохраните атрибуцию и включите файл NOTICE, если он предоставлен правообладателем. [Карточка GGUF](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF) · [Лицензия Qwen](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct/blob/main/LICENSE)

**GitHub Release.** Создайте черновик релиза с тегом от проверенного коммита. Прикрепите оригинальный `qwen2.5-1.5b-instruct-q4_k_m.gguf` отдельным asset, добавьте лицензию и опубликуйте в описании ссылку на источник, ревизию, размер и SHA-256 из таблицы. Скачайте asset из черновика для контрольной сверки до публикации. Размер 1 117 320 736 байт укладывается в лимит GitHub Release меньше 2 GiB на файл. Участник скачивает asset из релиза и указывает папку как `-FromCache`. [Лимиты GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)

**Git LFS.** Создайте отдельную рабочую ветку. Установите Git LFS, выполните `git lfs install` и `git lfs track "distribution/qwen/qwen2.5-1.5b-instruct-q4_k_m.gguf"`. Добавьте точное исключение `!/distribution/qwen/qwen2.5-1.5b-instruct-q4_k_m.gguf` после правил GGUF в `.gitignore` и скопируйте туда проверенные веса. Подтвердите `filter: lfs` через `git check-attr filter -- distribution/qwen/qwen2.5-1.5b-instruct-q4_k_m.gguf`. После добавления файла в индекс команда `git cat-file -s :distribution/qwen/qwen2.5-1.5b-instruct-q4_k_m.gguf` должна показать размер указателя меньше 1 КиБ. Сверьте его строку `oid sha256` с таблицей и выполните `git lfs fsck`. Добавьте лицензию и `.gitattributes` перед публикацией ветки. Участник после клонирования выполняет `git lfs pull` и подаёт папку `distribution/qwen` в установщик. Размер файла укладывается в лимит 2 GB на файл для Free и Pro. Перед публикацией проверьте остаток квот хранения и трафика аккаунта. [Лимиты Git LFS](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-git-large-file-storage) · [Квоты и оплата](https://docs.github.com/en/billing/concepts/product-billing/git-lfs)

# Проверка GHOST//GUARD на официальном наборе «Центр-инвест»

**Результат на открытом учебном наборе — 15 из 15 находок, Precision 100%, Recall 100%.** Сошлись все файлы, строки и уровни критичности. Ни один из шести безопасных примеров организаторов не попал в отчёт. Проверка проведена 20 ноября 2026 года на коммите `fe1fcbe212669783480666b9b60147c8a8c6eef4`. [Репозиторий организаторов](https://github.com/TBagirov/training/tree/fe1fcbe212669783480666b9b60147c8a8c6eef4)

Данные для сдачи — [единый JSON с 15 находками](./TEST_FINDINGS.json). Проверка была статической, код Repair Desk и Gradle не запускались. Находки получены собственными анализаторами GHOST//GUARD. Эталон применялся для сверки после сканирования.

## Состав учебного набора

В Git зафиксировано 38 файлов, из них 29 относятся к приложению Repair Desk. Ключевые технологии видны в Gradle и конфигурации: Kotlin 2.2.21, Spring Boot 4.0.9, Spring MVC, Spring Security, Spring JDBC, H2 in-memory, JVM 21 и Gradle 8.14.6 с Kotlin DSL. [Сборка и файлы проекта](https://github.com/TBagirov/training/tree/fe1fcbe212669783480666b9b60147c8a8c6eef4/training-project)

| Каталог относительно корня репозитория | Файлы |
| --- | --- |
| Корень | `README.md` |
| `docs/` | `submission-format.md`, `training-result-example.json` |
| `ground-truth/` | `README.md`, `training-findings.json`, `training-findings.md` |
| `vulnerability-database/` | `README.md`, `schema.json`, `vulnerabilities.json` |
| `training-project/` | `.gitignore`, `README.md`, `build.gradle.kts`, `gradle.lockfile`, `gradle.properties`, `gradlew`, `gradlew.bat`, `settings.gradle.kts`, `gradle/wrapper/gradle-wrapper.jar`, `gradle/wrapper/gradle-wrapper.properties` |
| `training-project/src/main/kotlin/lab/repairdesk/` | `RepairDeskApplication.kt`, `catalog/ServiceCatalogController.kt`, `config/RepairAccounts.kt`, `config/RepairCors.kt`, `config/RepairSecurity.kt`, `integration/DepotStatusClient.kt`, `integration/LegacyIntake.kt`, `integration/ManualsHttpsClient.kt`, `integration/PartsImportSettings.kt`, `integration/QuoteRequest.kt`, `integration/SupplierHttpsClient.kt`, `integration/WarrantyHeaders.kt`, `pickup/PickupExportController.kt`, `repair/RepairLookupController.kt`, `repair/RepairTicketController.kt`, `repair/RepairTicketReader.kt` |
| `training-project/src/main/resources/` | `application.yml`, `data.sql`, `schema.sql` |

Официальный [справочник Maven](https://github.com/TBagirov/training/blob/fe1fcbe212669783480666b9b60147c8a8c6eef4/vulnerability-database/vulnerabilities.json) содержит 41 запись. [Эталон](https://github.com/TBagirov/training/blob/fe1fcbe212669783480666b9b60147c8a8c6eef4/ground-truth/training-findings.json) содержит 15 находок и 6 отрицательных проверок. [Формат сдачи](https://github.com/TBagirov/training/blob/fe1fcbe212669783480666b9b60147c8a8c6eef4/docs/submission-format.md) определяет ключи и допустимые значения для JSON.

## Первый прогон

Исходный сканер нашёл `PartsImportSettings.kt:4` и `QuoteRequest.kt:7` как `hardcoded-secret`. Сопоставление с кодом и эталоном подтвердило пароль и API-ключ. Для ключа сканер выдал `HIGH`, а в эталоне стоит `MEDIUM`. Пароль был найден по правильной строке, но его общий класс не совпал с `password` и допустимыми псевдонимами. SAST вернул ноль находок. При передаче официального каталога CLI завершался с кодом `2`, поскольку ждал массив в корне JSON. Отчёт первого прогона сформирован отдельным запуском с отсутствующим каталогом, поэтому SCA в нём пропущен.

## Подтверждённые находки после правок

Пути указаны от корня `training-project/`. В таблицах Kotlin путям добавляется `src/main/kotlin/lab/repairdesk/`.

### Secrets

| Эталон | Класс | Файл и строка | Уровень | Основание |
| --- | --- | --- | --- | --- |
| A-SEC-01 | `password` | `integration/PartsImportSettings.kt:4` | HIGH | Пароль импорта задан литералом. Переменная используется для заголовка импорта |
| A-SEC-02 | `api-key` | `integration/QuoteRequest.kt:7` | MEDIUM | Строковый литерал используется как ключ для запроса прайса |
| A-SEC-03 | `configuration-token` | `src/main/resources/application.yml:13` | HIGH | В свойстве авторизации обратного вызова присутствует литеральный Bearer-токен |
| A-SEC-04 | `secret-fallback` | `integration/DepotStatusClient.kt:8` | LOW | Для переменной окружения токена статуса задан строковый запасной вариант |
| A-SEC-05 | `recoverable-token` | `integration/WarrantyHeaders.kt:7–10` | MEDIUM | Оба фрагмента токена определены локально и соединяются перед передачей в заголовок |

Значения секретов не входят ни в таблицы, ни в JSON. Устранение сводится к вынесению литералов и запасных значений в окружение или хранилище и замене действующих секретов.

### SCA

Все пять версий сверены с `gradle.lockfile` и диапазонами официального справочника. Строка указывает на объявление в `build.gradle.kts`.

| Эталон | Строка | Координаты и версия | Уровень | Подтверждение диапазона |
| --- | --- | --- | --- | --- |
| A-SCA-01 | 31 | `org.apache.commons:commons-text:1.9` | CRITICAL | `CVE-2022-42889`, `[1.5, 1.10.0)` |
| A-SCA-02 | 32 | `org.jsoup:jsoup:1.14.1` | HIGH | `CVE-2021-37714`, версии ниже `1.14.2` |
| A-SCA-03 | 33 | `org.apache.commons:commons-compress:1.25.0` | MEDIUM | `CVE-2024-25710`, `[1.3, 1.26.0)`. В объявлении используется локальная переменная |
| A-SCA-04 | 36 | `commons-net:commons-net:3.8.0` | MEDIUM | `CVE-2021-37533`, версии ниже `3.9.0`. Объявление использует многострочный `add` |
| A-SCA-05 | 38 | `org.json:json:20230227` | HIGH | `CVE-2023-5072`, версии до `20230618` включительно. Версия объявлена через `gradle.properties` |

### SAST

| Эталон | Класс | Файл и строка | Уровень | Статическое основание |
| --- | --- | --- | --- | --- |
| A-SAST-01 | `sql-injection` | `repair/RepairLookupController.kt:13–14` | HIGH | Значение параметра запроса входит в текст SQL, переданный JDBC. Соседний безопасный пример передаёт значение отдельно |
| A-SAST-02 | `tls-verification` | `integration/SupplierHttpsClient.kt:13` | MEDIUM | Пользовательский `HostnameVerifier` безусловно принимает имя хоста |
| A-SAST-03 | `credentialed-cors` | `config/RepairCors.kt:13–14` | MEDIUM | Одна конфигурация одновременно принимает любой origin и разрешает учётные данные |
| A-SAST-04 | `route-authorization` | `config/RepairSecurity.kt:18` | HIGH | Публичное правило для точного маршрута стоит перед ограничением роли на префикс этого маршрута |
| A-SAST-05 | `object-authorization` | `repair/RepairTicketReader.kt:10–11` | HIGH | Контроллер передаёт идентификатор в чтение записи. Запрос возвращает данные о владельце, но отбор по владельцу отсутствует |

## Точность и пропуски

Сопоставление делалось один к одному. Для Secrets и SAST использованы категория, путь, класс или разрешённый псевдоним и пересечение строк с эталоном. Для SCA использованы путь, координаты, версия и `advisoryId`; строка проверена дополнительно. Все 15 итоговых путей и диапазонов совпали точно. Критичность сверена отдельно и совпала у 15 из 15 находок.

| Прогон | TP | FP | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Исходный, по смыслу и месту | 2 | 0 | 13 | 100% | 13,33% |
| Исходный, строго по формату организаторов | 1 | 1 | 14 | 50% | 6,67% |
| Итоговый, строго по формату организаторов | 15 | 0 | 0 | 100% | 100% |

`Precision = TP / (TP + FP)`, `Recall = TP / (TP + FN)`. Строгий `FP` исходного прогона — существующая находка с неподходящим классом, поэтому та же позиция считается `FN` для класса `password`. Реального срабатывания на безопасный участок в исходном прогоне не было. Исходный результат по месту пропускал три Secrets и все десять SCA/SAST. Итог по категориям — `5/5` в каждой.

**Безопасные контроли — 0 из 6 срабатываний.** Проверены документационный placeholder, токен из переменной окружения, исправленная версия `commons-lang3`, параметризованный SQL, публичный каталог услуг и штатная проверка TLS. Три тестовые зависимости на строках 41–43 `build.gradle.kts` остались без разрешённой версии в статических данных. Сканер показал их в `unresolved_versions`. В эталон они не входят, а файлов с ошибками чтения нет.

## Что изменилось в анализаторах

- **Secrets** учитывает роль переменной, окружение и запасные литералы, заголовки с токенами и простое объединение строк в локальной области. Комментарии, ссылки на окружение и маркеры подстановки отфильтровываются.
- **SCA** читает официальный контейнер `vulnerabilities` и старый демоформат. Разбирает объявления Gradle по блоку зависимостей, учитывает свойства и отдаёт приоритет lockfile. Обе границы диапазона обрабатываются по флагам включения. Повторные идентификаторы одной записи объединяются.
- **SAST** смотрит на контекст Spring и JDBC. Для проверки доступа к объекту связывает параметр контроллера с типизированным получателем и запросом. Для CORS проверяет, что wildcard и credentials принадлежат одной конфигурации.

Правила не используют имена файлов или метки эталона. Дополнительные тесты меняют имена полей и классов, проверяют безопасные соседние конструкции, комментарии, включённую границу версии и приоритет lockfile. Результат измерен на открытом наборе, по которому дорабатывались правила. Скрытая вариация не проверялась. Сканирование остаётся эвристическим и не строит полный семантический граф Kotlin или транзитивных зависимостей Gradle.

## Проверка через GHOST//GUARD

| Шаг | Фактический результат |
| --- | --- |
| Официальный ZIP и каталог в Edge | Загрузка успешна. Secrets, SCA и SAST завершились, все 15 находок совпали с CLI |
| Условие и отчёт | Порог `high` выбрал ветку **Да**. Сравнение по `CVE-2025-48924` из безопасного контроля выбрало **Нет**. В отчёте обеих веток сохранились те же 15 находок |
| Отображение результата | Критический фильтр оставил одну находку. Встроенное демо по-прежнему возвращает три |
| AI и уведомление | В текущем редакторе и исполнителе этих нод нет. Запрос к LLM и доставка в Telegram не проверены, сквозное подтверждение заканчивается на отчёте |
| Локальная копия организаторов | `git status --porcelain` пустой. Приложение и тесты Kotlin не запускались |

## Как повторить статическую проверку

Из корня GHOST//GUARD, где локальная копия лежит в `.runtime/organizers-training`:

```powershell
.\.venv\Scripts\python.exe -B .\scan.py .\.runtime\organizers-training\training-project --catalog .\.runtime\organizers-training\vulnerability-database\vulnerabilities.json --submission
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Для проверки интерфейса запустите приложение по [README](./README.md). В режиме **Мой ZIP** выберите `.runtime/organizers-project.zip` с содержимым `training-project/` от корня архива и передайте `vulnerabilities.json` отдельно в поле справочника. CLI можно запускать без `--submission`, чтобы увидеть служебные поля, строки SCA и неразрешённые версии.

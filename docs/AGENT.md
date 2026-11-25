# Инструкция для агента: раскатить DataVault на рабочую машину

Документ для AI-агента (Claude Code или аналог), которому поручили поставить DataVault на
машину инженера. Человек, поставивший задачу, работает с данными заказчиков и не хочет, чтобы
они попадали в облачную модель. Модуль он может не знать. Работай по шагам. Каждый шаг
заканчивается проверкой, без неё к следующему не переходи. Схема шагов:
[diagrams/09-rollout.png](diagrams/09-rollout.png).

## Что ставим

DataVault - локальный слой между облачным агентом и данными. Агент получает доступ к данным
через MCP-сервер `datavault` и видит только id, типы, агрегаты и handles `[[DV:TYPE:id]]`.
Сырые значения читают локальные модели (LM Studio / Ollama) на этой же машине. Реальные
значения появляются только в файлах `~/DataVault/cases/<case>/out/`, их открывает человек.

Четыре точки контроля ([diagrams/08-control-points.png](diagrams/08-control-points.png)):

| Точка | Механизм | Что делает |
|---|---|---|
| Промпт человека | hook `UserPromptSubmit` -> `datavault hook-prompt` | блокирует секреты и значения дел, показывает замаскированную копию |
| Файл на диске | hook `PreToolUse` (Read\|Bash) -> `datavault hook-file` | отказывает в чтении xlsx/csv/docx/pdf/eml, заводит дело и ингестирует его в фоне |
| Ответы vault | output guard в MCP-сервере | sweep известных значений, DLP, только слова корпуса |
| Ловушки в данных | детектор инъекций | метит чанки `[[DV:WARN:...]]`, не пускает их в `extract` |

Плюс `permissions.deny` на `~/DataVault/**`, чтобы агент не читал хранилище в обход MCP.

Чего DataVault НЕ делает: не защищает от злонамеренного владельца машины, не видит вложенные
картинки и промпты в других клиентах (claude.ai, API). Bash-deny сравнивает строку команды,
поэтому защищает от случайного чтения, а не от намеренного обхода.

## Шаг 0. Разведка

Выясни и выпиши человеку одним сообщением:

- **ОС и железо.** Проверено только на macOS, Apple Silicon. Маршруты по умолчанию
  (`src/datavault/models.yaml`) рассчитаны на 24 GB unified memory. При 16 GB нужны модели
  легче (шаг 2). Linux не проверялся: всё, кроме проверки FileVault в `harden`, должно
  работать, но скажи об этом человеку заранее.
- **Python 3.12+** (`python3.12 --version` или `uv`).
- **Локальные модели.** Стоят ли LM Studio (`lms`, порт 1234) и/или Ollama (порт 11434),
  какие модели уже скачаны (`lms ls`, `ollama list`), свободно ли место (~30 GB для набора по
  умолчанию).
- **Где лежат данные заказчиков** (папка документов, выгрузки) и **в каких папках обычно
  работает агент**. `~/DataVault` должен быть вне всех рабочих директорий агента.
- **Текущий `~/.claude/settings.json`.** Есть ли уже hooks на `UserPromptSubmit` и
  `PreToolUse`, есть ли `permissions.deny`. Их нельзя затирать, только дополнять.
- **iCloud Drive.** Синхронизируются ли `~/Documents` или `~/Desktop`. Если да, venv туда не
  класть: iCloud помечает `.pth` скрытыми, и editable-установка ломается.

Не начинай установку, пока человек не подтвердил путь для данных и не согласился на правку
`settings.json`.

## Шаг 1. Установка и самопроверка

```bash
git clone https://github.com/igrbtn/datavault-kit.git ~/src/datavault-kit
cd ~/src/datavault-kit
python3.12 -m venv ~/.venvs/datavault
~/.venvs/datavault/bin/pip install ".[dev]"     # не editable (-e): см. iCloud выше
~/.venvs/datavault/bin/python -m pytest -q      # 145 passed, без моделей и сети
~/.venvs/datavault/bin/ruff check src tests scripts
```

Дальше `DV=~/.venvs/datavault/bin/datavault`. Проверка: тесты зелёные, `$DV -h` печатает
список команд.

## Шаг 2. Локальные модели

Маршруты по задачам и запасные модели заданы в `src/datavault/models.yaml`:

| Маршрут | По умолчанию | Запасная |
|---|---|---|
| `ner` | `lmstudio:qwen/qwen3-4b-2507` | `lmstudio:liquid/lfm2.5-1.2b` |
| `extract` | `lmstudio:liquid/lfm2-24b-a2b` | `ollama:qwen2.5:7b` |
| `classify` | `lmstudio:qwen/qwen3-4b-2507` | `lmstudio:microsoft/phi-4` |
| `heavy` (аудит) | `lmstudio:qwen/qwen3.8-27b` | нет |
| embeddings | `lmstudio:text-embedding-bge-m3` | `ollama:nomic-embed-text:latest` |

1. Скачай модели (`lms get <id>`, `ollama pull <id>`). Минимум для работы - `ner`,
   `extract` и embeddings. `heavy` нужен только для `datavault audit`.
2. Если RAM меньше 24 GB или моделей нет, скопируй `models.yaml` в `~/DataVault/models.yaml`
   и поставь то, что влезает. Человеку скажи, что поменял.
3. LM Studio: сервер только на `127.0.0.1`. Ollama: "Expose to the network" выключен,
   облачные модели (`*-cloud`) не использовать. Gateway их отклоняет сам, но проверь.
4. Проверка:

```bash
$DV check     # providers up, cloud_models 0, у каждого маршрута хотя бы одна available
```

Если маршрут недоступен, вернись к пунктам 1-2. Без рабочих `ner` и `extract` дальше не идти.

## Шаг 3. Подключение к Claude Code

1. **MCP-сервер** (для всех проектов пользователя):

```bash
claude mcp add --scope user datavault -- "$DV" serve
claude mcp list            # datavault: connected
```

2. **Hooks и deny-правила.** Готовый фрагмент лежит в
   [../examples/claude-settings.json](../examples/claude-settings.json). Подставь
   `DATAVAULT_BIN` (абсолютный путь к `datavault`) и `HOME_ABS` (абсолютный путь домашней
   папки). Затем **дополни** `~/.claude/settings.json`: добавь элементы в существующие массивы
   `permissions.deny`, `hooks.UserPromptSubmit`, `hooks.PreToolUse`, ничего не удаляй.
   Сначала сделай резервную копию файла, потом покажи человеку diff и дождись согласия.
3. **Политика guards.** Скопируй [../examples/promptguard.yaml](../examples/promptguard.yaml)
   в `~/DataVault/promptguard.yaml`. В `allow` впиши только то, что человек назовёт сам
   (лабораторные подсети, тестовые домены), пример из файла убери. Без файла действуют те же
   значения по умолчанию.
4. **Strict mode** (`/vault on` в промпте) закрывает чтение всех некодовых файлов под cwd.
   Если у человека есть постоянная папка с документами заказчиков, добавь её в
   `DATAVAULT_STRICT_ROOTS` (несколько через `:`), в `env` в `settings.json`.

Проверка: в **новой** сессии Claude Code видны tools `mcp__datavault__*`, вызов `cases`
возвращает пустой список без ошибок.

## Шаг 4. Hardening

```bash
$DV harden                 # отчёт: права ~/DataVault, FileVault, оба hook, логи LM Studio
$DV harden --tighten       # 700 на каталоги, 600 на файлы
```

- FileVault должен быть `on`. Если нет, скажи человеку. Включает он сам, ты этого не делаешь.
- LM Studio пишет сырые промпты (куски данных при NER и extract) в `~/.lmstudio/server-logs`.
  Предложи выключить логирование сервера в LM Studio. Если человек согласится, после
  каждого дела запускать `$DV harden --clean-lmstudio-logs`.
- SQLite хранилища не шифруется осознанно: sweeper ищет значения в тексте. Защита покоя -
  FileVault плюс права.

Проверка: в `harden` `home_mode` 0o700, `loose_permissions` пуст, `hooks.prompt_guard` и
`hooks.file_guard` true, `filevault` on.

## Шаг 5. Приёмка

Все пункты на синтетике, данные заказчика пока не трогать.

1. **Детекция и утечки** на публичных синтетических данных dlptest.com (фикстуры в репо):

```bash
DATAVAULT_HOME=$(mktemp -d) ~/.venvs/datavault/bin/python scripts/dlptest_bench.py
```

   Ожидаемо: `recall_hard=1.0 recall_all=1.0 leaks=0 unrelated={}` (несколько минут). С `--no-llm`
   recall около 0.86: имена ловит только LLM, значит модели не работают.

2. **Prompt guard:**

```bash
$DV hook-prompt --text "$(head -3 tests/fixtures/dlptest/dlptest-name-ssn-ccn.csv)"
```

   Ожидаемо: `"decision": "block"`, `found` = `DLP: BANK x2, ID x2`, в `masked` номера карт и
   SSN заменены плейсхолдерами.

3. **File guard:** скопируй фикстуру во временную папку вне репо
   (`mkdir -p /tmp/dv-accept && cp tests/fixtures/dlptest/dlptest-name-ssn-dob.csv /tmp/dv-accept/`)
   и в новой сессии Claude Code попроси агента прочитать её через Read. Ожидаемо: отказ с
   сообщением о деле `auto-...`, через несколько секунд `status` этого дела показывает
   сущности. Затем удали дело и папку: `$DV case-rm auto-... --yes`, `rm -r /tmp/dv-accept`.

4. **Deny:** в той же сессии попроси прочитать любой файл под `~/DataVault/`. Ожидаемо:
   отказ по правилу permissions.

5. **Наблюдение:** `$DV web` -> http://127.0.0.1:8787/: видны вызовы из п.3 и события prompt
   guard.

Если хоть один пункт не прошёл: стоп. Данные заказчика не грузить, отчитаться человеку, что
именно не прошло, с выводом команды.

## Отчёт человеку

Одним сообщением: версия (`pip show datavault`), путь к `datavault`, какие модели на каких
маршрутах (вывод `check`), что изменено в `settings.json` (diff), вывод `harden`, результаты
пяти пунктов приёмки, что осталось за человеком (FileVault, логи LM Studio, папки
`DATAVAULT_STRICT_ROOTS`).

## Работа с делами после раскатки

```bash
$DV case-new case-07 --source "/path/to/customer/folder"   # читает на месте, без копии
$DV case-mask case-07 ORG "Customer LLC"     # название заказчика и домены маскировать всегда
$DV ingest case-07                           # parse -> detect -> handles -> sweep -> embed
$DV case-policy case-07 person_rows deny     # таблицы о людях: без идентифицирующих колонок
$DV audit case-07                            # heavy-модель ищет недомаскированное (counts only)
$DV case-rm case-07 --yes                    # удалить производные данные дела
```

- **Id дела виден облачному агенту** в каждом вызове. Никаких имён заказчиков в id
  (`case-rename`, если ошиблись).
- После правки правил или `case-mask` нужен `ingest --fresh`: при обычном переингесте старые
  handles сохраняются.
- Режимы сессии (команда в промпте, до модели она не доходит): `/vault on [пути]` - strict,
  `/vault off` - default, `/vault status`, `/vault bypass` - человек сам решил отдать эти
  данные в облако, guards только предупреждают.
- Отчёт с реальными значениями: агент пишет шаблон с handles -> `render` -> `exec docx`. Файл
  появляется в `out/` дела, его открывает человек. Свои генераторы (схемы, конвертеры)
  добавляются в `~/DataVault/tools.yaml` (формат в `src/datavault/tools.yaml`).

## Известные подводные камни

| Симптом | Причина | Что делать |
|---|---|---|
| `pip install -e .` работает, потом `ModuleNotFoundError` | iCloud скрывает `.pth` | ставить без `-e`, venv вне синхронизируемых папок |
| Metal OOM при `audit` | 27B + KV-кэш не влезают в лимит GPU macOS | `sudo sysctl iogpu.wired_limit_mb=21504` (до перезагрузки), `lms load qwen/qwen3.8-27b -c 8192 --parallel 1`, остальные большие модели выгрузить |
| Пустой ответ thinking-модели под JSON-схемой | LM Studio кладёт ответ в `reasoning_content` | gateway это обрабатывает; если всё равно пусто, сменить модель маршрута |
| Длинный промпт молча обрезан в Ollama | context length 4k | поставить 16k-32k |
| Поиск стал хуже после смены embeddings | эмбеддинги закреплены за делом | `ingest --fresh` с новой моделью |
| Hook упал, промпт прошёл | guards fail-open (не мешают работе) | смотреть `~/DataVault/promptguard.log` |
| Много ложных SECRET/BANK на выгрузках (RVTools и т.п.) | числа и пути похожи на секреты | `$DV diag <case>` показывает формы срабатываний без значений |

Дизайн, threat model и журнал решений: [ARCHITECTURE.md](ARCHITECTURE.md).

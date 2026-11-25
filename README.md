# datavault-kit

Локальный "карантинный" слой между облачным AI-агентом (Claude Code) и данными заказчиков:
конфигами, выгрузками AD, Excel, письмами, документами. Агент планирует и пишет отчёты, но
видит только handles `[[DV:PER:k3f9qa]]`, типы и агрегаты. Сырые значения читают локальные
модели (LM Studio / Ollama) на той же машине. Реальные имена появляются только в итоговых
файлах на диске, которые открывает человек.

Паттерн dual LLM / quarantined LLM: привилегированная модель не видит данных, карантинная
видит данные, но не вызывает tools и не управляет потоком.

**Раскатывает агент. Начните с [docs/AGENT.md](docs/AGENT.md)** - пошаговая инструкция для
AI-агента: разведка машины, установка, локальные модели, подключение к Claude Code (MCP,
hooks, deny), hardening и приёмка на синтетических данных с ожидаемыми результатами.

| Документ | О чём |
|---|---|
| [docs/AGENT.md](docs/AGENT.md) | раскатка по шагам, приёмка, работа с делами, подводные камни |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | threat model, инварианты, MCP-контракт, конвейер, журнал решений и замеров |
| [examples/](examples/) | фрагмент `~/.claude/settings.json` (hooks + deny), политика `promptguard.yaml` |
| [docs/diagrams/](docs/diagrams/) | схемы: PNG/SVG для чтения, `.drawio` для правки, `.yaml` - исходник |

## Как это работает

![Архитектура](docs/diagrams/01-architecture.png)

1. **Ingest.** `datavault ingest` разбирает csv/xlsx/docx/pdf/eml/txt, находит сущности
   (regex + DLP-детекторы + локальная LLM для имён и организаций, типизация колонок таблиц),
   выдаёт каждому значению случайный handle и вычищает все известные значения из всего
   корпуса.
2. **Запросы.** Агент вызывает MCP tools `schema`, `search`, `read`, `rows`, `aggregate`,
   `extract`, `describe`. Каждый ответ проходит output guard: sweep значений дела, DLP,
   инвариант "только слова корпуса", k-анонимность для таблиц о людях.
3. **Render / exec.** Агент пишет отчёт или спеку схемы с handles, `render` подставляет
   значения локально в `out/` дела, `exec` гоняет allow-listed инструмент (pandoc и свои
   генераторы). Агенту возвращаются только размер, хэш и счётчики.

![Путь одной записи](docs/diagrams/07-roundtrip-example.png)

## Точки контроля

![Точки контроля](docs/diagrams/08-control-points.png)

| Путь утечки | Защита |
|---|---|
| Человек вставил секрет или выгрузку в промпт | prompt guard (hook `UserPromptSubmit`): блок и замаскированная копия |
| Агент открыл xlsx/csv/docx/pdf напрямую | file guard (hook `PreToolUse`): отказ, автоматическое дело, фоновый ingest |
| Ответ vault пересказывает данные | output guard: sweep + DLP + словарь корпуса, fail-closed |
| В данных инструкции для ИИ | детектор инъекций: метка `[[DV:WARN:...]]`, такие чанки не идут в `extract` |
| Агент читает хранилище в обход MCP | `permissions.deny` на `~/DataVault/**` |

Режимы сессии задаются командой в промпте: `/vault on` (strict: все некодовые файлы под cwd
только через vault), `/vault off`, `/vault status`, `/vault bypass`.

## Замеры

| Проверка | Результат |
|---|---|
| Синтетический корпус (RU/UZ имена со склонениями, eml/docx/pdf/xlsx/cfg), seeds 7/11/23 | recall 1.0 / 0.997 / 1.0 |
| Публичные синтетические PII/PCI dlptest.com (csv/docx/pdf/xlsx) | recall 1.0, 0 утечек, 0 лишних сущностей |
| A/B на реальной выгрузке AD: агент напрямую vs через vault | цифры разделов аудита совпали; в контексте агента через vault 0 имён, хостов, IP и ID против сотен у прямого чтения |

![A/B](docs/diagrams/04-ab-dataflow-b.png)

## Требования

- macOS на Apple Silicon (проверено), 24 GB unified memory для маршрутов моделей по
  умолчанию; на 16 GB - модели легче. Linux не проверялся.
- Python 3.12+, LM Studio и/или Ollama, Claude Code.
- `pandoc` для `exec docx` (опционально).

## Быстрый старт (для человека)

```bash
python3.12 -m venv ~/.venvs/datavault && ~/.venvs/datavault/bin/pip install ".[dev]"
~/.venvs/datavault/bin/python -m pytest -q
~/.venvs/datavault/bin/datavault check
claude mcp add --scope user datavault -- ~/.venvs/datavault/bin/datavault serve
```

Hooks, deny-правила, hardening и приёмка - в [docs/AGENT.md](docs/AGENT.md). Проще всего
открыть Claude Code в этой папке и попросить: "раскатай DataVault по docs/AGENT.md".

## Чего здесь нет

- Защиты от злонамеренного владельца машины и от компрометации самой машины. Цель - не дать
  данным попасть в облако по ошибке или попутно.
- Шифрования хранилища handles: sweeper ищет значения в тексте. Защита покоя - FileVault и
  права 700/600 (`datavault harden`).
- Гарантий против квазиидентификаторов и вытягивания по битам через `extract`: есть
  ограничители (`extract_free_fields`, `person_rows: deny`, журнал вызовов), а не доказательство.
  Подробно в разделах 13 и 14b [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Лицензия

MIT. Фикстуры `tests/fixtures/dlptest/` - публичные синтетические данные
https://dlptest.com/sample-data/.

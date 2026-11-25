# CLAUDE.md - DataVault

## Overview
Локальный "карантинный" слой между облачным агентом (Claude Code) и чувствительными данными заказчиков. Агент работает через MCP-сервер и видит только id, типы, агрегаты и handles; сырые данные читают локальные модели (LM Studio / Ollama) на той же машине. Дизайн: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), раскатка: [docs/AGENT.md](docs/AGENT.md).

**Правило для агента:** не читать `~/DataVault/` (cases, out) напрямую - только через MCP tools `datavault`.

## Quick Start
```bash
uv venv -p 3.12 .venv && uv pip install -p .venv ".[dev]"
uv pip install -p .venv .                  # non-editable (iCloud hides .pth files, editable breaks)
.venv/bin/datavault case-new acme-ad --title "ACME AD audit"   # -> ~/DataVault/cases/acme-ad/data/
.venv/bin/datavault case-new res --source "<dir>"   # read sources in place, no copy
.venv/bin/datavault ingest acme-ad         # parse -> detect -> handles -> sweep -> embed
.venv/bin/datavault ingest acme-ad --fresh # after rule changes: old handles survive a plain re-ingest
.venv/bin/datavault audit acme-ad          # qwen3.8-27b re-reads a sample, counts residual leaks
#   before audit: sudo sysctl iogpu.wired_limit_mb=21504 && lms load qwen/qwen3.8-27b -c 8192 --parallel 1
.venv/bin/datavault case-mask acme-ad ORG "Customer LLC"   # always masked (also HOST domains)
.venv/bin/datavault case-rename acme-ad case-07  # case ids are visible to the agent
.venv/bin/datavault diag acme-ad           # rule hits with value shapes, no values
.venv/bin/datavault call search '{"case":"case-07","query_text":"backup"}'   # tool in-process
.venv/bin/datavault check                  # LM Studio / Ollama health + routes
.venv/bin/datavault call render '{"case":"case-07","name":"r.md","content":"..."}'
.venv/bin/datavault call exec '{"case":"case-07","tool":"docx","input":"r.md"}'
claude mcp add datavault -- $PWD/.venv/bin/datavault serve
.venv/bin/datavault hook-prompt --text "..."   # what the prompt guard would do; hook in ~/.claude/settings.json
.venv/bin/datavault web                    # http://127.0.0.1:8787/ calls, answers, prompt guard events
.venv/bin/datavault case-policy case-07 person_rows deny   # people tables: no identifying columns in rows/read
.venv/bin/datavault harden [--tighten] [--clean-lmstudio-logs]   # perms, FileVault, hooks, LM Studio logs
.venv/bin/datavault case-rm case-07 --yes          # delete store/out/audit/backups; --auto-older-than 7 prunes auto-* cases
```

## Architecture
```
src/datavault/
  server.py       MCP (stdio): cases, schema, status, search, read, rows, extract,
                  aggregate, describe, render, out_files, exec, models
  render.py       P3: handles -> real values into <case>/out/ (format escaping), allow-listed
                  exec (tools.yaml: docx + host-defined tools), guarded output
  injection.py    prompt-injection rules (override, exfil, hidden text, ...): chunks are scored at
                  ingest, marked [[DV:WARN:...]] in search/read, kept away from extract, warned in prompts
  harden.py       host report: vault perms (700/600), FileVault, hooks, LM Studio prompt logs
  web.py/.html    datavault web: read-only loopback UI over the access log (what the agent asked
                  and got, handles/REDACTED/WARN counts) and promptguard.jsonl events
  session_mode.py /vault on|off|status|bypass in a prompt: strict or bypass per session (marker), the
                  file guard then denies every non-code file under the session roots
  fileguard.py    PreToolUse hook (Read|Bash): a data file outside allowed dirs is denied, an
                  auto-NNN case is created and ingested in the background, agent is pointed to MCP
  promptguard.py  UserPromptSubmit hook: DLP + case values in what the human types; blocks and
                  shows the prompt with secrets cut and values as handles (~/DataVault/promptguard.yaml)
  query.py        P2 tools + OutputGuard (sweep + DLP + corpus vocabulary invariant)
  parsers.py      csv/xlsx/docx/pdf/eml/text -> chunks + tables
  detect.py       regex rules + DLP detectors, LLM column typing, LLM NER (verbatim spans only)
  store.py        SQLite handle store (per surface value, shared handles for name forms),
                  person linking (declension-aware), stop-list, Sweeper (one alternation)
  ingest.py       pipeline; handles survive re-ingest
  evaluate.py     leak recall vs truth.json (synthetic), unrelated-value count
  audit.py        no-truth leak audit by the heavy route -> <case>/audit.json
  cases.py        case layout, case.yaml policy, name validation
  inspect_src.py  structure of csv/xlsx/text (types, counts) - never values
  guard.py        label guard: masked ids or DLP-checked labels
  dlp/detectors.py vendored DLP detectors (secrets, PCI, UZ/RU PII)
  gateway.py      OpenAI-compatible client, loopback-only, task routes + fallback
  models.yaml     default routes (override: ~/DataVault/models.yaml or DATAVAULT_MODELS)
```

## Configuration
`DATAVAULT_HOME` (default `~/DataVault`), `DATAVAULT_MODELS`, `DATAVAULT_STRICT_ROOTS` (strict mode roots besides cwd, `:`-separated), `~/DataVault/tools.yaml` (exec allow-list). Маршрут `heavy` (27B) без fallback: на 24 GB рядом с ним не держать другие большие модели. Политика дела в `case.yaml`: `file_labels` (masked|dlp), `column_labels` (dlp|masked), `k_anonymity`, `person_rows` (handles|deny), `extract_free_fields` (4).

## Testing
- `.venv/bin/python -m pytest` - unit (без моделей)
- `.venv/bin/python -m pytest -m live` - живые LM Studio :1234 / Ollama :11434
- `.venv/bin/ruff check src tests scripts`
- `DATAVAULT_HOME=<scratch> .venv/bin/python scripts/synth/bench.py --seeds 7 11 23` - synthetic
  corpus (RU/UZ names with declension, eml/docx/pdf/xlsx/cfg/env/ps1) + leak recall per type
- `DATAVAULT_HOME=<scratch> .venv/bin/python scripts/dlptest_bench.py` - public dlptest.com
  PII/PCI samples (fixtures in tests/fixtures/dlptest/), exit 1 on any leak or stray entity

## Versioning
SemVer в `pyproject.toml` и `src/datavault/__init__.py`. Фазы P0-P4 - см. roadmap в ARCHITECTURE.md. Текущая: P3 + guards (prompt, file, injection, session strict mode) + web UI + P4 hardening (0.9.x).

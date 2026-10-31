# AGENTS.md

TMB: брокер привилегированного выполнения для агента в песочнице OpenShell. Что это и как работает: [README.md](README.md). Термины: [CONTEXT.md](CONTEXT.md). Решения: [docs/adr/](docs/adr/).

## Где что лежит

- `src/`: Go-модуль продукта, stdlib-only. `cmd/tmb` клиент, `cmd/tmb-broker` брокер, `internal/proto` протокол. Брокер поддерживается только на Linux: на macOS он компилируется для тестов, но не публикуется; релизный macOS-бинарник только у клиента.
- `ci/`: `run.sh` и отдельный Go-модуль `tmbci`; те же команды идут локально и в Actions. Политики в JSON рядом (`coverage-policy`, `exceptions`, `fuzz-targets`, `security-manifest`, `required-checks`).
- `harness/`: сценарные стенды. `run.sh` N-серия, `run-pair.sh` docker-pair, `run-openshell.sh` OpenShell-риг, `run-vm.sh` VM-пруф на Lima (V-серия, только локально), `run-all.sh` первые три, с `--vm` и VM-пруф. Реестры ожидаемых проверок в `ci/scenarios/`. Логи последних прогонов `harness/last-*.log` лежат в репозитории: это источник цифр для README и VERDICT.
- `prototype/`: сохранённые эксперименты, не продукт.

## Проверки

Перед PR:

```bash
ci/run.sh tools && ci/run.sh local
```

`local` это lint, тесты, самопроверка CI, покрытие, security, сборка и короткий fuzz. Отдельные проверки и пороги: [docs/ci.md](docs/ci.md). Lint проверяет и документацию: относительная ссылка в любом tracked Markdown обязана указывать на существующий файл.

PR в `main` сливается только после зелёного `ci-gate`. Ruleset на `main` (см. «Phase C» в [docs/ci.md](docs/ci.md)) этого требует, но у роли admin есть bypass для job `badges`, а сессии работают с токеном владельца-admin: слияние в обход GitHub не остановит, поэтому правило держит сессия. Она дожидается проверок и мержит merge-коммитом, ветка удаляется автоматически:

```bash
gh pr checks <номер> --watch --fail-fast && gh pr merge <номер> --merge
```

Красный `ci-gate` чинится в той же ветке; `--admin`, `--auto` без обязательных проверок и слияние красного PR запрещены.

Стенды (`ci/run.sh harness`, `harness/run-*.sh`) требуют Docker и используют фиксированные имена контейнеров: два одновременных прогона на одной машине конфликтуют. OpenShell-риг идёт только на macOS с Docker Desktop. Привилегированные контейнеры, проброс `docker.sock` и монтирование путей хоста запрещены.

## Соглашения

- Документация на русском, код, комментарии и коммиты на английском.
- Тема коммита: `область: что сделано` в повелительном наклонении (`ci:`, `src:`, `broker:`, `harness:`, `docs:`).
- Trailer `Co-Authored-By` с Claude или адресом Anthropic в коммит не добавлять: локальный хук `commit-msg` отклоняет такой коммит.
- В новом тексте нет длинного тире (`—`): двоеточие, запятая, точка или скобки. Абзац пишется одной строкой без переносов по ширине.
- ADR и `docs/design/grill-results.md` это записи решений: правится оформление, не смысл. Новое решение идёт новым ADR.
- Цифры прогонов (N=77/77 и подобные) берутся из `harness/last-full-run.log`, не из памяти.
- Заголовки `Updating pins` и `Phase B` в `docs/ci.md` упоминаются из `.github/dependabot.yml` и workflow: при переименовании править обе стороны.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary: needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

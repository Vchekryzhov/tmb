# CI TMB

Контракт CI описан в спецификации [#13](https://github.com/Vchekryzhov/tmb/issues/13), реализация в задаче [#14](https://github.com/Vchekryzhov/tmb/issues/14).
CI состоит из трёх независимых фаз:

| Фаза | Что доказывает | Где | Состояние |
| --- | --- | --- | --- |
| A | Переносимое ядро: сборка, тесты, покрытие, безопасность, N/pair-стенды | `.github/workflows/ci.yml` | действует |
| B | Полная приёмка OpenShell (O-серия + N/pair) | `.github/workflows/openshell-acceptance.yml` | UNAVAILABLE: нет выделенного Mac |
| C | Запрет слияния в main без зелёного `ci-gate` | `ci/main-protection/` | BLOCKED: ждёт решения владельца |

Зелёная фаза A не означает выполнения B или C.

## Локальный запуск

Одни и те же команды работают локально и в Actions. Нужны Go из [.go-version](../.go-version), git, curl, а для стендов и образов Docker.

```bash
ci/run.sh tools
```

```bash
ci/run.sh local
```

`tools` собирает `tmbci` и закреплённые инструменты в `out/ci/bin`. `local` прогоняет lint, тесты, самопроверку CI, покрытие, gosec/govulncheck, сборку и короткий fuzz. Отдельные проверки: `ci/run.sh lint`, `test <метка> [race]`, `coverage [base-ref]`, `security`, `build`, `fuzz short|long`, `secrets range|full`, `harness`, `images`, `manifest`, `stress`, `mutation`, `bench`. Полный список выводит `ci/run.sh` без аргументов.

Каждая проверка пишет `out/ci/results/<check>.json`. В файле есть статус (PASS, FAIL, ERROR, NOT_RUN, UNAVAILABLE или NOT_APPLICABLE), проверенный SHA, номер запуска, версии инструментов и сводка. Отчёты лежат в `out/ci/reports/`. Красная проверка воспроизводится той же командой, что указана в шаге workflow.

## ci-gate

`ci-gate` это единственная обязательная проверка. Список того, что она требует для каждого события, задан в [ci/required-checks.json](../ci/required-checks.json). Gate красный, если:

- обязательная job завершилась не `success` (в том числе skipped, cancelled или timed out);
- отчёт обязательной проверки отсутствует, повреждён или дублирован;
- отчёт относится к другому SHA или к другому запуску;
- статус проверки не PASS. NOT_APPLICABLE допускается только там, где он объявлен, и только с причиной.

Фильтров по путям нет: docs-only PR проходит все jobs и получает тот же `ci-gate`. `continue-on-error` не используется.

Для PR проверяется merge-коммит (`github.sha`), а не голова ветки. Summary показывает оба SHA.

## Jobs

| Job | Проверки | Лимит |
| --- | --- | --- |
| lint | gofmt, go vet и Staticcheck (продукт под linux и darwin, находки через исключения), stdlib-only и `go mod tidy -diff`, согласованность pins, `bash -n`, ShellCheck, actionlint, zizmor, Hadolint, исключения, локальные ссылки | 15 мин |
| test | Go 1.27.2 и 1.26.9 × Linux amd64/arm64 и macOS arm64; `-count=1`, timeout, JSON + JUnit; race detector на Linux | 20 мин |
| ci-selftest | тесты `tmbci`, включая негативные и позитивные фикстуры gate | 10 мин |
| coverage | профиль всего модуля, сравнение с merge-base, diff coverage, цели | 20 мин |
| security | gosec (исходники и тесты, сборки linux и darwin, находки объединяются), govulncheck на уровне символов | 15 мин |
| build | `tmb` и `tmb-broker` для Linux amd64/arm64, `tmb` для macOS arm64; две чистые сборки с одинаковым SHA-256, build manifest, govulncheck по бинарникам | 15 мин |
| fuzz | реестр fuzz targets; PR: до 30 с на target и 3 мин всего; nightly: до 5 мин и 15 мин | 25 мин |
| secrets | Gitleaks: диапазон коммитов PR и дерево; nightly: вся история | 10 мин |
| harness | `run-pair.sh`, который заново запускает `run.sh`, на одноразовом Linux runner; логи сверяются с [ci/scenarios](../ci/scenarios) | 25 мин |
| images | сборка host/sandbox-образов, Trivy (уязвимости, misconfiguration), SBOM CycloneDX, лицензии | 20 мин |
| manifest | матрица SEC-01…SEC-21 против реально выполненных тестов и сценариев | 5 мин |
| nightly | повторные перемешанные тесты под race, mutation checks, benchmarks, внешние ссылки | 55 мин |

Mac-брокер собирается только как часть тестов: привилегированный брокер на Mac не заявлен и не публикуется. Диагностические артефакты хранятся 14 дней, отчёты плановых security-аудитов 30 дней. Репозиторий public, поэтому артефакты Actions может скачать любой авторизованный пользователь GitHub. В них нет секретов: Gitleaks редактирует значения, PEM-ключи блокируют загрузку. Но логи стендов, SBOM и fuzz-входы публичны. В registry и releases ничего не публикуется.

## Пороги

- Покрытие ([ci/coverage-policy.json](../ci/coverage-policy.json)): общий процент и процент каждого пакета не ниже базы. База: профиль merge-base на той же платформе (linux/amd64), том же toolchain и в том же режиме `atomic`. Diff coverage не ниже 90%: считаются операторы Go coverage blocks, которые пересекают добавленные строки (statement coverage, не branch). Если исполняемых изменений нет, результат NOT_APPLICABLE. Пакет, отсутствующий в профиле, даёт ERROR. Исключать пакеты нельзя: политика отвергает неизвестные поля.
- Цели: общее покрытие 80%, `internal/proto` 90%, логика идентичности, одобрения и погашения 90%. Недостигнутая цель это GAP с владельцем, issue и сроком. Достигнутую цель нужно закрепить (`enforced: true`), иначе gate красный.
- Fuzz ([ci/fuzz-targets.json](../ci/fuzz-targets.json)): обязательный target либо существует, либо объявлен GAP. Объявленный, но не зарегистрированный target тоже даёт красный результат.
- Security manifest ([ci/security-manifest.json](../ci/security-manifest.json)): каждый тест или сценарий, указанный в SEC-кейсе, должен реально выполниться и пройти. SEC-14 подтверждается только в фазе B.
- gosec: MEDIUM и HIGH блокируют, LOW остаётся в отчёте.
- Mutation: мутант, который не компилируется, даёт ERROR, а не «убит». govulncheck: блокирует достижимый уязвимый символ. Trivy: HIGH/CRITICAL в образах и конфигурации блокируют, отсутствие исправления не даёт автоматического ignore. Gitleaks: блокирует любая находка, значения редактируются (`--redact`).
- Свежесть: БД Trivy скачивается заново на каждый запуск и должна быть собрана не более 24 часов назад, иначе ERROR. govulncheck каждый раз обращается к vuln.go.dev; при сбое сети результат ERROR, а не PASS.

Известные ограничения фазы A (ещё не сделано в рамках #14):

- интеграционное покрытие инструментированными бинарниками (`go build -cover`, GOCOVERDIR) не собирается, есть только Go-test профиль;
- профиль покрытия снимается на linux/amd64, поэтому изменения в файлах только для darwin в diff coverage не видны;
- образ `Dockerfile.opensbx` (база только linux/arm64) проверяется Trivy только как конфигурация, без сканирования уязвимостей;
- харнессы используют фиксированные имена контейнеров. Конфликтов нет, потому что каждая job получает свою VM. Два одновременных локальных прогона на одной машине конфликтуют.

Текущие GAP собраны в [#15](https://github.com/Vchekryzhov/tmb/issues/15). Mutation checks на момент внедрения находят выживших мутантов: проверку client cert, привязку токена к запросу и one-shot claim продуктовые тесты не ловят. Поэтому nightly красный, пока не появятся эти тесты.

## Бейджи

Бейджи в README и здесь это shields.io endpoint-файлы из [docs/badges](badges/): CI не имеет write-токенов и внешних сервисов, поэтому значения лежат в репозитории и обновляются коммитом.

[![tool-go](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-go.json)](../.go-version)
[![tool-staticcheck](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-staticcheck.json)](../ci/tools/staticcheck/go.mod)
[![tool-gosec](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-gosec.json)](../ci/tools/gosec/go.mod)
[![tool-govulncheck](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-govulncheck.json)](../ci/tools/govulncheck/go.mod)
[![tool-trivy](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-trivy.json)](../ci/tools.lock)
[![tool-gitleaks](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-gitleaks.json)](../ci/tools.lock)
[![tool-zizmor](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-zizmor.json)](../ci/tools.lock)
[![tool-actionlint](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-actionlint.json)](../ci/tools/actionlint/go.mod)
[![tool-shellcheck](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-shellcheck.json)](../ci/tools.lock)
[![tool-hadolint](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FVchekryzhov%2Ftmb%2Fmain%2Fdocs%2Fbadges%2Ftool-hadolint.json)](../ci/tools.lock)

- `tool-*.json` выводятся из пинов (`.go-version`, `ci/tools.lock`, `ci/tools/*/go.mod`) командой `ci/run.sh badges tools`. `lint/pins` падает, если файлы отстали от пинов: после обновления пина команду нужно повторить и закоммитить результат.
- `coverage`, `image-vulns`, `gosec`, `govulncheck`, `secrets` и `ci-results` обновляет job `badges`: после зелёного `ci-gate` на push в main она собирает результаты всех jobs, перегенерирует оба набора и коммитит `docs/badges` в main от имени `github-actions[bot]`. Это единственная job с `contents: write`; push токеном GITHUB_TOKEN не запускает workflow, поэтому цикла нет. Бейдж `ci-results` показывает SHA и номер прогона, из которого взяты цифры. Вручную то же самое: `gh run download <run-id> -D out/ci/run && ci/run.sh badges results out/ci/run`.

## Исключения

[ci/exceptions.json](../ci/exceptions.json): единственное место для принятых находок. В каждой записи:

- сканер (gosec, govulncheck, trivy, gitleaks, staticcheck) и одно правило или advisory ID;
- один файл или пакет, для gosec, Gitleaks и Staticcheck ещё и фрагмент кода (`match`);
- причина, владелец, issue этого репозитория и дата истечения не дальше 180 дней.

Исключения, принятые по дизайну, ссылаются на постоянную задачу [#29](https://github.com/Vchekryzhov/tmb/issues/29): она не закрывается, а при пересмотре запись продлевается с обоснованием или исправляется в коде.

Gate отвергает истёкшие и широкие записи (маски, каталоги). Запись, которая больше ничего не покрывает, тоже даёт красный результат. Подавление в конфигурации сканеров не используется. Исключение: точечные `hadolint ignore` и `zizmor: ignore` с причиной на той же строке.

## Безопасность CI

- `permissions: {}` на уровне workflow, `contents: read` у jobs; checkout без сохранённых credentials. Секретов и OIDC нет. Единственный write-токен у job `badges` (push в main после зелёного gate): она коммитит только `docs/badges`, в PR не запускается и артефактов не загружает. `pull_request_target` и `workflow_run` не используются.
- Actions закреплены полным SHA. Инструменты: Go-утилиты собираются из отдельных модулей `ci/tools/<name>` с проверкой go.sum, бинарные проверяются по SHA-256 из [ci/tools.lock](../ci/tools.lock). Базовые образы закреплены digest.
- Кеши отключены (`cache: false`, свежий кеш Trivy). Данные PR попадают в shell только через переменные окружения.
- Стенды работают на одноразовых GitHub-hosted VM. Ключи CA и per-run ключи остаются во временных каталогах стенда. Отчёт с PEM-ключом удаляется до загрузки, проверка становится ERROR.
- Phase B запускается только на trusted main (ручной запуск или расписание). PR на выделенный runner не попадает.

## Updating pins

Обновления приходят через Dependabot ([.github/dependabot.yml](../.github/dependabot.yml)): actions, Go-модули инструментов и базовые образы, после выдержки 14 дней, без auto-merge. Вручную обновляются:

1. Go: [.go-version](../.go-version), `GO_PRIMARY` и матрица в `ci.yml`, строка `go` в `ci/tools/*/go.mod`, `golang:<версия>-alpine@sha256:…` в `harness/images/Dockerfile.*` и в `harness/run-pair.sh`/`run-openshell.sh`. Рассогласование ловит `lint/pins`.
2. Бинарные инструменты: версия, URL и SHA-256 в `ci/tools.lock`. SHA-256 сверяется с upstream checksum-файлом или digest ассета в GitHub. `latest` и `master` не допускаются.
3. Выдержка 14 дней нарушается только ради совместимости, с причиной в коммите. Так сделано для Staticcheck 2026.2.2 (поддержка export data Go 1.27.2) и для `golang.org/x/tools` v0.51.0 в модуле gosec: gosec v2.29.0 со старым x/tools не загружал пакеты Go 1.27.2.

## Phase B

Нужен выделенный Mac arm64, без пользовательских данных, с Docker Desktop, собственным gateway OpenShell и закреплённым образом. На нём регистрируется self-hosted runner с метками `self-hosted, macOS, ARM64, tmb-openshell`, а в репозитории ставится переменная `TMB_OPENSHELL_RUNNER=ready`. До этого workflow сообщает UNAVAILABLE и остаётся красным.

Ручное воспроизведение на таком Mac:

```bash
ci/run.sh tools
```

```bash
ci/run.sh openshell
```

`openshell` запускает `harness/run-all.sh` и сверяет три лога с реестрами. Ветка O4 dropped/recreated (`CHECK WARN`) считается NOT_PROVEN, и приёмка красная, даже если runner вернул 0. Ответы через PTY в O6 это автоматическая проверка консоли, не Touch ID и не одобрение человеком.

## Phase C

Подготовлены [ruleset](../ci/main-protection/ruleset.json) для main и [скрипт](../ci/main-protection/apply.sh) владельца. Ruleset запрещает удаление ветки и force-push, требует PR и зелёный `ci-gate` от GitHub Actions. Изменения `.github/`, `ci/`, pins и стендовых образов закреплены за владельцем в [CODEOWNERS](../.github/CODEOWNERS).

История доступности:

- 2026-10-12: репозиторий был private, API rulesets отвечал 403 с требованием GitHub Pro.
- 2026-10-16: репозиторий public, API rulesets отвечает (правил нет).
- 2026-10-17: в настройках репозитория включены auto-merge и удаление ветки после слияния. Ruleset не включён: job `badges` пушит в `main` через `GITHUB_TOKEN`, а bypass для GitHub Actions в ruleset доступен только репозиториям организаций (API отвечает 422). Перед включением ruleset job `badges` нужно перевести на PAT владельца с bypass для роли admin или на PR. До тех пор зелёный `ci-gate` перед слиянием это правило в [AGENTS.md](../AGENTS.md), а не запрет GitHub.

Включение правил остаётся отдельным решением владельца:

```bash
ci/main-protection/apply.sh apply
```

После включения нужно проверить на PR с намеренно падающим тестом, что слияние заблокировано. Пока правила не включены, красный `ci-gate` видим, но технически слияние не запрещает.

## Недоступные сервисы

CodeQL, загрузка SARIF, dependency review и attestations не входят в обязательное ядро. Основная проверка держится на открытых CLI и собственных артефактах. Для public-репозитория эти сервисы стали доступны; подключать их или нет, отдельное решение.

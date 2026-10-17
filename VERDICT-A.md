# Вердикт по майлстоуну A «политика и харденинг»

Прототип (throwaway PoC). Решение: [ADR 0004](docs/adr/0004-approver-role-and-approval-queue.md). Спека: [#27](https://github.com/Vchekryzhov/tmb/issues/27) с тикетами с [#30](https://github.com/Vchekryzhov/tmb/issues/30) по [#37](https://github.com/Vchekryzhov/tmb/issues/37). Источник решений: [итоги грила 2026-10-17](docs/design/grill-results-stage2.md).

Прогон: `bash harness/run-all.sh` от 2026-10-17, три харнесса подряд одним скриптом.

Стенд: macOS arm64 + Docker Desktop, docker 29.6.1 (контейнеры linux/arm64 в VM), openshell 0.1.3.

Логи: `harness/last-run.log` (N-серия), `harness/last-pair-run.log` (docker-pair), `harness/last-openshell-run.log` (OpenShell-риг), суммарный `harness/last-full-run.log`.

Итог: **N=159/159, pair=67/67, openshell=65/65. FULL-RUN VERDICT: GREEN, runner exit 0.**

Доказано на стенде:

- одобряет отдельная роль: одобряющий из `approver_uids` решает командой `tmb approve` через свой unix-сокет хоста; брокер работает без терминала;
- запрос ждёт в очереди одобрений не дольше `approval_wait_seconds`, отключение запросчика снимает его с очереди, ожидание одного запроса не держит другие;
- через TLS-листенер и сокет запросчиков одобрить запрос нельзя: команд `list` и `decide` там нет;
- брокер проверяет политику запроса раньше, чем показывает запрос одобряющему: корни cwd по realpath, фиксированное окружение, значения окружения в одну строку и не длиннее 4 KiB;
- брокер держит одобренный каталог открытым через fd до exec, дочерний процесс входит в него через `/proc/self/fd/N`;
- у claim-файлов есть срок, брокер удаляет истёкшие при старте и раз в час; повтор внутри TTL после рестарта по-прежнему отклоняется.

## Что изменилось по тикетам

| Тикет | PR | Что |
|-------|----|-----|
| [#37](https://github.com/Vchekryzhov/tmb/issues/37) | [#48](https://github.com/Vchekryzhov/tmb/pull/48) | отладочные шаги переехали в `tmb debug approve\|claim\|raw`; консоль `manual` показывает итоговое окружение; событие `approval` получило `approver` и `decision` |
| [#32](https://github.com/Vchekryzhov/tmb/issues/32) | [#49](https://github.com/Vchekryzhov/tmb/pull/49) | `allowed_cwd_roots`, отказ `cwd_not_allowed` |
| [#33](https://github.com/Vchekryzhov/tmb/issues/33) | [#50](https://github.com/Vchekryzhov/tmb/pull/50) | политика окружения: `env_key_invalid`, `env_fixed_key`, `env_value_invalid`, `env_value_too_long`; `PATH` в `allowed_env_keys` останавливает старт |
| [#34](https://github.com/Vchekryzhov/tmb/issues/34) | [#51](https://github.com/Vchekryzhov/tmb/pull/51) | удерживаемый fd каталога cwd от одобрения до exec |
| [#35](https://github.com/Vchekryzhov/tmb/issues/35) | [#52](https://github.com/Vchekryzhov/tmb/pull/52) | `expires_at` в claim-файлах, сборщик `claim_gc` |
| [#30](https://github.com/Vchekryzhov/tmb/issues/30) | [#54](https://github.com/Vchekryzhov/tmb/pull/54) | очередь одобрений, режим `queue` по умолчанию, сокет и роль одобряющего, `tmb approve` |
| [#31](https://github.com/Vchekryzhov/tmb/issues/31) | [#55](https://github.com/Vchekryzhov/tmb/pull/55) | `approval_wait_seconds`, `approval_timeout`, `request_abandoned`, кадр `waiting` |

## Реестр новых сценариев

Обозначения: `host` = `docker exec` в host-sim, `sbx` = `docker exec` в sandbox-sim (uid 4242), `human` = пользователь host-sim с uid 1500, единственный элемент `approver_uids`.

N13–N22 идут в `harness/run.sh`, PAIR-APPROVE в `harness/run-pair.sh`.

| # | Сценарий | Ожидание | Наблюдение | Результат |
|---|----------|----------|------------|-----------|
| N13 | очередь, живое одобрение | запрос ждёт; `human` видит его целиком; `--yes` → exit 0, stdout `0`; `--no` → 125 `approval_denied_by_human`; JSONL `queued`, `approval` с `approver=uid:<human>`, `claim`, `exec_start`, `exec_exit` | `--list` показывает `requester : uid=4242`, `/usr/bin/id`, argv, cwd `/tmp`, окружение с `PATH` из `fixed_env`; `--yes` → 0 и `0`; `--no` → 125 `approval_denied_by_human`; в JSONL `approver=uid:1500`, `decision=approve` | PASS |
| N14 | одобряющий не запросчик | uid 4242 на сокете одобряющего → 125 `approver_not_allowed`; сокета нет в песочнице; `list` на сокет запросчика → `unknown_request_type` | всё так; `approver_denied` с `requester_uid=4242`; очередь пуста | PASS |
| N15 | таймаут ожидания | `approval_wait_seconds=2`, без решения → 125 `approval_timeout` за 2–10 с; маркера нет; очередь пуста | отказ через ~2 с; `waiting for approval` в stderr ровно один раз; JSONL `approval_timeout` | PASS |
| N16 | два одобряющих | второе решение по тому же элементу → exit 1, `already decided`; один `exec_start` | всё так | PASS |
| N17 | очередь не мьютекс | второй запрос одобрен и завершён, пока первый ждёт; клиент убит SIGKILL → элемент снят | всё так; JSONL `request_abandoned` | PASS |
| N18 | корни cwd | `--cwd /etc` и ссылка `/tmp/n18-link` → `/etc` → 125 `cwd_not_allowed` до одобрения; `/tmp/n18-dir` проходит; пустой список запрещает всё | detail `/etc` у ссылки; событий `approval` для отказов нет; относительный корень → брокер не стартует, stderr называет путь | PASS |
| N19 | фиксированные ключи | `--env LANG=ru_RU` → `env_fixed_key`; `--env PATH=/evil` → `env_key_not_allowed`; `PATH` в `allowed_env_keys` → брокер не стартует | всё так; сокет после неудачного старта не появился | PASS |
| N20 | значения окружения | перевод строки → `env_value_invalid`; 4097 байт → `env_value_too_long`; 4096 байт → проходит, показ одобрения одной строкой | всё так; дочерний процесс получил значение целиком | PASS |
| N21 | сборщик claim-файлов | после рестарта истёкший файл удалён, живой на месте, `claim_gc` с `removed=1`; повтор погашенного токена → `token_consumed_replay` | всё так | PASS |
| N22 | fd каталога | переименование после одобрения до claim → 125 `cwd_changed`; контроль без подмены → `marker` в `/tmp/n22` | всё так; `exec_start` несёт `cwd_via_fd=true` | PASS |
| PAIR-APPROVE | одобрение по TLS невозможно | `list` и `decide` на TLS-листенер → 125 `unknown_request_type`; очередь не изменилась; `approval` нет | при ждущем в очереди TLS-запросе обе попытки (`decide` с верными id и хэшем) отклонены; элемент на месте; событий `approval` не прибавилось | PASS |

Окно «после проверки cwd, до chdir» доказывает Go-тест `TestExecChdirsThroughHeldCwdDespiteSwapAfterCheck`: подмена пути в этом окне не меняет каталог дочернего процесса, `marker` появляется в удерживаемой иноде; с передачей пути вместо fd тот же тест падает.

Счёт по частям:

- N-серия (Unix/SO_PEERCRED): **159/159**, 77 проверок OpenShell-майлстоуна плюс N13–N22.
- docker-pair: **67/67**, включая PAIR-APPROVE и повторный прогон N-серии внутри `run-pair.sh`.
- OpenShell-риг: **65/65** (O0–O6).

Реестры `ci/scenarios/n-series.txt` и `ci/scenarios/pair.txt` содержат все секции; `ci/security-manifest.json` получил SEC-17…SEC-22 (корни cwd, политика окружения, fd каталога, сборщик, роль одобряющего, ожидание в очереди), SEC-12 ссылается на N19; файлы очереди и одобряющего входят в цель `security` в `ci/coverage-policy.json`.

## Отклонения от спеки

1. **Порядок проверок `PATH`**: спека ставит `fixed_env` раньше allowlist, но требует для `--env PATH=/evil` ответ `env_key_not_allowed`. `PATH` проверяется отдельно сразу после синтаксиса и получает `env_key_not_allowed`, остальные фиксированные ключи получают `env_fixed_key`.
2. **Клиент больше не шлёт `LANG` по умолчанию**: при `LANG` в `fixed_env` каждый запрос получал бы `env_fixed_key`. Окружение запроса теперь только из `--env`.
3. **Сокет одобряющего на стенде лежит в `/run/tmb-approver/`**, а не в `/run/tmb/` по умолчанию: `/run/tmb` на стенде это том, общий с sandbox-sim, и N14 проверяет, что сокета одобряющего в песочнице нет. В эксплуатации песочница ходит по TLS и `/run/tmb` не видит.
4. **Сокет одобряющего 0666**: подключиться может любой локальный пользователь, право видеть очередь и решать даёт только SO_PEERCRED против `approver_uids` (N14).
5. **Пользователь `human` в host-sim получил явный uid 1500**: образ ubuntu:24.04 уже занимает uid 1000, а uid нужен в `approver_uids` конфига стенда.
6. **Повторная постановка того же запроса** (тот же хэш, пока первый ждёт) отклоняется `request_already_queued`; спека этот случай не описывает.
7. **Сертификаты стендов выпускает `tmb-broker ca`** ([#40](https://github.com/Vchekryzhov/tmb/issues/40), майлстоун B) уже в этом прогоне; ключи клиентов генерирует openssl на стороне песочницы, идентичность на TLS-листенере по-прежнему отпечаток сертификата до [#41](https://github.com/Vchekryzhov/tmb/issues/41).
8. **N11 стал детерминированным**: наблюдатель подмены в host-sim теперь сначала считает claim-файлы и ставит метку `armed`, и только после неё харнесс шлёт claim. Раньше подсчёт шёл в фоне параллельно с claim, и при быстром claim подмена не срабатывала (`swapper never fired`); такой провал был в первом прогоне этого майлстоуна.

## Остаточные риски

- **Запись в ту же иноду исполняемого файла** между одобрением и exec: fd-пиннинг держит иноду, но не её содержимое. Нужен immutable-носитель или подпись; `execveat` и собственный ForkExec в этот майлстоун сознательно не вошли.
- **Одобряющему нужен shell на принимающем хосте**: канал одобрения только локальный. Снимается удалённым одобрением ([#3](https://github.com/Vchekryzhov/tmb/issues/3)).
- **Токен не секрет**: короткий id от хэша запроса; защищён привязкой одобрения к идентичности (`requester_mismatch` до погашения), а не энтропией.
- **Владелец и права cwd не проверяются**: решает человек по показанному realpath; корни cwd ограничивают только место.
- **Отключение запросчика определяется чтением соединения**: клиент, который после запроса шлёт ещё байты, считается ушедшим, и его запрос снимается.
- **«Хост» доказательства: Docker Desktop VM**, не настоящий хост. Пруф на VM с systemd это майлстоун B ([#45](https://github.com/Vchekryzhov/tmb/issues/45)).

## Как воспроизвести

Пререквизиты: как у [VERDICT-OPENSHELL.md](VERDICT-OPENSHELL.md) плюс Go на харнесс-хосте (`tmb-broker ca` собирается под хост и выпускает сертификаты). Скрипту `run-openshell.sh` нужен доступ python3 к настройкам Docker Desktop (`~/Library/Group Containers/group.com.docker/settings-store.json`): macOS один раз спрашивает разрешение, без него прогон стоит на O0.

```bash
bash harness/run-all.sh
```

Выход 0 только если все три части зелёные; суммарный вердикт пишется в `harness/last-full-run.log`.

## Вывод

Спека майлстоуна A выполнена: брокер получает одобрение от отдельной роли через очередь, отклоняет запрос с неразрешённым cwd или окружением ещё до показа человеку, закрепляет каталог запуска так же, как исполняемый файл, а каталог состояния больше не растёт без предела. Механики, доказанные в OpenShell-майлстоуне (одноразовый токен, привязка к идентичности, fail-closed), не сломались.

Дальше: майлстоун B «эксплуатация» ([#39](https://github.com/Vchekryzhov/tmb/issues/39)): идентичность по ключу, reload, журнал, пакеты, пруф на VM.

## Ссылки

- [ADR 0004](docs/adr/0004-approver-role-and-approval-queue.md): одобряющий и очередь одобрений.
- [Спека #27](https://github.com/Vchekryzhov/tmb/issues/27), [итоги грила](docs/design/grill-results-stage2.md).
- [VERDICT-OPENSHELL.md](VERDICT-OPENSHELL.md): предыдущий майлстоун, реестр O0–O9.

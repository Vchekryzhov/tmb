# Вердикт по OpenShell-майлстоуну TMB

Прототип, throwaway PoC. Решение: [ADR 0003](docs/adr/0003-sandbox-transport-tcp-mtls.md). Спека: [#5](https://github.com/Vchekryzhov/tmb/issues/5) с тикетами #6–#11.

Прогон: `bash harness/run-all.sh` от 2026-10-11, три харнесса подряд одним скриптом.
Стенд: macOS arm64 + Docker Desktop, docker 29.6.1 (контейнеры linux/arm64 в VM), openshell 0.1.3, gateway как нативный brew-бинарник.
Логи: `harness/last-run.log` (N-серия), `harness/last-pair-run.log` (docker-pair), `harness/last-openshell-run.log` (OpenShell-риг), суммарный `harness/last-full-run.log`.

Итог: **N=77/77, pair=59/59, openshell=65/65. FULL-RUN VERDICT: GREEN, runner exit 0.**

Доказано на живой связке (gateway на Mac → Docker VM → host-sim с брокером → супервизор → песочница с образом opencode):

- агент в песочнице OpenShell с deny-by-default egress достигает брокера ровно через одно сетевое правило (`protocol: tcp`, `tls: skip` → `host.openshell.internal:17600`);
- идентичность запросчика: SHA-256 отпечаток клиентского сертификата в allowlist, JSONL-журнале, консоли одобрения и привязке одобрения;
- mTLS двусторонний: клиент верифицирует брокера против CA и имени из `TMB_ADDR`;
- смерть брокера закрывает агентный путь, человеческий парольный sudo нетронут.

Роли в связке: OpenShell обеспечивает изоляцию и сетевую политику, `tmb`-клиент передаёт запрос, брокер получает одобрение и выполняет команду на host-sim.
OpenCode здесь только базовый образ песочницы: сценарии вызывают `tmb` через `openshell sandbox exec`, не проверяют автономную работу OpenCode с LLM и не доказывают совместимость других агентов.

## Реестр O-серии

O0–O6 идут на полном OpenShell-риге (`harness/run-openshell.sh`).
O7–O9 идут на docker-pair (`harness/run-pair.sh`, без OpenShell): это свойства транспорта, не топологии.

| # | Сценарий | Ожидание | Наблюдение | Результат |
|---|----------|----------|------------|-----------|
| O0 | пререквизиты | openshell 0.1.3; DD host networking ON, ECI OFF; digest образа; `go list -m all` = только `tmb-poc`; в образе sh/id/test/openssl | всё совпало; провал любого = прогон не стартует | PASS |
| O1a | порт без правила | exit 3, FAIL CLOSED, nc получил 0 байт | супервизор режет на proxy-этапе (`permission denied`), 0 байт | PASS |
| O1b | положительный контроль (временное правило на :19999) | ClientHello проходит, но это не брокер | nc получил 1463 байта (TLS ClientHello), рукопожатие умерло, клиент exit 3 FAIL CLOSED | PASS |
| O1c | правило снято | снова как O1a | 0 байт, exit 3 | PASS |
| O2a | ровно одно правило, exec | exit 0, stdout `0` | `sbx-exec tmb exec --root -- /usr/bin/id -u` → 0 / `0` | PASS |
| O2b | правило изъято (hot-reload) | exit 3, FAIL CLOSED, маркер не создан, JSONL без `request` | всё так; policy DNS перестаёт резолвить алиас (`server misbehaving`) | PASS |
| O2c | правило возвращено на живую песочницу | O2a снова зелёный | exit 0, без пересоздания | PASS |
| O3 | изоляция хоста | uid≠0; sudo нет; сокета нет; mount нет | uid=1000; sudo отсутствует; `test -e` → 1; mount → 0 | PASS |
| O4 | рестарт gateway | политика и deny-by-default переживают | песочница пережила рестарт (survived); повтор O1a → 3 (0 байт), O2a → 0, изъятие → 3. Ветка dropped+recreated (если рестарт сронил песочницу) печатает в сводку `WARN … policy persistence NOT PROVEN`: повторные проверки остаются smoke, персистентность политики такой прогон не доказывает | PASS |
| O5 | SIGKILL брокера | агентный путь закрыт, человеческий sudo жив | kill -9 по pidfile внутри host-sim; exec в песочнице → exit 3 «FAIL CLOSED … nothing executed», `/tmp/marker` не создан; `sudo -S id` (human) → `uid=0(root)`; `grep -c "^Plugin" /etc/sudo.conf` → **0** | PASS |
| O6 | живое одобрение (без человека, pty) | консоль показывает точный запрос + `requester : cert fp=…`; y → исполнено, stdout в песочнице; n → 125 `approval_denied_by_human`; JSONL: request/approval/claim/exec_start/exec_exit с `requester_fp=fp1` | харнесс гоняет брокера `-approval manual` через python3-pty и подаёт y/n сам; все проверки зелёные (текст консоли ниже) | PASS |
| O7 | чужой сертификат | отказ до показа одобрения | fp2 → 125 `requester_not_allowed`, JSONL `requester_denied` с `requester_fp=fp2`; `openssl s_client` без сертификата → alert `certificate required`, JSONL `tls_handshake_failed` без отпечатка; без `TMB_CERT` → exit 2, соединения нет; консоль не беспокоилась | PASS |
| O8 | чужой брокер | верификация, кадр не уходит | TLS-сервер чужого CA на том же порту: клиент exit 3, причина `x509: certificate signed by unknown authority`, сервер не получил ни одного app-data кадра | PASS |
| O9 | чужое одобрение | `requester_mismatch` до погашения | approve под fp1 → токен; claim под fp3 (в allowlist) → 125 `requester_mismatch`, токен цел; повтор под fp1 → exit 0, stdout `0` | PASS |

Счёт по частям:

- N-серия (Unix/SO_PEERCRED): **77/77**, 62 исходных проверки плюс N11/N12 харденинга запуска.
- docker-pair: **59/59**, включая regression-повтор N-серии внутри `run-pair.sh`.
- OpenShell-риг: **65/65** (O0–O6, из них O5 даёт 10 проверок, O6 даёт 14).

## Точный текст консоли O6

Из прогона; отпечаток меняется от прогона к прогону.

```
tmb-broker: listening on /run/tmb/tmb.sock (mode=manual ttl=15s pid=248)
tmb-broker: tls listening on :17600 (client certificates required, no plaintext)
=== TMB APPROVAL REQUIRED ===
  requester : cert fp=c19fc27bcd104118
  executable: /usr/bin/id (realpath /usr/bin/id, dev=73 ino=3025125)
  argv      : ["/usr/bin/id","-u"]
  cwd       : /tmp
  run as uid: 0
  env       : {"LANG":"C.UTF-8"}
  nonce     : 81085d76ea85079dfbc7f5d8487f3b5f
Approve exactly this command? [y/N]: y
HUMAN ANSWER: "y" -> APPROVED
=== TMB APPROVAL REQUIRED ===
  requester : cert fp=c19fc27bcd104118
  executable: /usr/bin/id (realpath /usr/bin/id, dev=73 ino=3025125)
  argv      : ["/usr/bin/id","-G"]
  cwd       : /tmp
  run as uid: 0
  env       : {"LANG":"C.UTF-8"}
  nonce     : 7fc7284e405ff079a234d13d413c155d
Approve exactly this command? [y/N]: n
HUMAN ANSWER: "n" -> DENIED
```

Буква после `[y/N]:` это эхо pty: харнесс пишет ответ в тот же терминал, где брокер печатает промпт (python3 `pty`, без внешних зависимостей; ответ подаётся строго после появления промпта по опросу захвата консоли).
Оба запроса видны человеку целиком: argv, cwd, uid, env, nonce и кто просит.
Клиент при `y` получил `0` в песочнице (exit 0); при `n` получил exit 125 `approval_denied_by_human`.
Все события окна O6 в JSONL несут `"requester_fp":"c19f…2b00"` (полный fp1): `request`×2, `approval`×2, `claim`×1, `exec_start`×1, `exec_exit`×1, плюс `deny`×1 с той же идентичностью.

## Fail-closed: доказательства

- Брокер убит SIGKILL (O5) → клиент в песочнице: exit 3, «FAIL CLOSED, nothing executed», маркер в host-sim не создан.
- Правило изъято (O2b/O4) → exit 3 до всякого соединения, в JSONL нет события `request`.
- Порт есть, правила нет (O1a/O1c/O4) → супервизор режет на proxy-этапе, до host-sim доходит 0 байт.
- На том конце не брокер или чужой CA (O1b/O8) → exit 3: рукопожатие не состоялось, запрос не отправлен.
- Человеческий парольный sudo не зависит от TMB (O5): `uid=0(root)` при убитом брокере, в `/etc/sudo.conf` 0 строк `Plugin`.

## Харденинг запуска (review #12)

Добавлен после ревью [PR #12](https://github.com/Vchekryzhov/tmb/pull/12); N-серия выросла с 62 до 77 проверок.

- Replace-атака на одобренный exe закрыта fd-пиннингом: одобрение держит read-only fd на иноде, exec идёт через `/proc/self/fd/N`. Выполняется ровно та инода, которую видел человек; подмена файла по пути между одобрением, claim и execve не срабатывает (N11: подмена внутри claim-окна с заморозкой брокера SIGSTOP → выполняется одобренная инода).
- cwd в момент exec перепроверяется по идентичности каталога (dev/ino): подменённый тем же путём каталог → deny `cwd_changed`, команда не выполняется (N12).

Остающиеся риски этого харденинга:

1. In-place запись в одобренный бинарник между одобрением и exec: та же инода, fd-пиннинг бессилен; нужен immutable-носитель или подпись.
2. Остаточное микроокно между перепроверкой cwd и execve.
3. Не-Linux путь брокера не пиннится: PoC-брокер запускается только на Linux.

## Отклонения от спеки

Зафиксированы и осознанны.

1. **Песочница создаётся без политики, правило добавляется горячей загрузкой** (`openshell policy set` сразу после create): `sandbox create --policy` на OpenShell 0.1.3 + Docker Desktop ломается upstream (spawn EACCES в proxy-режиме). Deny-by-default держится весь период.
2. **Правило применяется полной заменой политики** (`policy set` с сохранённой filesystem-секцией), а не `policy update --add-endpoint`: CLI-строка endpoint не выражает `tls: skip`.
3. **Стендовая сантехника**: патч `grpc_endpoint = "https://127.0.0.1:17671"` в `gateway.toml` (бэкап рядом) плюс socat-форвардер `tmb-osh-gwreach` (VM loopback → Mac gateway), иначе docker-драйвер не пинит `host.openshell.internal`.
4. **`netcat-openbsd` добавлен в образ host-sim, published-порт 19999**: одноразовый контрольный листенер O1 на том же интерфейсе, что и брокер.
5. **O8: одноразовый контейнер fake-broker** (TLS-сервер чужого CA) поднимается харнессом на время сценария.

## Остаточные риски

- **«Хост» доказательства: Docker Desktop VM**, не настоящий хост.
- **Клиентский ключ живёт в песочнице** (выпечен в per-run образ, `/usr/share/tmb/certs/`, 0644): любой процесс песочницы может его прочесть. Для продакшена нужен секрет-стор или короткоживущие сертификаты.
- **Токен не секрет**: короткий id от хэша запроса; защищён привязкой одобрения к идентичности (`requester_mismatch` до погашения), а не энтропией.
- **Серийный manual-approval**: консоль брокера сериализована мьютексом на все соединения; под конкурентными клиентами это узкое место. Удалённое одобрение: [#3](https://github.com/Vchekryzhov/tmb/issues/3).
- **Churn OpenShell 0.1.x**: версия 0.1.3 и digest образа opencode пиннуты в харнессе; смена релиза может сломать топологию.
- Наследие PoC: TTL=3 c в конфиге прогона, см. [VERDICT-BROKER.md](harness/ref/VERDICT-BROKER.md).

## Как воспроизвести

Пререквизиты: macOS + Docker Desktop 29.x (host networking включён, Enhanced Container Isolation выключен), openshell 0.1.3 с запущенным gateway (`brew services start openshell`), python3, openssl, coreutils (`timeout`).

```bash
bash harness/run-all.sh
```

Выход 0 только если все три части зелёные; суммарный вердикт пишется в `harness/last-full-run.log`.
Прогон идемпотентен: каждый харнесс сносит свои остатки до старта и подчищает за собой cleanup-ловушкой (песочница, контейнеры, named-тома, per-run образ с сертификатами); CA-ключ не попадает ни в один образ или контейнер.
Точечные прогоны и топология: [harness/ref/README-PROTOTYPE.md](harness/ref/README-PROTOTYPE.md).

## Вывод

Спека майлстоуна выполнена:

- точка входа TMB: ровно одно сетевое правило песочницы;
- идентичность запросчика сертификатная и видна человеку в момент одобрения;
- одобрение привязано к идентичности: чужой claim не погашает токен;
- брокер аутентифицирован клиентом: чужой CA или SAN даёт отказ до запроса;
- смерть брокера закрывает агентный путь, человеческий sudo не тронут;
- N-серия не регрессировала.

Следующие шаги лежат за пределами прототипа: подписант с Touch ID ([#2](https://github.com/Vchekryzhov/tmb/issues/2)), удалённое одобрение ([#3](https://github.com/Vchekryzhov/tmb/issues/3)), TOCTOU-харденинг, упаковка и пруф на настоящем хосте ([#4](https://github.com/Vchekryzhov/tmb/issues/4)).

## Ссылки

- [ADR 0003](docs/adr/0003-sandbox-transport-tcp-mtls.md): принятое решение, транспорт и mTLS-идентичность.
- [Спека #5](https://github.com/Vchekryzhov/tmb/issues/5) и тикеты #6–#11; реестр O-серии определён в спеке.
- [VERDICT-BROKER.md](harness/ref/VERDICT-BROKER.md): исторический вердикт исходного Unix-PoC (56/56).
- [harness/ref/README-PROTOTYPE.md](harness/ref/README-PROTOTYPE.md): топология стенда, пререквизиты, отклонения.

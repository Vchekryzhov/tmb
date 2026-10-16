# TMB broker prototype: PROTOTYPE, throwaway PoC

> **ПРОТОТИП / PROTOTYPE.** Одноразовый код для проверки архитектуры. Не продакшен, не безопасен для реального использования как есть. В текущей ветке исходники находятся в `src/`, сценарные проверки и образы в `harness/`.

Документ описывает текущие стенды; команды ниже выполняются из корня репозитория. Исходный Unix-PoC сохранён на ветке `prototype/tmb-broker` в каталоге `prototype/tmb-broker/`; его результаты: историческая основа [VERDICT-BROKER.md](VERDICT-BROKER.md). Актуальный итог связки с OpenShell: [VERDICT-OPENSHELL.md](../../VERDICT-OPENSHELL.md).

## Вопрос, на который отвечает прототип

Может ли привилегированное выполнение команд агентом идти через **отдельный брокер** (без единого изменения в sudo/sudoers/PAM) так, чтобы:

- одобрение человека привязывалось к **точному** запросу (абсолютный путь, упорядоченный `argv`, cwd, uid, env, nonce);
- команда запускалась **ровно один раз** (one-shot токен, погашаемый до запуска, с сохранением состояния при перезапуске);
- при смерти брокера путь агента **закрывался** (fail closed), а обычный человеческий `sudo` продолжал работать, не затронутый ничем?

Исходный Unix-PoC подтвердил 56/56 проверок (см. [VERDICT-BROKER.md](VERDICT-BROKER.md)). Текущая N-серия `bash harness/run.sh` даёт 77/77, включая привязку одобрения к идентичности запросчика и харденинг запуска (N11/N12); лог создаётся в `harness/last-run.log`.

## Схема

```
+---------------------------+          +--------------------------------------+
| sandbox-sim container     |          | host-sim container                   |
| uid 4242, --network none  |          | tmb-broker as root                   |
|                           |          |                                      |
| +-----------------------+ |  request |  +--------------------------------+ |
| | Агент                 | |          |  | 1. SO_PEERCRED: uid в allowlist| |
| |                       | |          |  +--------------------------------+ |
| +-----------+-----------+ |          |                 |                    |
|             |             |          |                 v                    |
| +-----------v-----------+ |          |  +--------------------------------+ |
| | tmb client CLI        | |          |  | 2. approval (y/n на консоли    | |
| | НИЧЕГО не исполняет;  | |          |  |    брокера / mock-approve /    | |
| | резолвит в abs path,  +-------------->|    mock-deny / mock-timeout)   | |
| | строит точный запрос  | |  unix    |  +--------------------------------+ |
| +-----------------------+ |  socket  |                 |                    |
|                           | /run/tmb |                 v                    |
|                           | /tmb.sock|  +--------------------------------+ |
|                           |  0660    |  | 3. one-shot токен (sha256 от   | |
|                           | root:4242|  |    точного запроса), TTL 60s   | |
|                           |          |  +--------------------------------+ |
|                           |          |                 |                    |
|                           |          |                 v                    |
|                           |          |  +--------------------------------+ |
|                           |          |  | 4. РОВНО ОДИН execve:          | |
|                           |          |  |    abs path, без sh -c, без    | |
|                           |          |  |    PATH-поиска; env только из  | |
|  stdout/stderr/exit code  +--------------+ allowlist брокера; realpath+    | |
| <-------------------------+ |          |  | dev/ino пин; stdin=/dev/null; | |
|                           |          |  |    токен+nonce гашены          | |
|                           |          |    O_CREAT|O_EXCL+fsync до запуска|
|                           |          +--------------------------------------+ |
|                           |          | JSONL-лог /var/log/tmb/broker.log    |
+---------------------------+          +--------------------------------------+
```

Контейнеры делят **только** unix-сокет через named volume `/run/tmb`. Ни docker.sock, ни host-mounts, ни `--privileged`; sandbox без сети. Человеческий `sudo -S id` в host-sim работает как обычно: TMB его не касается.

## Как запустить

```bash
# из корня репозитория: N-серия (Unix-путь)
bash harness/run.sh          # сборка образов, матрица, harness/last-run.log
```

Требования: Docker (проверено на 29.6.1, macOS arm64; контейнеры нативный Linux, поэтому SO_PEERCRED между ними работает). Раннер идемпотентный: сносит контейнеры и named-тома `tmb-poc-*-wipe-me`, пересобирает образы, прогоняет все сценарии, печатает таблицу PASS/FAIL и полное состояние брокера (JSONL-лог + claim store) после каждого сценария. Выход ненулевой, если что-то неожиданно. Время прогона: пара минут (TTL сокращён до 1–3 c вместо продакшен-минуты).

## Почему Go

- Один язык для клиента и брокера, stdlib-only (zero зависимостей, offline-сборка).
- `syscall.SysProcAttr`/`exec.Cmd` дают точный контроль над execve: прямой `Path` без PATH-поиска, `Args` дословно, `Env` пересобирается с нуля, `ExtraFiles=nil` + CLOEXEC по умолчанию, поэтому сокет не утекает в ребёнка.
- `SO_PEERCRED` через `GetsockoptUcred`, статические бинарники (CGO_ENABLED=0).

## Mock vs manual одобрение

- `manual`: брокер печатает на **своей** консоли точный запрос (uid/pid requester'а, executable с realpath+dev/ino, argv, cwd, uid, env, nonce) и читает y/n со stdin. `harness/run.sh` подаёт ответы через FIFO: это автоматическая проверка консольного пути, не подтверждение участия человека.
- `mock-approve` / `mock-deny` / `mock-timeout`: детерминированные заглушки для автотестов: одобрить / отказать / «человек не ответил» (истекает TTL). Режим задаётся флагом брокера `-approval ...`.

## Границы текущего прототипа

- **Подписи разрешений / Touch ID**: одобрение это y/n на консоли или mock; подписи разрешений нет. mTLS защищает транспорт песочница→брокер.
- **Удалённое одобрение на Mac**: будущая работа; существующий mTLS-канал связывает tmb-клиент с брокером, а не с удалённым UI одобрения.
- **Интеграция с OpenShell**: реализована отдельным стендом ниже. OpenShell изолирует агента и контролирует сетевой доступ; запросы отправляет tmb-клиент, одобрение и выполнение остаются в TMB. OpenCode это базовый образ этого стенда, не требование протокола; автономная работа агента с LLM не проверяется.
- **Жёсткие гарантии env/cwd**: allowlist ключей env есть, но cwd не ограничивается политикой, symlink-гонки cwd не закрыты (см. риски в VERDICT).
- **Упаковка**: нет systemd-юнитов, ротации лога, GC claim-файлов.
- **Принимающий хост**: брокер проверен только в Linux-контейнере host-sim внутри Docker Desktop VM. Его Unix-путь использует Linux SO_PEERCRED; запуск брокера на настоящем macOS-хосте не подтверждён.

## Исходники

- `src/cmd/tmb/`: клиент (не исполняет запрошенную команду на хосте; `exec`, плюс debug `approve`/`claim`/`raw` для двухфазных/враждебных запросов).
- `src/cmd/tmb-broker/`: брокер: `broker.go` (SO_PEERCRED, approval, claim), `exec.go` (единственный execve + сборка env), `store.go` (O_EXCL+fsync claim store), `log.go` (JSONL), `config.go`, `main.go`.
- `src/internal/proto/proto.go`: length-prefixed JSON-фреймы, канонический хэш запроса, токен/nonce.
- `harness/images/`: Dockerfile.host (ubuntu:24.04 + нетронутый sudo + `human`-юзер), Dockerfile.sandbox (ubuntu:24.04, uid 4242, без sudo), config.json (политики).
- `harness/run.sh`: N-серия; `harness/run-pair.sh`: mTLS-проверки; `harness/run-openshell.sh`: OpenShell-стенд; `harness/run-all.sh`: полный прогон. Логи создаются рядом со скриптами.

## OpenShell-обвязка ([#8](https://github.com/Vchekryzhov/tmb/issues/8), [#9](https://github.com/Vchekryzhov/tmb/issues/9), [#10](https://github.com/Vchekryzhov/tmb/issues/10)): песочница с одним правилом достаёт брокер

`harness/run-openshell.sh` поднимает связку с нуля одним скриптом на macOS + Docker Desktop и прогоняет O0–O6: исходную обвязку [#8](https://github.com/Vchekryzhov/tmb/issues/8), политику как выключатель [#9](https://github.com/Vchekryzhov/tmb/issues/9), отказ при смерти брокера и консольное одобрение [#10](https://github.com/Vchekryzhov/tmb/issues/10). Последний зафиксированный прогон: 65/65; лог создаётся в `harness/last-openshell-run.log`. O7–O9 проверяет `harness/run-pair.sh`. Полный сценарный план O-серии в спеке [#5](https://github.com/Vchekryzhov/tmb/issues/5).

### Топология

```
Mac (host)
 └─ openshell gateway: нативный бинарник brew, слушает *:17670 (mTLS),
     конфиг ~/.config/openshell/gateway.toml
 └─ Docker Desktop VM (linux/arm64)
     ├─ host-sim (tmb-osh-host): tmb-broker as root
     │    TLS-листенер :17600, порт опубликован -p 17600:17600
     │    на ВСЕХ интерфейсах VM (docker-proxy на 0.0.0.0)
     ├─ supervisor-контейнер песочницы (host network, uid 65534):
     │    медирует ВЕСЬ egress песочницы
     ├─ tmb-osh-gwreach (host network): socat 127.0.0.1:17671
     │    -> host.docker.internal:17670 (дверь супервизоров к gateway на Mac)
     └─ sandbox-контейнер (NET=none, uid 1000, Landlock, deny-by-default):
          образ opencode (digest) + openssl + статический tmb
          единственное сетевое правило: protocol: tcp, tls: skip
          -> host.openshell.internal:17600
```

### Почему `host.openshell.internal` резолвится и попадает на брокер

Docker-драйвер OpenShell пинит зарезервированный алиас `host.openshell.internal` в адрес, выведенный из `grpc_endpoint`, и этот endpoint обязан быть IPv4/localhost-строкой: именной endpoint (как `host.docker.internal`) оставляет алиас без пина, и policy DNS отказывает с `policy_dns_trusted_gateway_unavailable`. Нативный gateway живёт на Mac, а супервизоры в VM, поэтому между ними нужен форвардер:

- `~/.config/openshell/gateway.toml`: `grpc_endpoint = "https://127.0.0.1:17671"` (скрипт патчит сам, бэкап `gateway.toml.pre-tmb8.bak`; SAN `127.0.0.1` уже есть в локальном сертификате gateway);
- форвардер `tmb-osh-gwreach` (socat) слушает loopback VM :17671 и ходит на `host.docker.internal:17670` = gateway на Mac. Живёт на другом порту (17671), потому что Docker Desktop проксирует host-networked слушатели VM на localhost Mac: форвардер на :17670 зациклился бы сам на себя.

Итог: policy DNS песочницы отвечает на `host.openshell.internal` адресом loopback VM (супервизор сам открывает соединение, получатель видит адрес супервизора), а опубликованный `-p 17600:17600` порт брокера отвечает на loopback VM. Egress песочницы закрыт deny-by-default, кроме ровно одного правила.

### Пререквизиты и пины

- Docker Desktop: host networking ВКЛ, Enhanced Container Isolation ВЫКЛ (скрипт проверяет оба флага в `settings-store.json`, провал = прогон не стартует);
- openshell 0.1.3 (`OPENSHELL_VERSION` в скрипте);
- базовый образ агента `ghcr.io/anomalyco/opencode` пиннем DIGEST'ом (`OPENCODE_IMAGE_REF`, linux/arm64-манифест `:latest`, резолвлен 2026-10-09; тот же digest в `FROM` images/Dockerfile.opensbx; скрипт сверяет локальный образ с пином);
- gateway запущен один на Mac (brew services; скрипт его не дублирует, при необходимости перезапускает после патча конфига).

### Доставка сертификатов в песочницу

Способ (фиксируем один): клиентский сертификат+ключ и CA **выпекаются в кастомный образ песочницы** (второй build-этап с контекстом из временного каталога прогона, файлы в `/usr/share/tmb/certs/`, режим 0644), а `--env` при create передаёт только ПУТИ: `TMB_ADDR=host.openshell.internal:17600`, `TMB_CA=/usr/share/tmb/certs/ca.crt`, `TMB_CERT=.../client1.crt`, `TMB_KEY=.../client1.key`. CA-ключ никогда не попадает ни в образ, ни в контейнер.

Риск (осознанный, прототип): клиентский ключ проката живёт в локальном образе Docker до конца прогона (cleanup делает `docker rmi` per-run тега); однокомнатная песочница (uid 1000, файлы certs читает любой локальный процесс песочницы, а их там один). Альтернатива `--upload` держала бы ключ вне слоёв образа, но связывает доставку с filesystem-политикой рабочей директории; для PoC выбрана простота. Продакшен-решение (секрет-стор / короткоживущие сертификаты) вне скоупа.

### Политика как выключатель ([#9](https://github.com/Vchekryzhov/tmb/issues/9)): hot-reload правил и рестарт gateway

Тикет [#9](https://github.com/Vchekryzhov/tmb/issues/9) доказывает, что доступ агента к брокеру управляется политикой песочницы, а не кодом клиента. Все сценарии гоняются на ОДНОЙ живой песочнице из [#8](https://github.com/Vchekryzhov/tmb/issues/8); между сценариями крутится ровно одна ручка: `network_policies` (hot-reload, песочница не пересоздаётся).

**Жизненный цикл правила**: всегда полная замена политики с сохранённой filesystem-секцией (рецепт как при первом hot-add):

```bash
openshell policy get <sbx> --full -o json > live.json   # fs-секция + текущие правила
# python-merge: live.json -> next.json (меняется только network_policies)
openshell policy set <sbx> --policy next.json --wait    # hot-reload на живую песочницу
```

Три состояния, которые переключает харнесс (`policy_set_net` в скрипте):

- `single`: ровно одно правило `tmb`: endpoint брокера `host.openshell.internal:17600` (tcp, tls: skip), binary `/usr/local/bin/tmb`;
- `two`: то же правило со вторым endpoint `:19999` (положительный контроль O1b);
- `none`: пустая `network_policies` (fs-секция цела), deny-by-default везде, изъятие правила O2b.

Наблюдаемое поведение этапа [#9](https://github.com/Vchekryzhov/tmb/issues/9) (41/41, до добавления O5/O6 в [#10](https://github.com/Vchekryzhov/tmb/issues/10)):

- **Порт есть, правила нет (O1a/O1c/O4)**: супервизор режет соединение на proxy-этапе: клиент видит `dial tcp 198.18.0.2:19999: connect: permission denied`, exit 3, `FAIL CLOSED`; одноразовый `nc -l -p 19999` в host-sim не получает ни байта.
- **Правило есть, но на том конце не брокер (O1b)**: соединение проходит, nc получает TLS ClientHello (1463 байт в прогоне), рукопожатие умирает (i/o timeout 5 c у клиента). Клиент всё равно exit 3 `FAIL CLOSED`, но это транспортная ошибка, а не отказ брокера. Без этого положительного контроля O1a доказывал бы лишь «порт никто не слушает».
- **Правило изъято целиком (O2b/O4)**: policy DNS перестаёт резолвить алиас, клиент видит `lookup host.openshell.internal ... server misbehaving`, exit 3 `FAIL CLOSED`; в JSONL брокера не появляется события `request`, маркер `/tmp/o2-marker` в host-sim не создаётся.
- **Правило возвращено (O2c)**: та же живая песочница, без пересоздания, `tmb exec` снова exit 0.

**Рестарт gateway (O4)**. Чистый перезапуск: `brew services restart openshell` (без kill -9; форвардер `tmb-osh-gwreach` живёт отдельно и переживает рестарт). Наблюдение прогона: **песочница ПЕРЕЖИЛА рестарт** (`sandbox get` остаётся Ready, супервизор переподключился к gateway сам), политика и deny-by-default сохранились: повтор O1a → exit 3 (ноль байт), повтор O2a → exit 0, изъятие правила → exit 3. Источник истины по политике: состояние песочницы на стороне gateway, а не процесс песочницы. Репорт [#8](https://github.com/Vchekryzhov/tmb/issues/8) опасался, что рестарт дропает бегущие песочницы; в этом прогоне дропа не было. Если песочница исчезла, скрипт пересоздаёт её и заново добавляет правило, но явно выводит `WARN … policy persistence NOT PROVEN`: повторные проверки после пересоздания не доказывают сохранение политики через рестарт. Факт «survived/dropped» печатается в лог прогона.

### Отклонения от спеки/ADR (и почему)

1. **Песочница создаётся БЕЗ политики, правило добавляется горячей загрузкой** (`openshell policy set` сразу после create). Причина: `sandbox create --policy <файл>` на OpenShell 0.1.3 + Docker Desktop ломается upstream (workload spawn `Permission denied` в proxy-режиме, воспроизводится минимальной политикой `version: 1`). Hot-add это путь, который ADR 0003 прямо предвидит («TCP-endpoint добавляется в живую песочницу без пересоздания»); deny-by-default сохраняется: до загрузки правила egress полностью закрыт встроенной политикой.
2. **Правило применяется полной заменой политики** (`policy set` с сохранённой filesystem-секцией), а не `policy update --add-endpoint`, потому что CLI-строка endpoint не выражает `tls: skip` (в опциях CLI его нет), а ADR требует именно `tcp` + `tls: skip`.
3. **Форвардер `tmb-osh-gwreach`** (см. выше): локальная инфраструктура стенда, не часть TMB; существовала бы и при create-time политике.
4. **`netcat-openbsd` добавлен в образ host-sim + published-порт `-p 19999:19999`** (тикет [#9](https://github.com/Vchekryzhov/tmb/issues/9)): одноразовый контроль-листенер O1 должен жить на том же опубликованном интерфейсе VM, что и брокер. Изменение аддитивное, общий с `run-pair.sh` образ не ломает (лишний пакет); `run.sh`/`run-pair.sh` не тронуты.

### Как воспроизвести

```bash
# пререквизиты: Docker Desktop (host networking on, ECI off), openshell
# 0.1.3, запущенный gateway (brew services start openshell)
bash harness/run-openshell.sh     # всё с нуля; лог: harness/last-openshell-run.log
```

Скрипт идемпотентный: перед прогоном сносит остатки прошлых прогонов (sandboxes `tmb8-*`/`tmb-osh-sbx-*`, контейнер host-sim, per-run образ), поднимает сертификаты/образы/топологику, гоняет сценарии, печатает таблицу PASS/FAIL, выходит 0 только при полном зелёном. Cleanup-ловушка удаляет: песочницу, host-sim, named-тома, per-run образ с сертификатами, форвардер. Между прогонами gateway.toml остаётся с `grpc_endpoint = "https://127.0.0.1:17671"`: следующий прогон (и [#9](https://github.com/Vchekryzhov/tmb/issues/9)) поднимает форвардер заново; откат к исходному состоянию: вернуть `gateway.toml.pre-tmb8.bak` и `brew services restart openshell`.

Ключевые команды топологии (для чтения, не для ручного повтора):

```bash
# песочница (блок-режим; окружение передаётся путями к файлам в образе)
openshell sandbox create --name tmb8-... --from tmb-osh-sbx:<run> \
  --env TMB_ADDR=host.openshell.internal:17600 \
  --env TMB_CA=/usr/share/tmb/certs/ca.crt \
  --env TMB_CERT=/usr/share/tmb/certs/client1.crt \
  --env TMB_KEY=/usr/share/tmb/certs/client1.key \
  --detach -- sleep infinity
# единственное правило (полная политика с сохранённой fs-секцией):
#   network_policies: { tmb: { endpoints: [ { host: host.openshell.internal,
#     port: 17600, protocol: tcp, tls: skip } ],
#     binaries: [ { path: /usr/local/bin/tmb } ] } }
openshell policy set tmb8-... --policy policy-tmb.json --wait
# сценарный seam O-серии:
openshell sandbox exec tmb8-... --no-login-shell -- tmb exec --root -- /usr/bin/id -u
```

# Вердикт по майлстоуну B «эксплуатация»

Прототип, throwaway PoC. Решение: [ADR 0005](docs/adr/0005-requester-identity-by-public-key.md). Спека: [#39](https://github.com/Vchekryzhov/tmb/issues/39) с тикетами #40–#45, зонтик [#4](https://github.com/Vchekryzhov/tmb/issues/4). Источник решений: [итоги грила 2026-10-17](docs/design/grill-results-stage2.md).

Прогон: четыре харнесса на коммите `main` после PR [#80](https://github.com/Vchekryzhov/tmb/pull/80), по частям (см. отклонение 1). OpenShell-риг владелец прогнал 2026-10-31 21:11 UTC; N-серия, docker-pair и VM-пруф прогнаны следом той же ночью.
Стенд: macOS 26.5.2 arm64, Docker Desktop, docker 29.6.1 (контейнеры linux/arm64 в VM Docker Desktop), openshell 0.1.3, Lima 2.2.1 с гостем Ubuntu 24.04 LTS arm64 (образ закреплён по digest).
Логи: `harness/last-run.log` (N-серия), `harness/last-pair-run.log` (docker-pair), `harness/last-openshell-run.log` (OpenShell-риг), `harness/last-vm-run.log` (VM-пруф).

Итог: **N=195/195, pair=112/112, openshell=65/65, vm=114/114. Все четыре части GREEN, каждый runner вышел с кодом 0.**

Доказано на стенде:

- идентичность песочницы это отпечаток её открытого ключа: два сертификата на один ключ дают один `requester_fp` в журнале и на показе одобрения, allowlist не трогается; другой ключ с тем же Subject получает `requester_not_allowed`;
- приватный ключ рождается в песочнице командой `tmb keygen` и наружу уходит только открытый ключ: PAIR-KEY и V3 не находят приватного ключа песочницы на хосте (там лежат только ключи самого хоста: серверный ключ брокера и ключ CA);
- сертификаты выпускает CA внутри `tmb-broker`: CA на 10 лет с ключом 0600 под root, серверный на 1 год с нужным SAN, песочницы на 7 дней; истёкший сертификат песочницы даёт `tls_handshake_failed` без `deny` и без `request`;
- SIGHUP (на хосте `systemctl reload`) перечитывает allowlist и TLS-материал из одного снимка, сокеты и pid остаются, очередь и pending-одобрение переживают reload, невалидный конфиг оставляет старый, поле `tls_addr` не перезагружается и объявляется событием `reload_ignored_field`;
- журнал открывается заново по SIGHUP, недоступный журнал закрывает агентный путь отказом `audit_unavailable` и ничего не запускает, каждая строка несёт `schema`, пакетный logrotate с `postrotate` работает под настоящим systemd и `tail -F` видит события после ротации;
- пакет deb ставится на Ubuntu 24.04 с systemd: без конфига unit остаётся failed с понятной причиной в журнале systemd, с конфигом стартует, `systemctl kill -s KILL` закрывает агентный путь (exit 3), `Restart=on-failure` поднимает сервис, `systemctl restart` не убивает одобренную команду (`KillMode=process`), `apt remove` оставляет конфиг, состояние и журнал.

## Что изменилось по тикетам

| Тикет | PR | Что |
|-------|----|-----|
| [#40](https://github.com/Vchekryzhov/tmb/issues/40) | [#53](https://github.com/Vchekryzhov/tmb/pull/53), [#61](https://github.com/Vchekryzhov/tmb/pull/61) | `tmb-broker ca init \| issue-server \| issue-sandbox`, stdlib, PEM; ключ CA создаётся эксклюзивно и удаляется при неудачном `init` |
| [#41](https://github.com/Vchekryzhov/tmb/issues/41) | [#57](https://github.com/Vchekryzhov/tmb/pull/57) | `allowed_requester_keys` вместо `allowed_requester_fps`, отпечаток SPKI, `tmb keygen` и `tmb fingerprint`, показ одобрения печатает `requester : key fp=…` |
| [#42](https://github.com/Vchekryzhov/tmb/issues/42) | [#60](https://github.com/Vchekryzhov/tmb/pull/60) | reload по SIGHUP из атомарного снимка, события `reload`, `reload_failed`, `reload_ignored_field`, TLS через `GetCertificate` |
| [#43](https://github.com/Vchekryzhov/tmb/issues/43) | [#65](https://github.com/Vchekryzhov/tmb/pull/65), [#73](https://github.com/Vchekryzhov/tmb/pull/73) | fsync на событие, `audit_unavailable`, reopen по SIGHUP, поле `schema` и [docs/audit-schema.md](docs/audit-schema.md) с тестом против кода; схема поднята до `2` |
| [#44](https://github.com/Vchekryzhov/tmb/issues/44) | [#66](https://github.com/Vchekryzhov/tmb/pull/66) | nfpm: deb и rpm `tmb-broker` и `tmb` для amd64 и arm64, unit, `config.json.example`, logrotate, tmpfiles, релиз по тегу |
| [#45](https://github.com/Vchekryzhov/tmb/issues/45) | [#67](https://github.com/Vchekryzhov/tmb/pull/67) | `harness/run-vm.sh`, V-серия V0–V9 на Lima, реестр `ci/scenarios/v-series.txt`, `run-all.sh --vm` |
| [#68](https://github.com/Vchekryzhov/tmb/issues/68) | [#80](https://github.com/Vchekryzhov/tmb/pull/80) | скрипт с `#!` отклоняется кодом `executable_script` до показа одобрения и повторно при предъявлении токена (claim): иначе интерпретатор получал бы уже закрытый `/proc/self/fd/N` |
| [#69](https://github.com/Vchekryzhov/tmb/issues/69) | [#80](https://github.com/Vchekryzhov/tmb/pull/80) | digest образа opencode берётся только из `FROM` в `Dockerfile.opensbx`, риг и VM-пруф сверяются с ним |

## Реестр новых сценариев

Обозначения: `host` = `docker exec` в host-sim, `sbx` = `docker exec` в sandbox-sim, `human` = пользователь host-sim из `approver_uids`; в V-серии `vm` = команда через `limactl shell`, `sbx` = `openshell sandbox exec`, `human` = одобряющий во второй сессии `limactl shell`.
N24, N28 и N29 идут в `harness/run.sh`; N23, N30, PAIR-KEY, N25, N26 и N27 в `harness/run-pair.sh` (им нужен TLS-листенер); V0–V9 в `harness/run-vm.sh`.

| # | Сценарий | Ожидание | Наблюдение | Результат |
|---|----------|----------|------------|-----------|
| N23 | идентичность по ключу | два сертификата на один ключ → один `requester_fp` в JSONL и на показе одобрения (`tmb approve --list`), allowlist не менялся; другой ключ с тем же Subject → 125 `requester_not_allowed` | `ca issue-sandbox` напечатал тот же отпечаток; показ одобрения дал `key fp=adfff17ad6d663fa` для обоих сертификатов, оба запроса exit 0, оба `queued` с `requester_fp=fp1`; client4 → 125, `requester_denied` с его отпечатком; хэш конфига не изменился | PASS |
| N24 | старый конфиг и флаги | `allowed_requester_fps` → брокер не стартует, stderr называет поле и замену; `-tls-ca` → неизвестный флаг | exit 1, stderr содержит `allowed_requester_fps` и `allowed_requester_keys`; `-tls-ca` → exit 2, `flag provided but not defined` | PASS |
| N25 | reload allowlist | отпечаток удалён, SIGHUP → `reload`, следующий запрос 125 `requester_not_allowed`; возвращён, SIGHUP → проходит; pid и иноды сокетов те же | `reload` с `changed:["allowed_requester_keys"]`; 125 и затем exit 0 со stdout `0`; pid 742 и иноды сокетов не изменились | PASS |
| N26 | reload невалидный | синтаксическая ошибка → `reload_failed`, старый allowlist действует; смена `tls_addr` → `reload_ignored_field`, старый порт слушает | `reload_failed`, stderr `reload failed, keeping the running config`, события `reload` нет; fp1 → 0, fp2 → 125; один `reload_ignored_field` с `field=tls_addr`; порт 17600 отвечает, 17601 → exit 3 | PASS |
| N27 | reload сертификата | после SIGHUP новое соединение видит новый серийный номер, открытое до reload соединение дорабатывает на старом | до reload серийный `89F0…476A`; `reload` с `tls_material`; новое соединение видит `CC3C…8E32`; `sleep 4`, запущенный до reload, завершился с exit 0 на старом серийном | PASS |
| N28 | reload с очередью | запрос в очереди переживает SIGHUP и одобряется после; токен одобрения, полученный до SIGHUP, предъявляется после | тот же элемент `b09b96d0af62cb57` в очереди после reload, `approve --yes` → exit 0, запрос exit 0 со stdout `0`; токен `1f5590127cecf71b` получен до второго SIGHUP и предъявлен после; pid 1559 тот же | PASS |
| N29 | журнал | переименование плюс SIGHUP → новый файл, старый не растёт; каталог 0500 и файл удалён, SIGHUP → `audit_unavailable`, команда не выполнена, причина в stderr; права назад, SIGHUP → запросы проходят; `schema` в каждой строке | брокер без `CAP_DAC_OVERRIDE` (CapEff `a80425f9`); новый файл с `reload`, старый остался 73833 байта; запрос → 125 `audit_unavailable`, маркер не создан, файл журнала не появился, stderr `journal unavailable … permission denied`; после chmod и SIGHUP `accepting requests again`, exit 0; каждая строка обоих файлов и stderr-резерва несёт `"schema":2` | PASS |
| N30 | истёкший сертификат | `tls_handshake_failed`, в JSONL нет `deny` и `request` | клиент exit 3; `tls_handshake_failed` с `certificate has expired or is not yet valid`; счётчики `request` и `deny` не изменились | PASS |
| PAIR-KEY | ключ рождается в песочнице | `tmb keygen` в sandbox-sim, наружу только открытый ключ, host выпускает сертификат, приватного ключа на хосте нет, запрос проходит | ключ 0600, в выводе keygen нет `PRIVATE KEY`; отпечатки keygen, CA и `tmb fingerprint` совпали; запрос exit 0 со stdout `0`; `grep -rlI` по host-sim нашёл только `/etc/tmb/certs/server.key` | PASS |
| V0 | пререквизиты | Lima 2.x, гость Ubuntu 24.04 LTS aarch64 с systemd PID 1, deb текущего коммита, Docker в VM, openshell 0.1.3, digest песочницы равен digest рига; провал любого = прогон не стартует | limactl 2.2.1; Ubuntu 24.04.5 LTS, ядро 6.8.0-142; deb `0.0.0~dev+cdcca660b597-1`; docker 29.1.3; openshell 0.1.3; digest `f4cfe16…` совпал; VM создана и провижена за 42 с, каталоги Mac не смонтированы | PASS |
| V1 | установка и старт | `dpkg -i` ставит бинарники, unit, `config.json.example`, logrotate, tmpfiles и не включает сервис; `systemctl start` без конфига → failed с причиной в journald; с конфигом → active, сокеты в `/run/tmb`, `broker_start` в журнале | все шесть файлов на месте, сервис `disabled`, `config.json` не поставлен; без конфига `start` → exit 1, unit `failed`, journald `/etc/tmb/config.json not found`; с конфигом active, `tmb.sock` и `approve.sock` есть, `broker_start` записан | PASS |
| V2 | CA и reload сертификата | `ca init` → ключ 0600 root, сертификат ~10 лет; `ca issue-server` → 1 год с SAN `host.openshell.internal`; перевыпуск плюс `systemctl reload` → листенер отдаёт новый серийный, pid тот же | ключ `0600 root`, сроки сошлись; после рестарта с `tls_addr` листенер отдаёт `C3F2…C38D`; `reload` с `tls_material`; после reload серийный `8563…B087`; pid 9017 сохранён | PASS |
| V3 | анроллмент по ключу | `tmb keygen` в песочнице OpenShell, наружу открытый ключ, `ca issue-sandbox` печатает отпечаток, 7 дней; отпечаток в allowlist, `systemctl reload`; запрос ждёт одобрения; `tmb approve --yes` из второй сессии → stdout `0` | ключ 0600, в выводе нет приватного ключа; отпечаток `836e…f87b` одинаков у keygen, CA и `tmb fingerprint`; на хосте нет чужих приватных ключей; `reload` с `allowed_requester_keys`; элемент `fcee07b3903f2b9d` ждал, `queued` с тем же `requester_fp`; human (uid 1000) увидел и одобрил; exit 0, stdout `0` | PASS |
| V4 | перевыпуск | `ca issue-sandbox` на тот же ключ → тот же отпечаток, новый серийный; allowlist не тронут, reload не нужен; запрос проходит с тем же `requester_fp` | тот же отпечаток, серийный `F8DD…0E28` вместо `BE06…6CD0`; хэш `config.json` не изменился; exit 0, stdout `0`, `request` с `requester_fp` `836e…f87b` | PASS |
| V5 | отзыв | отпечаток удалён, `systemctl reload` → 125 `requester_not_allowed`, `requester_denied` с отпечатком, очередь пуста | всё так; `tmb approve --list` → `queue is empty` | PASS |
| V6 | ротация журнала | `logrotate --force` с пакетным конфигом → старый файл переименован, новый 0600, `postrotate` reload пишет в новый, события продолжаются, `tail -F` видит их | `journal.jsonl.1` с той же инодой, новый `journal.jsonl` 0600, `reload` в новом файле, `broker_start` только в старом; запрос после ротации exit 0, его события в новом файле и в выводе `tail -F` вместе с `exec_exit` | PASS |
| V7 | fail-closed на хосте | `systemctl kill -s KILL` при ждущем запросе → клиент exit 3, ничего не выполнено; `Restart=on-failure` поднимает сервис; `sudo -S id` человека → `uid=0(root)`; в `/etc/sudo.conf` 0 строк `Plugin` | exit 3, `connection to broker lost`, для элемента `0cdc0d6a8ec610b5` нет `exec_start`; pid 9017 → 11364, NRestarts 0 → 1; sudo дал `uid=0(root)`; 0 строк `Plugin`; новый брокер снова обслужил песочницу | PASS |
| V8 | рестарт не убивает одобренное | одобренная команда на 30 с с маркером по завершении; `systemctl restart` → брокер active с новым pid, команда жива, маркер появляется | `exec_start` без `exec_exit`, рестарт exit 0, новый pid 11807, `pgrep` видит процесс после рестарта, маркер появился через 28 с | PASS |
| V9 | удаление | `apt remove` → бинарник и unit удалены, брокер не работает; конфиг, ключ CA, серверный сертификат, `/var/lib/tmb`, оба файла журнала на месте | всё так | PASS |

Счёт по частям:

- N-серия (Unix/SO_PEERCRED): **195/195**: 159 проверок майлстоуна A плюс N24, N28, N29 и проверки ревью (#73).
- docker-pair: **112/112**, включая N23, N30, PAIR-KEY, N25–N27 и regression-повтор N-серии внутри `run-pair.sh`.
- OpenShell-риг: **65/65** (O0–O6), прогон владельца 2026-10-31 на digest opencode `f4cfe16…`.
- VM-пруф: **114/114** (V0–V9) на Lima с настоящим systemd.

Каждый id реестров `ci/scenarios/n-series.txt`, `pair.txt` и `v-series.txt` объявлен секцией своего скрипта (тест `TestRegistriesMatchRunners` проверяет только это включение). Обратное, что у скрипта нет секций вне реестра, проверяет сверка лога с реестром при прогоне (`Verify` в `ci/internal/harness`), а для `run-vm.sh` ещё и статический тест `TestVSeriesRegistryIsComplete`. `ci/security-manifest.json` покрывает идентичность по ключу (SEC-23: N23, N24, PAIR-KEY; SEC-06 расширен N30), reload (SEC-24: N25–N28), журнал (SEC-26: N29) и уровень `vm` (SEC-27: V6, SEC-28: V7).

## Отклонения от спеки

1. **Полный прогон собран из четырёх отдельных прогонов.** Спека ждёт одного `run-all.sh --vm`. OpenShell-риг требует разрешения macOS на чтение настроек Docker Desktop (TCC), его дал и прогнал владелец 2026-10-31 21:11 UTC на том же коммите `main`; N-серия, docker-pair и VM-пруф прогнаны следом без рига. `harness/last-full-run.log` поэтому не обновлялся и остался от прогона 2026-10-18 (без VM-части); цифры этого вердикта и README берутся из четырёх частных логов.
2. **Схема журнала поднята до `2`.** Спека вводила `schema: 1`; ревью [#73](https://github.com/Vchekryzhov/tmb/pull/73) подняло версию: полный nonce, `hash` в `request`, `deny` и `approval`, `client_gone` в `exec_exit`, отдельные поля идентичности одобряющего. N29 проверяет `"schema":2` в каждой строке.
3. **OpenShell gateway на Linux поднялся**, поэтому запасной вариант спеки (docker-pair внутри VM) не понадобился: V-серия идёт на OpenShell 0.1.3 с драйвером docker, песочница из образа opencode того же digest, что в риге, с одним сетевым правилом. Отличие от рига: gateway это пользовательский unit systemd внутри VM, без патча `gateway.toml` и без socat-форвардера.
4. **`tls_addr` в V2 задаётся рестартом.** Пример конфига из пакета не включает TLS-листенер; `tls_addr` это поле только для старта (N26 проверяет, что reload его игнорирует), поэтому V2 один раз делает `systemctl restart` после записи `tls_addr`, а смену серверного сертификата проверяет уже через `systemctl reload`.
5. **V8 запускает one-liner `python3 -c`.** Оболочки стоят в `shell_deny_list`, а скрипт с `#!` отклоняется с [#68](https://github.com/Vchekryzhov/tmb/issues/68); долгоживущая одобренная команда это one-liner python3 с маркером по завершении.
6. **V7 шлёт SIGKILL только главному процессу** (`systemctl kill --kill-whom=main`): с `--kill-whom=all` systemd сообщает об ошибке для уже завершившегося `ExecStartPre`-помощника.
7. **N29 запускает брокер под `setpriv` без `CAP_DAC_OVERRIDE` и `CAP_DAC_READ_SEARCH`**: иначе root в host-sim пишет в каталог 0500 и сценарий недоступного журнала не воспроизвести.
8. **Reload-сценарии docker-pair (N25–N27) держат конфиг и TLS-файлы в `/etc/tmb/reload` внутри host-sim**, записанные через `docker exec`, чтобы менять их и слать SIGHUP без новых монтирований.
9. **Сокет одобряющего**: на стенде N-серии он лежит в `/run/tmb-approver/` (том `/run/tmb` общий с sandbox-sim, см. VERDICT-A), в пакете и в VM по умолчанию `/run/tmb/approve.sock`.
10. **Одобряющий в VM создаётся с паролем `human` и правом sudo** только ради V7 (`sudo -S id` при убитом брокере); пакет пользователей не создаёт.

## Остаточные риски

- **Ключ песочницы читается любым процессом песочницы.** Он рождается внутри и не покидает её, но лежит файлом 0600 под пользователем песочницы, под которым работает и агент. Сертификат живёт 7 дней, но перевыпуск идёт на тот же ключ без правки allowlist (ADR 0005), поэтому украденный ключ годится, пока хост выпускает на него сертификаты, а сами сертификаты не секрет. Предел в 7 дней начинает действовать только после смены ключа: новый ключ в песочнице, новый отпечаток в allowlist, старый удалён. Секрет-стор или аппаратный ключ в скоуп не входят.
- **Удалённая из allowlist песочница предъявляет токен уже показанного одобрения внутри TTL.** Элемент очереди и pending-одобрение хранят идентичность и при reload не перепроверяются (решение спеки): следующий запрос получит `requester_not_allowed`, но токен одобрения, которое человек уже дал, предъявляется до истечения `token_ttl_seconds`.
- **Запись в ту же иноду исполняемого файла** между одобрением и exec: закрепление держит иноду, а её содержимое остаётся изменяемым. С [#68](https://github.com/Vchekryzhov/tmb/issues/68) переписывание в скрипт обнаруживается при предъявлении токена (claim); переписывание в другой ELF проходит незамеченным. Нужен immutable-носитель или подпись.
- **«Хост» это VM на Mac.** Lima с Ubuntu 24.04 и настоящим systemd ближе к хосту, чем контейнер Docker Desktop, но это всё ещё гость под Virtualization.framework на arm64; amd64, другие дистрибутивы и настоящее железо не проверялись. rpm ставится только в контейнере Fedora под `ci/run.sh package`, без systemd. Ручная проверка на omen это следующий шаг (пункт 35 спеки), не часть харнесса.
- **Отзыв это правка allowlist плюс reload.** CRL и OCSP не используются (ADR 0005), поэтому сертификат, выпущенный на удалённый ключ, остаётся формально действительным до истечения; его держит только allowlist.
- **Ключ CA лежит на хосте под root** (`/etc/tmb/ca/ca.key`, 0600). Root на хосте правит и allowlist, поэтому ключ CA не даёт отдельной границы против компрометации root. Сама подпись CA допускает к соединению и не даёт права просить (ADR 0003, ADR 0005).
- **VM-пруф идёт только локально.** В Actions нет Lima; CI проверяет закоммиченный `harness/last-vm-run.log` (`TestCommittedVMLogIsGreen`), и смена `run-vm.sh` или реестра требует нового локального прогона.
- **Пробелы доказательства.** Стенды проходят, но часть ожиданий проверена слабее, чем звучит в реестре:
  - V7 проверяет, что у убитого запроса нет события `exec_start`; след команды на диске не проверяется (запрошен `/usr/bin/id -u`, у которого его нет).
  - N29 считает строки без `"schema":2`; на пустом файле счёт равен нулю, и проверка проходит, ничего не проверив.
  - N23 «allowlist не менялся» это хэш файла конфига на стороне Mac, который монтируется в host-sim только для чтения: изменить его брокер не мог, поэтому проверка подтверждает, что не правил харнесс.
  - Предъявление токена удалённой из allowlist песочницей внутри TTL и запись в ту же иноду исполняемого файла остаются рисками без сценария на стенде.
  - Отказ `executable_script` из #80 проверяется Go-тестами (`validate_test.go`, этап одобрения и повторная проверка при предъявлении токена); сценария N-серии или V-серии для него нет.
  - CI сверяет с реестром только закоммиченный `harness/last-vm-run.log` (`TestCommittedVMLogIsGreen`) и принимает лог любого возраста; закоммиченные логи N-серии, docker-pair и OpenShell-рига CI не сверяет, их цифры держатся на этом вердикте.
  - Логи стендов содержат домашние пути Mac (`/Users/…`, временные каталоги); так было и в логах прежних вердиктов.
- **Открытый вопрос владельцу.** `executable_script` это новое правило политики запроса (отказ до показа одобрения), но у него нет ADR и статьи в [CONTEXT.md](CONTEXT.md). Вердикт это фиксирует и не решает, нужен ли ADR.
- Риски предыдущих вердиктов остаются: одобряющему нужен shell на хосте до [#3](https://github.com/Vchekryzhov/tmb/issues/3), токен не секрет, права cwd не проверяются.

## Как воспроизвести

Пререквизиты: как у [VERDICT-A.md](VERDICT-A.md) плюс Lima 2.x (`brew install lima`) для VM-части. Скрипту `run-openshell.sh` нужен доступ python3 к настройкам Docker Desktop: macOS спрашивает разрешение один раз.

```bash
bash harness/run-all.sh --vm
```

Выход 0 только если все четыре части зелёные; суммарный вердикт пишется в `harness/last-full-run.log`. Только VM-часть:

```bash
ci/run.sh vm
```

VM `tmb-vm` создаётся с нуля и удаляется при любом исходе (`TMB_VM_KEEP=1` оставляет её); каталоги Mac в VM не монтируются, порты не пробрасываются. Подробности: [docs/ci.md](docs/ci.md#vm-пруф).

## Вывод

Спека майлстоуна B выполнена: брокер ставится пакетом на хост с systemd, выпускает сертификаты собственным CA, узнаёт песочницу по её ключу и переживает перевыпуск без правки allowlist, перечитывает конфигурацию и TLS-материал без закрытия агентного пути, пишет журнал с fsync и схемой и закрывается при его недоступности. Механизмы прежних майлстоунов (одноразовый токен, привязка одобрения к идентичности, очередь одобрений, fail-closed) не регрессировали: N-серия, docker-pair и OpenShell-риг зелёные.

Зонтик [#4](https://github.com/Vchekryzhov/tmb/issues/4) закрывается: спека A доказана в [VERDICT-A.md](VERDICT-A.md), спека B в этом документе. Дальше: ручная установка на omen, подписант с Touch ID ([#2](https://github.com/Vchekryzhov/tmb/issues/2)), удалённое одобрение ([#3](https://github.com/Vchekryzhov/tmb/issues/3)).

## Ссылки

- [ADR 0005](docs/adr/0005-requester-identity-by-public-key.md): идентичность по открытому ключу, короткоживущие сертификаты.
- [Спека #39](https://github.com/Vchekryzhov/tmb/issues/39), [итоги грила](docs/design/grill-results-stage2.md).
- [docs/audit-schema.md](docs/audit-schema.md): схема журнала.
- [docs/ci.md](docs/ci.md): VM-пруф, пакеты, фазы CI.
- [VERDICT-A.md](VERDICT-A.md) и [VERDICT-OPENSHELL.md](VERDICT-OPENSHELL.md): предыдущие майлстоуны.

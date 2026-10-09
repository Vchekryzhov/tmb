# Вердикт по брокер-прототипу TMB — PROTOTYPE, throwaway PoC

Прогон: `./run.sh` от 2026-10-08, Docker 29.6.1 (macOS arm64, контейнеры —
нативный Linux). Полный лог: [last-run.log](last-run.log).
Итог: **56 PASS / 0 FAIL, RESULT: GREEN, runner exit 0.**

Архитектура подтверждена: привилегированное выполнение через отдельный брокер
работает и **не требует ни одного изменения в sudo/sudoers/PAM/sudo.conf**
(нулевой coupling с sudo). Убийство брокера закрывает агентский путь (fail
closed), человеческий password-sudo не задет.

## Сценарии (из реального прогона)

| # | Сценарий | Ожидание | Результат |
|---|----------|----------|-----------|
| 0 | Контейнеры: sandbox uid=4242, host uid=0, sandbox в сети `none` | старта без сети | PASS |
| H | `tmb exec --root -- /usr/bin/id -u` (mock-approve) | exit 0, stdout `0` | PASS |
| FD | ребёнок листает `/proc/self/fd` | fd0=`/dev/null`, ни одного `socket:` fd | PASS |
| M1 | manual: точный запрос на консоли брокера, человек `y` | exit 0, stdout `0` | PASS |
| M2 | manual: тот же показ, человек `n` | exit 125, `approval_denied_by_human` | PASS |
| N1 | токен от запроса A + `argv` запроса B | `token_binding_mismatch` | PASS |
| N2 | повторный claim того же токена | `token_consumed_replay`, ничего не исполнилось | PASS |
| TTL | claim после истечения TTL (3 c) | `no_pending_approval`, маркер не создан | PASS |
| N3a | mock-deny | exit 125, `approval_denied_by_mode`, маркер не создан | PASS |
| N3b | mock-timeout (TTL=1 c) | exit 125, `approval_timeout`, маркер не создан | PASS |
| N4 | `/bin/sh -c 'touch /tmp/pwned'` | `shell_policy` (realpath → `/usr/bin/dash`), `/tmp/pwned` отсутствует | PASS |
| N5a | `LD_PRELOAD` в окружении клиента | env ребёнка: только `PATH`+`LANG`, без `LD_PRELOAD` | PASS |
| N5b | явный `--env LD_PRELOAD=...` | `env_key_not_allowed`, отказ до approval | PASS |
| N6 | не-абсолютный executable (`id`, `./id`) | `executable_not_absolute` (брокер), локальный отказ (клиент) | PASS |
| N7 | клиент с uid 1000 (gid 4242) и uid 0 | SO_PEERCRED: `requester_not_allowed` обоим, даже root | PASS |
| N8 | байт-в-байт повтор запроса после `docker restart` host-sim | `token_consumed_replay` — погашение пережило рестарт (named volume) | PASS |
| N9a | брокер убит SIGKILL | клиент: exit 3, «FAIL CLOSED, nothing executed» | PASS |
| N9b | `sudo -S id` пользователем `human` в host-sim | `uid=0(root)` — sudo работает как раньше | PASS |
| N9c | `/etc/sudo.conf` | **0 строк `Plugin`**; `/etc/sudoers.d/` — стоковый README | PASS |

Точный текст показа запроса человеку (из консоли брокера, сценарий M1):

```
=== TMB APPROVAL REQUIRED ===
  requester : uid=4242 pid=0 (kernel SO_PEERCRED)
  executable: /usr/bin/id (realpath /usr/bin/id, dev=71 ino=3025125)
  argv      : ["/usr/bin/id","-u"]
  cwd       : /tmp
  run as uid: 0
  env       : {"LANG":"C.UTF-8"}
  nonce     : bea08c7e3eba2f1a68a249388650e17b
Approve exactly this command? [y/N]: HUMAN ANSWER: "y" -> APPROVED
```

## Fail-closed: доказательства

- Брокер убит SIGKILL → клиент получает connection refused, ретраит ≤3 c, выходит
  с кодом 3 и текстом «FAIL CLOSED, nothing executed». Команда не запускается.
- mock-deny / mock-timeout / отказ человека / просроченный токен / повтор
  токена / не тот argv / не-абсолютный путь / shell-denylist / посторонний env-ключ
  / посторонний uid — во всех случаях **до execve дело не доходит**, deny-коды
  стабильные, JSONL-лог фиксирует каждую попытку (`request`, `approval`,
  `claim`, `deny`, `exec_start`, `exec_exit`).
- Гашение токена/nonce — `O_CREAT|O_EXCL` + fsync файла и каталога **до**
  запуска; переживает рестарт контейнера (N8).

## Sudo не тронут: доказательства

- `/etc/sudo.conf` в host-sim: `grep -c "^Plugin"` → **0**.
- `/etc/sudoers.d/`: только стоковый `README`; образ собирается без правок
  sudoers/PAM (см. `images/Dockerfile.host` — только `apt-get install sudo`).
- `sudo -S id` под пользователем `human` возвращает `uid=0(root)` — обычный
  парольный путь человека жив при убитом брокере (N9b выполнен после N9a).

## Остаточные риски (почему это прототип)

- **stat→execve TOCTOU**: executable пинится realpath+dev+ino при approval и
  re-stat'ится при claim, но между последним stat и execве файл теоретически
  можно заменить (dev/ino совпадение не проверяется в момент execve). Продакшен:
  `fexecve`/открытый fd, или верификация в момент exec.
- **cwd symlink-гонки**: cwd realpath'ится дважды (approval, claim), но между
  claim и execve каталог можно подменить symlink'ом; политики на cwd нет
  (разрешён любой абсолютный каталог).
- **Один хост**: сокет и claim store локальны; удалённый транспорт, репликация
  состояния, multi-host — вне прототипа.
- Прочее: approval-bound TTL сейчас 3 c в конфиге PoC (продакшен — 60 c);
  claim-файлы не чистятся (GC нужен); `requester_pid` в логах = 0 — артефакт
  разных PID-namespace контейнеров (uid SO_PEERCRED при этом корректен и
  является авторитетным идентификатором).

## Вывод

Брокерная схема отвечает на вопрос прототипа положительно: точное одобрение,
ровно один запуск, погашение с сохранением состояния, fail-closed при смерти
брокера — и всё это с **нулевой** интеграцией в sudo. Следующие шаги (вне
прототипа): подписант с Touch ID, TCP/MCP-транспорт для OpenShell (см.
[RESEARCH-OPENSHELL.md](RESEARCH-OPENSHELL.md), вариант B), закрытие TOCTOU и
cwd-политик, упаковка.

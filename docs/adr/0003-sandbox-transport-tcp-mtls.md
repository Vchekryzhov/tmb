# ADR 0003: Транспорт песочницы - TCP endpoint (вариант B) с mTLS-идентичностью

Дата: 2026-10-09. Расширяет [ADR 0002](0002-standalone-tmb-broker.md): закрывает открытый в нём вопрос sandbox-слоя и транспорта.

## Контекст

ADR 0002 оставил слой песочницы вопросом MVP. Исследование OpenShell (RESEARCH-OPENSHELL.md) рекомендовало вариант B: единственный TCP endpoint, разрешённый одним правилом `network_policies`; вариант A (bind-mount unix-сокета) остался запасным, но он ослабляет admission песочницы (`enable_bind_mounts`), канал не медируется OpenShell вовсе, и socket-bind-mount не верифицирован в доках. PoC брокера живёт на unix-сокете с SO_PEERCRED, который на TCP не существует. ADR 0002 прямо требует аутентификацию beyond SO_PEERCRED как обязательную работу MVP.

Факты, закрывшие выбор (документация NVIDIA/OpenShell @ v0.1.x, коммит fe2dd3e): `protocol: tcp` - первоклассный тип сетевого правила (байтовый passthrough без инспекции, документированный пример - базы данных); `tls: skip` - документированный режим ровно для клиентских сертификатов («when the client must complete TLS itself, for example to present a client certificate»); супервизор сам открывает внешнее соединение, поэтому получатель видит адрес супервизора, а не песочницы - IP-идентичность невозможна на обоих концах.

## Решение

- Вариант B: брокер слушает TCP endpoint; в политике песочницы он разрешён ровно одним правилом `network_policies` c `protocol: tcp` и `tls: skip`. Весь остальной egress закрыт deny-by-default.
- Существующий протокол не меняется: length-prefixed JSON (4-байтовый big-endian заголовок) поверх TCP; framing и так транспортно-агностичен, go.mod остаётся без внешних зависимостей.
- Идентичность запросчика: mTLS. Клиентский сертификат на песочницу; allowlist брокера - SHA-256 fingerprint'ы разрешённых сертификатов; fingerprint заменяет uid из SO_PEERCRED в журнале, claim-метаданных и на approval-консоли («requester: cert fp=…»). Идентичность только сертификатная: IP не используется.
- Unix-сокет остаётся вторым листенером: host-local путь с SO_PEERCRED (N-серия проверочного реестра жива нетронутой). В коде вводится одна абстракция «идентичность запросчика» (uid | cert fp), выбираемая per-listener.
- Аудит TMB-канала живёт в TMB: `tls: skip` делает канал непрозрачным для OpenShell, JSONL-журнал брокера - летопись канала (как зафиксировано в RESEARCH-OPENSHELL Q5).
- Клиент в песочнице: статический Go-бинарник, запечённый в кастомный образ поверх пиненного opencode-образа; адрес - `TMB_ADDR=host.openshell.internal:<port>` через `--env` при create.
- Топология доказательства: macOS + Docker Desktop (gateway - нативный бинарник, супервизор - отдельный контейнер; пререквизиты: host networking включён, Enhanced Container Isolation выключен). Одобрение - консоль foreground-брокера, как в PoC.
- Вне скоупа этого решения: MCP-over-HTTP и HTTP/JSON (будущий этап, кандидат на #2/#3), env/cwd-политика, TOCTOU-харденинг, packaging, аудит-пайплайн.

## Статус

Принято (2026-10-09) по итогам грила: скоуп майлстоуна - OpenShell-обвязка + минимум аутентификации (issue #4, пункты 1-2).

## Последствия

Положительные:

- Канал песочница→брокер медируется и логируется OpenShell на уровне соединения без ослабления admission песочницы.
- TCP-endpoint добавляется в живую песочницу без пересоздания - упрощает проверку O2 (изъятие правила → deny).
- Kernel-auth (SO_PEERCRED) сохранён для host-local пути; сертификатная идентичность закрывает allowlist, журнал и approval-дисплей одной конструкцией.

Отрицательные и риски:

- CA-инфраструктура появляется в харнессе (генерация CA и клиентских сертификатов на прогонах).
- Канал непрозрачен для OpenShell (`tls: skip`): инспекция уровня запросов невозможна - осознанный размен.
- OpenShell 0.1.x API churn: версии пинуются (стартуем с v0.1.2).
- Консольный manual-approval сериализован мьютексом на все соединения - при нескольких TCP-клиентах станет узким местом (перенос в packaging-этап).
- «Хост» доказательства - Docker Desktop VM, не настоящий хост; вердикт обязан это фиксировать.

## Ссылки

- [ADR 0002](0002-standalone-tmb-broker.md): родительское решение.
- [RESEARCH-OPENSHELL.md](https://github.com/Vchekryzhov/tmb/blob/prototype/tmb-broker/prototype/tmb-broker/RESEARCH-OPENSHELL.md): вариант A/B, Q2-Q5.
- [VERDICT-BROKER.md](https://github.com/Vchekryzhov/tmb/blob/prototype/tmb-broker/prototype/tmb-broker/VERDICT-BROKER.md): остаточные риски PoC.
- [Issue #4](https://github.com/Vchekryzhov/tmb/issues/4): MVP, разбивается на тикеты.
- Словарь домена: [CONTEXT.md](../../CONTEXT.md), термины «Точка входа TMB» и «Идентичность запросчика».

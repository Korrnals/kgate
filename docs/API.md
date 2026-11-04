# KGATE · mTLS API

Демон `kgate serve` слушает HTTPS с обязательной клиентской сертификатной аутентификацией.
Все эндпоинты требуют валидный клиентский сертификат, подписанный CA из `web_root/ca.crt`
демона. Ключей/токенов нет — только сертификаты (TLS 1.2+).

## Аутентификация

При `kgate apply` генерируется локальный PKI-набор (ECDSA P-256, срок 10 лет):

| Файл (по умолчанию) | Роль | Где живёт |
|---|---|---|
| `ca.crt` / `ca.key` | удостоверяющий центр | локально; `.crt` также на роутере |
| `server.crt` / `server.key` | сертификат API-сервера демона | роутер: `<web_root>/` |
| `client.crt` / `client.key` | сертификат клиента (CLI) | ноутбук: `~/.kgate/` |

Сеть: демон слушает `api_listen` (по умолчанию `:9443`). Ограничивайте доступ
файрволом LAN (интернет-экспозиция не предполагается).

## Эндпоинты

| Метод | Путь | Назначение |
|---|---|---|
| `GET` | `/api/v1/status` | состояние стека одним JSON: процессы, FD-лимит, Proxy0, пины, DNS-правила, режим clash, uptime |
| `GET` | `/api/v1/verify` | батарея проверок + отчёт супервизора (то же, что `kgate verify`, без локального socks-теста) |
| `POST` | `/api/v1/toggle` | тумблер туннеля. Body: `{"state":"on"\|"off"}` |
| `POST` | `/api/v1/ruexit` | режим маршрутизации. Body: `{"mode":"global"\|"rule"}` (см. [USER → RU-exit](USER.md#ru-exit)) |
| `GET` | `/api/v1/logs` | хвост логов демона и загрузки |
| `POST` | `/api/v1/reboot` | ребут роутера (соединение обрывается — это норма) |

## Примеры (curl)

```bash
CERT=~/.kgate
BASE=https://192.168.1.1:9443

curl --cacert $CERT/ca.crt --cert $CERT/client.crt --key $CERT/client.key \
     $BASE/api/v1/status

curl --cacert $CERT/ca.crt --cert $CERT/client.crt --key $CERT/client.key \
     -X POST $BASE/api/v1/toggle -H 'Content-Type: application/json' \
     -d '{"state":"on"}'
```

То же — готовыми командами: `kgate status`, `kgate toggle on`, `kgate ruexit on`.

## Семантика ответов

- успешный JSON — 200; ошибки валидации тела — 400; ошибки демона — 500
- `/api/v1/reboot` всегда завершается обрывом соединения (демон уходит вместе с роутером)
- верификация TLS взаимная: без клиентского сертификата — handshake отказ
- паника обработчика изолируется (`recover`): демон не умирает, соединение закрывается

## CLI ↔ API

Команды `kgate` (кроме `apply`) — тонкая обёртка над API: читают `kgate.yaml`
(адрес, порт, сертификаты). `kgate apply` — отдельный деплойер, работает по ssh
и не требует живого демона.

# API · Эксплуатация: logs и reboot

> 🟢 Хвост логов демона и 🔴 перезагрузка роутера — команды обслуживания,
> аналоги `kgate logs` и `kgate reboot`.

## 🔎 На этой странице

- 🟢 [GET /api/v1/logs](#get-apiv1logs) — хвост логов (plain text)
- 🔴 [POST /api/v1/reboot](#post-apiv1reboot) — перезагрузка роутера

---

## GET /api/v1/logs

![GET](https://img.shields.io/badge/GET-2ea44f) `/api/v1/logs`

### 📖 Описание

Хвост логов демона: runtime-лог (`kgate.log`, последние 40 строк) и boot-лог
(`kgate-boot.log`, последние 10 строк), разделённые маркером `--- boot ---`.
Формат — plain text, готов к `grep`/`tail`.

### 📮 Ответы

| Код | Формат | Описание |
|---|---|---|
| `200` | `text/plain` | два блока логов с разделителем `--- boot ---` |

### 🧪 Пример запроса

```bash
curl --cacert ~/.kgate/ca.crt --cert ~/.kgate/client.crt --key ~/.kgate/client.key \
     https://192.168.1.1:9443/api/v1/logs
```

### 📥 Пример ответа

```text
2026-11-04 12:00:01 api: mTLS listener :9443
2026-11-04 12:00:03 supervisor: sing-box ok
2026-11-04 12:00:05 tunnel: Proxy0 up
--- boot ---
2026-11-04 11:59:40 daemon: starting
2026-11-04 11:59:41 relay: listening 127.0.0.1:1090
```

### 🚫 Ошибки

| Код | Причина |
|---|---|
| `404` | опечатка в пути |
| handshake failure | нет/чужой клиентский сертификат — TLS-уровень, до HTTP |

---

## POST /api/v1/reboot

![POST](https://img.shields.io/badge/POST-0969da) `/api/v1/reboot` ![DESTRUCTIVE](https://img.shields.io/badge/DESTRUCTIVE-cf222e)

### 📖 Описание

Перезагрузка роутера через `ndmc system reboot`. Ответ приходит, затем демон
завершается и соединение закрывается — обрыв после ответа ожидаем.
Роутер снова доступен примерно через 2 минуты; стек и туннель поднимутся
автоматически (см. [Admin · Эксплуатация · Ребут](../admin/operations.md)).

### 📮 Ответы

| Код | Формат | Описание |
|---|---|---|
| `200` | JSON | команда перезагрузки принята ndm; после ответа соединение закрывается |

### 🧪 Пример запроса

```bash
curl --cacert ~/.kgate/ca.crt --cert ~/.kgate/client.crt --key ~/.kgate/client.key \
     -X POST https://192.168.1.1:9443/api/v1/reboot
```

### 📥 Пример ответа

```json
{ "ndmc": "..." }
```

Содержимое `ndmc` — эхо команды перезагрузки; зависит от прошивки.

### 🚫 Ошибки

| Код | Причина |
|---|---|
| handshake failure | нет/чужой клиентский сертификат — TLS-уровень, до HTTP |

> [!CAUTION]
> `/reboot` обрывает все сессии в доме — туннель, интерфейсы, Wi-Fi.
> Не путать с `toggle off`: тумблер лишь уводит трафик напрямую, ребут
> перезагружает весь роутер.

## 👉 См. также

- [Диагностика: status и verify](endpoints-status-verify.md) — проверка стека до и после ребута
- [User · Повседневное управление](../user/day-to-day.md) — то же через CLI
- [Admin · Эксплуатация и диагностика](../admin/operations.md)

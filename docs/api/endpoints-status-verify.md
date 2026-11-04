# API · Диагностика: status и verify

> 🟢 Чтение состояния стека. Оба эндпоинта соответствуют командам
> `kgate status` и `kgate verify`; нюанс — `verify` заодно перезапускает упавшие процессы.

## 🔎 На этой странице

- 🟢 [GET /api/v1/status](#get-apiv1status) — состояние стека одним объектом
- 🟢 [GET /api/v1/verify](#get-apiv1verify) — батарея проверок супервизора

---

## GET /api/v1/status

![GET](https://img.shields.io/badge/GET-2ea44f) `/api/v1/status`

### 📖 Описание

Состояние всего VPN-стека одним JSON-объектом. Параметров нет; вызов можно
повторять в любой момент — состояние только читается.

### 📮 Ответы

| Код | Формат | Описание |
|---|---|---|
| `200` | JSON · `Status` | стек опрошен; состав полей — ниже |

### 🧪 Пример запроса

```bash
curl --cacert ~/.kgate/ca.crt --cert ~/.kgate/client.crt --key ~/.kgate/client.key \
     https://192.168.1.1:9443/api/v1/status
```

### 📥 Пример ответа

```json
{
  "singbox": "running",
  "relay": "running",
  "fd_limit": "16383 16384",
  "proxy0": "state: up",
  "pins": "pins: 2",
  "dns_rules": "dns rules: 2",
  "mode": "Rule",
  "uptime": "8628s",
  "debug": "raw=\"...\""
}
```

| Поле | Значение |
|---|---|
| `singbox` / `relay` | `running` / `DEAD` — процессы движка и socks-relay |
| `fd_limit` | FD-лимит sing-box: soft/hard (`16383 16384`) |
| `proxy0` | состояние туннельного интерфейса ndm: `state: up` / `state: down` |
| `pins` | route-pins: ожидаются `pins: 2` или больше |
| `dns_rules` | активные DNS-правила перехвата |
| `mode` | режим движка: `Rule` / `Global` / `unknown` |
| `uptime` | аптайм роутера в секундах |
| `debug` | сырой дамп интерфейса Proxy0 — прикладывайте к отчёту об ошибке |

### 🚫 Ошибки

| Код | Причина |
|---|---|
| `404` | опечатка в пути (неизвестный путь всегда даёт `404`) |
| handshake failure | нет/чужой клиентский сертификат — TLS-уровень, до HTTP (см. [Ошибки handshake](authentication.md#-ошибки-handshake)) |

---

## GET /api/v1/verify

![GET](https://img.shields.io/badge/GET-2ea44f) `/api/v1/verify`

### 📖 Описание

Батарея проверок супервизора плюс полный статус: упавшие дочерние процессы
перезапускаются на месте, отчёт о каждом — в ответе.

> [!IMPORTANT]
> `verify` — не «чистое чтение»: вызов может перезапустить движок или relay.
> Для пассивного опроса используйте `/status`.

### 📮 Ответы

| Код | Формат | Описание |
|---|---|---|
| `200` | JSON · `status` + `supervisor` | статус стека и отчёт супервизора |

### 🧪 Пример запроса

```bash
curl --cacert ~/.kgate/ca.crt --cert ~/.kgate/client.crt --key ~/.kgate/client.key \
     https://192.168.1.1:9443/api/v1/verify
```

### 📥 Пример ответа

```json
{
  "status": {
    "singbox": "running",
    "relay": "running",
    "proxy0": "state: up",
    "mode": "Rule"
  },
  "supervisor": ["xray: running", "sing-box: running"]
}
```

Объект `status` — полный `Status`, см. [/status](#get-apiv1status).

### 🚫 Ошибки

| Код | Причина |
|---|---|
| `404` | опечатка в пути |
| handshake failure | нет/чужой клиентский сертификат — TLS-уровень, до HTTP |

## 👉 См. также

- [Эксплуатация: logs и reboot](endpoints-logs-reboot.md) — соседние команды обслуживания
- [Admin · Эксплуатация и диагностика](../admin/operations.md) — как читать результаты проверок
- [Глоссарий](../glossary.md)

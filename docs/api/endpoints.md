# API · Эндпоинты

Индикация методов: 🟢 `GET` — чтение · 🔵 `POST` — действие · 🔴 разрушающие/необратимые.

---

## 🟢 GET /api/v1/status

> Состояние стека одним JSON-объектом.

**Параметры:** нет.

**🟩 Пример запроса**

```bash
curl --cacert ca.crt --cert client.crt --key client.key \
     https://192.168.1.1:9443/api/v1/status
```

**🟦 Ответ 200**

```json
{
  "relay": "running",
  "singbox": "running",
  "fd_limit": "16383 16384",
  "proxy0": "state: up",
  "pins": "pins: 2",
  "dns_rules": "dns rules: 2",
  "mode": "Rule",
  "uptime": "8628s"
}
```

| Поле | Значение |
|---|---|
| `relay` / `singbox` | состояние процессов relay и движка |
| `fd_limit` | текущий FD-лимит sing-box |
| `proxy0` | состояние туннельного интерфейса ndm |
| `pins` | наличие route-pins (должно быть ≥2) |
| `dns_rules` | активные DNS-правила перехвата |
| `mode` | режим движка: `Rule` / `Global` |

---

## 🟢 GET /api/v1/verify

> Батарея проверок супервизора + статус. Перезапускает упавших детей.

**🟩 Пример запроса**

```bash
curl --cacert ca.crt --cert client.crt --key client.key \
     $BASE/api/v1/verify
```

**🟦 Ответ 200**

```json
{
  "status": { "relay": "running", "singbox": "running", "...": "..." },
  "supervisor": ["xray: running", "sing-box: running"]
}
```

---

## 🔵 POST /api/v1/toggle

> Тумблер VPN для всего дома (Proxy0 up/down через ndm).

**🟧 Тело запроса**

```json
{"state": "on"}
```

**🟦 Ответ 200** (после ожидания смены состояния)

```json
{ "ndmc": "interface is up.", "proxy0": "state: up" }
```

**🔴 Ошибки:** `400` — `state` не `on`/`off`.

---

## 🔵 POST /api/v1/ruexit

> Переключение режима маршрутизации: RU-exit (Global) ↔ обычный (Rule).

**🟧 Тело запроса**

```json
{"mode": "global"}
```

**🟦 Ответ 200**

```json
{ "mode": "Global" }
```

> [!NOTE]
> Требуется серверное правило «RU-destined → exit node» — без него Global
> направляет локальный трафик через обычный зарубежный exit.

---

## 🟢 GET /api/v1/logs

> Хвост логов демона (boot + runtime), plain text.

---

## 🔴 POST /api/v1/reboot

> Перезагрузка роутера. Соединение обрывается сразу — это ожидаемо.
> Повторный доступ — через ~2 минуты после загрузки.

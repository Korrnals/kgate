# API · RU-exit: ruexit

> 🔵 Переключение режима маршрутизации движка: обычный сплит (**Rule**) ↔
> анонимизация через выходной узел (**Global**). Аналог `kgate ruexit on|off`.

## 🔎 На этой странице

- 🔵 [POST /api/v1/ruexit](#post-apiv1ruexit) — Rule ↔ Global

---

## POST /api/v1/ruexit

![POST](https://img.shields.io/badge/POST-0969da) `/api/v1/ruexit`

### 📖 Описание

Меняет `clash_mode` движка sing-box: `global` направляет весь трафик через
выходной туннель (RU-exit), `rule` возвращает обычный RU-сплит. Значения
передаются в нижнем регистре, возвращаются — в регистре движка (`Global`/`Rule`).

### 📮 Ответы

| Код | Формат | Описание |
|---|---|---|
| `200` | JSON | режим применён и прочитан обратно из движка |

### 🧾 Тело запроса

| Поле | Тип | Допустимые значения |
|---|---|---|
| `mode` | string | `global` · `rule` |

```json
{"mode": "global"}
```

### 🧪 Пример запроса

```bash
curl --cacert ~/.kgate/ca.crt --cert ~/.kgate/client.crt --key ~/.kgate/client.key \
     -H 'Content-Type: application/json' \
     -d '{"mode":"global"}' \
     https://192.168.1.1:9443/api/v1/ruexit
```

### 📥 Пример ответа

```json
{ "mode": "Global" }
```

### 🚫 Ошибки

| Код | Причина |
|---|---|
| `400` | `mode` не `global`/`rule` — тело ответа: `mode: global|rule` (plain text) |
| `500` | движок недоступен — clash API не ответил; тело: текст ошибки (plain text) |
| handshake failure | нет/чужой клиентский сертификат — TLS-уровень, до HTTP |

```text
PATCH http://127.0.0.1:9090/configs: dial tcp 127.0.0.1:9090: connect: connection refused
```

> [!NOTE]
> Для корректного RU-exit нужно серверное правило «RU-destined → exit node»:
> без него `Global` направляет локальный трафик через обычный зарубежный exit.
> Настройка — [Admin · Конфигурация](../admin/configuration.md).

## 👉 См. также

- [User · RU-exit (анонимизация)](../user/ru-exit.md) — когда включать и что меняется
- [Тумблер toggle](endpoints-toggle.md) — переключатель уровня туннеля, а не режима движка
- [Архитектура · Модель данных](../architecture/data-model.md) — POST-тела `/toggle` и `/ruexit`

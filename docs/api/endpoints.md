# API · Эндпоинты: обзор и навигация

> 🧭 Карта всех эндпоинтов mTLS API демона. Каждый эндпоинт — отдельная карточка
> с готовыми примерами; из этой страницы — переходы по группам.

## 🔎 На этой странице

- 🎨 [Легенда методов](#-легенда-методов)
- 🗺 [Карта эндпоинтов](#-карта-эндпоинтов)
- 📏 [Конвенции](#-конвенции)
- 🧯 [Общие ошибки](#-общие-ошибки)

---

## 🎨 Легенда методов

Цвет бейджа кодирует семантику метода (shields.io static):

| Метод | Бейдж | Цвет | Семантика |
|---|---|---|---|
| `GET` | 🟢 | `#2ea44f` | только чтение |
| `POST` | 🔵 | `#0969da` | действие (для `/reboot` — необратимое) |
| `PUT` / `PATCH` | 🟠 | `#f0883e` | изменение — в API v1 не используется |
| `DELETE` | 🔴 | `#cf222e` | удаление — в API v1 не используется |

## 🗺 Карта эндпоинтов

### Диагностика — [endpoints-status-verify.md](endpoints-status-verify.md)

- 🟢 `GET /api/v1/status` — состояние стека одним JSON-объектом
- 🟢 `GET /api/v1/verify` — батарея проверок супервизора + перезапуск упавших

### Тумблер — [endpoints-toggle.md](endpoints-toggle.md)

- 🔵 `POST /api/v1/toggle` — VPN для всего дома: ON / OFF

### RU-exit — [endpoints-ruexit.md](endpoints-ruexit.md)

- 🔵 `POST /api/v1/ruexit` — режим маршрутизации: Rule ↔ Global (анонимизация)

### Политики трафика — [endpoints-policy.md](endpoints-policy.md)

- 🟢 `GET /api/v1/policy/list` — таблица привязок: устройства + сегменты + политики
- 🟢 `GET /api/v1/policy/segments` — сегменты с числом устройств
- 🔵 `POST /api/v1/policy/set-device` — привязка устройства (MAC|hostname) к VPN/NO-VPN/none
- 🔵 `POST /api/v1/policy/set-segment` — привязка сегмента (Bridge|имя)
- 🔵 `POST /api/v1/policy/all-vpn` — все активные устройства → VPN
- 🔵 `POST /api/v1/policy/all-direct` — снять все привязки (всё напрямую)

### Эксплуатация — [endpoints-logs-reboot.md](endpoints-logs-reboot.md)

- 🟢 `GET /api/v1/logs` — хвост логов демона (plain text)
- 🔴 `POST /api/v1/reboot` — перезагрузка роутера

## 📏 Конвенции

- база путей: `/api/v1`; базовый URL: `https://<роутер>:9443`
- аутентификация: mTLS на каждом запросе —
  [Аутентификация и общие правила](authentication.md)
- тела — JSON (`Content-Type: application/json`), ошибки — plain text
- `GET` — только чтение; `POST` — действие

| Код | Значение |
|---|---|
| `200` | успех |
| `400` | некорректное тело запроса |
| `404` | неизвестный путь |
| `500` | внутренняя ошибка демона |

## 🧯 Общие ошибки

Ошибки mTLS происходят на этапе handshake — до HTTP, без статус-кода:

```text
curl: (56) ... TLS alert certificate required
```

> [!NOTE]
> `/reboot` завершается обрывом соединения после ответа — это ожидаемое
> поведение, а не ошибка. Повторный доступ — через ~2 минуты после загрузки.

## 👉 См. также

- [Аутентификация и общие правила](authentication.md) — сертификаты и handshake
- [Архитектура · Модель данных](../architecture/data-model.md) — объекты `Status` и POST-тела
- [Глоссарий](../glossary.md)

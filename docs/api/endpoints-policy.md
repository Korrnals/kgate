# API · Политики трафика: policy

> 🧭 Привязки устройств и сегментов к политикам VPN/NO-VPN (policy-v2).
> Честный дефолт: устройство без привязки ходит НАПРЯМУЮ через провайдера;
> туннель включается только явной привязкой. CLI-эквивалент — `kgate policy`.
> Первоисточник привязок — живая таблица `show ip hotspot`.

## 🔎 На этой странице

- 🟢 [GET /api/v1/policy/list](#get-apiv1policylist) — устройства + сегменты + политики
- 🟢 [GET /api/v1/policy/segments](#get-apiv1policysegments) — сегменты с числом устройств
- 🔵 [POST /api/v1/policy/set-device](#post-apiv1policyset-device) — привязка устройства (MAC|hostname)
- 🔵 [POST /api/v1/policy/set-segment](#post-apiv1policyset-segment) — привязка сегмента (Bridge|имя)
- 🔵 [POST /api/v1/policy/all-vpn](#post-apiv1policyall-vpn) — все активные устройства → VPN
- 🔵 [POST /api/v1/policy/all-direct](#post-apiv1policyall-direct) — снять все привязки

---

## GET /api/v1/policy/list

![GET](https://img.shields.io/badge/GET-2ea44f) `/api/v1/policy/list`

### 📖 Описание

Живая таблица привязок: список объектов политик ndm (`show ip policy`),
устройства (`show ip hotspot`) и сегменты с их привязками. Пустая строка в
`policy` = устройство не привязано = честный дефолт (напрямую).

### 📮 Ответы

| Код | Формат | Описание |
|---|---|---|
| `200` | JSON | таблица привязок |

### 🧪 Пример запроса

```bash
curl --cacert ~/.kgate/ca.crt --cert ~/.kgate/client.crt --key ~/.kgate/client.key \
     https://192.168.1.1:9443/api/v1/policy/list
```

### 📥 Пример ответа

```json
{
  "policies": ["VPN", "NO-VPN"],
  "hosts": [
    {"hostname":"pixel-phone","ip":"192.168.1.52","mac":"5c:eb:f6:aa:bb:01",
     "segment":"Bridge0","policy":"VPN","active":true},
    {"hostname":"smart-tv","ip":"192.168.2.20","mac":"aa:bb:cc:dd:ee:ff",
     "segment":"Bridge1","policy":"","active":true}
  ],
  "segments": [
    {"name":"Bridge0","description":"Home","policy":"","active":true,"hosts":1},
    {"name":"Bridge1","description":"LAN","policy":"","active":true,"hosts":1}
  ]
}
```

## GET /api/v1/policy/segments

![GET](https://img.shields.io/badge/GET-2ea44f) `/api/v1/policy/segments`

Только блок `segments` из [list](#get-apiv1policylist): имя, описание,
привязка, флаг активности и число устройств в сегменте.

## POST /api/v1/policy/set-device

![POST](https://img.shields.io/badge/POST-0969da) `/api/v1/policy/set-device`

### 📖 Описание

Привязывает устройство к политике или снимает привязку (`none`). Цель — MAC
(надёжно) или hostname (неуникальные имена → 400 с перечислением MAC).
Демон проверяет существование объекта политики (`show ip policy`) и после
успеха выполняет `system configuration save`.

### 🧾 Тело запроса

| Поле | Тип | Допустимые значения |
|---|---|---|
| `target` | string | MAC (`aa:bb:cc:dd:ee:ff`) или hostname |
| `policy` | string | `VPN` · `NO-VPN` · `none` (снять привязку) |

```json
{"target": "pixel-phone", "policy": "VPN"}
```

### 📥 Пример ответа

```json
{
  "resolved": {"hostname":"pixel-phone","mac":"5c:eb:f6:aa:bb:01","ip":"192.168.1.52","segment":"Bridge0"},
  "policy": "VPN",
  "ndmc": "ip hotspot host 5c:eb:f6:aa:bb:01 policy VPN",
  "save": "OK"
}
```

### 🚫 Ошибки

| Код | Причина |
|---|---|
| `400` | недопустимая политика (разрешены `VPN\|NO-VPN\|none`), устройство не найдено, hostname неоднозначен, объект политики не создан (не прогонён deploy v2), битое тело |
| `500` | ndm отклонил verb (`system failed`) |

## POST /api/v1/policy/set-segment

![POST](https://img.shields.io/badge/POST-0969da) `/api/v1/policy/set-segment`

То же для сегмента целиком: `target` — имя моста/точки доступа (`Bridge0`)
или описание (`Home`); индивидуальные привязки устройств перекрывают
сегментную. Формы ndm: `ip hotspot <segment> policy <NAME>` /
`ip hotspot <segment> no policy`.

## POST /api/v1/policy/all-vpn

![POST](https://img.shields.io/badge/POST-0969da) `/api/v1/policy/all-vpn`

Привязывает **все активные** устройства к `VPN`. Уже привязанные и offline
пропускаются без ndmc-записи (идемпотентно). Ответ:

```json
{"policy":"VPN","bound":3,"skipped":2,"total":5,"errors":[],"saved":true}
```

Требует созданной политики `VPN` — иначе `400` (сначала `kgate deploy`).

## POST /api/v1/policy/all-direct

![POST](https://img.shields.io/badge/POST-0969da) `/api/v1/policy/all-direct`

Снимает **все** привязки (включая offline-устройства — их устаревшие биндинги
иначе тихо вернулись бы позже). Непривязанные пропускаются:

```json
{"policy":"none","unbound":1,"skipped":4,"total":5,"errors":[],"saved":true}
```

---

## 👉 См. также

- [endpoints-toggle.md](endpoints-toggle.md) — тумблер туннеля (на привязки не влияет)
- [endpoints-status-verify.md](endpoints-status-verify.md) — состояние стека
- [../admin/segments-and-policies.md](../admin/segments-and-policies.md) — модель policy-v2 глазами администратора

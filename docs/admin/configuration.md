# Администрирование · Конфигурация

## 📄 `kgate.yaml` — единый файл

Одинаковый на ноутбуке и роутере; секции изолированы. Полная модель —
[architecture/data-model.md](../architecture/data-model.md).

| Секция | Кто читает | Ключевое |
|---|---|---|
| `host`, `ssh_*` | деплойер | адрес/порт/ключ для `deploy` (ssh-транспорт — чистый Go x/crypto/ssh: ключ из `ssh_key`, host-ключи TOFU в `~/.ssh/known_hosts`) |
| `api` | клиент + демон | порт mTLS API, пути сертификатов (`~/.kgate/`) |
| `daemon` | демон на роутере | пути, `rlimit_nofile`, `supervisor_interval`, `boot_autoup`, `api_listen`, `web_root`, `log` |
| `policies` | деплойер (apply) + destroy | декларативные hotspot-привязки: `segments` (ndm-имя → VPN\|NO-VPN) и `devices` (mac+policy); идемпотентный apply, см. [segments-and-policies](segments-and-policies.md) |

> [!IMPORTANT]
> Секретов в `kgate.yaml` нет. Секреты hy2 живут в `sing-box` конфиге
> (`local/etc/sing-box/config.json` → payload → `/opt/etc/sing-box/config.json`).

## 🏗 Шаблоны и плейсхолдеры

Пакет создаёт живые конфиги из шаблонов `.example` (это делает `postinst`
при первом запуске — правки не затираются при переустановке). Шаблоны
содержат маркерные значения — **плейсхолдеры**:

| Плейсхолдер | Файл | Поле | Заменить на |
|---|---|---|---|
| `203.0.113.10` | `/opt/etc/kgate/kgate.yaml` | `server_ip` | реальный IP exit-сервера |
| `hy2.example.com` | `/opt/etc/sing-box/config.json` | `outbounds[hy2-out].server`, `tls.server_name` | хост вашего hysteria2-сервера |
| `HY2_PASSWORD` | `/opt/etc/sing-box/config.json` | `password`, `obfs.password` | пароль вашего hysteria2-сервера |

Демон при старте сканирует sing-box конфиг на `HY2_PASSWORD` и
`hy2.example.com`. Если находит — пишет в boot-лог **«КОНФИГ НЕ НАСТРОЕН»**,
опускает Proxy0 и пропускает автоподъём: заведомо мёртвый туннель не
поднимается, интернет дома остаётся прямым. Реальные значения — параметры
вашего hysteria2-сервера; после замены выполните
`/opt/etc/init.d/S99kgate restart` (шаги — [install.md](install.md)).

## ⚙️ Конфиг sing-box — критичные для kgate поля

| Поле | Зачем | Слом при ошибке |
|---|---|---|
| `outbounds[direct].bind_interface: "eth3"` | RU-direct не попадает в политику ndm (иначе петля через tun2socks → таймауты RU) | RU-сайты таймаутят при ON |
| `dns.servers[].{address: udp://<dns>, detour: direct}` | резолв движка мимо ndm-резолвера (тот умирает при ON) | зарубежные домены не резолвятся |
| `route.rules[0] {clash_mode: Global → hy2-out}` | включение RU-exit через режим Global | ruexit не переключает routing |
| route-pins ndm (`/32 → ISP`) | hy2 и DNS не захватываются политикой | туннель/DNS умирают при ON |

Проверка конфига перед рестартом: `sing-box check -c /opt/etc/sing-box/config.json`.

## 🗂 Rulesets

Локальные rule-sets (`.srs`) живут в `/opt/etc/sing-box/rulesets/`. С версии
1.1.2 набор **вендорен** в репозитории (`examples/etc/sing-box/rulesets/`) и
входит в `.ipk` самодостаточно — скачивать правила при установке не нужно.
При собственной payload-сборке из `local/` ваши наборы копируются из
`local/etc/sing-box/rulesets/`.

## 🛡 mTLS-сертификаты

- генерируются автоматически при `kgate deploy` (ECDSA P-256, 10 лет):
  полный набор (`ca`, `server`, `client`) — локально в `~/.kgate/`, затем
  `ca.crt` + `server.crt` + `server.key` загружаются на роутер в `web_root`;
- перегенерация вручную: удалить `~/.kgate/*` и `web_root` на роутере → повторный `deploy`
  (перевыдача разорвёт доверие старых клиентов — обновите их наборы);
- серверный ключ: `0600`; используйте его только на роутере
  (`<web_root>/server.key`), с ноутбука он нужен лишь как источник деплоя.

## 📜 Логи

| Лог | Что содержит |
|---|---|
| `/opt/var/log/kgate-boot.log` | старт демона, супервизор, relay |
| `/opt/var/log/kgate.log` | записи relay/супервизора |
| `/opt/var/log/singbox.log` | stderr sing-box |
| `kgate logs` | агрегированный хвост через mTLS |

## 👉 См. также

- [operations.md](operations.md) — диагностика и типовые неисправности
- [architecture/data-model.md](../architecture/data-model.md) — полная модель конфига и payload
- [api/authentication.md](../api/authentication.md) — сертификаты в действии

## 🔧 Переменные окружения (поверх yaml)

Приоритет: **env `KGATE_*` > yaml > дефолты**. Удобно для контейнеров/сервисов,
когда не хочется править файл. Список зеркалит yaml-пути и читается из
`internal/model/config.go`.

| Переменная | Поле |
|---|---|
| `KGATE_HOST` | host |
| `KGATE_SERVER_IP` | server_ip (ndm route-pin) |
| `KGATE_SSH_PORT` / `KGATE_SSH_USER` / `KGATE_SSH_KEY` | ssh_* |
| `KGATE_API_PORT` | api.port |
| `KGATE_API_CA` / `KGATE_API_CERT` / `KGATE_API_KEY` | пути сертификатов клиента |
| `KGATE_DAEMON_SINGBOX_BIN` / `_SINGBOX_CONFIG` / `_SINGBOX_LOG` | пути движка |
| `KGATE_DAEMON_RELAY_LISTEN` / `_RELAY_UPSTREAM` | socks-relay |
| `KGATE_DAEMON_API_LISTEN` | адрес mTLS API |
| `KGATE_DAEMON_WEB_ROOT` / `_LOG` | каталог сертов / лог |
| `KGATE_DAEMON_RLIMIT_NOFILE` | FD-лимит sing-box |
| `KGATE_DAEMON_BOOT_AUTOUP` | `1`/`true`/`yes` — авто-подъём туннеля |

Пример: `KGATE_API_PORT=9443 KGATE_DAEMON_LOG=/tmp/kgate.log kgate serve -c kgate.yaml`

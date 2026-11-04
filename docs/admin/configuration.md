# Администрирование · Конфигурация

## 📄 `kgate.yaml` — единый файл

Одинаковый на ноутбуке и роутере; секции изолированы. Полная модель —
[architecture/data-model.md](../architecture/data-model.md).

| Секция | Кто читает | Ключевое |
|---|---|---|
| `host`, `ssh_*` | деплойер | адрес/порт/ключ для `apply` |
| `api` | клиент + демон | порт mTLS API, пути сертификатов (`~/.kgate/`) |
| `daemon` | демон на роутере | пути, `rlimit_nofile`, `supervisor_interval`, `boot_autoup`, `api_listen`, `web_root`, `log` |

> [!IMPORTANT]
> Секретов в `kgate.yaml` нет. Секреты hy2 живут в `sing-box` конфиге
> (`local/etc/sing-box/config.json` → payload → `/opt/etc/sing-box/config.json`).

## ⚙️ Конфиг sing-box — критичные для kgate поля

| Поле | Зачем | Слом при ошибке |
|---|---|---|
| `outbounds[direct].bind_interface: "eth3"` | RU-direct не попадает в политику ndm (иначе петля через tun2socks → таймауты RU) | RU-сайты таймаутят при ON |
| `dns.servers[].{address: udp://<dns>, detour: direct}` | резолв движка мимо ndm-резолвера (тот умирает при ON) | зарубежные домены не резолвятся |
| `route.rules[0] {clash_mode: Global → hy2-out}` | включение RU-exit через режим Global | ruexit не переключает routing |
| route-pins ndm (`/32 → ISP`) | hy2 и DNS не захватываются политикой | туннель/DNS умирают при ON |

Проверка конфига перед рестартом: `sing-box check -c /opt/etc/sing-box/config.json`.

## 🗂 Rulesets

Локальные rule-sets (`.srs`) кладутся в `/opt/etc/sing-box/rulesets/`.
При сборке payload Makefile копирует их из `local/etc/sing-box/rulesets/`
(или скачивает при сборке .ipk — если источник доступен).

## 🛡 mTLS-сертификаты

- генерируются автоматически при `kgate apply` (ECDSA P-256, 10 лет);
- перегенерация вручную: удалить `~/.kgate/*` и `web_root` на роутере → повторный `apply`
  (перевыдача разорвёт доверие старых клиентов — обновите их наборы);
- серверный ключ: `0600`, живёт только на роутере (`<web_root>/server.key`).

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

# Архитектура · Модель данных

## 📄 `kgate.yaml` — единый конфиг

Один файл живёт и на ноутбуке, и на роутере. Секции изолированы.

```yaml
host: 192.168.1.1        # адрес роутера
ssh_port: 222            # ssh деплойера
ssh_user: root
ssh_key: ~/.ssh/id_ed25519

api:                     # секция клиента
  port: 9443             # mTLS API демона
  ca: ~/.kgate/ca.crt
  cert: ~/.kgate/client.crt
  key: ~/.kgate/client.key

daemon:                  # секция демона (роутер)
  singbox_bin: /opt/sbin/sing-box
  singbox_config: /opt/etc/sing-box/config.json
  singbox_log: /opt/var/log/singbox.log
  rlimit_nofile: 8192    # наследуется sing-box'ом
  supervisor_interval: 15s
  boot_autoup: true      # авто-подъём туннеля после старта
  autoup_delay: 25s
  api_listen: ":9443"
  web_root: /opt/etc/kgate   # CA/серверные сертификаты
  log: /opt/var/log/kgate.log
```

Соответствие Go-структуре: `internal/model/config.go` → `model.Config`.

## 📦 Payload деплоя

Самодостаточный `tar.gz`, собирается Makefile'ом:

| Член | Источник | Назначение на роутере |
|---|---|---|
| `kgate-arm64` | `go build` | `/opt/sbin/kgate` |
| `sing-box` | официальный static release (pinned версия) | `/opt/sbin/sing-box` |
| `S99kgate` | `examples/` | `/opt/etc/init.d/S99kgate` |
| `ndm-commands.sh` | `examples/` | `/opt/etc/ndm-commands.sh` |
| `root/opt/etc/...` | `local/etc/` (реальные) или `examples/etc/` (шаблоны) | конфиги sing-box, authorized_keys, passwd-строка sshd |

Секреты и правила (`.srs`) в репозиторий не попадают: реальные материалы
живут в `local/` (gitignored), в `examples/` — шаблоны с плейсхолдерами.

## 🛡 mTLS-набор

| Объект | Где | Кто генерирует |
|---|---|---|
| `ca.crt` / `ca.key` | ноутбук (`~/.kgate/`) + `ca.crt` на роутере | `kgate apply` (ECDSA P-256, 10 лет) |
| `server.crt` / `server.key` | роутер (`<web_root>/`) | `kgate apply`; SAN: IP роутера + `kgate` |
| `client.crt` / `client.key` | ноутбук (`~/.kgate/`) | `kgate apply` |

## 🔌 Объекты API

`GET /api/v1/status` → `Status` (см. `internal/daemon/daemon.go`):

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

POST-тела: `/toggle` — `{"state":"on"|"off"}`; `/ruexit` — `{"mode":"global"|"rule"}`.
Полное описание и готовые примеры — [API · Эндпоинты](../api/endpoints.md):
карточки [status/verify](../api/endpoints-status-verify.md),
[toggle](../api/endpoints-toggle.md), [ruexit](../api/endpoints-ruexit.md),
[logs/reboot](../api/endpoints-logs-reboot.md).

## 👉 См. также

- [api/authentication.md](../api/authentication.md) — mTLS-набор в действии
- [admin/configuration.md](../admin/configuration.md) — критичные поля конфига sing-box
- [glossary.md](../glossary.md)

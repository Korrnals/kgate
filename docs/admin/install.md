# Администрирование · Установка

> 🟢 Установка идемпотентна: повторный `kgate apply` безопасен.
> Предусловия: Netcraze/Keenetic (ndm 4.x–5.x), USB с Entware в `/opt`,
> ssh-доступ по ключу, компонент ndm «Клиент прокси».

## 🚀 Быстрый путь (полный стек через деплойер)

```bash
git clone <repo> && cd kgate
cp examples/kgate.yaml.example kgate.yaml      # поправить host / ssh_key

# реальные материалы стека (шаблоны лежат в examples/etc)
mkdir -p local/etc/sing-box/rulesets local/etc/ssh
cp <путь>/sing-box-config.json  local/etc/sing-box/config.json
cp <путь>/rulesets/*.srs        local/etc/sing-box/rulesets/
cp <путь>/deploy-key.pub        local/etc/ssh/authorized_keys

make build
./kgate apply -c kgate.yaml
```

Стадии `apply` (точечно — `--only files|config|ndm|services`):

| Стадия | Что происходит на роутере |
|---|---|
| preflight | Entware в `/opt`, uptime |
| files | payload: `kgate` arm64, sing-box, init-скрипт, конфиги, ключи; opkg: `iptables`, `openssh-server`, `ca-bundle` |
| config | рендер `/opt/etc/kgate/kgate.yaml`, генерация mTLS-сертификатов (CA → роутер, клиент → ноутбук) |
| migrate | глушение legacy: `S99sing-box`, `S24xray`, watchdog, `routerctl` — дети переходят под демон |
| ndm | Proxy0 (upstream на relay :1090), route-pins, DNS, политики-сценарии |
| services | `S99kgate start` → верификация через mTLS + локальный socks-тест |

## 📦 Альтернатива: .ipk-пакет (только бинарь + init)

Когда движок (sing-box, конфиги) уже стоит на роутере:

```bash
make ipk     # dist/kgate_<ver>-1_aarch64-3.10.ipk
scp dist/kgate_*.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'opkg install /tmp/kgate_*.ipk'
```

Пакет кладёт: `/opt/sbin/kgate`, `/opt/etc/init.d/S99kgate`,
`/opt/etc/kgate/kgate.yaml` (conffile), `/opt/etc/sing-box/config.json`
(conffile). Конфиги редактируются до первого старта.

> [!NOTE]
> rulesets (`.srs`) в пакет включаются при сборке, если удалось скачать
> актуальный набор; при отсутствии — добавьте вручную в
> `/opt/etc/sing-box/rulesets/`.

## ✅ После установки

```bash
kgate status          # всё зелёное?
kgate toggle on       # включить VPN для дома
kgate verify          # движок + правила + выходной IP
```

Проверка сегментов ndm — обязательный шаг: [segments-and-policies.md](segments-and-policies.md).

## 👉 См. также

- [releases.md](releases.md) — обновление, откат, верификация подписей
- [configuration.md](configuration.md) — что проверить в конфигах после установки
- [glossary.md](../glossary.md) — стадия apply, payload, route-pins

# KGATE · Администрирование

Установка с нуля, конфигурация, сегменты ndm, диагностика, обновление и откат.
Пользовательский раздел — [USER.md](USER.md). API — [API.md](API.md).

## 1. Требования

Роутер Netcraze / Keenetic (ndm OS 4.x / 5.x):

- USB-накопитель с Entware, смонтированным в `/opt` (`opkg disk <диск>:/`)
- компонент ndm **«Клиент прокси»** (Управление → Параметры системы → Изменить набор компонентов)
- ssh-доступ по ключу с машины оператора (порт по умолчанию 222)
- готовый конфиг sing-box с правилами маршрутизации и rule-sets (`.srs`)

## 2. Установка с нуля

```bash
git clone <repo> && cd kgate
cp examples/kgate.yaml.example kgate.yaml        # host/ssh_port/ssh_user/ssh_key
mkdir -p local/etc/sing-box/rulesets local/etc/ssh
cp мой-sing-box-config.json local/etc/sing-box/config.json
cp rule-sets/*.srs                        local/etc/sing-box/rulesets/
cp мой-ключ.pub                           local/etc/ssh/authorized_keys

make build
./kgate apply -c kgate.yaml
```

`kgate apply` выполняет стадии (можно точечно: `--only files|config|ndm|services`):

| Стадия | Что происходит на роутере |
|---|---|
| preflight | Entware на месте, uptime |
| files | payload: `kgate` arm64, sing-box static, init-скрипт, конфиги, ключи; opkg-пакеты `iptables`, `openssh-server`, `ca-bundle` |
| config | рендер `/opt/etc/kgate/kgate.yaml`, генерация mTLS-сертификатов (CA → роутер, клиент → ноутбук) |
| migrate | глушит legacy-обвязку (S99sing-box / S24xray / watchdog / routerctl) — дети перейдут под демон |
| ndm | Proxy0 (протокол, upstream на relay), route-pins, DNS, политики-сценарии |
| services | `S99kgate start` → демон берёт стек на себя, затем верификация через mTLS |

Первая установка также: отключает заводские конкурирующие init-скрипты
(S99sing-box, S24xray) — они переименовываются в `.disabled`, не удаляются.

## 3. Конфигурация (`kgate.yaml`)

Единый файл для клиента и демона (см. `examples/kgate.yaml.example`):

- `host / ssh_*` — доступ для деплоя
- `api` — порт mTLS API и пути клиентских сертификатов (`~/.kgate/` по умолчанию)
- `daemon` — пути бинарей/конфигов, `rlimit_nofile` (наследуется sing-box),
  `supervisor_interval`, `boot_autoup` + `autoup_delay` (авто-подъём туннеля),
  `api_listen`, `web_root`, `log`

Конфиг sing-box (`/opt/etc/sing-box/config.json`) — обычный sing-box JSON:
inbound mixed :1080, правила маршрутизации (в т.ч. `clash_mode`), outbound
выходного туннеля, `bind_interface` на direct-outbound (важно на Keenetic —
иначе трафик direct ловится политикой ndm и петляет через tun2socks).

## 4. Сегменты ndm — главные грабли

Политики ndm (`ip hotspot`) действуют **на весь сегмент** и перекрывают тумблер:

| Сегмент | Политика | Эффект |
|---|---|---|
| Home / Bridge1 | `permit` (дефолтная) | устройства следуют тумблеру |
| сегмент IoT | `DIRECT-NOVPN` | **весь сегмент всегда напрямую**, тумблер игнорируется |

Диагностика «тумблер включён, а трафик прямой»: проверьте `ndmc -c "show running-config"`,
секцию `ip hotspot` — нет ли `policy <сегмент> DIRECT-NOVPN`. Снять:
`ndmc -c "ip hotspot policy <сегмент> permit"`. Индивидуальные привязки устройств
(`host <mac> policy ...`) перекрывают сегментные.

Галки в «Политике по умолчанию» веб-интерфейса не редактируются — это приоритетная
модель ndm (все подключения участвуют по `ip global <приоритет>`), не дефект.

## 5. Как работает демон (serve)

Тик супервизора (15 с):

1. `sing-box` жив? нет → рестарт с бэкоффом (RLIMIT_NOFILE наследуется детьми)
2. jump DNS-правил в nat на месте? нет → переприменить (ndm пересобирает nat
   при любом событии интерфейсов — тумблер = 3 рефреша)
3. зонды ndm-чекера (нестандартный SOCKS-verb) принимает relay — health-check
   ndm проходит, политика не фолбэчится

Автоподъём: после старта демон ждёт `:1080` и поднимает Proxy0 — детерминированно,
без бут-гонки ndm↔Entware.

## 6. Диагностика

```bash
kgate status            # все компоненты одним экраном
kgate logs              # хвост логов демона
ssh router 'tail /opt/var/log/kgate-boot.log'
ssh router 'tail /opt/var/log/singbox.log'
```

| Симптом | Причина → действие |
|---|---|
| «not available in your region» при включённом туннеле | устройство в сегменте/политике DIRECT-NOVPN (§4) |
| foreign-сайты таймаутят, локальные работают | выходной туннель не поднялся; `kgate verify` + лог sing-box |
| `dial tcp 0.0.0.0:0` в логе sing-box | зонды ndm-чекера через relay — безвредно |
| демон не отвечает после бута | `S99routerctl status`/`S99kgate status`; лог бут-загрузки |
| sing-box не стартует после ручных правок конфигов | `sing-box check -c <config>`; целостность бинаря (`ls -la`) |

Инструментальные нюансы Entware/ndm: `iptables` — полный путь `/opt/sbin/iptables`,
флаг `-S` не поддерживается; `ip rule/route` пустые; `pkill`/`xargs` отсутствуют;
правки файлов — только heredoc-stdin (busybox sed не разворачивает `\n` в замене);
потоки LAN→WAN при hardware-offload невидимы tcpdump'ом — верьте тестам выходного IP.

## 7. Обновление и откат

```bash
git pull && make build && ./kgate apply -c kgate.yaml   # идемпотентно
```

Откат версии: `git checkout vX.Y.Z && make build && ./kgate apply`.
Полный отказ от стека: `/opt/etc/init.d/S99kgate stop` (демон и дети остановятся;
init-скрипт legacy можно вернуть из `.disabled`).

Аварийное отключение VPN для всего дома — тумблер Proxy0 в вебе (off) или
`kgate toggle off`: ndm переведёт политику на ISP-бэкап.

## 8. Релизы

Версия — SemVer, хранится в файле `VERSION`. Релиз собирает:

- `kgate-<ver>-linux-arm64` — демон/клиент для роутера
- `kgate-<ver>-linux-amd64` — CLI оператора
- `kgate_<ver>-1_aarch64-3.10.ipk` — Entware-пакет (бинарь + init-скрипт + конфиг-пример)

```bash
make release-binaries ipk     # артефакты в dist/
```

Публикация — через релизный конвейер (сборка, подписи SHA256/cosign/GPG, GitHub Release).
Установка из пакета: `opkg install kgate_<ver>_aarch64-3.10.ipk` — кладёт бинарник,
init-скрипт и конфиг-пример; конфиги редактируются до первого старта.

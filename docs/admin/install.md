# Администрирование · Установка

> 🟢 Один рекомендуемый путь из коробки: **CLI на ноутбук → `kgate config
> create` → `kgate deploy`** — утилита сама поставит весь стек на роутер по
> ssh. Другие способы (opkg-фид, вручную из Releases) — в
> [alternatives-install.md](alternatives-install.md). База роутера:
> [preparation.md](preparation.md) — Entware в `/opt`, aarch64, ssh.

## Основной путь · с ноутбука одним потоком

Три команды и один редактор:

```bash
kgate config create      # шаблон конфига + редактор ($VISUAL/$EDITOR)
kgate deploy             # стек на роутер: бинари, конфиги, ndm-правила, сервис
kgate man                # man-страница kgate(1) по всем командам
```

Обратная операция — `kgate destroy` (с подтверждением; см. [uninstall.md](uninstall.md)).

Что происходит на каждом шаге:

### 1 · CLI на ноутбук

Инсталлер скачивает свежий релизный архив в `~/.local/bin`. Репозиторий
публичный — `GITHUB_TOKEN` не нужен. Ручной вариант (без пайпа): скачайте
`kgate_<версия>_linux_<arch>.tar.gz` из [Releases](https://github.com/Korrnals/kgate/releases),
распакуйте, положите `kgate` в `$PATH` — и переходите к шагу 2.

### 2 · Если у тебя есть подписка провайдера

Провайдер дал URL подписки (vless/hysteria2/trojan/ss-узлы или sing-box JSON)?
Тогда шаг 2 заменяется одной командой — пароли и серверы приедут из подписки:

```bash
kgate subscribe add <url>     # до или после deploy — оба порядка работают
```

Пароль вручную не нужен: узлы подписки применяются на роутер, RU-split
kgate сохраняется. Статический путь (без подписки) — шаг 2 ниже.

### 2 · `kgate config create`

Создаёт `~/.kgate/kgate.yaml` из встроенного шаблона, открывает редактор и
печатает путь. Замените шаблонные значения реальными:

| Поле | Шаблон → реальное | Что это |
|---|---|---|
| `host` | `192.168.1.1` | адрес роутера (обычно верен) |
| `server_ip` | `203.0.113.10` → **IP вашего exit-сервера** | hy2-сервер (ndm route-pin) |
| `ssh_key` | `~/.ssh/kgate-ed25519` | ключ с доступом к роутеру по ssh |

Остальные поля (`api`, `daemon`) трогать не нужно. Если после сохранения
шаблонные значения остались — утилита предупредит. Позже: `kgate config
view|path|edit`.

### 3 · `kgate deploy`

Стадии выполняются по порядку и идемпотентны — повторный запуск безопасен
(`apply` работает как алиас):

| Стадия | Что делает на роутере |
|---|---|
| **Preflight** | проверка Entware (`/opt/etc/init.d`) и uptime |
| **Files** | payload: `kgate` arm64 + `sing-box` → `/opt/sbin/`, `S99kgate`, `ndm-commands.sh`, sing-box конфиг + rulesets, ssh-ключи; opkg-зависимости `iptables openssh-server` |
| **Migrate** | глушение legacy: `S99routerctl`, `S99sing-box`, `S24xray`, watchdog; чистка `rc.unslung` |
| **ConfigAndCerts** | рендер `/opt/etc/kgate/kgate.yaml` из локального конфига, генерация mTLS-сертификатов (CA и серверные → роутер, клиентские → `~/.kgate/`) |
| **NDM** | `KGATE_SERVER_IP=<server_ip> sh /opt/etc/ndm-commands.sh`: Proxy0, route-pins, DNS, политики |
| **Services** | `S99kgate` stop → start → status; после полного `deploy` — пауза 5 с и верификация `status` + `verify` |

Точечный перезапуск стадии: `kgate deploy --only files|config|ndm|services`;
план без изменений: `--dry-run`.

> [!CAUTION]
> Стадия ConfigAndCerts **перезаписывает** `/opt/etc/kgate/kgate.yaml` из
> локального конфига. Правьте локальный `~/.kgate/kgate.yaml` на ноутбуке
> (`kgate config edit`), а не роутерный файл напрямую.

> [!NOTE]
> sing-box конфиг (`/opt/etc/sing-box/config.json`) деплойер ставит из
> шаблона с плейсхолдерами `HY2_PASSWORD` / `hy2.example.com`. Замените их
> реальными `server`/`password` на роутере и рестартните — см. «Первый
> запуск» ниже; до этого туннель намеренно не поднимается.

### 4 · Проверка

```bash
kgate status      # стек одним экраном (mTLS)
kgate verify      # вердикт демона + socks-тест: выходной IP (ожидаем NL-адрес)
```

curl-батарея с ноутбука в домашней сети (тумблер ON):

| Проверка | Команда | Ожидание |
|---|---|---|
| выходной IP | `curl -s https://api.ipify.org` | NL-адрес exit-узла |
| youtube | `curl -s -o /dev/null -w '%{http_code}' https://www.youtube.com` | 200 |
| ya.ru | `curl -s -o /dev/null -w '%{http_code}' https://ya.ru` | 302 |
| grok | `curl -s -o /dev/null -w '%{http_code}' https://grok.com` | 200 |

Boot-лог демона (старт, супервизор, autoup): `tail -50 /opt/var/log/kgate-boot.log`.
Трактовка строк — [operations.md](operations.md).

## 🥇 Первый запуск: поведение «из коробки»

Шаблонные конфиги безопасны: детектор плейсхолдеров находит
`HY2_PASSWORD` / `hy2.example.com` в конфиге sing-box и пишет в boot-лог
**«КОНФИГ НЕ НАСТРОЕН»**, Proxy0 опускается, автоподъём пропускается —
заведомо мёртвый туннель не поднимается, интернет дома остаётся прямым.

После заполнения реальных `server`/`password` и рестарта туннель поднимается
автоматически:

```sh
vi /opt/etc/sing-box/config.json        # server / password
/opt/etc/init.d/S99kgate restart        # туннель через ~25 с
```

## ⬆️ Обновление

На ноутбуке и на роутере:

```bash
kgate update    # GitHub Releases → сравнение версий → sha256 → атомарная замена;
                # на роутере ещё и перезапуск сервиса (туннель вернётся за ~30-60 с)
```

Пакетное обновление (`opkg upgrade kgate`) —
[alternatives-install.md](alternatives-install.md). Откат — [releases.md](releases.md).

## 🟠 OpenWrt 23.05+/24.10 · beta (Phase 1)

> Вторая платформа, shim-based: демон и деплойер Go не менялись — на OpenWrt
> их ndm-вербы переводит shell-слой `/usr/bin/ndmc` (symlink `/bin/ndmc`) в
> uci/ip/nft. **Beta**: поле-необкатано, E2E на живом устройстве впереди.

**Что работает в Phase 1:** демон-супервизор (sing-box под присмотром, mTLS
API), route-pins (uci/netifd static routes — переживают reboot и WAN-reconnect,
hotplug reapply), flap self-heal, тумблер/state (nft-таблица `inet kgate`),
procd-сервис, socks-выдача `:1080`/`:1090` для ручных клиентов.
**Что НЕ входит (Phase 2):** transparent redirect LAN-клиентов (tproxy/marks —
нужны `kmod-nft-tproxy` и реальное железо), per-device политики (policy-v2:
VPN/NO-VPN, привязки через `kgate policy`), dnsmasq-full.

Предпосылки (проверяются и репортятся, НИЧЕГО не ставится — opkg руками при
желании): `nft` + `uci` (ядро 23.05+), рекомендованы `iptables-nft ip6tables-nft
ca-bundle` (LAN-DNS bypass демона и TLS наружу), `kmod-nft-tproxy` — Phase 2.

```bash
# с ноутбука (или scp install.sh на роутер и запустить локально):
ssh root@192.168.1.1 'curl -fsSL \
  https://raw.githubusercontent.com/Korrnals/kgate/main/scripts/install.sh \
  | sh -s -- --platform=openwrt'
```

Инсталлер сам ставит: `kgate`+`sing-box` (pinned 1.11.15) в `/usr/bin`, shim в
`/usr/bin/ndmc` + `/bin/ndmc`, procd-init `/etc/init.d/kgate` (enabled),
hotplug-хук, `/etc/kgate/{kgate.yaml,sing-box/}` (плейсхолдеры, существующие
конфиги не перетираются) и /opt-compat symlinks для жёстко прописанных путей
демона (`/opt/var`→`/var`, `/opt/etc/{kgate,sing-box}`→`/etc/kgate/...`,
`/opt/sbin/{iptables,ip6tables}`→`*-nft`). authorized_keys → dropbear
(`/etc/dropbear/authorized_keys` — только создаёт, ключи не трогает).

Далее:

```sh
vi /etc/kgate/kgate.yaml              # host, server_ip
vi /etc/kgate/sing-box/config.json    # server / password (плейсхолдеры)
# mTLS-серты: на ноутбуке kgate certs, потом
# scp ~/.kgate/{ca.crt,server.crt,server.key} root@192.168.1.1:/etc/kgate/
/etc/init.d/kgate start && /etc/init.d/kgate stack   # демон + sing-box + Proxy0 + пины
```

Клиент с ноутбука — как обычно (`kgate status/verify/toggle`, указав в
`~/.kgate/kgate.yaml` `host` роутера; клиентские серты — те же `kgate certs`).
Выключение туннеля — `kgate toggle off` (intent-файл `/etc/kgate/intent`
переживает reboot; веб-клик lasting-off не даёт — контракт 1.4.6 сохранён).

## 👉 См. также

- [alternatives-install.md](alternatives-install.md) — opkg-фид, вручную из Releases
- [preparation.md](preparation.md) — подготовка роутера и носителя Entware
- [configuration.md](configuration.md) — плейсхолдеры, `KGATE_*`, критичные поля sing-box
- [operations.md](operations.md) — эксплуатация, диагностика boot-лога
- [segments-and-policies.md](segments-and-policies.md) — «тумблер ON, а трафик прямой»
- [releases.md](releases.md) — артефакты, подписи, откат
- [glossary.md](../glossary.md) — payload, стадия deploy, route-pins

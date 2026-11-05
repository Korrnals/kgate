# Администрирование · Установка

> 🟢 Три пути из коробки. Для домашнего роутера выбирайте **Путь A
> (opkg-фид)** — несколько команд. Фид недоступен — **Путь B** (вручную из
> GitHub Releases). Полный стек «с нуля» с ноутбука — **Путь C** (деплойер).
> База роутера: [preparation.md](preparation.md) — Entware в `/opt`,
> aarch64, ≥ 120 МБ, ssh.

## 🧭 Выбор пути

| Путь | Чем ставит | Кому подходит |
|---|---|---|
| 🅰 **opkg-фид** | `opkg install kgate` | большинство: быстро, обновления через `opkg upgrade` |
| 🅱 **вручную из Releases** | скачанный `.ipk` или бинари | фид недоступен / нужен контроль каждой версии |
| 🅲 **деплойер `kgate apply`** | ssh с ноутбука | полный стек «с нуля»: ndm-правила, туннель, mTLS-сертификаты |

> [!IMPORTANT]
> Пакет (`.ipk`) ставит **файлы стека**: бинари `kgate` и `sing-box`,
> init-скрипт, ndm-скрипт, шаблоны конфигов, rulesets. ndm-конфигурацию
> (Proxy0, route-pins, DNS, политики) пакет **не применяет** — её делает
> деплойер (Путь C) либо ручной прогон ndm-скрипта (шаг в путях A и B).

## 🅰 Путь A · opkg-фид (рекомендуемый)

Всё — на роутере по ssh.

```sh
opkg install wget-ssl libustream-ssl uclient-fetch   # SSL-транспорт для opkg (фид по https)
echo "src/gz kgate https://korrnals.github.io/kgate/" >> /opt/etc/opkg.conf
opkg update
opkg install kgate
```

Пакет самодостаточен: внутри `kgate` + `sing-box` + init-скрипт +
`ndm-commands.sh` + rulesets. Зависимости (`iptables`, `openssh-server`,
`ca-bundle`, `curl`) opkg подтянет автоматически. При первом запуске `postinst`
создаст живые конфиги из шаблонов `.example` и подскажет следующий шаг.

Дальше — секция **«⚙️ Настройка после установки»** ниже.

## 🅱 Путь B · вручную из GitHub Releases

Репозиторий и релизы публичны — токены не нужны.

### 🅱1 · готовый `.ipk`

С роутера:

```sh
cd /tmp
wget https://github.com/Korrnals/kgate/releases/download/v1.1.2/kgate_1.1.2-1_aarch64-3.10.ipk
opkg install ./kgate_1.1.2-1_aarch64-3.10.ipk
```

или с ноутбука:

```bash
curl -sSLO https://github.com/Korrnals/kgate/releases/download/v1.1.2/kgate_1.1.2-1_aarch64-3.10.ipk
scp kgate_1.1.2-1_aarch64-3.10.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'opkg install /tmp/kgate_1.1.2-1_aarch64-3.10.ipk'
```

### 🅱2 · голые бинари

Когда пакет ставить нельзя — раскладка руками. `kgate` скачивается из
артефактов релиза, `sing-box` — изнутри того же `.ipk` (архив `data.tar.gz`):

```sh
cd /tmp
# движок: достаём sing-box из ipk
wget https://github.com/Korrnals/kgate/releases/download/v1.1.2/kgate_1.1.2-1_aarch64-3.10.ipk
mkdir /tmp/ipk && cd /tmp/ipk && tar -xzf /tmp/kgate_*.ipk && tar -xzf data.tar.gz
install -m 0755 opt/sbin/sing-box /opt/sbin/sing-box

# супервизор: релизный бинарь kgate
cd /tmp
wget https://github.com/Korrnals/kgate/releases/download/v1.1.2/kgate-1.1.2-linux-arm64
install -m 0755 kgate-1.1.2-linux-arm64 /opt/sbin/kgate
```

Остальные файлы берутся из репозитория (`examples/` — вендоренные, включая
rulesets) и раскладываются так:

| Источник | Путь на роутере | Права |
|---|---|---|
| `kgate-1.1.2-linux-arm64` (Release) | `/opt/sbin/kgate` | 0755 |
| `sing-box` (из `data.tar.gz` ipk) | `/opt/sbin/sing-box` | 0755 |
| `examples/S99kgate` | `/opt/etc/init.d/S99kgate` | 0755 |
| `examples/ndm-commands.sh` | `/opt/etc/ndm-commands.sh` | 0755 |
| `examples/etc/sing-box/config.json` | `/opt/etc/sing-box/config.json` (копия из `.example`) | 0644 |
| `examples/kgate.yaml.example` | `/opt/etc/kgate/kgate.yaml` (копия) | 0644 |
| `examples/etc/sing-box/rulesets/*.srs` | `/opt/etc/sing-box/rulesets/` | 0644 |

Зависимости ставятся вручную:

```sh
opkg install wget-ssl libustream-ssl uclient-fetch iptables openssh-server ca-bundle curl
```

Дальше — секция **«⚙️ Настройка после установки»** ниже.

## ⚙️ Настройка после установки (пути A и B)

1. **sing-box конфиг** — замените плейсхолдеры реальными параметрами вашего
   hysteria2-сервера:

   ```sh
   vi /opt/etc/sing-box/config.json
   ```

   В `outbounds[hy2-out]`: `server` (`hy2.example.com` → ваш хост),
   `server_port`, `password` (`HY2_PASSWORD` → ваш пароль), при obfs — пароль
   salamander, в `tls.server_name` — SNI.

2. **kgate.yaml** — IP exit-сервера вместо `203.0.113.10`:

   ```sh
   vi /opt/etc/kgate/kgate.yaml
   ```

3. **ndm-конфигурация** — Proxy0, route-pins, DNS, политики
   (идемпотентно, повторный прогон безопасен) — вместо `203.0.113.10`
   подставьте реальный IP exit-сервера:

   ```sh
   KGATE_SERVER_IP=203.0.113.10 sh /opt/etc/ndm-commands.sh
   ```

4. **старт**:

   ```sh
   /opt/etc/init.d/S99kgate start
   ```

   Туннель поднимется автоматически через ~25 с (`boot_autoup: true`,
   `autoup_delay: 25s` — демон ждёт готовности движка на `:1080`).

## 🅲 Путь C · деплой с ноутбука (`kgate apply`)

### CLI на ноутбук

```bash
curl -fsSL https://raw.githubusercontent.com/Korrnals/kgate/main/scripts/install.sh | sh
```

Скрипт скачивает свежий релизный бинарь в `~/.local/bin` и кладёт шаблон
конфига в `~/.kgate/`. Репозиторий публичный — `GITHUB_TOKEN` не нужен.

### Конфиг деплойера

Путь поиска: флаг `-c` (по умолчанию `kgate.yaml` в текущем каталоге);
инсталлер кладёт шаблон в `~/.kgate/kgate.yaml` — можно работать оттуда,
указав `-c ~/.kgate/kgate.yaml`.

```bash
cp ~/.kgate/kgate.yaml ~/.kgate/kgate.yaml.orig 2>/dev/null
vi ~/.kgate/kgate.yaml     # host, server_ip, ssh_port/ssh_user/ssh_key
```

Ключевые поля: `host` — адрес роутера, `server_ip` — IP exit-сервера
(плейсхолдер `203.0.113.10` заменить!), `ssh_key` — ключ с доступом к роутеру.

### Деплой

```bash
kgate apply -c ~/.kgate/kgate.yaml
```

Стадии выполняются в порядке и идемпотентны — повторный запуск безопасен:

| Стадия | Что делает на роутере |
|---|---|
| **Preflight** | проверка Entware (`/opt/etc/init.d`) и uptime |
| **Files** | payload: `kgate` arm64 + `sing-box` → `/opt/sbin/`, `S99kgate`, `ndm-commands.sh`, sing-box конфиг + rulesets, ssh-ключи; opkg-зависимости `iptables openssh-server ca-bundle` |
| **Migrate** | глушение legacy: `S99routerctl`, `S99sing-box`, `S24xray`, watchdog; чистка `rc.unslung` |
| **ConfigAndCerts** | рендер `/opt/etc/kgate/kgate.yaml` из локального конфига, генерация mTLS-сертификатов (CA и серверные → роутер, клиентские → `~/.kgate/`) |
| **NDM** | `KGATE_SERVER_IP=<server_ip> sh /opt/etc/ndm-commands.sh`: Proxy0, route-pins, DNS, политики |
| **Services** | `S99kgate` stop → start → status; после полного `apply` — пауза 5 с и верификация `status` + `verify` |

Точечный перезапуск стадии: `--only files|config|ndm|services`; план без
изменений: `--dry-run`.

> [!CAUTION]
> Стадия ConfigAndCerts **перезаписывает** `/opt/etc/kgate/kgate.yaml` из
> локального конфига. Правьте локальный `kgate.yaml` на ноутбуке, а не
> роутерный файл напрямую.

Секреты hy2 (`local/etc/sing-box/config.json`) — материал для payload-сборки;
для домашнего сценария проще конфиг от путей A/B. Детали —
[configuration.md](configuration.md).

## 🥇 Первый запуск: поведение «из коробки»

Пакет создаёт конфиги из шаблонов `.example` — и демон **стартует**, но с
шаблонными значениями работает так:

- детектор плейсхолдеров находит `HY2_PASSWORD` / `hy2.example.com` в конфиге
  sing-box и пишет в boot-лог **«КОНФИГ НЕ НАСТРОЕН»**;
- Proxy0 намеренно опускается, автоподъём (`autoup`) **пропускается** —
  заведомо мёртвый туннель не поднимается;
- интернет дома остаётся **прямым**: ничего не ломается.

После заполнения реальных `server`/`password` и рестарта туннель поднимается
автоматически:

```sh
vi /opt/etc/sing-box/config.json        # server / password
/opt/etc/init.d/S99kgate restart        # туннель через ~25 с
```

## ✅ Проверка

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

## ⬆️ Обновление

> [!CAUTION]
> Перед любой пакетной операцией — **бэкап конфигов**:
>
> ```bash
> ssh root@192.168.1.1 'tar -czf /tmp/kgate-etc.tgz /opt/etc/kgate /opt/etc/sing-box'
> scp root@192.168.1.1:/tmp/kgate-etc.tgz .
> ```
>
> В ipk **≤ 1.1.1** конфиги входили в пакет как conffiles: при переустановке
> той же версии opkg мог заменить отредактированные конфиги шаблонами
> (известная ловушка). В ipk **≥ 1.1.2** конфигов в пакете нет вовсе —
> `postinst` создаёт их из `.example` только при первом запуске, поэтому
> переустановка и удаление пакета живые конфиги не трогают. Для пакетов
> ≤ 1.1.1 правило бэкапа обязательно.

```sh
opkg update && opkg upgrade kgate
/opt/etc/init.d/S99kgate status
```

Обновление деплойером и откат — [releases.md](releases.md).

## 👉 См. также

- [preparation.md](preparation.md) — подготовка роутера и носителя Entware
- [configuration.md](configuration.md) — плейсхолдеры, `KGATE_*`, критичные поля sing-box
- [operations.md](operations.md) — эксплуатация, диагностика boot-лога
- [segments-and-policies.md](segments-and-policies.md) — «тумблер ON, а трафик прямой»
- [releases.md](releases.md) — артефакты, подписи, откат
- [glossary.md](../glossary.md) — payload, стадия apply, route-pins

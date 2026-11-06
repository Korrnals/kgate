# Администрирование · Альтернативные пути установки

> Основной путь (CLI → `config create` → `deploy`) — в
> [install.md](install.md). Здесь — opkg-фид, ручная установка из Releases и
> нюансы каждого пути. База роутера: [preparation.md](preparation.md).

> [!IMPORTANT]
> Пакет (`.ipk`) ставит **файлы стека**: бинари `kgate` и `sing-box`,
> init-скрипт, ndm-скрипт, шаблоны конфигов, rulesets. ndm-конфигурацию
> (Proxy0, route-pins, DNS, политики) пакет **не применяет** — её делает
> деплойер (`kgate deploy`) либо ручной прогон ndm-скрипта (шаг в путях
> ниже).

## 🅰 opkg-фид

Всё — на роутере по ssh. Быстро, обновления через `opkg upgrade`.

```sh
opkg install wget-ssl libustream-ssl uclient-fetch   # SSL-транспорт для opkg (фид по https)
echo "src/gz kgate https://korrnals.github.io/kgate/" >> /opt/etc/opkg.conf
opkg update
opkg install kgate
```

Пакет самодостаточен: внутри `kgate` + `sing-box` + init-скрипт +
`ndm-commands.sh` + rulesets. Зависимости (`iptables`, `openssh-server`)
opkg подтянет автоматически. При первом запуске `postinst` создаст живые
конфиги из шаблонов `.example` и подскажет следующий шаг.

CLI на ноутбук (управление `kgate status/toggle/…` через mTLS) ставится
отдельно — тем же однострочником из [install.md](install.md); тумблер
доступен и из веб-интерфейса роутера, без CLI.

### Настройка после установки (фид)

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

### Обновление пакета

```sh
opkg update && opkg upgrade kgate
/opt/etc/init.d/S99kgate status
```

## 🅱 вручную из GitHub Releases

Репозиторий и релизы публичны — токены не нужны.

### 🅱1 · готовый `.ipk`

С роутера:

```sh
cd /tmp
wget https://github.com/Korrnals/kgate/releases/download/v1.4.2/kgate_1.4.2-1_aarch64-3.10.ipk
opkg install ./kgate_1.4.2-1_aarch64-3.10.ipk
```

или с ноутбука:

```bash
curl -sSLO https://github.com/Korrnals/kgate/releases/download/v1.4.2/kgate_1.4.2-1_aarch64-3.10.ipk
scp kgate_1.4.2-1_aarch64-3.10.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'opkg install /tmp/kgate_1.4.2-1_aarch64-3.10.ipk'
```

После установки — те же шаги настройки, что для фида (см. выше).

### 🅱2 · голые бинари

Когда пакет ставить нельзя — раскладка руками. `kgate` скачивается из
артефактов релиза, `sing-box` — изнутри того же `.ipk` (архив `data.tar.gz`):

```sh
cd /tmp
# движок: достаём sing-box из ipk
wget https://github.com/Korrnals/kgate/releases/download/v1.4.2/kgate_1.4.2-1_aarch64-3.10.ipk
mkdir /tmp/ipk && cd /tmp/ipk && tar -xzf /tmp/kgate_*.ipk && tar -xzf data.tar.gz
install -m 0755 opt/sbin/sing-box /opt/sbin/sing-box

# супервизор: релизный архив kgate
cd /tmp
wget https://github.com/Korrnals/kgate/releases/download/v1.4.2/kgate_1.4.2_linux_arm64.tar.gz
tar -xzf kgate_1.4.2_linux_arm64.tar.gz
install -m 0755 kgate /opt/sbin/kgate
```

Остальные файлы берутся из репозитория (`examples/` — вендоренные, включая
rulesets) и раскладываются так:

| Источник | Путь на роутере | Права |
|---|---|---|
| `kgate` (из `kgate_1.4.2_linux_arm64.tar.gz`) | `/opt/sbin/kgate` | 0755 |
| `sing-box` (из `data.tar.gz` ipk) | `/opt/sbin/sing-box` | 0755 |
| `examples/S99kgate` | `/opt/etc/init.d/S99kgate` | 0755 |
| `examples/ndm-commands.sh` | `/opt/etc/ndm-commands.sh` | 0755 |
| `examples/etc/sing-box/config.json` | `/opt/etc/sing-box/config.json` (копия из `.example`) | 0644 |
| `examples/kgate.yaml.example` | `/opt/etc/kgate/kgate.yaml` (копия) | 0644 |
| `examples/etc/sing-box/rulesets/*.srs` | `/opt/etc/sing-box/rulesets/` | 0644 |
| `assets/ca-bundle.crt` (репо) | `/opt/etc/kgate/ca-bundle.crt` | 0644 |

CA-файл — запасной пул корневых сертификатов (нужен только прошивкам без
`/etc/ssl/certs`: утилита подключает его через `SSL_CERT_FILE` автоматически).

Зависимости ставятся вручную:

```sh
opkg install wget-ssl libustream-ssl uclient-fetch iptables openssh-server
```

После раскладки — те же шаги настройки, что для фида (см. выше).

## 🅲 из исходников (для разработчиков)

```bash
git clone https://github.com/Korrnals/kgate.git && cd kgate
cp examples/kgate.yaml.example kgate.yaml           # host / ssh-ключ
mkdir -p local/etc/sing-box/rulesets local/etc/ssh  # реальные конфиги и ключи
make build && ./kgate deploy -c kgate.yaml
./kgate verify                                      # всё зелёное — готово
```

## 👉 См. также

- [install.md](install.md) — основной путь установки
- [uninstall.md](uninstall.md) — удаление ([альтернативные сценарии](alternatives-uninstall.md))
- [preparation.md](preparation.md) — подготовка роутера и носителя Entware
- [opkg-feed.md](opkg-feed.md) — как устроен фид
- [releases.md](releases.md) — артефакты, подписи, откат

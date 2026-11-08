# Администрирование · Требования и совместимость

> Страница-фильтр: проверь, подходит ли kgate под твоё железо, ОС и сервер,
> прежде чем ставить. Всё, чего у kgate **нет**, здесь перечислено явно —
> чтобы не было сюрпризов после установки.

## 🖥 Роутер

| Требование | Детали | Как проверить |
|---|---|---|
| Платформа **Netcraze / Keenetic** (production) **или OpenWrt 23.05+/24.10** (beta) | production-путь глубоко завязан на ndm (Proxy-подключения, `ndmc`, политики); OpenWrt — через shim-слой `platform/openwrt/` (те же ndm-вербы → uci/ip/nft, Go-код не меняется); прочие прошивки не поддерживаются | бренд устройства / `/etc/openwrt_release` |
| Архитектура **aarch64** | релизные бинари kgate и sing-box собраны под arm64; MIPS-роутеры (legacy KN-класс) не поддерживаются; x86_64 OpenWrt-боксы — архив `linux_amd64` | `uname -m` → `aarch64` |
| **KeeneticOS / NetcrazeOS 4.x–5.x** (для Keenetic) | проверено на 5.01.C.7.0-4 (Netcraze Ultra); ожидаемая совместимость — семейство 4.2+ (ndmc-команды стабильны), но каждой версии ОС требуется контроль после обновления | `ndmc -c "show version"` |
| **OpenWrt 23.05+ / 24.10** (для OpenWrt, beta) | shim-based: `nft` + `uci` (ядро), рекомендованы `iptables-nft ip6tables-nft ca-bundle` (LAN-DNS bypass, TLS); `kmod-nft-tproxy` — Phase 2; Entware НЕ нужен | `cat /etc/openwrt_release && nft --version` |
| **Entware (opkg) в `/opt`** (только Keenetic) | стек живёт в Entware: бинари, init-скрипт, зависимости (`iptables`, `openssh-server`); на OpenWrt стек живёт в `/usr/bin` + `/etc/kgate` | `[ -d /opt/etc/init.d ] && echo OK` |
| Свободное место **≥ 120 МБ** | распакованный стек ~50–85 МБ (`kgate` ~10 МБ + `sing-box` ~31 МБ + rulesets + CA-пул); рекомендуемый носитель — USB; на OpenWrt — место на overlay (`/usr`, `/etc`), extroot/USB опционально | `df -h /opt` (Keenetic) / `df -h /` (OpenWrt) |

Подготовка роутера пошагово — [preparation.md](preparation.md).

## 💻 Ноутбук оператора (CLI)

| Требование | Детали |
|---|---|
| ОС | Linux amd64/arm64 (инсталлер и релизные архивы — под Linux; Windows-пользователи: скачайте архив вручную и положите `kgate` в PATH) |
| ssh-ключ до роутера | клиентский ssh-транспорт — чистый Go (x/crypto/ssh), бинарник ssh на ноутбуке **не нужен**; host-ключи пишутся TOFU в `~/.ssh/known_hosts` |
| Редактор для `config create` | любой (`$VISUAL`/`$EDITOR`) |
| curl | только для однострочника-инсталлера; сам kgate ходит в сеть чистым Go (net/http) |

## 🔐 Туннель: с чем работает kgate

| Компонент | Что поддерживается |
|---|---|
| **Протокол туннеля** | **hysteria2 (hy2)** — единственный протокол, который kgate конфигурирует и сопровождает из коробки: шаблон `config.json`, обфускация salamander (опционально), TLS с SNI |
| **Сервер** | свой или предоставленный hysteria2-эндпоинт (sing-box ≥ 1.11 или официальный hysteria2); TLS-сертификат на домен (Let's Encrypt) либо self-signed + `insecure` |
| **Учётные данные** | логин-пароль hy2 (один пользователь на роутер) **или подписка** (см. ниже) |
| **Локальная выдача на роутере** | SOCKS5/mixed `:1080`, redirect `:1081`, толерантный SOCKS-relay `:1090` (для ndm tun2socks — принимает любые SOCKS-вербы) |
| **Маршрутизация** | RU-сплит из коробки: geosite/geoip rulesets в комплекте (RU-direct, зарубежное — через туннель), режимы rule/global (`kgate ruexit`) |
| **DNS** | перехват клиентского DNS (iptables SBREDIRECT → чистый резолвер) + анти-утечка IPv6 DNS |

### Подписки и протоколы — подробно

**Два пути получить туннель:**

| Путь | Что нужно | Пароль |
|---|---|---|
| **Статический** (по умолчанию) | свой hysteria2-сервер (sing-box/hysteria2, TLS на домен) | задаёшь ты в `kgate config create` → в конфиг sing-box |
| **Подписка провайдера** | URL подписки — сервер/узлы/пароли приезжают из неё | руками не задаётся |

Форматы подписки (`kgate subscribe add <url>`): base64 URI-лист — **vless** (Reality: pbk/sid, flow xtls-rprx-vision, utls, ws/grpc), **hysteria2** (± obfs salamander), **trojan**, **shadowsocks** — и готовый **sing-box JSON** (какой рендерит инфраструктура Korrnals).

Подписка применяется одной командой (до или после `deploy` — оба порядка), обновление — `kgate subscribe update`. RU-split и правила kgate сохраняются: узлы подписки = пул выходов, маршрутизация остаётся kgate'овской.

Чего в подписках пока нет: vmess, wireguard, tuic (движок умеет — парсер ещё нет); авто-обновление по таймеру демон-сайд (сейчас — `kgate subscribe update` вручную).
- **Другие протоколы** (wireguard, tuic, vmess) — движок sing-box их умеет, но парсер подписки их пока не разбирает.
- **Режим сервера** — kgate только клиент: сервер hysteria2/vless нужно поднять отдельно (VPS) или использовать предоставленный
- **Нативной карточки в веб-интерфейсе роутера** — реестр компонентов KeeneticOS закрыт; управление: тумблер Proxy0 в вебе + CLI/mTLS API
- **Не-aarch64 роутеров** и сторонних прошивок (кроме OpenWrt 23.05+/24.10 — beta, см. выше; TP-Link Broadcom-класс — невозможно: см. [operations.md](operations.md))

## ✅ Быстрая проверка «подходит ли мне»

```bash
uname -m                                  # aarch64 (или x86_64 для OpenWrt-бокса)
ndmc -c "show version" | head -3          # KeeneticOS 4.x/5.x (для OpenWrt — нет ndmc)
[ -d /opt/etc/init.d ] && echo Entware-OK # путь Keenetic
[ -f /etc/openwrt_release ] && nft --version   # путь OpenWrt (beta, 23.05+)
df -h /opt                                # ≥ 120MB (Keenetic) / df -h / (OpenWrt)
```

Все четыре пункта зелёные → [install.md](install.md). Что-то не сходится —
см. «Чего у kgate НЕТ» выше и [faq.md](../user/faq.md).

## 👉 См. также

- [preparation.md](preparation.md) — подготовка носителя и ssh
- [install.md](install.md) — установка
- [configuration.md](configuration.md) — плейсхолдеры и критичные поля sing-box
- [glossary.md](../glossary.md) — hy2, tun2socks, RU-сплит

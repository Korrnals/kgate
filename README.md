<div align="center">

<img src="assets/banner.svg" alt="KGATE — Home VPN Gateway Supervisor" width="100%">

**KGATE** — единая утилита для VPN-стека на роутерах **Netcraze / Keenetic**:
демон-супервизор на роутере + mTLS-клиент + деплойер «с нуля до рабочего состояния».

[![release](https://img.shields.io/badge/release-v1.1.2-4fc3f7)](https://github.com/Korrnals/kgate/releases)
[![platform](https://img.shields.io/badge/platform-Netcraze%20%2F%20Keenetic-7c8cff)](#поддерживаемые-роутеры)
[![arch](https://img.shields.io/badge/arch-aarch64%20%7C%20amd64-9fc0e8)](#артефакты)
[![api](https://img.shields.io/badge/API-mTLS%20%3A9443-2e7d32)](docs/api/authentication.md)
[![docs](https://img.shields.io/badge/docs-полный%20комплект-blue)](#-документация)

`kgate serve` · `kgate apply` · `kgate status` · `kgate toggle on` · `kgate ruexit on`

</div>

---

## ⚡ Быстрый старт

### Вариант 1 · однострочная установка CLI (ноутбук оператора)

```bash
curl -fsSL https://raw.githubusercontent.com/Korrnals/kgate/main/scripts/install.sh | sh
```

> [!NOTE]
> Репозиторий и релизы публичные — токены не нужны. Скрипт кладёт CLI в
> `~/.local/bin` и шаблон конфига в `~/.kgate/`.

### Вариант 2 · opkg-фид на роутере (рекомендуемый)

```sh
opkg install wget-ssl libustream-ssl uclient-fetch   # SSL-транспорт для opkg
echo "src/gz kgate https://korrnals.github.io/kgate/" >> /opt/etc/opkg.conf
opkg update && opkg install kgate
```

Конфиги и старт — [docs/admin/install.md](docs/admin/install.md); подготовка
роутера и носителя — [docs/admin/preparation.md](docs/admin/preparation.md).

### Вариант 3 · полный стек с нуля (деплойер)

```bash
git clone https://github.com/Korrnals/kgate.git && cd kgate
cp examples/kgate.yaml.example kgate.yaml           # host / ssh-ключ
mkdir -p local/etc/sing-box/rulesets local/etc/ssh  # реальные конфиги и ключи
make build && ./kgate apply -c kgate.yaml
./kgate verify                                      # всё зелёное — готово
```

---

## 📚 Документация · дерево навигации

```
docs/
├── 🏗 architecture/                 — как это устроено
│   ├── overview.md                  — назначение, роли бинаря, принципы
│   ├── components.md                — компоненты, схемы демона, интеграция с ndm
│   ├── data-flow.md                 — потоки трафика и сценариев (ON / OFF / RU-exit)
│   └── data-model.md                — конфиг-модель, payload, объекты API
│
├── 🛠 admin/                        — администрирование
│   ├── preparation.md               — 🧰 подготовка роутера и носителя Entware
│   ├── install.md                   — установка: фид / вручную / деплойер
│   ├── configuration.md             — kgate.yaml + критичные поля sing-box
│   ├── segments-and-policies.md     — ⚠️ сегменты ndm: грабли №1
│   ├── operations.md                — эксплуатация и диагностика
│   ├── releases.md                  — обновление, откат, верификация подписей
│   ├── opkg-feed.md                 — 📦 opkg-фид: подключение и публикация
│   └── uninstall.md                 — 🔴 удаление и очищение
│
├── 👤 user/                         — пользователю
│   ├── getting-started.md           — начало работы
│   ├── day-to-day.md                — повседневное управление
│   ├── ru-exit.md                   — 🕶 RU-анонимизация
│   └── faq.md                       — частые вопросы
│
├── 🔌 api/                          — интеграция
│   ├── authentication.md            — mTLS, сертификаты, конвенции
│   ├── endpoints.md                 — карта эндпоинтов, легенда методов
│   ├── endpoints-status-verify.md   — 🟢 status · verify
│   ├── endpoints-toggle.md          — 🔵 toggle (тумблер VPN)
│   ├── endpoints-ruexit.md          — 🔵 ruexit (RU-exit)
│   └── endpoints-logs-reboot.md     — 🟢 logs · 🔴 reboot
│
└── 📖 glossary.md                   — глоссарий терминов
```

| Хочу… | Открой |
|---|---|
| понять, как устроено | [architecture/overview](docs/architecture/overview.md) → [components](docs/architecture/components.md) |
| подготовить роутер к установке | [admin/preparation](docs/admin/preparation.md) |
| установить/обновить | [admin/install](docs/admin/install.md) → [admin/releases](docs/admin/releases.md) |
| настроить конфиги | [admin/configuration](docs/admin/configuration.md) |
| разобраться, «почему трафик прямой» | [admin/segments-and-policies](docs/admin/segments-and-policies.md) |
| включить RU-анонимизацию | [user/ru-exit](docs/user/ru-exit.md) |
| интегрироваться по API | [api/authentication](docs/api/authentication.md) → [карта эндпоинтов](docs/api/endpoints.md) |
| свериться с терминами | [glossary](docs/glossary.md) |
| удалить всё | [admin/uninstall](docs/admin/uninstall.md) |

---

## Что это

Один статический Go-бинарь, три роли:

| Роль | Команда | Где | Ответственность |
|---|---|---|---|
| 🧠 **Демон** | `kgate serve` | роутер (Entware, init-скрипт) | супервизор sing-box, DNS-правила, авто-подъём туннеля, толерантный SOCKS-relay для ndm, mTLS API |
| 🎛 **Клиент** | `kgate status / verify / toggle / ruexit / logs / reboot` | ноутбук | управление и диагностика через mTLS |
| 🚀 **Деплойер** | `kgate apply` | ноутбук, по ssh | установка и обновление стека «с нуля», идемпотентные стадии |

## Архитектура (кратко)

```mermaid
flowchart LR
    U["Устройства дома"] -->|"TCP"| P["политика ndm (Proxy0)"]
    P --> T["tun2socks (t2s0)"]
    T -->|"любые SOCKS-вербы"| R["kgate relay :1090"]
    R -->|"CONNECT"| S["sing-box :1080"]
    S -->|"RU"| DIR["direct (bind eth3)"]
    S -->|"foreign + RU-media"| H["hy2 → RU front → exit"]
    U -->|"DNS :53"| DNAT["DNAT → защищённый DNS"]
```

Подробные схемы и описания — [docs/architecture/](docs/architecture/overview.md).

## Поддерживаемые роутеры

**Netcraze / Keenetic** (ndm OS 4.x–5.x, Entware, aarch64). Интеграция с ndm —
суть утилиты: тумблер Proxy0, route-pins, сегменты/политики, переживание
пересборок netfilter. Порт на другие платформы — через адаптеры (roadmap).

## Сборка

```bash
make build             # payload (sing-box + kgate arm64) + хостовый CLI
make release-binaries  # релизные бинари в dist/
make ipk               # Entware .ipk
make install-cli       # CLI в ~/.local/bin
```

## 🗂 Структура репозитория

```
├── internal/                  — исходники Go (демон, клиент, деплойер, конфиг)
├── main.go                    — единая точка входа (serve + client + deployer)
├── scripts/
│   ├── build-ipk.sh           — сборка самодостаточного Entware .ipk
│   ├── build-feed.sh          — индекс opkg-фида (Packages / Packages.gz)
│   └── install.sh             — one-liner установка CLI с ноутбука
├── examples/                  — вендоренные материалы для пакета:
│   ├── S99kgate               — init-скрипт демона
│   ├── ndm-commands.sh        — ndm-конфигурация (Proxy0, pins, DNS, политики)
│   ├── kgate.yaml.example     — шаблон kgate.yaml
│   └── etc/sing-box/          — config.json + rulesets/*.srs (входят в ipk)
├── docs/                      — документация (дерево выше)
├── local/                     — реальные материалы стека (gitignored)
└── dist/, build/              — артефакты сборки
```

Легаси-каталога `deploy/` больше нет: единственный источник init- и
ndm-скриптов — `examples/` (проверяется на этапе сборки ipk).

## Безопасность

- mTLS: клиентский сертификат обязателен; ключи сервера — только на роутере
- API не экспонируется в интернет (LAN + файрвол)
- секреты стека не входят в репозиторий: `examples/` — шаблоны, `local/` — реальные (gitignored)
- деплой — по ssh ключом, BatchMode; интерактивных паролей нет

## Roadmap

- [ ] адаптеры платформ: OpenWrt (nftables/uci)
- [ ] веб-мини-панель демона

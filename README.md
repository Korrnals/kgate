<div align="center">

<img src="assets/banner.svg" alt="KGATE — Home VPN Gateway Supervisor" width="100%">

**KGATE** — единая утилита для VPN-стека на роутерах **Netcraze / Keenetic**:
демон-супервизор на роутере + mTLS-клиент + деплойер «с нуля до рабочего состояния».

[![release](https://img.shields.io/badge/release-v1.1.0-4fc3f7)](https://github.com/Korrnals/kgate/releases)
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
> Репозиторий приватный — экспортируйте `GITHUB_TOKEN` с доступом к репо,
> либо соберите `kgate` из исходников (`make build`).

### Вариант 2 · Entware-пакет на роутере

```bash
make ipk                                            # сборка пакета
scp dist/kgate_*_aarch64-3.10.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 'opkg install /tmp/kgate_*.ipk'
```

### Вариант 3 · полный стек с нуля (деплойер)

```bash
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
│   ├── install.md                   — установка с нуля (стадии apply)
│   ├── configuration.md             — kgate.yaml + критичные поля sing-box
│   ├── segments-and-policies.md     — ⚠️ сегменты ndm: грабли №1
│   ├── operations.md                — эксплуатация и диагностика
│   ├── releases.md                  — обновление, откат, верификация подписей
│   └── uninstall.md                 — 🔴 удаление и очищение
│
├── 👤 user/                         — пользователю
│   ├── getting-started.md           — начало работы
│   ├── day-to-day.md                — повседневное управление
│   ├── ru-exit.md                   — 🕶 RU-анонимизация
│   └── faq.md                       — частые вопросы
│
└── 🔌 api/                          — интеграция
    ├── authentication.md            — mTLS, сертификаты, конвенции
    └── endpoints.md                 — все эндпоинты (цветовая индикация, примеры)
```

| Хочу… | Открой |
|---|---|
| понять, как устроено | [architecture/overview](docs/architecture/overview.md) → [components](docs/architecture/components.md) |
| установить/обновить | [admin/install](docs/admin/install.md) → [admin/releases](docs/admin/releases.md) |
| настроить конфиги | [admin/configuration](docs/admin/configuration.md) |
| разобраться, «почему трафик прямой» | [admin/segments-and-policies](docs/admin/segments-and-policies.md) |
| включить RU-анонимизацию | [user/ru-exit](docs/user/ru-exit.md) |
| интегрироваться по API | [api/authentication](docs/api/authentication.md) → [api/endpoints](docs/api/endpoints.md) |
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

## Безопасность

- mTLS: клиентский сертификат обязателен; ключи сервера — только на роутере
- API не экспонируется в интернет (LAN + файрвол)
- секреты стека не входят в репозиторий: `examples/` — шаблоны, `local/` — реальные (gitignored)
- деплой — по ssh ключом, BatchMode; интерактивных паролей нет

## Roadmap

- [ ] адаптеры платформ: OpenWrt (nftables/uci)
- [ ] opkg-фид для `opkg install kgate`
- [ ] веб-мини-панель демона

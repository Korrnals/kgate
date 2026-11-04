# Администрирование · Эксплуатация и диагностика

## 🔁 Повседневные операции

```bash
kgate status      # стек одним экраном (mTLS)
kgate verify      # батарея проверок + выходной IP
kgate logs        # хвост логов демона
kgate reboot      # перезагрузка роутера
```

## ⏱ Что делает демон на тике (15 с)

1. sing-box жив? → нет: рестарт с бэкоффом (5→30 с), `RLIMIT_NOFILE` наследуется.
2. DNS-jump `SBREDIRECT` в nat на месте? → нет: переприменить
   (ndm пересобирает nat при любом событии интерфейса: тумблер = 3 рефреша).

Авто-подъём при старте: демон ждёт `:1080`, затем `Proxy0 up` — бут-гонка
ndm↔Entware исключена.

## 🔄 Ребут

Полная цепочка автоматическая: `S99kgate` → демон → sing-box (FD 16384) →
ожидание `:1080` → `Proxy0 up` → DNS-правила → mTLS API.
Состояние тумблера переживает ребут (ndm хранит enabled).
Мигания чекера ndm («lost/detected») — косметика: интерфейс держится,
маршрут не меняется.

## 🩺 Типовые неисправности

| 🔴 Симптом | 🟡 Причина | 🟢 Действие |
|---|---|---|
| Тумблер ON, трафик прямой | сегмент/привязка DIRECT-NOVPN у устройства | [segments-and-policies.md](segments-and-policies.md) |
| RU-сайты таймаутят при ON | слетел `bind_interface` на direct-outbound (петля tun2socks) | вернуть `bind_interface: "eth3"` в конфиг sing-box |
| зарубежные таймаутят | выходной туннель не поднялся | `kgate verify` → лог sing-box; сервер доступен? |
| DNS не резолвит | снесены DNS-правила | сторож вернёт ≤15 с; вручную `S99kgate`-цикл или `ndmc` |
| sing-box не стартует после правок | невалидный конфиг / усечённый бинарь | `sing-box check -c`; размер бинаря (`ls -la`) |
| relay паникует | зонд с некорректным телом | изолировано `recover()` — демон продолжает работу |

## 🧰 Инструментальные нюансы Entware / ndm

- `iptables` — полный путь `/opt/sbin/iptables`; флаг `-S` не поддерживается → `-L -n`
- `ip rule/route` пустые в busybox → смотреть `/proc/net/route`
- `pkill`, `xargs`, `timeout` отсутствуют → kill по PID из `ps`, циклы на sleep
- правки файлов — только heredoc-stdin (`ssh 'cat > f' << 'EOF'`); busybox sed
  не разворачивает `\n` в замене и может усечь цель через `2> файл`
- потоки LAN→WAN при hardware-offload невидимы tcpdump'у — верьте тестам
  выходного IP (`curl -sS https://1.1.1.1/cdn-cgi/trace | grep ip=`)
- ndmc в PATCH clash API принимает значения в нижнем регистре (`global`/`rule`)

## 👉 См. также

- [segments-and-policies.md](segments-and-policies.md) — главный источник «тумблер ON, а трафик прямой»
- [api/endpoints-status-verify.md](../api/endpoints-status-verify.md) — то же через mTLS API
- [releases.md](releases.md) — если неисправность пережила обновление

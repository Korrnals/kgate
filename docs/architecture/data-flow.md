# Архитектура · Потоки данных

## Поток при тумблере ON (штатный режим)

```mermaid
flowchart TD
    D["Устройство дома"] -->|"DNS :53"| DNAT["DNAT → защищённый DNS<br/>(всегда, мимо ndm-фильтров)"]
    D -->|"TCP"| POL["политика ndm:<br/>Proxy0 primary :800"]
    POL --> T2S["tun2socks (t2s0)"]
    T2S -->|"SOCKS, любые verбы"| RELAY["kgate relay :1090"]
    RELAY -->|"CONNECT"| SB["sing-box :1080"]
    SB -->|"RU (geosite/geoip)"| DIRECT["direct, bind eth3<br/>→ сайт видит домашний IP"]
    SB -->|"foreign / RU-media"| HY2["hy2 → RU front → exit NL<br/>→ сайт видит IP узла"]
```

- TCP устройства помечается политикой ndm → tun2socks → relay → sing-box.
- sing-box классифицирует: локальные сети и RU — напрямую (`bind eth3`,
  чтобы не зациклиться в политике), зарубежное и заблокированные RU-медиа —
  через выходной туннель.
- DNS устройств всегда уходит на защищённый резолвер мимо ndm-фильтров и
  DNS-подавления провайдера — независимо от положения тумблера.

## Поток при тумблере OFF

```mermaid
flowchart TD
    D["Устройство дома"] -->|"TCP"| POL["политика ndm:<br/>Proxy0 down → ISP backup"]
    POL --> ISP["провайдер напрямую"]
    D -->|"DNS :53"| DNAT["DNAT → защищённый DNS (работает как раньше)"]
```

- ndm сам переводит политику на backup-подключение: туннель и relay не участвуют.
- RU-ресурсы работают; зарубежные — в соответствии с ограничениями провайдера.

## Поток тумблер-команды (`kgate toggle`)

```mermaid
sequenceDiagram
    participant U as Оператор
    participant C as kgate CLI
    participant D as kgate daemon (роутер)
    participant N as ndm
    U->>C: toggle on
    C->>D: POST /api/v1/toggle (mTLS)
    D->>N: ndmc interface Proxy0 up
    N-->>D: interface is up
    D-->>C: state: up
    C->>U: статус + верификация
```

## Поток деплоя (`kgate apply`)

```mermaid
sequenceDiagram
    participant A as Администратор
    participant C as kgate (deployer)
    participant R as Роутер
    A->>C: apply -c kgate.yaml
    C->>R: preflight (Entware, uptime)
    C->>R: payload.tar.gz (kgate arm64, sing-box, конфиги, скрипты)
    C->>R: opkg install; раскладка файлов; миграция legacy
    C->>R: рендер kgate.yaml + mTLS-сертификаты
    C->>R: ndm-команды (Proxy0, route-pins, DNS, политики)
    C->>R: S99kgate start
    C->>A: verify (mTLS) + локальный socks-тест
```

Payload — самодостаточный tar: `kgate-arm64`, `sing-box` (pinned static),
`S99kgate`, `ndm-commands.sh`, `root/opt/etc/...` (конфиги из `local/etc` или
шаблоны `examples/etc`).

## Инварианты

- DNS устройств ходит через защищённый резолвер при любом состоянии тумблера.
- Выходной туннель (hy2) и DNS sing-box никогда не попадают в туннельную
  политику — за это отвечают route-pins (`/32 → ISP`).
- `direct`-outbound sing-box привязан к физическому WAN (`bind_interface`),
  иначе RU-трафик ловится политикой и зацикливается в tun2socks.

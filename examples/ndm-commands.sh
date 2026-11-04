#!/bin/sh
# {routerctl} ndm-конфиг: Proxy0, route-pins, DNS, политики-сценарии.
# Идемпотентно: повторный прогон просто перезаписывает те же значения.
# Выполняется НА РОУТЕРЕ: ndmc -c "<строка>" на каждую строку конфига.

# --- Proxy0 (туннель-переключатель; ndm создаёт интерфейс при первом set) ---
ndmc -c "interface Proxy0 description \"HYST VPN (sing-box)\""
ndmc -c "interface Proxy0 security-level public"
ndmc -c "interface Proxy0 ip global 800"
ndmc -c "interface Proxy0 proxy protocol socks5"
ndmc -c "interface Proxy0 proxy upstream 127.0.0.1 1090"
ndmc -c "interface Proxy0 proxy connect via ISP"

# --- route-pins (без них трафик sing-box ловится политикой -> петля) ---
SERVER_IP="${KGATE_SERVER_IP:?KGATE_SERVER_IP is not set}"
ndmc -c "no ip route $SERVER_IP ISP"
ndmc -c "no ip route 77.88.8.8 ISP"
ndmc -c "ip route $SERVER_IP ISP"
ndmc -c "ip route 77.88.8.8 ISP"

# --- DNS: Яндекс напрямую (обход DNS-подавления ТСПУ) ---
ndmc -c "ip name-server 77.88.8.8"

# --- политики-сценарии (per-device переключение в вебе) ---
ndmc -c "ip policy VPN-TV"
ndmc -c "ip policy VPN-TV description \"телевизоры и консоли через VPN (привяжите устройства на вкладке Применение политик)\""
ndmc -c "ip policy VPN-TV permit global ISP"
ndmc -c "ip policy VPN-TV no permit global Proxy0"

ndmc -c "ip policy VPN-Laptops-Phones"
ndmc -c "ip policy VPN-Laptops-Phones description \"ноутбуки и телефоны через VPN\""
ndmc -c "ip policy VPN-Laptops-Phones permit global ISP"
ndmc -c "ip policy VPN-Laptops-Phones no permit global Proxy0"

ndmc -c "ip policy DIRECT-NOVPN"
ndmc -c "ip policy DIRECT-NOVPN description \"устройства в обход VPN (только провайдер)\""
ndmc -c "ip policy DIRECT-NOVPN permit global ISP"
ndmc -c "ip policy DIRECT-NOVPN no permit global Proxy0"

# --- поднять туннель (тумблер ON) ---
ndmc -c "interface Proxy0 up"

# Администрирование · Удаление и очищение

> 🔴 Все операции необратимы без бэкапа. Снимите копию `/opt/etc/`
> перед началом: `ssh router 'tar -czf /tmp/opt-etc.tgz /opt/etc' && scp ...`

## 🟠 Сценарий А — убрать только VPN-стек kgate

Для пакетной установки (Пути A/B из [install.md](install.md)):

```bash
ssh router '
opkg remove kgate                        # снимет и sing-box: с 1.1.2 движок входит в пакет
rm -rf /opt/etc/kgate /opt/etc/sing-box  # живые конфиги пакету не принадлежат — сносим руками
'
```

Для ручной раскладки (Путь B без opkg):

```bash
ssh router '
/opt/etc/init.d/S99kgate stop
rm -f /opt/etc/init.d/S99kgate
rm -rf /opt/etc/kgate
rm -f  /opt/sbin/kgate
rm -rf /opt/var/log/kgate*.log
'
```

Останется: sshd и Entware (при пакетном удалении); при ручном варианте —
ещё и sing-box бинарь/конфиги: движок без супервизора и без правил DNS
(трафик пойдёт напрямую).

## 🔴 Сценарий Б — полное очищение стека (kgate + sing-box + правила)

```bash
ssh router '
opkg remove kgate 2>/dev/null            # если ставился пакетом (≥ 1.1.2 снимет и sing-box)
/opt/etc/init.d/S99kgate stop
rm -f  /opt/etc/init.d/S99kgate /opt/etc/init.d/S99kgate.disabled
rm -f  /opt/etc/init.d/S99sing-box /opt/etc/init.d/S99sing-box.disabled
rm -f  /opt/etc/init.d/S99routerctl /opt/etc/init.d/S99routerctl.disabled
rm -f  /opt/etc/init.d/S24xray /opt/etc/init.d/S24xray.disabled
rm -rf /opt/etc/kgate /opt/etc/sing-box /opt/etc/ndm-commands.sh
rm -f  /opt/sbin/kgate /opt/sbin/sing-box
rm -rf /opt/var/log/kgate*.log /opt/var/log/singbox.log
killall sing-box kgate 2>/dev/null
# ndm-конфигурация: снять пины и туннель
ndmc -c "interface Proxy0 down"
ndmc -c "no ip route <SERVER_IP> ISP"
ndmc -c "no ip route <DNS_IP> ISP"
'
```

> [!CAUTION]
> `no ip route` выполняйте с реальными значениями пинов (см. `show ip route`).
> Сегментные политики и Proxy0-подключение удаляются в веб-интерфейсе
> (Другие подключения / Приоритеты подключений).

## 🕳 Восстановление заводского поведения DNS

```bash
ndmc -c "no ip name-server <DNS_IP>"   # если был настроен статический DNS
```

## ✅ Проверка после очищения

```bash
pidof sing-box kgate || echo "процессов нет"
ssh router 'grep -c SBREDIRECT <(/opt/sbin/iptables -t nat -L -n)'   # 0 = правил нет
```

## 👉 См. также

- [install.md](install.md) — установить заново с нуля
- [releases.md](releases.md) — откат версии вместо удаления
- [glossary.md](../glossary.md) — route-pins, Proxy0, SBREDIRECT

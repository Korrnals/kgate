# Администрирование · Удаление и очищение

> 🔴 Все операции необратимы без бэкапа. Снимите копию `/opt/etc/`
> перед началом: `ssh router 'tar -czf /tmp/opt-etc.tgz /opt/etc' && scp ...`

## Сценарий А — убрать только VPN-стек kgate

```bash
ssh router '
/opt/etc/init.d/S99kgate stop
rm -f /opt/etc/init.d/S99kgate
rm -rf /opt/etc/kgate
rm -f  /opt/sbin/kgate
rm -rf /opt/var/log/kgate*.log
'
```

Останется: sing-box бинарь/конфиги, sshd, Entware — движок без супервизора
и без правил DNS (трафик пойдёт напрямую).

## Сценарий Б — полное очищение стека (kgate + sing-box + правила)

```bash
ssh router '
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

## Восстановление заводского поведения DNS

```bash
ndmc -c "no ip name-server 77.88.8.8"   # если был настроен статический DNS
```

## Проверка после очищения

```bash
pidof sing-box kgate || echo "процессов нет"
ssh router 'grep -c SBREDIRECT <(/opt/sbin/iptables -t nat -L -n)'   # 0 = правил нет
```

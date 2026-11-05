# Администрирование · Альтернативные сценарии удаления

> Основное удаление — `kgate destroy` ([uninstall.md](uninstall.md)). Здесь —
> удаление без CLI (голый ssh), полное очищение и восстановление DNS.

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

## 🟠 Удаление без CLI (голый ssh — kgate не установлен или недоступен)

Для ручной раскладки (или когда клиентский бинарник недоступен):

```bash
ssh router '
/opt/etc/init.d/S99kgate stop
rm -f /opt/etc/init.d/S99kgate
rm -rf /opt/etc/kgate /opt/etc/sing-box
rm -f  /opt/etc/ndm-commands.sh /opt/sbin/kgate /opt/sbin/sing-box
rm -rf /opt/var/log/kgate*.log /opt/var/log/singbox.log
killall kgate sing-box 2>/dev/null
ndmc -c "no ip route <SERVER_IP> ISP"
ndmc -c "no ip route 77.88.8.8 ISP"
ndmc -c "no ip name-server 77.88.8.8"
'
```

Если стек ставился пакетом (фид/`.ipk`):

```bash
ssh router '
opkg remove kgate                        # снимет и sing-box: с 1.1.2 движок входит в пакет
rm -rf /opt/etc/kgate /opt/etc/sing-box  # живые конфиги пакету не принадлежат — сносим руками
'
```

Останется: sshd и Entware.

## 🔴 Полное очищение стека (kgate + sing-box + правила + legacy)

Максимальная зачистка — после экспериментов или миграции со старых схем:

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

- [uninstall.md](uninstall.md) — основное удаление
- [alternatives-install.md](alternatives-install.md) — пакетные пути установки
- [releases.md](releases.md) — откат версии вместо удаления
- [glossary.md](../glossary.md) — route-pins, Proxy0, SBREDIRECT

# Администрирование · Удаление

> 🔴 Все операции необратимы без бэкапа. Снимите копию `/opt/etc/`
> перед началом: `ssh router 'tar -czf /tmp/opt-etc.tgz /opt/etc' && scp ...`

## Основной путь · снять стек, поставленный `kgate deploy`

Зеркало основного пути установки — на ноутбуке, одна ssh-сессия:

```bash
kgate toggle off          # опустить туннель (трафик дома пойдёт напрямую)
ssh router '
/opt/etc/init.d/S99kgate stop
rm -f  /opt/etc/init.d/S99kgate /opt/etc/ndm-commands.sh
rm -rf /opt/etc/kgate /opt/etc/sing-box
rm -f  /opt/sbin/kgate /opt/sbin/sing-box
rm -f  /opt/var/log/kgate*.log /opt/var/log/singbox.log
killall sing-box 2>/dev/null
true'
```

На роутере останутся: sshd, Entware и ndm-объекты (Proxy0, route-pin на
`server_ip`). Пин снимается одной командой (значение — ваш exit-IP):

```bash
ssh router 'ndmc -c "no ip route 203.0.113.10 ISP"'
```

Клиентская часть на ноутбуке:

```bash
rm -f ~/.local/bin/kgate
rm -rf ~/.kgate           # конфиг + mTLS-сертификаты
```

Проверка:

```bash
ssh router 'pidof sing-box kgate || echo "процессов нет"'
```

Сегментные политики и Proxy0 удаляются в веб-интерфейсе (Другие подключения /
Приоритеты подключений).

## 👉 См. также

- [alternatives-uninstall.md](alternatives-uninstall.md) — пакетное удаление
  (opkg), полное очищение с legacy, восстановление заводского DNS
- [install.md](install.md) — установить заново с нуля
- [releases.md](releases.md) — откат версии вместо удаления
- [glossary.md](../glossary.md) — route-pins, Proxy0, SBREDIRECT

# Администрирование · Удаление

> 🔴 Все операции необратимы без бэкапа. Снимите копию `/opt/etc/`
> перед началом: `ssh router 'tar -czf /tmp/opt-etc.tgz /opt/etc' && scp ...`

## Основной путь · `kgate destroy`

Одна команда на ноутбуке — зеркало `kgate deploy`:

```bash
kgate destroy
```

Утилита покажет план (что будет остановлено и удалено) и потребует
подтверждения — введите `y` (принимаются `y`/`yes`/`д`/`да`). Если stdin — не
терминал, без `--yes` команда откажется выполнять что-либо. Для скриптов:
`kgate destroy --yes`; план без изменений: `kgate destroy --dry-run`.

Что делает:

- останавливает `S99kgate` (Proxy0 опустится — дом пойдёт напрямую);
- снимает пакет `opkg remove kgate`, если стек ставился пакетом
  (снимет и sing-box);
- удаляет файлы стека: `/opt/sbin/{kgate,sing-box}`, `/opt/etc/{kgate,sing-box}`,
  init-скрипт, `ndm-commands.sh`, логи;
- чистит ndm полностью: route-pin'ы (`server_ip`, `77.88.8.8`),
  name-server `77.88.8.8`, **полное удаление интерфейса Proxy0** и
  политик-сценариев (VPN-TV, VPN-Laptops-Phones, DIRECT-NOVPN);
- контрольный шаг: счётчик следов kgate в running-config — ожидается 0,
  любые остатки помечаются ✗ и роняют команду (`exit 1`).

На роутере остаются только sshd и Entware — без rudimentов. Клиентская
часть на ноутбуке:

```bash
rm -f ~/.local/bin/kgate
rm -rf ~/.kgate           # конфиг + mTLS-сертификаты
```

Проверка:

```bash
ssh router 'pidof sing-box kgate || echo "процессов нет"'
```

## 👉 См. также

- [alternatives-uninstall.md](alternatives-uninstall.md) — удаление без CLI
  (голый ssh), полное очищение с legacy, восстановление заводского DNS
- [install.md](install.md) — установить заново с нуля
- [releases.md](releases.md) — откат версии вместо удаления
- [glossary.md](../glossary.md) — route-pins, Proxy0, SBREDIRECT

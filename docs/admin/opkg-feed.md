# Администрирование · opkg-фид (публикация и установка)

## Публикация фида

```bash
make ipk                       # собирает dist/kgate_<ver>_<arch>.ipk
scripts/build-feed.sh dist feed   # генерирует feed/{Packages, Packages.gz, *.ipk}
```

Содержимое `feed/` публикуется на любой HTTP-хостинг:

- **gh-pages публичного фид-репо** (например, `Korrnals/kgate-feed`):
  ветка `gh-pages` → `https://<owner>.github.io/kgate-feed/`
- **свой веб-серер** / любой static-hosting с HTTPS

Индекс (`Packages`) генерируется в формате opkg: стanza
`Package/Version/Architecture/Filename/SHA256sum/Size/Description` на пакет,
рядом лежат сами `.ipk` и gzip'нутый `Packages.gz`.

## Подключение на роутере

```bash
opkg update
# один раз: добавить фид в /opt/etc/opkg.conf (или /opt/etc/opkg/customfeeds.conf):
echo 'src/gz kgate https://<host>/<путь>/' >> /opt/etc/opkg/customfeeds.conf
opkg update
opkg install kgate
opkg upgrade kgate            # последующие обновления
```

opkg сам проверит SHA256sum из индекса при скачивании.

## Замечания

- Приватный репозиторий: GitHub Pages для private-репо требует платного плана;
  альтернативы — отдельный публичный фид-репо (в .ipk нет секретов) или свой хостинг.
- Установка пакета не запускает демон автоматически: отредактируйте
  `/opt/etc/kgate/kgate.yaml` и `/opt/etc/sing-box/config.json`, затем
  `/opt/etc/init.d/S99kgate start` (см. [install.md](install.md)).
- Полный стек «с нуля» (правила ndm, туннель, сертификаты) ставится деплойером:
  `kgate apply` с ноутбука ([install.md](install.md)).

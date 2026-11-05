# Администрирование · opkg-фид (подключение и публикация)

## 📦 Подключение фида на роутере

Фид публикуется в gh-pages **этого** репозитория:
`https://korrnals.github.io/kgate/`.

```sh
opkg install wget-ssl libustream-ssl uclient-fetch   # SSL-транспорт для opkg (фид по https)
echo "src/gz kgate https://korrnals.github.io/kgate/" >> /opt/etc/opkg.conf
opkg update
opkg install kgate
opkg upgrade kgate            # последующие обновления
```

opkg проверит SHA256sum из индекса при скачивании. Что делает установщик и
какие шаги следуют за ним — [install.md](install.md) (Путь A).

> [!NOTE]
> Ранее фид жил в отдельном репозитории `kgate-feed` — он **выведен из
> эксплуатации** и не обновляется. Старый URL `https://<owner>.github.io/kgate-feed/`
> не используйте.

## 🏗 Публикация фида (мейнтейнерам)

```bash
make ipk                          # собирает dist/kgate_<ver>-1_aarch64-3.10.ipk
scripts/build-feed.sh dist feed   # генерирует feed/{Packages, Packages.gz, *.ipk}
```

Содержимое `feed/` публикуется в ветку `gh-pages` этого репозитория —
github.io раздаёт её по HTTPS. Альтернатива — любой static-hosting: индекс
`Packages` генерируется в формате opkg (stanza
`Package/Version/Architecture/Filename/SHA256sum/Size/Description` на пакет),
рядом лежат сами `.ipk` и gzip'нутый `Packages.gz`.

## 🔎 Замечания

- установка пакета **не запускает демон автоматически**: `postinst` создаёт
  конфиги из шаблонов `.example` (только если их ещё нет) и печатает
  подсказку; с шаблонными значениями демон стартует, но туннель намеренно не
  поднимается (см. [configuration.md](configuration.md));
- полный стек «с нуля» (ndm-правила, туннель, сертификаты) ставится
  деплойером: `kgate apply` с ноутбука ([install.md](install.md), Путь C);
- в `.ipk` секретов нет — пакет содержит бинари, скрипты, шаблоны и rulesets.

## 👉 См. также

- [install.md](install.md) — установка и обновление через фид
- [releases.md](releases.md) — релизные артефакты и подписи
- [preparation.md](preparation.md) — требования к роутеру и место на носителе

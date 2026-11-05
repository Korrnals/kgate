# Администрирование · Обновление, релизы, откат

## ⬆️ Обновление: `kgate update` (основной путь)

На ноутбуке и на роутере — самобновление из GitHub Releases:

```bash
kgate update
```

Что делает: запрос Releases API → сравнение версий → скачивание архива для
платформы → проверка sha256 по `checksums-sha256.txt` → атомарная замена
бинарника (tmp + rename). На роутере дополнительно перезапускает `S99kgate` —
туннель опустится на ~30-60 с и поднимется сам (boot_autoup).

## ⬆️ Обновление пакетное (opkg-фид)

```sh
opkg update && opkg upgrade kgate
/opt/etc/init.d/S99kgate status
```

> [!CAUTION]
> Перед пакетными операциями — **бэкап конфигов**. Пакеты **≤ 1.1.1**
> содержали конфиги как conffiles: переустановка той же версии могла заменить
> отредактированные конфиги шаблонами. В ipk **≥ 1.1.2** конфигов в пакете
> нет вовсе (`postinst` создаёт их из `.example` только при первом запуске),
> но правило бэкапа — всегда первое. Подробности — [install.md](install.md).

## ⬆️ Обновление из исходников (ноутбук)

```bash
git pull && make build             # в каталоге клона репозитория
./kgate deploy                     # идемпотентно; миграции выполняются автоматически
./kgate verify
```

Точечные стадии: `./kgate deploy --only files|config|ndm|services`.

## 📦 Релизные артефакты

| Артефакт | Для чего |
|---|---|
| `kgate_<ver>_linux_arm64.tar.gz` | демон/клиент на роутере (внутри — бинарь `kgate`) |
| `kgate_<ver>_linux_amd64.tar.gz` | CLI оператора |
| `kgate_<ver>-1_aarch64-3.10.ipk` | установка через `opkg install`; самодостаточен: `kgate` + `sing-box` + `ndm-commands.sh` + rulesets + CA-пул |
| `checksums-sha256.txt` + подписи | контрольные суммы; подписи cosign + GPG (`.sig`/`.bundle`/`.asc`) |

С 1.2.0 релизы собираются goreleaser'ом (репо-конфиг `.goreleaser.yaml`);
подписи — конвейером. `kgate update` отказывается ставить архив, чья sha256
не сошлась с `checksums-sha256.txt`.

## 🔏 Верификация подписей (потребитель)

```bash
curl -sSLO <release-url>/checksums-sha256.txt
# подписи (файлы .sig/.bundle/.asc прикладываются конвейером к чексамму)
cosign verify-blob --key cosign.pub --bundle checksums-sha256.txt.bundle checksums-sha256.txt
gpg --import gpg-release.pub.asc && gpg --verify checksums-sha256.txt.asc checksums-sha256.txt
# суммы самих артефактов:
sha256sum -c --ignore-missing checksums-sha256.txt
```

## ⏪ Откат версии

```bash
git checkout vX.Y.Z && make build && ./kgate deploy
```

Для пакетной установки — скачайте артефакт нужной версии (например,
`kgate_1.1.1-1_aarch64-3.10.ipk`) и поставьте его:
`opkg install ./kgate_1.1.1-1_aarch64-3.10.ipk`.

Аварийное отключение VPN без отката кода — тумблер Proxy0 off (`kgate toggle off`).

## 📏 Правила релизного цикла

- SemVer; несовместимые изменения конфига — только через заметки в релизе
- артефакты всегда подписываются (SHA256 + cosign + GPG)
- релизы публикуются через релизный конвейер (сборка → подпись → GitHub Release)

## 👉 См. также

- [install.md](install.md) — первая установка стеком
- [architecture/overview.md](../architecture/overview.md) — состав релиза и платформы
- [glossary.md](../glossary.md)

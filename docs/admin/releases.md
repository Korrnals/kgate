# Администрирование · Обновление, релизы, откат

## ⬆️ Обновление через opkg-фид (роутер)

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

## ⬆️ Обновление деплойером (ноутбук)

```bash
git pull && make build             # в каталоге клона репозитория
./kgate apply -c kgate.yaml        # идемпотентно; миграции выполняются автоматически
./kgate verify
```

Точечные стадии: `./kgate apply --only files|config|ndm|services`.

## 📦 Релизные артефакты

| Артефакт | Для чего |
|---|---|
| `kgate-<ver>-linux-arm64` | демон/клиент на роутере |
| `kgate-<ver>-linux-amd64` | CLI оператора |
| `kgate_<ver>-1_aarch64-3.10.ipk` | установка через `opkg install`; с 1.1.2 самодостаточен: `kgate` + `sing-box` + `ndm-commands.sh` + rulesets |
| `SHA256SUMS` + `.sig`/`.bundle`/`.asc` | подписи (cosign + GPG) |

## 🔏 Верификация подписей (потребитель)

```bash
curl -sSLO <release-url>/SHA256SUMS{,.sig,.bundle,.asc}
# подпись + доказательство Rekor в одном bundle (cosign ≥ 2.x, bundle v0.3)
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.bundle SHA256SUMS
# если cosign старше и не понимает bundle — по сырой подписи:
cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS
gpg --import gpg-release.pub.asc && gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

## ⏪ Откат версии

```bash
git checkout vX.Y.Z && make build && ./kgate apply -c kgate.yaml
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

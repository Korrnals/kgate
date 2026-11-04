# Администрирование · Обновление, релизы, откат

## Обновление на новую версию

```bash
cd <repo> && git pull && make build
./kgate apply -c kgate.yaml        # идемпотентно; миграции выполняются автоматически
./kgate verify
```

Точечные стадии: `./kgate apply --only files|config|ndm|services`.

## Релизные артефакты

| Артефакт | Для чего |
|---|---|
| `kgate-<ver>-linux-arm64` | демон/клиент на роутере |
| `kgate-<ver>-linux-amd64` | CLI оператора |
| `kgate_<ver>-1_aarch64-3.10.ipk` | установка через `opkg install` |
| `SHA256SUMS` + `.sig`/`.bundle`/`.asc` | подписи (cosign + GPG) |

## Верификация подписей (потребитель)

```bash
curl -sSLO <release-url>/SHA256SUMS{,.sig,.bundle,.asc}
# подпись + доказательство Rekor в одном bundle (cosign ≥ 2.x, bundle v0.3)
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.bundle SHA256SUMS
# если cosign старше и не понимает bundle — по сырой подписи:
cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS
gpg --import gpg-release.pub.asc && gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

## Откат версии

```bash
git checkout vX.Y.Z && make build && ./kgate apply -c kgate.yaml
```

Аварийное отключение VPN без отката кода — тумблер Proxy0 off (`kgate toggle off`).

## Правила релизного цикла

- SemVer; несовместимые изменения конфига — только через заметки в релизе
- артефакты всегда подписываются (SHA256 + cosign + GPG)
- релизы публикуются через релизный конвейер (сборка → подпись → GitHub Release)

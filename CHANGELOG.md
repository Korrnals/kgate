# Changelog

All notable changes to kgate are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/); the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [1.1.2] - 2026-11-05

Repository consolidation and install-hardening release: the project
repository goes public with the feed merged in, the ipk no longer
clobbers live configs, and the daemon fails loud on un-edited template
configs.

### Fixed
- ipk: tar members are built with `--format=ustar` — Entware `opkg`
  aborted with heap corruption ("free(): invalid next size") on
  GNU-format tars; installation now completes cleanly (verified on
  Netcraze Ultra).
- ipk: the package no longer ships live configs as conffiles. Templates
  are installed as `*.example` and `postinst` seeds real configs only
  if missing, so remove/reinstall can no longer destroy edited configs
  (the root cause of a dead-tunnel incident where Proxy0 was up but
  sing-box pointed at `HY2_PASSWORD` placeholders).
- ipk: init script and ndm script are required and verified non-empty
  at build time (a legacy empty `deploy/S99kgate` placeholder could
  ship a broken package silently).
- daemon: fails loud at startup when the sing-box config still contains
  template placeholders (`HY2_PASSWORD`, `hy2.example.com`) — the stack
  previously looked healthy (Proxy0 up) while the tunnel was unusable.

### Changed
- ipk is self-sufficient: ships the pinned sing-box engine, the ndm
  config script and the RU-split rulesets (previous feed artifact
  carried the kgate binary only).
- The opkg feed moved into this repository (gh-pages branch); the
  separate `kgate-feed` repository is retired.
- Vendored rulesets under `examples/etc/sing-box/rulesets/` so clean
  checkouts (release pipeline) build complete packages.

## [1.1.1] - 2026-11-04

Feed and packaging release: an opkg package feed for `opkg`-native
installs, a hardened ipk build, fully static release binaries, and a
documentation expansion (glossary, per-section navigation, dedicated
feed and API pages).

### Added
- opkg feed builder (`scripts/build-feed.sh`): generates an
  Entware-compatible feed (`Packages`, `Packages.gz`, `.ipk`) from
  `dist/`, enabling `opkg install kgate` from any HTTP host; the feed
  is published as the public `kgate-feed` repository.
- `KGATE_*` environment variable overrides: configuration values can
  be set or replaced via environment variables that take precedence
  over `kgate.yaml` (documented in `docs/admin/configuration.md`).
- Documentation: glossary (`docs/glossary.md`), an admin guide for the
  opkg feed (`docs/admin/opkg-feed.md`), and dedicated mTLS API
  endpoint references (`docs/api/endpoints-*.md`); all pages restyled
  with per-section navigation.

### Fixed
- ipk packaging: `data.tar.gz` is written where `ar` expects it and an
  empty rulesets directory no longer breaks the build — the package
  is now reliably installable.
- Release binaries are built with `CGO_ENABLED=0`, so both the amd64
  and arm64 builds are fully static ELF executables.
- Deploy hardening: stages continue on error and report failures at
  the end, payload root paths corrected, `KGATE_SERVER_IP` passed to
  the ndm-commands stage, `Proxy0` created if absent, `S99kgate` and
  `ndm-commands.sh` shipped in the payload, and the ndm route-pin
  parameterized via the server IP (sanitized example no longer
  carries a placeholder).
- Default SSH key for the managed router changed to `kgate-ed25519`
  (agent-independent).

## [1.1.0] - 2026-11-04

Documentation and onboarding release: a topic docs tree, a one-line
installer, and English-language source comments.

### Added
- One-line installer (`scripts/install.sh`): downloads the latest CLI
  binary (amd64/arm64) from GitHub Releases via `curl | sh`, honors
  `GITHUB_TOKEN` for the private repository, and drops a starter
  `kgate.yaml` into `~/.kgate`.

### Changed
- Documentation restructured from three monolithic pages (`ADMIN`,
  `USER`, `API`) into a topic tree: `docs/architecture/`, `docs/admin/`,
  `docs/user/`, `docs/api/` — 16 pages, including the RU-exit
  anonymization mechanics (clash_mode rules) and the release/signing
  procedure.
- Source comments translated to English across `internal/` and `main.go`.

## [1.0.0] - 2026-11-04

First stable release: one utility that supervises the whole home VPN stack
on Netcraze / Keenetic routers — deploy, run, control.

### Added
- Router-side supervisor daemon (`kgate serve`): runs sing-box 1.11.15,
  keeps DNS rules applied, auto-raises the ndm Proxy0 tunnel, and bridges
  local traffic into the proxy via a tolerant socks relay (tun2socks).
- mTLS control API (default `:9443`) with an ECDSA P-256 PKI generated at
  deploy time (10-year certificates); CLI commands `status`, `toggle`,
  `ruexit`, `reboot` are thin wrappers over the API.
- `kgate apply` — zero-to-working deployer over SSH: installs the Entware
  package on the router, generates the PKI, pushes configs, starts the
  S99 init script.
- Entware `.ipk` packaging (`aarch64-3.10`): kgate binary, S99 init
  script, `kgate.yaml` and sing-box config templates, routing rule-sets.
- Release pipeline: static Linux binaries (arm64 for the router, amd64
  for the operator's laptop), signed with SHA256SUMS + cosign + GPG.

[Unreleased]: https://github.com/Korrnals/kgate/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Korrnals/kgate/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Korrnals/kgate/releases/tag/v1.0.0

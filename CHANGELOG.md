# Changelog

All notable changes to kgate are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/); the project
follows [Semantic Versioning](https://semver.org/).

## [1.6.0] - 2026-11-10

kgate v1.6.0: the tunnel off-switch actually works now, the deploy path
fails loudly instead of lying green, and the management API/CLI follow
strict method and exit-code discipline. Shipped after a four-wave cascade
review (two consecutive clean waves from both the security and the
quality/architecture auditors).

### Fixed
- **The documented off-switch is now real.** Since 1.4.4 the docs promised
  that `kgate toggle off` persists and survives the flap self-heal — the
  implementation wrote a different word to the intent file than every
  reader expected, so the self-heal raised the tunnel back within one
  15-second tick. The vocabulary is unified (`up`/`down`), the intent is
  written before the tunnel is toggled, a failed intent write aborts the
  toggle with a clear 500, and boot auto-up respects an operator-set
  `down` on both platforms.
- `kgate destroy` no longer mis-detects the platform (a substring check
  matched "non-openwrt"); detection is now fail-closed — an ambiguous
  answer refuses the destroy instead of guessing.
- Deploy steps unpack/migrate/save/serve with `set -e` plus explicit
  asserts: a failed `ndmc system configuration save` no longer produces a
  green step with an unsaved flash, and the intent file is only written
  after the save succeeded.

### Changed
- **Subscription feeds are https-only** (including redirects: same host,
  up to 10 hops; cross-host/CDN redirects are rejected with a clear
  error). If your feed URL starts with `http://`, switch it to `https://`
  — feed credentials travel in the URL and must not go out in plaintext.
- Mutating API endpoints (`/api/v1/policy/*`, toggle, ruexit, reboot) are
  POST-only (405 otherwise). All behind the existing mTLS gate.
- CLI commands exit non-zero when the daemon reports an error (previously
  they printed the error and exited 0, breaking scripts).
- Policy binding is genuinely idempotent: re-binding a device/segment to
  its current policy sends no ndm writes and no flash save.
- `kgate apply` aborts loudly on the first push when no live config exists
  on the router (previously masked by a silent `mv`); run a full deploy
  for clean installs.
- OpenWrt installer hardening: checksums are mandatory (fail-loud),
  sing-box tarball sha256 is pinned, `KGATE_RELEASE_BASE` must be https,
  config files land 0600 (umask 077).
- `destroy` on OpenWrt refuses with step-by-step manual cleanup guidance
  instead of half-removing (full OpenWrt destroy comes with the field
  validation wave).

### Known scope
- The Phase 2 traffic-path files (`platform/openwrt/{nft-kgate.conf,
  sing-box-client.json,traffic-setup.sh}`) are scaffolding: they are NOT
  wired into install/init/shim, are not part of the release archives, and
  add no working traffic path yet. Wire-up is planned for the field
  validation on real hardware.

### Verification
Full test suite (`go test -race -count=1`, all packages) green on the
release commit; `go vet` and govulncheck clean (0 called vulnerabilities);
fresh suite re-run personally before merge. Review: four cascade waves —
P1 findings in waves 1–2 fixed and re-audited; waves 3–4 clean from both
auditors. Six new regression tests cover the fixes above.

## [Unreleased]

## [1.5.0] - 2026-11-09

### Added
- policies: `kgate policy` — per-device/segment policy management (list,
  devices, segments, set device/segment, all-vpn, all-direct). Deploy now
  creates exactly TWO policies — VPN (tunnel) and NO-VPN (direct) — with an
  honest default: the unbound device rides the base connection (ISP);
  Proxy0 priority raised to 1200 and the stale `0.0.0.0/0 Proxy0` static
  route is un-routed on every deploy (the web 'Приоритеты доступов' page
  re-checks both connections otherwise).
- openwrt (beta): ndmc-shim verb translation (uci/ip/nft), procd init,
  hotplug pin-reapply, `install.sh --platform=openwrt`, platform files in
  release archives; OpenWrt lab (podman) — shim verb matrix 19 PASS,
  migration matrix 21/21, install smoke PASS. Field E2E pending hardware.
- deploy migrates legacy policies (VPN-TV/VPN-Laptops-Phones/DIRECT-NOVPN)
  to NO-VPN bindings and removes the objects.

### Added
- policy-v2: честный дефолт = провайдер, политики VPN/NO-VPN и команда
  `kgate policy`. Деплой создаёт РОВНО ДВЕ политики — VPN (permit Proxy0,
  запрет ISP) и NO-VPN (permit ISP, запрет Proxy0) — и ставит Proxy0
  `ip global 1200`: дефолтный маршрут дома = ISP, устройство БЕЗ привязки
  ходит НАПРЯМУЮ (fail-safe дом), туннель включается только явной привязкой
  (`kgate policy set device <MAC> VPN` / `all-vpn`). CLI: `kgate policy
  list|devices|segments|set device|set segment|all-vpn|all-direct` через
  mTLS API демона (`/api/v1/policy/{list,segments,set-device,set-segment,
  all-vpn,all-direct}`); таблица привязок живая (`show ip hotspot`), пустая
  политика = дефолт. IaC-гарантия честного дефолта: застоявшийся статический
  `ip route 0.0.0.0/0 Proxy0` сносится и ndm-commands.sh, и стадией ndm
  (веб «Приоритеты доступов» возвращает его при каждом save) + финальный
  assert. Back-compat: legacy-эскейпы v1 (VPN-TV, VPN-Laptops-Phones,
  DIRECT-NOVPN) мигрируются деплоем — привязки (host и segment, включая
  offline-устройства и двухсловный ключ `access point:`) ре-указываются на
  NO-VPN, объекты удаляются, итог печатается; второй прогон — no-op.
  destroy чистит обе эпохи политик. Новый пакет internal/policy: разбор
  `show ip hotspot`/`show ip policy` + генераторы ndm-вербов (юнит-тесты на
  fixture'ах: пустая политика, отсутствующий hostname, offline-хост,
  мульти-хост). OpenWrt-лаба (podman, lab/): verb-покрытие шима с LAB-деградацией
  (rootless без NET_ADMIN — честные state-маркеры), миграционная матрица
  (реальный ndm-commands.sh под busybox sh с mock-ndmc), install.sh smoke из
  локального релиза (новый оффлайн-режим KGATE_RELEASE_BASE=<каталог>);
  policy-вербы шима отвечают явной Phase-2 заглушкой. Docs: operations.md
  (переписан per-device раздел), segments-and-policies.md (модель v2),
  api/endpoints-policy.md, day-to-day.md, glossary, man-страница.
- openwrt: platform support, Phase 1 (beta) — the Go daemon/deployer are
  unchanged; a POSIX-sh ndm-shim (platform/openwrt/ndmc-shim, installed as
  /usr/bin/ndmc + /bin/ndmc) translates the daemon's ndm verbs to uci/ip/nft:
  Proxy0 up/down = the `inet kgate` nft table (state marker, no redirect rules
  — traffic path is Phase 2), route pins = verified kernel /32 routes + netifd
  static routes (survive reboot and WAN reconnect, hotplug reapply on ifup),
  show running-config renders the ndm tokens so the destroy cleanliness grep
  works unchanged. procd init (/etc/init.d/kgate), WAN hotplug hook,
  install.sh --platform=openwrt (auto-routes on /etc/openwrt_release; no
  opkg/Entware dependency — prereqs checked and reported, dropbear
  authorized_keys, /opt compat symlinks for the daemon's hardcoded paths),
  release archives now carry platform/openwrt/* + the sing-box skeleton.
  Docs: README platforms section, install.md OpenWrt branch,
  requirements.md OpenWrt rows, operations.md platform boundaries.
  Field-untested — E2E on real hardware pending (see install.md for the
  honest Phase-1 scope: daemon/pins/self-heal/state, no LAN redirect yet).

## [1.4.6] - 2026-11-08

### Fixed
- stability: the flap self-heal intent moved to an operator intent file
  (/opt/etc/kgate/intent) — the sc view mirrors live state and cannot
  distinguish 'owner off' from 'flap'. kgate toggle on/off writes the file;
  the daemon re-raises a dropped tunnel unless it says down. The web
  dashboard switch can no longer take the tunnel down (clicks are overridden
  within one tick) — the off-switch is `kgate toggle off`.
- deploy: the ndm stage records intent=up after raising the tunnel.

## [1.4.5] - 2026-11-08

### Fixed
- deploy services: status poll (up to 20s) instead of a fixed 4s sleep — a
  fresh engine initializes longer, and the fixed wait raced it into a false
  FAIL (caught in the field on v1.4.4 immediately after deploy).

## [1.4.4] - 2026-11-07

### Fixed
- stability: the 06.11 flap class is closed — daemon flapSelfHeal re-raises
  Proxy0 when the SAVED intent is up (a deliberate off via web click or
  `kgate toggle off` persists intent=down and is respected); destroy asserts
  the processes actually died (SIGKILL escalation, loud failure on a silent
  survivor); deploy services force a fresh engine (a surviving old sing-box
  can no longer serve replaced configs; adoption removed). See
  task kgate-1.4.4-stability.

## [1.4.3] - 2026-11-06

## [1.4.2] - 2026-11-06

### Added
- ssh: self-managed keypair — kgate generates its own ed25519 pair
  (`~/.kgate/id_ed25519`, new default for `ssh_key`) and installs the
  public key on the router with a one-time password (env
  `KGATE_SSH_PASSWORD` or interactive prompt); append-only, existing
  keys preserved. Bootstrap chain: password on the main port →
  firmware ssh+SFTP (port 22, KeeneticOS admin user, default `temp`)
  for the case when the Entware keys file is clobbered/missing.

### Added
- subscriptions: `kgate subscribe add|update|remove|status` — provider
  subscriptions (base64 URI lists with vless incl. Reality/flow,
  hysteria2, trojan, shadowsocks — or a ready sing-box JSON) are parsed
  into sing-box outbounds, wrapped with a selector, and applied to the
  router while kgate's own inbounds and RU-split routing stay intact.
  The deploy files-stage no longer overwrites a subscription-managed
  config. URI-list parser is unit-tested (reality/flow/obfs/ss variants).

## [Unreleased]

### Known limitations
- KeeneticOS dashboard switch quirk RESOLVED for ≥ 1.4.3 (deploy/destroy now
  run `system configuration save` — the config-view up-node materializes).
  ⚠️ Clicking the switch on a live tunnel is NOT a no-op: it writes a `down`
  intent and SAVES it to flash (observed: a click took the tunnel down for 33
  minutes with no auto-recovery). Use `kgate toggle off` / `kgate destroy`.
  Full investigation: docs/admin/operations.md.

### Fixed
- daemon: route-pin removals are PROVENANCE-SCOPED (wave-2/3/4 cascade): a
  pin is held only while its owner is in-config but DNS-unhealthy (resolve
  error or AAAA-only); pins of owners that left the config flush even when
  other hosts' DNS is down; healthy-owner stale pins flush on DDNS flips.
  destroy sweeps daemon-era /32 ISP pins before the startup-config save, so
  stale subscription routes no longer fossilize; the cleanliness gate counts
  leftover pins.
- deploy: PushConfig validates on-router (sing-box check) and swaps
  atomically with a backup; swap echo no longer masks mv failure; the check
  uses the full /opt/sbin path; ndmc failure detection covers exec-level
  ERR( prefix.

## [1.4.2] - 2026-11-06

### Fixed
- deploy: the files stage never clobbers `/opt/etc/ssh/authorized_keys`
  anymore — release payloads carry a sanitized placeholder key, and the
  unconditional copy locked the operator out of the Entware sshd
  (caught live by the manual-based E2E on v1.4.1).
- install.sh: release archives were renamed to
  `kgate_<ver>_linux_<arch>.tar.gz` (underscores) in v1.4.0, but the
  installer kept grepping the legacy hyphen form — the primary-path
  install found no asset.
- update.go: response bodies closed per-iteration; request error checked.

## [1.4.1] - 2026-11-05

### Added
- release binaries carry the sanitized stack (examples/etc placeholders
  + rulesets + binaries) via `make payload-release` + goreleaser build
  tag: `kgate deploy` from an installed release installs the stack out
  of the box — real credentials never enter release builds by
  construction (the v1.3.1 lesson, verified by payload marker check).

### Fixed
- man page version string synced to the release.

## [1.4.0] - 2026-11-05

Deployment lifecycle and console UX release: destroy cleans up
completely (no ndm rudiments), every step reports itself to the console,
and the requirements/compatibility story is documented.

### Added
- destroy: full ndm cleanup — the Proxy0 interface and the scenario
  policies (VPN-TV, VPN-Laptops-Phones, DIRECT-NOVPN) are deleted
  outright, plus a final cleanliness step that counts kgate traces in
  the running-config (expected 0; leftovers fail the command with exit
  1). Verified against a live router (syntax probed on a throwaway
  Proxy9 object first).
- console UX: every deploy/destroy step prints a colored mark (green ✓
  / red ✗; [OK]/[FAIL] outside terminals or with NO_COLOR) with
  duration; successful script output is shown indented too, and failed
  output is indented under the red mark.
- docs: requirements & compatibility page (devices, OS versions,
  storage, tunnel protocols, what kgate deliberately does not do) + a
  mandatory fit-check block in the README.

### Changed
- examples/S99kgate gains a restart case (for manual restarts; deploy
  and self-update deliberately keep stop+start so they work with any
  deployed S99 generation).
- deploy's ndm stage no longer masks script failures with a fallback
  echo; failed steps reach the failure counter and the exit code.
- ssh upload recovers from a stale connection once (before the first
  byte); failures after the transfer started stay loud.

### Fixed
- deploy: `--only services` against a router deployed by an older kgate
  no longer silently no-ops (stop+start works with any S99 generation).
- destroy: failures now gate the exit code (asymmetric with deploy —
  fixed); dry-run prints the plan.
- deploy: leftover ca-bundle install dropped from the files stage
  (follow-up to the v1.2.0 dependency slimming).

## [1.3.2] - 2026-11-05

Security-hardening release: the deploy payload can never leak into the
repository or release artifacts again, and deploying from a payload-less
build refuses loudly.

### Fixed
- **Incident:** the v1.3.1 release artifacts (and a git blob reachable
  from the v1.3.1 tag) briefly contained a real deploy payload with
  live sing-box credentials — `make payload` output was swept into a
  commit by `git add -A` right after the path stopped being gitignored
  (v1.2.0 committed the embed placeholder at the same path). The
  release was retracted within minutes, the history was rewritten
  (git filter-repo replaced the payload blob with the 45-byte stub in
  every tree) and the affected credentials should be rotated.
  - the real payload path `internal/deploy/payload.tgz` is gitignored
    again; the committed embed stub now lives at
    `internal/deploy/payload.embed.tgz` and is copied into place by
    `make ensure-empty` (verify/lint/test depend on it).
  - `kgate deploy` refuses loudly (before touching the router) when the
    embedded payload is the stub: release binaries are built from clean
    checkouts and never carry a stack — local deploys run `make payload`
    first.

## [1.3.0] - 2026-11-05

Deployment lifecycle and library-native transport release: the deployer
speaks ssh itself (no ssh binary needed on the workstation), the stack
can be removed with a single confirmed command, and the tool ships its
own man page.

### Added
- CLI: `kgate destroy` — the inverse of `deploy`: stops S99kgate,
  removes the stack files (running `opkg remove kgate` first when the
  package was installed), and cleans the ndm pins (Proxy0, route-pins,
  static name-server). Requires an interactive confirmation; `--yes`
  skips it for scripts, `--dry-run` prints the plan. Alias: `undeploy`.
- CLI: `kgate man` — the embedded kgate(1) man page (roff), rendered
  through man(1) in a terminal; the release archive now carries
  `kgate.1` and the installer places it into `~/.local/share/man/man1`.

### Changed
- deploy: the ssh transport is implemented in Go (golang.org/x/crypto/ssh)
  instead of shelling out to the ssh(1) binary — a workstation without
  OpenSSH works too. Key auth from `ssh_key`; host keys are verified
  TOFU-style (accept-new) against `~/.ssh/known_hosts`, a changed key
  fails loud. The router-side `openssh-server` dependency is unchanged
  (it is the sshd the deployer connects to).
- docs: uninstall.md documents `kgate destroy` as the primary path;
  bare-ssh removal moved to alternatives-uninstall.md.

### Fixed
- CHANGELOG 1.1.1: dropped the stale `kgate-feed` repository mention
  (the repo is retired).

## [1.2.0] - 2026-11-05

Onboarding and slimming release: the primary install path is now three
commands on a laptop (CLI → `config create` → `deploy`), the binary
can update itself from GitHub Releases, and the package drops the curl
and ca-bundle dependencies.

### Added
- CLI: `kgate config create` — seeds `~/.kgate/kgate.yaml` from the
  embedded template, opens `$VISUAL`/`$EDITOR`, warns on leftover
  placeholders, prints the path; `config view|path|edit` round it out.
  The default config path is `~/.kgate/kgate.yaml` (or `$KGATE_CONFIG`);
  `./kgate.yaml` keeps working when present.
- CLI: `kgate deploy` — the primary deploy verb (`apply` kept as an
  alias); same idempotent stages, `--only`, `--dry-run`.
- CLI: `kgate update` — self-update via the GitHub Releases API over
  pure net/http (no curl): version compare, platform archive download,
  sha256 verified against `checksums-sha256.txt`, atomic tmp+rename
  replacement; on the router it also restarts `S99kgate` (tunnel
  returns automatically in ~30-60 s).
- ipk ships a CA pool at `/opt/etc/kgate/ca-bundle.crt` — a TLS fallback
  for firmware builds without `/etc/ssl/certs`; the daemon exports
  `SSL_CERT_FILE` for sing-box only when the system store is missing.

### Changed
- ipk `Depends` slimmed to `iptables, openssh-server`: curl is unused
  (the verify socks-test is pure Go now) and the system CA store or the
  shipped bundle replaces ca-bundle.
- Binaries are built with `-s -w`: arm64 ~14.3 MB → ~10 MB, ipk
  ~19 MB → ~15 MB.
- iptables dependency audited and kept: on KeeneticOS 5.x (5.01.C) the
  ndm DNS-redirect chains are empty and unmanaged via CLI, so the
  SBREDIRECT DNS-DNAT remains the only client-DNS interception (needed
  against provider DNS poisoning).
- Docs restructured to a primary-vs-alternatives pattern:
  `install.md` now documents only the recommended laptop path, opkg
  feed and manual installs moved to `alternatives-install.md`; the same
  split for uninstall (`alternatives-uninstall.md`).

### Fixed
- build: the empty payload placeholder is committed so `go build`
  (verify/lint gates) works on a fresh checkout — `//go:embed` no
  longer breaks CI from a clean clone.
- removed the dead `S99Script` const from the deployer (the single
  source of truth is `examples/S99kgate`).

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
- The opkg feed is served from this repository's gh-pages branch.
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
  `dist/`, enabling `opkg install kgate` from any HTTP host.
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

# Changelog

All notable changes to kgate are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/); the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/Korrnals/kgate/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Korrnals/kgate/releases/tag/v1.0.0

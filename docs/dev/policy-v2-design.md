# DESIGN: kgate policy model v2 — VPN/NO-VPN + policy CLI (kgate-policy-v2)

STATUS: approved (owner, 09.11). Implements in kgate 1.5.0.

## Owner requirements (verbatim intent)

1. Deploy creates exactly TWO policies: `VPN` and `NO-VPN`.
2. The DEFAULT policy must look ONLY at the base connection (ISP). The owner
   then binds segments or individual devices to whichever policy the
   segment/device needs. (Semantic change: default = ISP; VPN = by explicit
   bind. Fail-safe home.)
3. `kgate policy` command block: list devices with metadata (segment,
   policy), change policy per-device AND per-segment (choice from a list),
   plus a custom shortcut to switch EVERYTHING to VPN and back.
4. OpenWrt lab: container-based test environment (no hardware needed).

## ndm ground truth (verified live 09.11)

- Live binding table: `ndmc -c "show ip hotspot"` — per-host entries with
  `hostname/mac/ip/policy/active`. This is the SOURCE OF TRUTH for bindings
  (running-config's `ip hotspot` block does NOT reflect host binds).
- Host bind: `ip hotspot host <MAC> policy <NAME>`; unbind: `ip hotspot host
  <MAC> no policy` (NOT `no ... policy <NAME>` — that is a parse error).
- Segment bind: `ip hotspot <segment> policy <NAME>` where segment = the
  hotspot access point / bridge name as ndm knows it (Bridge0="Home",
  Bridge1="LAN", Bridge2="SMART" on the Ultra; enumerate via
  `show ip hotspot` interface blocks).
- Policy object: `ip policy <NAME>` + routes. An escape policy (direct) =
  `permit global ISP` + `no permit global Proxy0`. A tunnel policy =
  `permit global Proxy0` (+ `no permit global ISP`).
- Default route semantic: the interface with the LOWEST `ip global`
  priority wins (Proxy0 800 < ISP 1000). For "default = ISP" we set Proxy0
  priority LOWER than ISP (1200, ISP 700) — default = ISP; Proxy0 stays in the chain because ip global membership is REQUIRED for dashboard/priorities/policy bindings (vol.2 field lesson 2026-11-11: no-ip-global made the interface invisible)
  the Proxy0 default route. Bind decides everything.
- Unbind default: `policy: ` (empty) = follows the DEFAULT route table.

## New deploy model

1. Policies created by ndm-commands.sh:
   - `VPN`     : permit global Proxy0, no permit global ISP; routes: default via Proxy0 in its table.
   - `NO-VPN`  : permit global ISP, no permit global Proxy0.
2. Proxy0 priority 1200 below ISP 700 → unbound = DIRECT (failover to VPN only when ISP is down); the interface stays in the management plane (dashboard, priorities, bindings).
3. Hotspot: NO device binds created by deploy. Segment binds NOT created
   either. The house is fail-safe direct until the owner runs
   `kgate policy all-vpn` (or binds manually).
4. Back-compat: old policies (VPN-TV, VPN-Laptops-Phones, DIRECT-NOVPN)
   are deleted by deploy IF they have no bindings; if bindings exist,
   they are re-pointed to the closest new policy and then deleted
   (DIRECT-NOVPN→NO-VPN, VPN-TV/VPN-Laptops-Phones→NO-VPN as well — they
   were escapes; devices that should be in VPN get bound to VPN by the
   owner or `kgate policy all-vpn`).

## kgate policy CLI (all via the daemon mTLS API; daemon executes ndmc)

```
kgate policy list                  # table: hostname, ip, mac, segment(bridge/ap), policy (live)
kgate policy devices               # same, devices only
kgate policy set device <MAC|hostname> <VPN|NO-VPN|none>
kgate policy set segment <id|name> <VPN|NO-VPN|none>
kgate policy all-vpn               # bind EVERY active host to VPN
kgate policy all-direct            # unbind every host (default = direct)
kgate policy segments              # list segments with per-segment policy and host count
```

Implementation notes:
- daemon: /api/v1/policy/{list,set-device,set-segment,all-vpn,all-direct,segments}
  — each wraps ndmc commands; parse `show ip hotspot` (host blocks) and
  `show ip policy` (policy existence check).
- deploy: after ndm-commands.sh, deploy migrates old policies per the
  back-compat rule and prints the resulting binding summary.
- self-heal unaffected: intent file governs Proxy0 itself, not bindings.
- OpenWrt shim: `show ip hotspot` → render from /etc/kgate/hotspot.json
  (Phase 2); policy verbs → uci sets in the kgate config namespace
  (documented as Phase 2 in the shim, stubs return clear errors for now).

## Lab (OpenWrt in a container)

- docker: openwrt/rootfs-amd64 (23.05/24.10) + extra packages; kgate arm64
  binaries are static, but the container is amd64 → build amd64 binaries for
  the lab (make build GOARCH=amd64) or use qemu-user-static. Prefer amd64
  build in the lab.
- inside: install shim to /usr/bin/ndmc (with a LAB mode flag: the nft table
  and ip-route parts are exercised only if the container has
  NET_ADMIN; without it, shim runs in echo-mode asserting verb coverage).
- test matrix: deploy-files → deploy-ndm (verbs exercised) → policy verbs →
  destroy cleanliness. Smoke, not full integration.

## Verification

- unit: policy verb parsing (show ip hotspot blocks → structs), set-device
  command generation, back-compat migration decision table.
- lab: shim verb coverage + install.sh --platform=openwrt smoke in container.
- live router (manual): deploy → old policies migrated → policy list →
  set device → all-vpn → all-direct.

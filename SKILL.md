# Mihomo Downstream Build Skill

This repository keeps the expanded downstream source on `dev`. The `Alpha`
branch is a clean mirror of `MetaCubeX/mihomo:Alpha`; upstream changes enter
`dev` only through a review pull request.

## Canonical rule

The source checked into `dev` already contains every Mihomo downstream change.
Before any build, test, benchmark, package, or release task:

1. Build and test the checked-in `dev` source directly.
2. Apply dependency patches with `patches/apply-dependency-patches.sh`.
3. Use the downstream trimmed build tags:
   `no_tailscale no_zerotier no_wireguard no_openvpn no_mieru no_sudoku no_fake_tcp no_easytier`.
4. Preserve the configured Go 1.27 / optimized build settings used by
   `.github/workflows/build.yml`.

## Forbidden shortcuts

Do not:

- build or release the raw `Alpha` mirror as the downstream artifact;
- commit downstream source changes to `Alpha`;
- use `with_gvisor` for downstream release builds;
- omit `patches/apply-dependency-patches.sh` when building artifacts;
- silently change the downstream build-tag set;
- merge an upstream sync PR before its downstream CI passes.

## Current release targets

`.github/workflows/build.yml` intentionally builds only:

- Linux amd64, `GOAMD64=v3`;
- Windows amd64, `GOAMD64=v3`;
- Android arm64-v8.

CMFA update automation is intentionally disabled and must not be restored.

## Profile-guided optimization

`default.pgo` at the repository root is a CPU profile of the Linux amd64-v3
build under real proxy traffic. `go build` in the root package picks it up
automatically (`-pgo=auto`), so every `.github/workflows/build.yml` target uses
it without extra flags. Do not pass `-pgo=off` for release builds.

Refresh it after large hot-path changes: capture
`/debug/pprof/profile?seconds=300` from a running downstream build (the
profiler route is only mounted when the process starts with `log-level: debug`)
and replace `default.pgo`. Profiles contain only function names and sample
counts; never merge one taken from a build with local-only source changes.

## CI testing

Pull requests into `dev` and pushes to `dev` test the expanded source directly,
then apply the quic-go, sing-quic, and sing-tun dependency patches. Releases and
AndroidCyaml updates are produced from `dev`, never from `Alpha`.

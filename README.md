# VitaTunnel v0.3.3 — NFSMW 2005 AOT Test relay

VitaTunnel is a **foreground-only PS Vita deployment and diagnostic relay**. It is a separate Vita app (TITLE_ID `VITATUNN1`), not the Need for Speed game itself. You launch VitaTunnel manually to check for a new AOT test VPK, verify it, install it, and launch it. After testing, reopen VitaTunnel to collect explicitly selected logs if you have enabled uploads.

## Target and repository

| Item | Value |
| --- | --- |
| GitHub release and manifest repository | `ChatProductions/VitaTunnel-Relay` |
| Repository branch | `main` |
| AOT game/test display name | `NFSMW 2005 AOT Test` |
| AOT test Vita TITLE_ID | `NFMRA0001` |
| Original private PS2 input | `SLUS_213.51` (Most Wanted 2005 Black Edition) |
| Vita diagnostics directory | `ux0:data/ps2vita` |
| Selected text reports | `startup.txt`, `fault.txt`, `progress.txt` |
| Local tunnel configuration | `ux0:data/vitatunnel/config.ini` |

This is **not** `NFSMWVITA` (a separate port), and not `haloce-vita` or OpenCE. Original PS2 assets/ELFs and generated private game code must never be committed to this public repository.

## Preconfigured v0.3 VPK

The release build embeds `assets/config.ini` into the root of `VitaTunnel.vpk` as `config.ini`. On first launch, it creates `ux0:data/vitatunnel/config.ini` with those values. **An untouched old v0.1 OpenCE template is upgraded automatically.** If you previously customized the configuration or added a token, it is preserved: check the file and adjust any stale fields yourself. The app warns if `title_id=OPENCE001` remains.

```ini
owner=ChatProductions
repo=VitaTunnel-Relay
branch=main
title_id=NFMRA0001
token=
log_dir=ux0:data/ps2vita
log_file=ux0:data/ps2vita/startup.txt
log_fault=ux0:data/ps2vita/fault.txt
log_progress=ux0:data/ps2vita/progress.txt
upload_logs=0
upload_core=0
auto_launch=1
```

The three named files are optional, so a crash before a particular file is generated does not automatically count as an upload error. The latest `.log` directly inside `ux0:data/ps2vita` is also eligible when uploads are enabled. Only the last 256 KiB of any file is sent, and unchanged logs are skipped.

**Privacy:** both `token=` and `upload_logs=0` ship disabled. For intentional public uploads, supply a fine-grained GitHub token on the Vita with Contents Read/Write access **only** to `ChatProductions/VitaTunnel-Relay`, then set `upload_logs=1`. Never put a token in a commit, screenshot, message, or chat. Logs uploaded to this repository are public. `upload_core=0` remains off because crash dumps may include memory from unrelated games.

## Building VitaTunnel

1. Open [Build VitaTunnel VPK](https://github.com/ChatProductions/VitaTunnel-Relay/actions/workflows/build.yml) in GitHub Actions, or let a source push start the workflow.
2. Download the successful `VitaTunnel-v0.3.3-VPK` artifact and extract `VitaTunnel.vpk`.
3. Install it in VitaShell. The app keeps its own TITLE_ID `VITATUNN1`. The build validates that all LiveArea PNGs are indexed and non-interlaced.
4. Launch VitaTunnel. Its config is prefilled; no GitHub account/repo editing is required for a new setup.

The CI workflow uses VitaSDK 2026.08, retrieves a pinned VPK installer, bundles a CA certificate store and preserves HTTPS certificate/hostname verification. The in-memory CA loader was introduced in v0.1.2. v0.3.1 normalizes its CA bundle. v0.3.2 tried the OpenSSL SSL_CTX callback but this triggered out-of-memory error 27 on real hardware. v0.3.3 instead splits the verified root bundle into small groups (up to eight), tries each group separately when TLS cannot build a verified chain, and remembers a successful group for future launches. Each attempt still verifies TLS peer and hostname; no insecure fallbacks or TLS Fixer changes are required. Curl's detailed failure text remains visible if HTTPS fails. **Hardware success of HTTPS and the Vita promoter remains unverified**.

## Publishing a separate NFSMW AOT test build

The game VPK is **not included** in VitaTunnel. The AOT test game must be built independently with embedded `sce_sys/param.sfo` TITLE_ID `NFMRA0001`. `relay/target_id.txt` is set to that same value.

When a real, appropriately distributable test VPK exists:

1. Publish a GitHub Release **in this relay repository**, with a tag beginning `game-`, and attach exactly one `.vpk` game asset.
2. The `publish-game.yml` action computes its SHA-256 and writes `tunnel/manifest.txt` on `main`.
3. On next launch, VitaTunnel fetches this manifest from the relay, checks the HTTPS release URL, the SHA-256, and the VPK's embedded `TITLE_ID` before installing. Then it launches the AOT test.
4. After the AOT test, reopen VitaTunnel; configured reports are uploaded only if both token and `upload_logs=1` are present.

Before the first actual game release, `tunnel/manifest.txt` may not exist. An HTTP/manifest error at that stage means **there is no AOT build to deploy yet**; it does not mean the AOT game has been tested. The example under `relay/manifest.txt` is a placeholder, not a published release.

## Safety and limitations

- No background process, PC bridge, remote shell, kernel plugin, or arbitrary filesystem scanning.
- Verified HTTPS only; release URL must be in the configured GitHub repository.
- Manifest hash and embedded game TITLE_ID must both match; VitaTunnel prevents using its own TITLE_ID as a game target.
- Public GitHub diagnostic commits are permanent unless intentionally removed. The token is held only on your Vita.
- The app and network behavior still need real-device verification; a passing CI build is not proof the PS2-to-Vita AOT game works.

Host protocol tests: `bash tests/run_host_tests.sh` (where host C/OpenSSL are available). For local VitaSDK builds: run `bash tools/prepare_vendor.sh`, supply `assets/cacert.pem`, then configure and build with the VitaSDK CMake toolchain.

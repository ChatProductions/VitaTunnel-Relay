# VitaTunnel 0.1 — on-demand PS Vita deployment/diagnostic application

**Status: VitaSDK C source + automated GitHub build workflow. NOT YET COMPILED ON REAL HARDWARE.**
There is no pre-built `VitaTunnel.vpk` in this source package because a VitaSDK toolchain is not present in the environment where this package was generated. The included GitHub Actions workflow is intended to compile one. The code has not been hardware tested. Do not assume it will install successfully without fixes after the first CI build.

VitaTunnel is a *foreground-only* PlayStation Vita homebrew application. You open it manually; it checks for diagnostic files left by the previous test, uploads selected reports **only if you configured a token**, downloads an approved game VPK from a dedicated public GitHub repository, checks its SHA-256 and embedded TITLE_ID, installs it using the Vita promoter, and launches the game. When testing is finished, reopen VitaTunnel to send the resulting log to GitHub.

```
ChatGPT / developer (updates source or supplies VPK)
                |
       dedicated GitHub release + manifest
                |
            VitaTunnel (open manually)
                |
    upload previous log -> verify -> install -> launch
                |
          game runs, VitaTunnel closes
                |
     reopen VitaTunnel to upload the new log
```

The app does NOT access a PC, execute remote shell commands, run resident plugins, upload anything by default without a token, change taiHEN, or scan arbitrary devices. A token enables uploads ONLY from configured paths. Only GitHub Release VPK links from the configured repository are allowed.

## First-time setup (GitHub + Vita, no PC bridge)

1. Create a **new, separate, public** GitHub repository, e.g. `ChatProductions/VitaTunnel-Relay`. Do not use a repository containing personal information. *All diagnostic uploads to this public repository will be publicly readable.*
2. Upload the *contents* of this source ZIP into that new repository. GitHub's web UI supports `Add file` -> `Upload files`, including directory contents. Keep `.github/workflows/build.yml` and `.github/workflows/publish-game.yml` in place. After pushing, open **Actions** -> **Build VitaTunnel VPK** -> **Run workflow** (or wait for automatic push trigger). Download the **VitaTunnel-v0.1-VPK** workflow artifact and extract `VitaTunnel.vpk`.
3. Use VitaShell once to install that VPK. The app's title ID is `VITATUNN1`. No kernel plugin is installed.
4. Open VitaTunnel once. It creates `ux0:data/vitatunnel/config.ini` and explains that configuration is needed. In VitaShell, edit/transfer that file *once* (you can use VitaShell FTP/USB; the bridge does not need to run on your PC). Set `owner`, `repo`, `branch=main`, and the exact `title_id` of the target game. Set its log folder/file path.
5. To enable automatic uploads, create a **fine-grained GitHub personal access token**, selected repository **only the new relay**, repository permission **Contents: Read and write** (Metadata: read is implicit), short expiration. Put it as `token=...` in `config.ini` on the Vita **only**. Do not paste tokens in ChatGPT or share them through screenshots. If `token=` remains blank, installation and launching still work, but reports will not be uploaded.
6. In the repo edit `relay/target_id.txt` to match the exact nine-character game title ID (`OPENCE001` is a dummy example). The target ID in the game VPK **must match both this and the Vita config**, or installation is rejected.
7. Attach a compiled game `.vpk` to a GitHub Release whose tag begins with `game-` (e.g. `game-open-ce-001`). The `Publish game update to VitaTunnel` action computes SHA-256 and updates `tunnel/manifest.txt` on `main`. If GitHub Actions says it cannot push, enable repository **Settings -> Actions -> General -> Workflow permissions -> Read and write permissions**.
8. Open VitaTunnel. It reads the new manifest, checks that the VPK belongs to the configured relay repository, verifies its SHA-256 and package TITLE_ID, installs it, and launches the game. Reopen VitaTunnel after testing; it uploads the most recent configured log if it has changed.

**Only the first-time account/repo/Vita setup is manual.** Subsequent deployment and log transfer are automatic when you launch VitaTunnel. Sending a VPK as a GitHub release can itself be automated through the game repository's CI, but this 0.1 bundle cannot infer how an arbitrary project is built.

## Application configuration

An example for OpenCE (adjust the title ID and log folder to the REAL game build):

```ini
owner=ChatProductions
repo=VitaTunnel-Relay
branch=main
title_id=OPENCE001
token=YOUR_RESTRICTED_TOKEN_OR_LEAVE_BLANK
log_dir=ux0:data/open-ce/logs
log_file=
upload_logs=1
upload_core=0
auto_launch=1
```

`upload_core=1` is **explicit opt-in**, and currently sends just the last 256 KiB of the most recent `.psp2dmp` under `ux0:data` (which might be from another app). Full core-dump collection/chunking is planned; it is **not** implemented. A selected `.log` file also uploads only its last 256 KiB. Reports are stored as files under `diagnostics/<TITLEID>/` in the public relay repository. Duplicate reports are skipped using local SHA-256 state files. No authentication token is written to app logs.

## Security constraints

- TLS certificate and hostname verification are **always enabled**. No insecure HTTP fallback. `assets/cacert.pem` is copied from the GitHub Actions build container's CA store.
- Downloads must be `https://github.com/<configured owner>/<configured repo>/releases/download/.../*.vpk`; HTTP redirects are HTTPS-only.
- The published SHA-256 must match the download, and the VPK's embedded `sce_sys/param.sfo` TITLE_ID must match the configured game. VitaTunnel blocks updating its own title ID.
- No generic arbitrary remote commands, runtime kernel plugins, broad filesystem scans, silent deletion of app data, or unrestricted log collection.
- The token grants GitHub Contents WRITE to the relay repository; that is a significant capability if stolen. Rotate/revoke it if lost. The public repository should not contain private information. No secrets are placed in GitHub Actions build artifacts.
- A trusted repository owner can still distribute malicious VPKs. Neither TLS nor SHA-256 makes untrusted code safe. Use an isolated repository and carefully control contributors and release permissions.

## Building locally (optional)

Requires VitaSDK 2026.08 and packages: libvita2d, libzip, curl, openssl, zlib, zstd, xz, bzip2, libpng, libjpeg-turbo, freetype. Use VitaSDK's recommended Linux/WSL2 build environment, or run the included GitHub workflow instead.

```sh
vdpm install libvita2d libzip curl openssl zlib zstd xz bzip2 libpng libjpeg-turbo freetype
bash tools/prepare_vendor.sh
cp /etc/ssl/certs/ca-certificates.crt assets/cacert.pem
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$VITASDK/share/vita.toolchain.cmake"
cmake --build build --parallel 2
```

Result: `build/VitaTunnel.vpk`.

The vendor stage pins unmodified installer files from `theheroGAC/Vita-VPKInstaller-Direct` at SHA `4af7eb1c6f924de5a982248dc4e69ad962c15377` (MPL-2.0). Their original license is included by the clone. For the automatic GitHub workflow, source is public to permit `raw.githubusercontent.com` manifest access without embedding a download credential.

## First tests / limitations

1. Build via GitHub Actions. Inspect and fix any SDK ABI or linker problems reported by CI before calling this a working VPK.
2. Install VitaTunnel, confirm it creates the configuration folder, and test with a dummy small homebrew VPK with a distinct title ID, *not* OpenCE or an existing save-sensitive title.
3. Confirm repeated launches do not reinstall unchanged versions and do not reupload identical logs.
4. Confirm `token=` blank prevents any uploads, the wrong SHA-256 is rejected, a mismatched TITLE_ID is rejected, and HTTPS verification failure does not fall back to insecure transfer.
5. Then use it for OpenCE or another game; do NOT publish a log that contains private user data.

**Known unverified:** VitaSDK compile/link, GitHub modern TLS from the console, promoter runtime behavior, and app launching on real Vita. No guarantee of successful installation yet. The CI must be run in a GitHub repository; this environment had no VitaSDK or network access to download one.

# Auto-Update

v0.11.1+ Tauri auto-updater(Ed25519 signed)。

## Flow

```
v0.11.1+ client startup
  → Tauri updater plugin polls
    https://vigils.ai/desktop-updates/<target>-<arch>/<current_version>.json
  → server returns { version, url, signature, ... }
  → client compares server.version > local.version
  → download bundle + verify .sig with embedded pubkey
  → restart on new version
```

## Build signed bundle

```bash
export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/vigil-desktop-update.key)"
cargo tauri build --features gui --bundles deb,rpm,appimage  # + dmg/msi/nsis
# 产 <binary>.sig 同步
```

## Mirror endpoint

Caddy `handle_path /desktop-updates/*` → `/srv/vigil-desktop-updates/`。
SOP:`docs/operations/v0.11-roadmap/v0.11.1-auto-update-deployment.md`。

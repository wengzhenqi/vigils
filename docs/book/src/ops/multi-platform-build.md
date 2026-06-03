# Multi-Platform Build

Three platforms; seven installer/bundle artifacts.

## Linux

```bash
sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev libgtk-3-dev
cd apps/desktop
cargo tauri build --features gui --bundles deb,rpm,appimage
```

## macOS

```bash
export CI=true  # skips the AppleScript Finder styling that needs a GUI session
cd apps/desktop
cargo tauri build --features gui --bundles app,dmg
# app target = updater artifact (.app.tar.gz + .sig)
# dmg target = user-facing installer
```

## Windows

```bash
cd apps/desktop
cargo tauri build --features gui --bundles msi,nsis
```

## Binary layout

`apps/desktop/Cargo.toml` declares a single binary —
`[[bin]] name = "vigils" path = "src/bin/vigils.rs"` — aligned with the Tauri v2 bundle
default (the bin name matches the path basename and `mainBinaryName`). The installed
executable is `vigils` / `vigils.exe` (since v0.1.5; earlier builds shipped `gui`).

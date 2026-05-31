# Installation

## Desktop App(end users)

### Linux
```bash
sudo dpkg -i 'Vigil Desktop_0.0.1_amd64.deb'      # Debian/Ubuntu
sudo rpm -i 'Vigil Desktop-0.0.1-1.x86_64.rpm'    # Fedora/RHEL
chmod +x 'Vigil Desktop_0.0.1_amd64.AppImage' && ./Vigil*.AppImage  # portable
```

### Windows
- NSIS:双击 `Vigil Desktop_0.0.1_x64-setup.exe`(SmartScreen 警告 → "Run anyway")
- MSI:`msiexec /i "Vigil Desktop_0.0.1_x64_en-US.msi" /quiet`

### macOS
```bash
tar xzf 'Vigil Desktop.app.tar.gz'
mv 'Vigil Desktop.app' /Applications/
xattr -d com.apple.quarantine '/Applications/Vigil Desktop.app'  # 绕 Gatekeeper(未 notarized)
```

### Auto-Update
v0.11.1+ Tauri auto-updater 启用(Ed25519 signed)。详见 [Auto-Update](../ops/auto-update.md)。

## Rust SDK(developers)

```toml
[dependencies]
vigil-sdk = "0.13"
```

详见 [SDK Quickstart](./sdk-quickstart.md)。

## Browser Extension(Chrome MV3)

v0.4 起 4 站点支持(ChatGPT / Claude / Gemini / Perplexity):
1. `chrome://extensions` → "Load unpacked" → 选 `extensions/chrome-mv3/`
2. Ext 经 Native Host 与 desktop app 通信

## CLI Agent

```bash
cargo install --path apps/vigil-hub-cli
vigil-hub serve --stdio  # MCP agent entry(Claude Code / Codex / Cursor / Zed 可接)
```

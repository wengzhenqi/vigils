# Vigil mdBook User Guide

Public user guide source.

## Build

```bash
# 安装 mdbook(若未装):
cargo install mdbook

# 项目根:
cd docs/book
mdbook build
# 产出 docs/book/book/(gitignored),含 index.html + 全章节静态 HTML + search index
```

## Local preview

```bash
cd docs/book
mdbook serve --open  # 启动 http://localhost:3000 + auto-reload
```

## Deploy to vigils.ai/docs/

```bash
# 本地 build 后:
mdbook build

# SCP 上传到 mirror box:
scp -r docs/book/book/* vigil-mirror:/srv/vigil-docs/

# Caddy 配置(/etc/caddy/Caddyfile vigils.ai 块内):
#   handle_path /docs/* {
#       root * /srv/vigil-docs
#       file_server
#       try_files {path} {path}/index.html
#   }
# sudo systemctl reload caddy

# 验证:
# curl -I https://vigils.ai/docs/
# expected: HTTP 200 + Content-Type: text/html
```

## Structure

```
docs/book/
├── book.toml          # mdbook 配置(title / theme / site-url=/docs/)
├── src/               # 源 markdown
│   ├── SUMMARY.md     # TOC
│   ├── intro.md
│   ├── getting-started/
│   ├── concepts/
│   ├── sdk/
│   ├── ops/
│   ├── adr/
│   └── releases/
└── book/              # build 输出(gitignored,SCP 上传源)
```

## Edit

修改 `src/*.md` → 重 `mdbook build` → re-deploy。

`mdbook serve --open` 本地修改实时预览。

## 后续

- v0.13.x:补充 architecture / concepts 章节深度内容
- v0.14:Tauri integration cookbook(集成示例)
- v0.15:i18n(中文 + 英文 dual-language,等 mdbook 多 language 成熟)

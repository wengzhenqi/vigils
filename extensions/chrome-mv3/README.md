# chrome-mv3 — Vigils Browser Guard Extension

Chrome MV3 扩展，默认提供普通用户可直接使用的复制粘贴守门能力。普通模式在浏览器内用轻量 JS 规则检测常见密钥、token、JWT、`.env` 和数据库连接串；不需要 Native Host、不需要 Vigils 桌面应用、不需要终端命令。

企业模式保留 provider 接口，后续可以接 Native Host、localhost agent、企业 HTTPS API、浏览器内 Wasm 或其他受管 provider。Native Host 是企业 provider 的一种未来实现，不是普通用户默认依赖。

## 当前范围

- ✅ `manifest.json`: 真实 MV3 配置（name / version 0.1.10 / host_permissions / optional_host_permissions / content_scripts / CSP）；权限聚焦在浏览器内扫描、站点注入和状态保存
- ✅ `background.js`: service worker 负责消息编排、站点范围判定和结果路由；当前默认路径优先使用浏览器内 JS 扫描结果，不依赖本机守护进程
- ✅ `content-script.js`: paste + 防抖 input + submit + contenteditable Enter 路径 + 简易 `textContent` toast；同一套通用规则覆盖 manifest 注入的所有 host，站点适配器只负责更精确的输入定位，不负责把原文送去本机
  - **覆盖模型**: manifest 注入的**所有** host 都受**通用** paste/input/keydown 守门保护（与站点无关，主保护层）。content script 以 `all_frames: true` 注入匹配站点 iframe。**深选择器**（`siteAdapters.findPrimaryInput`、form-submit 主输入精确定位）目前覆盖 ChatGPT / Claude / Gemini / Perplexity 4 站；国内 AI 站点（DeepSeek / 豆包 / Kimi / 通义 / 千问 / 智谱 / 元宝 / 文心 / 星火）仅靠通用守门，深选择器待真站点 DOM 核验后补（无 adapter 时降级 form 聚合 / fail-safe block，绝不外发原文）
- ✅ `scanner-pipeline.js`: 普通模式默认调用浏览器本地 `consumerJsProvider`；企业模式通过 provider 接口预留扩展，不把 Native Host 写死为唯一实现
- ✅ options 自定义保护网站：用户输入域名 → Chrome 请求该 HTTPS 域名权限 → `chrome.storage.local.customProtectedSites` 持久保存 host/pattern 元数据 → SW 用 `chrome.scripting.registerContentScripts` 动态注入通用守门
- ✅ popup/options: 普通用户只看到推荐保护状态、最近记录、模式和网站权限；不暴露 `strict / balanced / recall-first` 档位选择

## 安全契约（当前默认 consumer 路径）

本目录遵守以下不变量：

- **浏览器内默认扫描**: 原文在页面侧由轻量 JS 规则识别；命中后由内容脚本直接给出阻断或脱敏确认的页面内反馈
- **原文不落库**: 原文不写 `chrome.storage`、不写 `console.log`、不写 `window.*`；`chrome.storage` 只保存自定义网站 host/pattern、模式和 UI 设置等元数据
- **特权 scheme fail-closed**: `file://` / `chrome://` / `chrome-extension://` / `devtools://` / `about://` 由浏览器侧逻辑直接拒绝；service worker 对非 http(s) origin 做同等早退（`origin_denied_sw` reason code）
- **大小上限前置拦截**: 浏览器内路径先做字符长度早退兜底，避免把明显过大的文本继续送入后续判断（`too_large_sw` reason code）
- **三态执行**: service worker / content script 按 `allow`、`confirm_redact`、`block` 三态处理；未知或非法 action → fail-closed `block`
- **toast 和弹窗不 HTML 注入**: UI 文案使用 DOM API 和 `textContent` 赋值，拒绝 `innerHTML`
- **纯 vanilla JS**: 无外部 npm 依赖，零构建步骤，manifest 声明的文件可直接 "load unpacked" 加载

## 企业 provider（未来）

Native Host 不是普通用户默认路径。它只属于企业 provider 体系中的一种未来接入方式，后续实现可以按需要切换为：

- Native Host
- localhost agent
- 企业 HTTPS API
- 浏览器内 Wasm
- 其他受管 provider

企业 provider 的目标是把扫描和策略执行迁移到受控环境；普通 consumer 版本继续以浏览器内 JS 扫描为默认行为。

## 后续规划

- **α2**: 按站点深度选择器（ChatGPT `#prompt-textarea` / Claude contenteditable / etc.）的精确 adapter，替代通用 textarea 降级
- **α3**: popup UI 展示最近 N 条 finding、模式状态和更细的站点保护反馈
- **β**: E2E（Playwright + headed Chrome + 构造含 hard-secret 的 paste），三平台打包，企业 provider 接入骨架
- **后续迭代**: i18n / 自定义站点深度 adapter / 用户可见的权限修复入口

## 本地加载（开发）

1. Chrome `chrome://extensions/` → 打开 Developer mode。
2. Load unpacked → 选择 `extensions/chrome-mv3/`。
3. 打开受保护 AI 网站，粘贴含测试 token 的文本。
4. 普通风险应出现“脱敏后继续 / 阻断”页面内确认；PEM 私钥应被强阻断。

普通模式不需要注册 `com.vigil.host`。企业模式的真实 provider 接入留给后续版本。

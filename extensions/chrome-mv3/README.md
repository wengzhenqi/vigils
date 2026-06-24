# chrome-mv3 — Vigils Browser Guard Extension

Chrome MV3 扩展，默认提供普通用户可直接使用的复制粘贴守门能力。普通模式在浏览器内用轻量 JS 规则检测常见密钥、token、JWT、`.env` 和数据库连接串；不需要 Native Host、不需要 Vigils 桌面应用、不需要终端命令。

企业模式保留 provider 接口，后续可以接 Native Host、localhost agent、企业 HTTPS API、浏览器内 Wasm 或其他受管 provider。Native Host 是企业 provider 的一种未来实现，不是普通用户默认依赖。

## 当前范围(I09b-α1)

- ✅ `manifest.json`:真实 MV3 配置(name / version 0.1.10 / host_permissions / optional_host_permissions / content_scripts / CSP);permissions 为 `nativeMessaging` + `activeTab` + `storage` + `scripting`
- ✅ `background.js`:service worker,`chrome.runtime.connectNative` 长连接 + pending-request map + UUIDv4 `request_id` + 10s TTL;ErrorFrame 按 error 字段优先分流(含 Rust 侧 Option request_id 场景):有 request_id 精准路由 block,无 request_id 立即 **全 pending fail-closed block**(R1 MUST-FIX 2)
- ✅ `content-script.js`:paste + 防抖 input + submit + contenteditable Enter 路径 + 简易 `textContent` toast;submit allow 走 `form.requestSubmit(submitter)` + `WeakSet` allow-once(R1 MUST-FIX 1 保留 HTML validation + 其他 submit listener 参与)
  - **覆盖模型**:manifest 注入的**所有** host 都受**通用** paste/input/keydown 守门保护(与站点无关,主保护层)。content script 以 `all_frames: true` 注入匹配站点 iframe。**深选择器**(`siteAdapters.findPrimaryInput`,form-submit 主输入精确定位)目前覆盖 ChatGPT / Claude / Gemini / Perplexity 4 站;国内 AI 站点(DeepSeek / 豆包 / Kimi / 通义 / 千问 / 智谱 / 元宝 / 文心 / 星火)**仅靠通用守门**,深选择器待真站点 DOM 核验后补(无 adapter 时降级 form 聚合 / fail-safe block,绝不外发原文)
- ✅ 协议严格对齐 `crates/vigil-browser/src/protocol.rs`(`BrowserCheckRequest` / `BrowserCheckResponse` / `BrowserErrorFrame`)
- ✅ options 自定义保护网站:用户输入域名 → Chrome 请求该 HTTPS 域名权限 → `chrome.storage.local.customProtectedSites` 持久保存 host/pattern 元数据 → SW 用 `chrome.scripting.registerContentScripts` 动态注入通用守门

## Native Host 注册

Native messaging host 必须注册到 Chrome 指定目录(OS 特定):

- **Windows**:注册表 `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vigil.host` 指向 host manifest json 的绝对路径
- **macOS**:`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vigil.host.json`
- **Linux**:`~/.config/google-chrome/NativeMessagingHosts/com.vigil.host.json`

Host manifest 需包含 `allowed_origins`(扩展 ID `chrome-extension://<id>/`)以授权此扩展连接。具体注册脚本延 β(需要知道打包后的扩展 ID)。

## 安全契约(ADR 0009 §I-9)

本目录遵守以下不变量:

- **§I-9.1 text in-memory only**:原文经 `chrome.runtime.sendMessage` → service worker → Native Host,中间**不写** `chrome.storage` / `console.log` / `window.*`;`chrome.storage` 仅保存自定义网站 host/pattern 元数据
- **§I-9.3 特权 scheme fail-closed**:`file://` / `chrome://` / `chrome-extension://` / `devtools://` / `about://` 由 Native Host 拒;service worker 层对非 http(s) origin 做同等早退(`origin_denied_sw` reason code)
- **§I-9.5 1 MB 帧上限**:Native Host 层规范化拒绝;service worker 做 32 MB 字符早退兜底(`too_large_sw` reason code)
- **§D6 三态执行**:service worker 按 Response.action ∈ {allow, redact, block} 原样转发;非法 action / 协议错误帧 → fail-closed `block`
- **toast 不 HTML 注入**:`textContent` 赋值,拒绝 `innerHTML`(content-script.js)
- **纯 vanilla JS**:无外部 npm 依赖,零构建步骤,manifest 声明的文件可直接 "load unpacked" 加载

## 后续规划

- **α2**:按站点深度选择器(ChatGPT `#prompt-textarea` / Claude contenteditable / etc.)的精确 adapter,替代通用 textarea 降级
- **α3**:popup UI 展示最近 N 条 finding + 用户临时豁免(session-scoped allow)
- **β**:E2E(Playwright + headed Chrome + 构造含 hard-secret 的 paste),三平台打包,Host manifest 注册脚本
- **后续迭代**:i18n / 自定义站点深度 adapter / 用户可见的权限修复入口

## 本地加载

1. Chrome `chrome://extensions/` → 打开 Developer mode。
2. Load unpacked → 选择 `extensions/chrome-mv3/`。
3. 打开受保护 AI 网站，粘贴含测试 token 的文本。
4. 普通风险应出现“脱敏后继续 / 阻断”页面内确认；PEM 私钥应被强阻断。

普通模式不需要注册 `com.vigil.host`。企业模式的真实 provider 接入留给后续版本。

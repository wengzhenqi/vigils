# ADR 0012 — Privacy Filter 模型与 ONNX Runtime 分发策略(v0.4 Stage 0)

- 状态:**Draft**(ISS-20260423-004;待 Codex R1 审查)
- 日期:2026-04-24
- 依赖:ADR 0007(sandbox)/ ADR 0009(Browser Extension)
- 相关 issue:ISS-20260423-001(选型 PoC)、ISS-20260423-004(本 ADR)、ISS-20260423-008(Rust 模型接入)
- 依赖的意外发现(来自 ISS-001 spike):
  - HF CDN 到中国测试环境 3-6 MB/min,809 MB 权重下载不可控
  - `ort-sys 2.0-rc.12` `download-binaries` 与 `ureq 3.3` 不兼容(upstream bug)
  - tokenizer.json **28 MB**,浏览器扩展冷启动 parse ≈ 860 ms

## 0. 摘要(TL;DR)

Vigil v2 要分发三类新增 artifacts:

| Artifact | 尺寸 | 用处 | 分发方 |
|---|---|---|---|
| **Privacy Filter ONNX 权重**(`model_q4f16.onnx` + `.onnx_data`)| ~809 MB | T0 模型推理 | Vigil mirror + HF 回源 + IndexedDB(扩展)|
| **tokenizer.json + config.json** | ~28 MB + 3 KB | BPE + id2label | 同上 |
| **ONNX Runtime 动态库**(onnxruntime.dll / .so / .dylib)| ~20 MB/平台 | Rust `ort` load-dynamic | 随 release tarball 捆 |

**核心决策**:
1. **桌面/Hub**:Vigil release binary 零模型内嵌;**首次运行下载**(Vigil mirror 优先,HF 回源)+ 本地缓存 + SHA256 校验
2. **ONNX Runtime lib**:随 release tarball 捆一份(Win/Linux/macOS 三份),**不**走 `ort` crate 的 `download-binaries`(upstream bug)
3. **浏览器扩展**:Transformers.js 走 HF CDN + IndexedDB / OPFS 缓存(MVP 阶段不走 Native Host RPC)
4. **fail-closed**:模型不可用(WebGPU 不支持 / 下载失败 / 校验失败)→ **降级到 v0.3 硬指纹规则层**(RULE_PROFILE_VERSION v4 的 13 类 FindingKind),**不** fail-open

## 1. 背景

### 1.1 v0.3 基线分发模型

- `vigil-hub.exe` Windows 9.11 MiB,Linux/macOS 类似
- `vigil-desktop-gui` Windows/Linux/macOS ~12-14 MiB(Tauri + WebView)
- 分发方式:GitHub Release tag 触发 GHA build matrix → 三平台二进制 + SHA256 清单
- 用户体验:单文件下载 + 运行,零外部依赖

### 1.2 v2 引入的新压力

| 维度 | v0.3 | v2(加 T0 模型后) |
|---|---|---|
| binary 尺寸 | 9-14 MiB | **内嵌:~850 MB(rejected)**<br>side-car:~850 MB 总 archive<br>**首次下载:保持 9-14 MiB ⭐** |
| 首次启动时间 | 即刻 | 取决于下载路径 |
| 离线可用性 | ✅ | 取决于缓存 |
| 跨平台一致 | ✅ | 需 Win/Linux/macOS 三份 ORT lib |
| 安全/审计 | SHA256 清单 | **模型文件必须同等校验** |

### 1.3 ISS-001 spike 产出的硬约束

1. HF CDN 可能到用户环境限速(实测单线程 3-6 MB/min);**并发 16 chunk 降到 ~280s/800MB 峰值 46 MB/s**。**必须** Vigil 自建镜像 + 并发下载双管齐下
2. `ort-sys 2.0-rc.12` 的 `download-binaries` 受 upstream ureq bug 影响;`ort 2.0-rc.10` 无此 bug 但捆的 ORT ≈ 1.19(旧)。**最小可行 ORT 版本 = 1.21**(支持 `GatherBlockQuantized.bits` 属性),**Vigil 产线硬定为 1.24 LTS**。`load-dynamic` + 自捆 libs/onnxruntime.* 是唯一可控路径
3. 28 MB tokenizer.json parse ~860 ms;桌面冷启动需考虑 lazy/cached
4. **q4 量化模型依赖 Microsoft contrib 算子 `GatherBlockQuantized`**;通过 ORT ≥ 1.21 的 `MSDomain` 算子注册支持;这是 "内嵌 libonnxruntime" 非"动态探测"的技术原因

## 2. 备选方案对比

| # | 方案 | 二进制尺寸 | 首次启动 | 离线可用 | 分发复杂度 | 更新便利 | 结论 |
|---|---|---|---|---|---|---|---|
| A | **内嵌**(cargo `include_bytes!` / embed-resource)| +850 MB(9→~860 MB)| 即刻 | ✅ | 低 | 每次权重更新要重发 vigil-hub | ❌ |
| B | **release archive 捆 side-car**(`vigil-hub-v0.4.0-win-x64.zip` 含 exe + models/)| exe 不变 | 即刻(解压后)| ✅ | 中 | 同上,要重打整个 archive | ❌(archive ~850 MB,下载体验差)|
| C | **⭐ 首次运行下载**(Vigil mirror 优先,HF 回源,本地缓存)| exe 不变 | 首次 5-60s(取决网速)/ 二次即刻 | ✅(下载后)| 中 | 权重独立版本,exe 和 models 解耦更新 | ✅ |
| D | Git LFS | — | — | — | 高(LFS 带宽费;用户要装 Git LFS)| 只适合 dev | ❌(不适合 release)|
| E | 按需流式(不缓存)| exe 不变 | 每次启动都下 | ❌ | 高 | 即时 | ❌(离线不行 + 重复流量)|

**选 C**(首次运行下载 + 本地缓存)。

## 3. 详细设计(桌面/Hub 侧)

### 3.1 分发目录结构

Release archive `vigil-v0.4.x-{platform}.tar.gz` 含:

```
vigil-v0.4.x-{platform}/
├── vigil-hub            # 10 MiB(不变)
├── vigil-desktop        # CLI
├── vigil-desktop-gui    # Tauri GUI 12-14 MiB
├── libs/
│   └── onnxruntime.{dll|so|dylib}   # ~20 MiB,随 ORT version 更新
├── assets/              # icon / tauri 资源
├── SHA256SUMS           # 二进制 + libs + 图标清单(不含 model)
├── MODELS_MANIFEST.json # 模型元数据:URL、SHA256、size、version
└── README.txt
```

**archive 总尺寸**:约 30-40 MiB(vs 方案 A 的 860 MB,用户体验好 20×)。

### 3.2 首次运行下载流程

```
vigil-hub/vigil-desktop-gui 启动
  ↓
读 MODELS_MANIFEST.json → 发现需要 `openai-privacy-filter-q4f16@2026-04-24`
  ↓
检查缓存目录(见 §3.3)
  ↓
缓存不存在 or SHA256 不匹配
  ↓
启动后台下载(进度条推送给 UI / CLI stderr)
  ├─ **主通道**:Vigil mirror(`https://models.vigil.local/privacy-filter/v1/...`)
  │   16 chunk 并行 byte-range split(见 §3.6)
  └─ **回源**:HF CDN(`https://huggingface.co/openai/privacy-filter/resolve/main/...`)
  ↓
下载完成 → 校验 SHA256
  ├─ 匹配 → 写缓存,T0 初始化
  └─ 不匹配 → 日志 + 删临时文件 + **fail-closed 降级硬指纹**
  ↓
ORT session commit + warm up(3 样本预跑)→ ready
```

### 3.3 缓存目录

跨平台 app data 标准路径 `~/.vigil/models/`(dirs crate):

| 平台 | 路径 |
|---|---|
| Windows | `%APPDATA%\vigil\models\` |
| Linux | `$XDG_DATA_HOME/vigil/models/` 或 `~/.local/share/vigil/models/` |
| macOS | `~/Library/Application Support/vigil/models/` |

目录内:
```
models/
└── privacy-filter/
    └── q4f16-2026-04-24/           # semver + date 标签
        ├── model_q4f16.onnx        # 166 KB ONNX graph
        ├── model_q4f16.onnx_data   # 809 MB 外挂权重
        ├── tokenizer.json          # 28 MB
        ├── config.json             # 3 KB
        └── meta.json               # 下载时间 / SHA256 / 源 URL
```

### 3.4 MODELS_MANIFEST.json schema(随 release 捆)

```json
{
  "schema_version": 1,
  "models": [
    {
      "id": "privacy-filter-q4f16",
      "version": "2026-04-24",
      "description": "OpenAI Privacy Filter 1.5B MoE / 50M active / q4f16 ONNX",
      "license": "Apache-2.0",
      "license_url": "https://github.com/openai/privacy-filter/blob/main/LICENSE",
      "required_by": ["vigil-redaction"],
      "total_size_bytes": 879239168,
      "files": [
        {
          "name": "model_q4f16.onnx",
          "size": 166400,
          "sha256": "<到 ISS-008 实算填>",
          "primary_url": "https://models.vigil.local/privacy-filter/q4f16-2026-04-24/model_q4f16.onnx",
          "fallback_urls": [
            "https://huggingface.co/openai/privacy-filter/resolve/main/onnx/model_q4f16.onnx"
          ]
        },
        {
          "name": "model_q4f16.onnx_data",
          "size": 849346560,
          "sha256": "<待填>",
          "primary_url": "https://models.vigil.local/privacy-filter/q4f16-2026-04-24/model_q4f16.onnx_data",
          "fallback_urls": [
            "https://huggingface.co/openai/privacy-filter/resolve/main/onnx/model_q4f16.onnx_data"
          ]
        },
        {
          "name": "tokenizer.json",
          "size": 27868174,
          "sha256": "<待填>",
          "primary_url": "https://models.vigil.local/privacy-filter/q4f16-2026-04-24/tokenizer.json",
          "fallback_urls": [
            "https://huggingface.co/openai/privacy-filter/resolve/main/tokenizer.json"
          ]
        },
        {
          "name": "config.json",
          "size": 3039,
          "sha256": "<待填>",
          "primary_url": "https://models.vigil.local/privacy-filter/q4f16-2026-04-24/config.json",
          "fallback_urls": [
            "https://huggingface.co/openai/privacy-filter/resolve/main/config.json"
          ]
        }
      ],
      "runtime_requirements": {
        "onnxruntime_version": ">=1.24",
        "min_ram_mb": 2048
      }
    }
  ]
}
```

### 3.5 Vigil mirror 基建

- **域名**:`models.vigil.local`(占位;ADR 0012 Revised 阶段定具体 DNS)
- **后端**:静态 CDN(Cloudflare R2 / S3 + CloudFront / GitHub Releases 超 2GB 限制用 Releases asset)
- **版本策略**:
  - 路径含 `{model-id}/{version}-{date}/`,内容不可变(immutable)
  - 新版本 = 新目录,manifest 指向新 URL
  - **绝不原地覆盖**(用户缓存命中 SHA256 判新旧)
- **冗余**:两个独立 origin(Cloudflare R2 + HF CDN 回源)+ 至少 1 个 region
- **校验链**:release SHA256SUMS 含 MODELS_MANIFEST.json 的 hash;manifest 内嵌每文件 SHA256

**ISS-001 网络实测结论**:HF CDN 不能作主通道(3-6 MB/min 不可接受);Vigil mirror 是硬需求。

### 3.6 并发下载(ISS-001 反馈驱动)

**反馈**:"模型下载可以直接使用并发下载方式,而不是单线程方式"

实装:
- HTTP range split 成 16 chunks(每 chunk ~51 MB @ 809 MB)
- 16 路并行 curl / reqwest `GET range: bytes=start-end`
- 进度聚合 → UI 进度条
- 断点续传:每 chunk 独立 temp 文件,任一失败只重 failed chunk
- 预期提速:单线程 3-6 MB/min → 并发 40-120 MB/min(视 CDN 限流粒度)

Rust 侧已验(见 ISS-001 spike `parallel-download.mjs`,Node 实现);Rust 产线版放 Stage 1 `vigil-redaction-bootstrap` 模块。

### 3.7 Runtime 检查与降级

每次 Hub 启动:

```rust
pub fn init_redaction_engine() -> Arc<dyn RedactionEngine> {
    match try_load_model_engine() {
        Ok(engine) => Arc::new(ComposedEngine::new(HardFingerprint, engine)),
        Err(e) => {
            tracing::warn!(error = ?e,
                "Privacy Filter model unavailable; degrading to hard-fingerprint-only. \
                 To restore: check {}/meta.json or rerun vigil-hub redaction init",
                cache_dir().display());
            // fail-closed:硬指纹仍 deny 硬敏感,只是覆盖面小
            Arc::new(HardFingerprintEngine::new())
        }
    }
}
```

**关键纪律**:
- ❌ **绝不** fail-open 默认 Allow(零信任)
- ✅ 降级模式要写 **显式审计事件**(`model_engine_degraded`)和 UI 提示
- ✅ `vigil-hub redaction status` 命令查当前引擎状态

## 4. 浏览器扩展侧(独立于桌面/Hub)

### 4.1 方案

Chrome MV3 扩展走 Transformers.js + HF CDN(不经 Vigil mirror,不经 Native Host RPC):

```javascript
import { pipeline } from '@huggingface/transformers';

const classifier = await pipeline(
  'token-classification',
  'openai/privacy-filter',
  { device: 'webgpu', dtype: 'q4' }
);
```

Transformers.js 自动管理:
- 首次从 HF CDN 拉模型文件(q4f16 ~809 MB + tokenizer 28 MB)
- 存 **IndexedDB 或 Origin Private File System (OPFS)**
- 后续启动命中缓存即刻可用

### 4.2 为什么扩展走 HF 而非 Vigil mirror

- Transformers.js 内部直查 HF API,改其 URL 基址要 fork / 自定义 loader —— 增复杂度
- 浏览器侧流量与桌面侧解耦;HF CDN 稳定性在北美/欧洲通常可接受
- 若用户环境 HF 也被限速 → 扩展首次加载会卡;可在 options 页加 "使用 Vigil mirror" 选项(Stage 1 后置)

### 4.3 首次加载 UX

- Service Worker 启动时后台预加载模型(非粘贴时刻)
- content script 粘贴前检查若模型未就绪 → 降级硬指纹(同桌面原则)
- 进度通知经 `chrome.runtime.sendMessage` 推到 popup UI

### 4.4 28 MB tokenizer.json 的影响

- 每次 Service Worker 冷启动都要 parse 28 MB JSON(~860 ms 测得)
- MV3 Service Worker 30s 无活动即回收 → 每次唤醒都付 860 ms 代价
- **缓解**:用 IndexedDB 存 tokenizer pre-parsed binary(若 Transformers.js 支持)或
  接受首次 paste 延迟 ~900 ms 的 UX(后续命中缓存 < 10 ms)

## 5. ONNX Runtime 动态库分发(Rust 桌面专用)

### 5.1 为什么不用 `ort` crate `download-binaries` feature

ISS-001 Phase 2 实测给了**两条独立理由**:

1. **`ort-sys 2.0-rc.12` 编译错**:build.rs 依赖 `ureq::tls` / `.tls_config()`,
   与 ureq 3.3.0 API 不兼容(E0432/E0599)
2. **`ort-sys 2.0-rc.10` 捆的 ORT 太旧**(≈ 1.19),不识别 q4 量化依赖的
   `GatherBlockQuantized.bits` 属性(ONNX Runtime 1.21+ 才加)—— 运行期
   `Load model from model_q4f16.onnx failed: Unrecognized attribute: bits`

两个版本都不能直接用:
- rc.10 编译通过但运行期加载 q4 模型失败
- rc.12 编译就失败

**唯一可行路径**:`ort = 2.0-rc.12` + `load-dynamic` + 手动捆 ORT ≥ 1.24。

### 5.2 Vigil 正式方案:release archive 捆 native lib + `load-dynamic`

```toml
# crates/vigil-redaction/Cargo.toml(Stage 1+)
[dependencies]
ort = { version = "=2.0.0-rc.12", default-features = false, features = [
    "std",
    "load-dynamic",   # 运行时加载,不要 build-time download
    "ndarray",
] }
```

Runtime loading:
```rust
// crates/vigil-redaction/src/engine.rs
pub fn init_ort() -> Result<()> {
    let lib_path = determine_ort_lib_path();  // libs/onnxruntime.dll / .so / .dylib
    std::env::set_var("ORT_DYLIB_PATH", &lib_path);
    ort::init()
        .with_name("vigil-redaction")
        .with_execution_providers([CPUExecutionProvider::default().build()])
        .commit()?;
    Ok(())
}

fn determine_ort_lib_path() -> PathBuf {
    // 1. 优先看环境变量(运维覆盖)
    if let Ok(p) = std::env::var("VIGIL_ORT_LIB") {
        return p.into();
    }
    // 2. release 目录下 libs/
    let exe = std::env::current_exe().unwrap();
    let libs = exe.parent().unwrap().join("libs");
    #[cfg(windows)]
    return libs.join("onnxruntime.dll");
    #[cfg(target_os = "linux")]
    return libs.join("libonnxruntime.so");
    #[cfg(target_os = "macos")]
    return libs.join("libonnxruntime.dylib");
}
```

### 5.3 Release build 捆绑

GHA `release.yml` matrix 步骤加:

```yaml
- name: Download ORT prebuilt
  run: |
    ORT_VER=1.24.0
    case "${{ matrix.os }}" in
      windows-*) url="https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VER/onnxruntime-win-x64-$ORT_VER.zip"; archive=zip ;;
      ubuntu-*)  url="https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VER/onnxruntime-linux-x64-$ORT_VER.tgz"; archive=tgz ;;
      macos-*)   url="https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VER/onnxruntime-osx-universal2-$ORT_VER.tgz"; archive=tgz ;;
    esac
    curl -L -o ort.$archive "$url"
    mkdir -p dist/libs
    # ... 解压 lib/onnxruntime.(dll|so|dylib) → dist/libs/
```

### 5.4 License 合规

ONNX Runtime 是 **MIT License**(Microsoft),与 Vigil Apache-2.0/MIT dual 兼容。
Release 根 `THIRD-PARTY-LICENSES.md` 追加 ORT + Privacy Filter(Apache-2.0)两条。

## 6. 失败模式矩阵

| 失败场景 | 检测方法 | Vigil 行为 |
|---|---|---|
| 模型文件下载失败(网络断)| HTTP 超时 / 重试耗尽 | **降级硬指纹**;stderr 警告;审计事件 `model_download_failed`;下次启动重试 |
| 模型文件 SHA256 不匹配 | 下载完校验 | 删除缓存 + **降级硬指纹**;不重试(可能镜像被攻击);审计 `model_checksum_mismatch`(high severity)|
| `onnxruntime.dll` 缺失 | `ort::init` 返 Err | **降级硬指纹**;提示用户重装 Vigil;审计 `ort_native_lib_missing` |
| WebGPU 不支持(扩展)| `navigator.gpu` 检测 | 降级到 WASM CPU(慢但能跑);若连 WASM 也不支持 → 降级硬指纹 |
| 推理延迟超时(> 2s preflight 路径)| 内部 timer | **降级硬指纹**(此次 tool call);审计 `model_inference_timeout` |
| 用户禁用 T0(options)| 配置 flag | **只跑硬指纹**(明示选择)|

所有路径:**硬指纹层(v0.3 RULE_PROFILE_VERSION v4,13 类 FindingKind)永远在线**,作为最后一道 fail-closed 防线。

## 7. 版本化与更新路径

### 7.1 模型版本策略

- Privacy Filter 版本号跟 OpenAI upstream + Vigil 重打时间戳:
  `openai-privacy-filter@2026-04-24`(upstream)+ `vigil-mirror-20260424`(Vigil 镜像版)
- MODELS_MANIFEST.json 指向明确 version;用户缓存按 version 隔离
- **向前兼容**:老 Vigil 认不了新 manifest 的 model id → 降级硬指纹(不会崩)
- **向后兼容**:新 Vigil 可读老缓存(只要 SHA256 对得上)

### 7.2 更新触发

- 用户手动:`vigil-hub redaction update` CLI
- 自动:`vigil-hub start` 若 manifest 中标记了 `{check_update: true}` → 每 N 天查一次 Vigil mirror 的 manifest
- UI:桌面 GUI 的 `Settings → Model` 显示当前版本 + 可用更新

### 7.3 回滚

- 老版本缓存保留(最近 2 版);`vigil-hub redaction rollback <version>` 切换
- 极端情况(新模型发现 regression):manifest 可标记 `{recalled: true}` 强制用户切回上版本

## 8. 决策清单

| # | 决策 | 原因 |
|---|---|---|
| D1 | 选方案 C(首次运行下载 + 本地缓存) | 保 binary 尺寸 + 离线可用 + 便于独立更新权重 |
| D2 | Vigil mirror 为主通道,HF CDN 回源 | HF 限速实测不可控;ADR 0012 强制自建基建 |
| D3 | 选 q4f16(809 MB)为默认权重 | 尺寸/精度最佳折中;browser + desktop 共用 |
| D4 | ONNX Runtime 随 release tarball 捆,不用 `download-binaries` | 规避 `ort-sys` upstream ureq bug;可控 |
| D5 | 并发 byte-range split(16 chunks)下载 | 单线程实测不可接受;并发可缓解 CDN per-conn 限速 |
| D6 | 模型目录按 `{id}/{version}-{date}/` 隔离 | immutable 内容 + 按 SHA 命中缓存 + 支持多版本共存 |
| D7 | 失败路径一律 **降级硬指纹** 而非 fail-open | 零信任纪律;硬指纹 v0.3 RULE_PROFILE_VERSION v4 作最后防线 |
| D8 | 浏览器扩展走 HF CDN(不经 Vigil mirror)| Transformers.js 内部直查;复杂度换简洁 |
| D9 | tokenizer.json 28 MB 首次 parse ~860 ms | 扩展 Service Worker 冷启动付一次;接受为 UX 代价(命中缓存后即刻)|

## 9. Non-goals(本 ADR 明确不做)

- **模型训练 / 微调分发**:Vigil 不托管训练后的自定义 checkpoint 分发(用户自行管)
- **GPU 加速基建**:Stage 0/1 先 CPU + WebGPU(扩展);CUDA / DirectML / CoreML provider 留 Stage 2 后续 ADR
- **模型压缩 / 蒸馏**:q4f16 已经是 OpenAI 发布的最小档;Vigil 不再自己压
- **离线首装**:企业禁网环境可用 `vigil-hub redaction import /path/to/models.tar.gz` 离线导入;是 CLI 扩展功能,非本 ADR 核心
- **差分更新 / delta patch**:每版 ~800 MB 全量下载;delta 到 Stage 2+ 视用户规模再判

## 10. 与其他 ADR 的关系

| ADR | 关系 |
|---|---|
| ADR 0007(sandbox)| 模型下载/初始化路径不在 sandbox 内;推理进程走 Wasmtime 沙箱(Stage 4 ISS-020) |
| ADR 0009(Browser Extension)| 扩展侧 Transformers.js 路径在本 ADR §4 明确;扩展 3 档策略是 ISS-007 范畴 |
| ADR 0013(硬指纹 × 模型合并,将写)| 本 ADR 失败模式 §6 均降级硬指纹,为 0013 提供 runtime 证据 |
| ADR 0014(Tauri embed Hub,Stage 4)| embed 后模型初始化可走 Tauri 端主进程;本 ADR 的 `init_redaction_engine` 被 embed 接管 |

## 10.5 Revised(v0.6,2026-05-01)— Mirror Strategy 落定

**Status**: Implemented + Production(degraded primary,HF fallback active)
**Commits**: `82836fa`(注入)+ `6b96db0`(ops SOP)+ `08ea0ff`(smoke 实证)
**Codex review**: R1 ACCEPT(session `019ddf19-626a-7411`)

### 10.5.1 真 mirror 部署

- Domain: `vigils.ai`(A → vigils.ai)
- Box: vigils.ai(ens3 直绑公网 IPv4),Caddy 2.11.2 :80
- Path: `/srv/vigil-models/privacy-filter/v1/`
- Files(OpenAI Privacy Filter,Apache 2.0,4 文件)与 sha256 见
  `docs/operations/v0.6-mirror-deployment.md` § 5

### 10.5.2 Manifest schema 修补(3 → 4 文件)

v0.5 P2 placeholder schema 仅含 3 文件;v0.6 修补加第 4 文件
`model_q4f16.onnx_data`。理由:OpenAI Privacy Filter ONNX 用 external-data
格式,model_q4f16.onnx 仅含 graph(~ 162 KB),真权重在 .onnx_data
(~ 772 MB);ORT runtime 加载时同目录自动找。manifest 必须独立列出确保
bootstrap 下载完整。

### 10.5.3 Primary mirror activated(v0.6.1,2026-05-01)

**真根因**(经 sudo iptables 深入诊断):**不是云 SDN**。机器跑 k3s,Traefik
LoadBalancer service `traefik` EXTERNAL-IP 设到 `vigils.ai:80/443`,
kube-proxy 在 `nat PREROUTING KUBE-SERVICES` chain DNAT 到 traefik pod;但
该 cluster 0 个 IngressRoute,所有 :80/:443 进 traefik 后返 default 404。
机器内 Caddy listen :80 收不到流量(被 KUBE-SERVICES 抢先 DNAT)。

**解锁(v0.6.1)**:`nat PREROUTING` chain 顶部 INSERT 2 条 REDIRECT 规则,
优先于 KUBE-SERVICES,把 dst `vigils.ai:80/443` 直接 REDIRECT 到
host `:8088`(Caddy 切到 :8088 listen,与 traefik :80 共存)。详细命令 +
持久化方案见 `docs/operations/v0.6-mirror-deployment.md` § 解锁完成。

**实测(v0.6.1)**:
- 外部 curl `https://vigils.ai/healthz` → `200 + ok`
- 外部 curl 4 文件全 200 OK + sha256 MATCH manifest 真值
- `bootstrap_fallback_smoke` example: primary used directly(Caddy access log 显示
  16-chunk Range byte-range 并发下载真请求)

### 10.5.4 v0.7 carryforward(可选优化)

- HTTPS 化:`vigils.ai` 启 LE TLS-ALPN-01(现 inbound 已通,可签证);
  Caddy 切回 `vigils.ai { ... }` 自动 manage cert
- 健康检查 / monitoring:加 prometheus exporter 采集 Caddy + iptables hit count
- IngressRoute alternative:把 vigil-mirror 真 deploy 到 k3s pod + 加 IngressRoute
  让 traefik 反代(等 traefik 修复 k8s API 连接 timeout 问题)

不做的事(继承 v0.6 显式 deferred):
- Cloudflare Tunnel / ngrok / Tailscale Funnel(违反 0 第三方账号约束)
- Manifest 加 `mirror_pool` schema(YAGNI;`fallback_urls` 已足够)

---

## 11. 后续工作(交 Stage 1+ issue)

- **ISS-20260423-005**(vigil-redaction scaffold):实装 `load_or_degrade` 路径 + hard-fingerprint fallback ✅ Done(v0.4)
- **ISS-20260423-008**(真 Privacy Filter 模型接入):Rust 下载器(并发 range split,参考 ISS-001 Node PoC)+ SHA256 校验 + 缓存管理 ✅ Done(v0.5 P2)
- **ISS-20260423-009**(扩展 E2E):验 Transformers.js + IndexedDB 缓存 + 降级硬指纹路径 ✅ Done(v0.5 + v0.6 Phase 3-α-B)
- **Vigil mirror 基建**(非 code issue,运维):决定域名 / 选 CDN / 上传首版 + SHA256SUMS ✅ **Done(v0.6,本 ADR §10.5)**
- **Provider SDN 解锁** carryforward → v0.7

## 附录 A — ISS-001 实测数据(2026-04-24)

| 指标 | 值 |
|---|---|
| `model_q4f16.onnx_data` 大小 | 809 MB(HF 声称)|
| HF CDN 到测试环境单线程速率 | 3-6 MB/min |
| 16-chunk 并发目标速率 | 40-120 MB/min(预期)|
| `tokenizer.json` 大小 | 27,868,174 bytes(~28 MB)|
| tokenizer.json Rust parse 延迟 | 861 ms |
| config.json parse 延迟 | < 1 ms |
| encode/decode round-trip 延迟(12-24 tok) | 29-279 μs |
| id2label 类别数 | 33(O + 8 privacy × BIOES) |

## 附录 B — 反馈固化

1. **"下载用并发而非单线程"**(用户反馈,2026-04-24)
   - **Why**:单线程 HF CDN 到测试环境 3-6 MB/min,极不稳定
   - **How to apply**:所有 Vigil 侧模型/runtime lib 大文件下载 **必须** byte-range split 16+ chunks 并行;见 §3.6 + 附录 A

//! Bootstrap 错误类型(v0.5 P2 ADR 0012 first-run-download)。
//!
//! 与 [`crate::engine::EngineError`] 的 6 变体策略一致:**全部 fail-closed**,
//! caller 拿到任意变体都应让 vigil-hub serve 启动失败,**绝不**降级 NoopEngine。
//! 用户感知"已启用 Privacy Filter"但实际未生效是安全事故(详见 ADR 0012 §F-2)。
//!
//! 文案纪律:每个变体的 `#[error(...)]` Display 文本给出**运维可执行的下一步操作**
//! (清空目录 / 检查代理 / 释放磁盘空间),让 stderr banner 直接可读。

use std::path::PathBuf;
use thiserror::Error;

/// 模型 first-run-download 的全部失败模式。
///
/// 5 变体覆盖从 manifest 解析 → 网络可达性 → 磁盘空间 → 字节完整性的全链路。
/// 不持有 `reqwest::Error` 之外的非 `Send + Sync` 类型(reqwest 0.12 自身满足)。
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// 整文件 sha256 校验失败:本地落盘字节与 manifest 期望值不符。
    /// caller 应清空 target_dir 重启(本模块已主动删除产物,但目录仍可能含其它残留)。
    #[error(
        "sha256 mismatch: expected={expected} actual={actual}; \
         请清空 target_dir 重启 vigil-hub(本模块已自动删除产物文件)"
    )]
    Sha256Mismatch {
        /// manifest 声明的期望 sha256(hex,小写)
        expected: String,
        /// 本地实算 sha256(hex,小写)
        actual: String,
    },

    /// 单 chunk(byte-range)下载失败:HTTP 非 2xx / 3xx 或 transport-level 错误。
    /// 上层会自动按 fallback URL 重试一次;若所有 URL 都进入此分支再升级为 NetworkUnreachable。
    #[error(
        "download failed: url={url} status={status}: {source}; \
         请检查网络与镜像可达性"
    )]
    DownloadFailed {
        /// 失败的具体 URL(便于运维定位是 mirror 还是 CDN)
        url: String,
        /// HTTP 状态码;0 表示 transport 级错误(connection refused / timeout / DNS)
        status: u16,
        /// 底层 reqwest 错误链
        #[source]
        source: reqwest::Error,
    },

    /// 磁盘空间 / 写入权限失败(create_dir_all / 写 .partial.* / rename / sha256 read)。
    /// caller 应释放至少 500 MB 空间或换 target_dir(模型 weights ~800 MB + buffer)。
    #[error(
        "disk full or io error at {path}: {source}; \
         请释放至少 500 MB 空间或通过 VIGIL_PRIVACY_FILTER_MODEL_DIR 切目录"
    )]
    DiskFull {
        /// 失败的具体路径(target_dir / .partial.<idx> / 三件套文件之一)
        path: PathBuf,
        /// 底层 io 错误链
        #[source]
        source: std::io::Error,
    },

    /// Manifest JSON 解析失败:schema 不匹配 / 字段缺失 / 非法 JSON。
    /// v0.5 P2 placeholder_manifest 是 Rust struct 字面量,此分支主要为 v0.5.1
    /// 真 manifest URL 拉取后的 deserialize 失败留口子。
    #[error(
        "manifest parse failed: {source}; \
         请检查 manifest schema 是否与 vigil-redaction 版本兼容"
    )]
    ManifestParse {
        /// 底层 serde_json 错误链
        #[source]
        source: serde_json::Error,
    },

    /// 所有 mirror(primary + fallback)都不可达:HEAD 阶段连不上,或全部 DownloadFailed
    /// 用尽 retry。tried_urls 完整记录尝试列表,便于运维抓代理/防火墙问题。
    #[error(
        "all mirrors unreachable: tried {tried_urls:?}; \
         last_error={last_error}; 请检查代理/防火墙或离线分发模型包"
    )]
    NetworkUnreachable {
        /// 按尝试顺序记录的 URL 列表(primary first,fallback after)
        tried_urls: Vec<String>,
        /// 最后一次尝试的错误描述(reqwest::Error::to_string() 或 io::Error::to_string())
        last_error: String,
    },
}

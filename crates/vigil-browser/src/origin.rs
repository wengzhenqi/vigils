//! Origin 校验(ADR 0009 §D7 / §I-9.3)。
//!
//! Core 不维护产品 allowlist(站点授权由扩展 `optional_host_permissions` 管);
//! 但 fail-closed 拒绝特权 scheme。

use crate::protocol::BrowserErrorCode;

/// 返回 Ok(()) 表示 origin 合法 http/https 且是**纯 origin 形态**;否则返对应 error code。
///
/// **Codex R1 BLOCKER 修复**:仅接受规范化 `scheme://host[:port]`,拒绝:
/// - 特权 scheme(chrome-extension / file / devtools / chrome / about)
/// - 非 http/https scheme(javascript / data / blob 等)
/// - 带 userinfo(`https://user:pass@...`)
/// - 带 path(`https://x.com/foo` 含非空/非"/"路径)
/// - 带 query / fragment
/// - 空 host
///
/// 防扩展侧误传或恶意构造的 URL 被写入 audit / FTS(ADR §I-8.2 / §I-9.2)。
pub fn validate_browser_origin(origin: &str) -> Result<(), BrowserErrorCode> {
    // `url::Url::parse` 对 `about:` 会接受,故先做字面 scheme 黑名单
    const DENY_SCHEMES: &[&str] = &[
        "chrome-extension://",
        "file://",
        "devtools://",
        "chrome://",
        "about:",
    ];
    for s in DENY_SCHEMES {
        if origin.starts_with(s) {
            return Err(BrowserErrorCode::OriginDenied);
        }
    }
    let parsed = url::Url::parse(origin).map_err(|_| BrowserErrorCode::OriginDenied)?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(BrowserErrorCode::OriginDenied),
    }
    // 必须有非空 host(用 match 保 Rust 1.80 MSRV 兼容,不用 1.82+ 的 is_none_or)
    match parsed.host_str() {
        Some(h) if !h.is_empty() => {}
        _ => return Err(BrowserErrorCode::OriginDenied),
    }
    // 不得含 userinfo(url::Url::username 返空字符串表示无 userinfo)
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BrowserErrorCode::OriginDenied);
    }
    // 路径必须是空或 "/"(url crate 对无 path 的 origin 会默认补 "/")
    let path = parsed.path();
    if !(path.is_empty() || path == "/") {
        return Err(BrowserErrorCode::OriginDenied);
    }
    // 不得含 query / fragment
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(BrowserErrorCode::OriginDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_https_allowed() {
        assert!(validate_browser_origin("https://chatgpt.com").is_ok());
        assert!(validate_browser_origin("http://internal.corp:8080").is_ok());
    }

    #[test]
    fn chrome_extension_denied() {
        assert_eq!(
            validate_browser_origin("chrome-extension://abc/"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn file_scheme_denied() {
        assert_eq!(
            validate_browser_origin("file:///etc/passwd"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn devtools_denied() {
        assert_eq!(
            validate_browser_origin("devtools://foo/"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn chrome_internal_denied() {
        assert_eq!(
            validate_browser_origin("chrome://extensions"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn about_denied() {
        assert_eq!(
            validate_browser_origin("about:blank"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn garbage_denied() {
        assert_eq!(
            validate_browser_origin("not a url"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    /// Codex R1 BLOCKER 回归:带 query 的 URL 不是纯 origin,拒
    #[test]
    fn query_string_denied() {
        assert_eq!(
            validate_browser_origin("https://chatgpt.com/?token=ghp_xxx"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn path_denied() {
        assert_eq!(
            validate_browser_origin("https://chatgpt.com/path/to/resource"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn userinfo_denied() {
        assert_eq!(
            validate_browser_origin("https://user:pass@example.com"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn fragment_denied() {
        assert_eq!(
            validate_browser_origin("https://example.com#frag"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn trailing_slash_only_allowed() {
        // 扩展实际传 location.origin 会是 "https://example.com"(无斜杠);url crate parse
        // 后 path 会是 "/"。两种形态都应允许。
        assert!(validate_browser_origin("https://example.com").is_ok());
        assert!(validate_browser_origin("https://example.com/").is_ok());
    }

    #[test]
    fn empty_host_denied() {
        assert_eq!(
            validate_browser_origin("https://"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn javascript_scheme_denied() {
        assert_eq!(
            validate_browser_origin("javascript:alert(1)"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }

    #[test]
    fn data_scheme_denied() {
        assert_eq!(
            validate_browser_origin("data:text/html,hi"),
            Err(BrowserErrorCode::OriginDenied)
        );
    }
}

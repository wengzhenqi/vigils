//! Tool namespacing —— ADR 0004 §D4。
//!
//! 公开 tool 名约定 `<server_id>__<upstream_tool_name>`,`server_id` 必须是
//! `[a-z0-9_-]+`。

use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;
use thiserror::Error;

/// Namespacing 错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NamespaceError {
    /// server_id 不合法(必须是 `[a-z0-9_-]+`)
    #[error("invalid server_id: `{0}` (must match [a-z0-9_-]+)")]
    InvalidServerId(String),
    /// public name 解析失败(缺少 `__` 分隔)
    #[error("invalid public tool name: `{0}` (expected `<server>__<tool>`)")]
    InvalidPublicName(String),
    /// 已注册过同名 public tool(不同 server 冲突)
    #[error("duplicate public tool name: `{0}`")]
    Duplicate(String),
}

/// 一条路由映射。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRoute {
    /// 对 agent 暴露的 public 名
    pub public: String,
    /// 上游 server id
    pub server_id: String,
    /// 上游原始 tool 名
    pub upstream_tool_name: String,
    /// **本次 tools/list 聚合时**算出的该 tool 的 descriptor_hash。
    /// Hub 在 `tools/call` 时把它写入 `ToolInvocation.descriptor_hash`,
    /// 供 oracle 对比。I05 引入 drift 检测时,这里也是比较的锚点。
    pub descriptor_hash: String,
}

static SERVER_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9_-]+$").expect("regex"));

/// 校验一个 server_id 是否合法。
pub fn validate_server_id(server_id: &str) -> Result<(), NamespaceError> {
    if SERVER_ID_RE.is_match(server_id) {
        Ok(())
    } else {
        Err(NamespaceError::InvalidServerId(server_id.to_string()))
    }
}

/// 组装 public 名。
pub fn make_public(server_id: &str, tool: &str) -> Result<String, NamespaceError> {
    validate_server_id(server_id)?;
    Ok(format!("{server_id}__{tool}"))
}

/// 解析 public 名为 `(server, tool)`。
pub fn parse_public(public: &str) -> Result<(String, String), NamespaceError> {
    let idx = public
        .find("__")
        .ok_or_else(|| NamespaceError::InvalidPublicName(public.to_string()))?;
    if idx == 0 || idx + 2 >= public.len() {
        return Err(NamespaceError::InvalidPublicName(public.to_string()));
    }
    let (a, b) = public.split_at(idx);
    Ok((a.to_string(), b[2..].to_string()))
}

/// 内存路由表:Hub 在 `tools/list` 聚合时构建,`tools/call` 反向查找。
#[derive(Debug, Default, Clone)]
pub struct ToolRouter {
    by_public: HashMap<String, ToolRoute>,
}

impl ToolRouter {
    /// 注册一条路由;若同 public 名已存在且 (server, tool) 不同 → 冲突。
    /// `descriptor_hash` 为本次 tools/list 时算出的 per-tool hash。
    pub fn register(
        &mut self,
        server_id: &str,
        tool_name: &str,
        descriptor_hash: &str,
    ) -> Result<String, NamespaceError> {
        let public = make_public(server_id, tool_name)?;
        if let Some(existing) = self.by_public.get(&public) {
            if existing.server_id != server_id || existing.upstream_tool_name != tool_name {
                return Err(NamespaceError::Duplicate(public));
            }
            // 相同 server+tool 重复注册:幂等 no-op(但 hash 可能更新)
            // 若 hash 不一致,也仅更新自身;I05 drift 检测在 tools/list 入口判定。
        }
        self.by_public.insert(
            public.clone(),
            ToolRoute {
                public: public.clone(),
                server_id: server_id.to_string(),
                upstream_tool_name: tool_name.to_string(),
                descriptor_hash: descriptor_hash.to_string(),
            },
        );
        Ok(public)
    }

    /// 查找一条路由。
    pub fn resolve(&self, public: &str) -> Option<&ToolRoute> {
        self.by_public.get(public)
    }

    /// 列出全部 public 名(按字典序)。
    pub fn public_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self.by_public.keys().cloned().collect();
        v.sort();
        v
    }

    /// 条目数。
    pub fn len(&self) -> usize {
        self.by_public.len()
    }

    /// 是否空。
    pub fn is_empty(&self) -> bool {
        self.by_public.is_empty()
    }

    /// 按 server_id 清除全部路由(用于 I05 的 server revoke;I04 用于测试)。
    pub fn unregister_server(&mut self, server_id: &str) {
        self.by_public.retain(|_, r| r.server_id != server_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_server_id_accepts_simple() {
        for ok in ["fs", "github", "my-tool", "srv_1", "a", "01"] {
            assert!(validate_server_id(ok).is_ok(), "{} 应合法", ok);
        }
    }

    #[test]
    fn validate_server_id_rejects_invalid() {
        for bad in ["", "FS", "my.tool", "my/tool", "中文", "foo bar"] {
            assert!(validate_server_id(bad).is_err(), "{} 应非法", bad);
        }
    }

    #[test]
    fn parse_public_roundtrip() {
        let p = make_public("fs", "read_file").unwrap();
        assert_eq!(p, "fs__read_file");
        let (s, t) = parse_public(&p).unwrap();
        assert_eq!(s, "fs");
        assert_eq!(t, "read_file");
    }

    #[test]
    fn parse_public_rejects_no_separator() {
        assert!(parse_public("no_separator").is_err());
    }

    #[test]
    fn parse_public_handles_upstream_name_with_underscores() {
        let (s, t) = parse_public("github__create_issue").unwrap();
        assert_eq!(s, "github");
        assert_eq!(t, "create_issue");
    }

    #[test]
    fn router_register_and_resolve() {
        let mut r = ToolRouter::default();
        let p = r.register("fs", "read_file", "abc").unwrap();
        assert_eq!(p, "fs__read_file");
        assert_eq!(r.len(), 1);
        let route = r.resolve(&p).unwrap();
        assert_eq!(route.server_id, "fs");
        assert_eq!(route.upstream_tool_name, "read_file");
        assert_eq!(route.descriptor_hash, "abc");
    }

    #[test]
    fn router_rejects_cross_server_duplicate_public() {
        let mut r = ToolRouter::default();
        r.register("srv_a", "tool", "h1").unwrap();
        let p2 = r.register("srv_a", "tool", "h2").unwrap();
        assert_eq!(p2, "srv_a__tool");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn router_unregister_server_clears_routes() {
        let mut r = ToolRouter::default();
        r.register("fs", "read_file", "h1").unwrap();
        r.register("fs", "write_file", "h2").unwrap();
        r.register("github", "create_issue", "h3").unwrap();
        assert_eq!(r.len(), 3);
        r.unregister_server("fs");
        assert_eq!(r.len(), 1);
        assert_eq!(r.public_names(), vec!["github__create_issue"]);
    }

    /// parse_public 对 `server__tool__subtool` 的行为:从**首个** `__` 分隔,
    /// 余下整段(含内部 `__`)作为 tool 名。
    #[test]
    fn parse_public_splits_on_first_double_underscore() {
        let (s, t) = parse_public("github__create__issue").unwrap();
        assert_eq!(s, "github");
        assert_eq!(t, "create__issue");
    }
}

//! 静态 effect 目录(D26 #2 首切片)。
//!
//! 现有 7 个 [`EffectExtractor`](crate::extract) 只能从 **args 内容** 推断效应。对很多第三方
//! MCP server,风险由 **工具身份**(`github`/`create_issue`、`fetch`/`fetch`)而非 args 隐含 —
//! 此时 arg-extractor 产出空 `EffectVector`,策略无规则可匹配 → 命中 default-deny 地板 → 在 monitor
//! 姿态下地板被降级放行,审计记录显示"allowed, no effects"。这既是**漏分类**也是**可读性缺口**。
//!
//! 本目录作为**第 8 个 extractor**(`CatalogExtractor`),按 `(server hint, tool_name)` 为常见 server
//! 的工具**预置 baseline 效应**,在 7 个 arg-extractor **之前**跑,让它们在其上叠加具体路径/host。
//!
//! ## 不变量(fail-safe by construction)
//! - **单调**:`extract` 只**追加** `effects`、只把 `destructive` 置 true,从不清空/降级任何字段
//!   (遵守 [`EffectExtractor`] 合并契约)。故对任意输入 `effects_with_catalog ⊇ effects_without`、
//!   `destructive_with ≥ destructive_without` —— 目录只会**抬高**可见性/严重度,绝不掩盖真实效应。
//! - **不触碰 monitor 姿态**:目录只填 `EffectVector`(已随每次决策入账本 → 立即在审计可见);
//!   monitor 默认仍非阻断(地板降级 + Approve 自动放行不变),**不新增任何用户审批弹窗**(D14 教训)。
//!   只有 `--enforce` 消费这些更丰富的效应做真实风控 gating。
//! - **保守键控**:`server_id` 是用户自取别名(非包名)。首切片按 **tool_name 精确 + server_id 子串提示**
//!   匹配(零签名改动);误键最坏是**过分类**(在 monitor 仅多一条审计、在 enforce 可能多一次非阻断
//!   approve),不会漏分类。精确按"解析后的包/argv"键控留作后续硬化。

use vigil_types::{EffectKind, EffectVector, ToolInvocation};

use crate::extract::EffectExtractor;

/// 一条目录项:某类 server 的某个工具 → 其 baseline 效应。
struct CatalogEntry {
    /// `server_id` 子串提示(小写,任一命中即可;空 = 仅按 tool_name 匹配任意 server)。
    /// 用户给 server 取的别名千差万别("filesystem"/"fs"/"files"),故用一组宽松子串而非精确名。
    server_hints: &'static [&'static str],
    /// upstream `tool_name`,精确匹配。
    tool: &'static str,
    /// 该工具的 baseline 效应(会被 dedup 追加到 `EffectVector.effects`)。
    effects: &'static [EffectKind],
    /// 是否破坏性(delete/drop 等不可逆);只在明确无歧义时置 true。
    destructive: bool,
}

use EffectKind::{CommSend, DbRead, FsRead, FsWrite, NetOutbound, SecretUse};

/// 非破坏性条目的简写构造。
const fn e(
    server_hints: &'static [&'static str],
    tool: &'static str,
    effects: &'static [EffectKind],
) -> CatalogEntry {
    CatalogEntry {
        server_hints,
        tool,
        effects,
        destructive: false,
    }
}

/// 静态目录。**编译进签名二进制**(不走用户家目录可写的外部 JSON —— 那是可被篡改下调风险的攻击面)。
/// 故意保持**小而保守**:覆盖高流量、效应无歧义的官方 server;覆盖面随后续迭代增长。
static CATALOG: &[CatalogEntry] = &[
    // ── @modelcontextprotocol/server-filesystem(本地文件)──
    e(&["filesystem", "file", "fs"], "read_file", &[FsRead]),
    e(&["filesystem", "file", "fs"], "read_text_file", &[FsRead]),
    e(&["filesystem", "file", "fs"], "read_media_file", &[FsRead]),
    e(
        &["filesystem", "file", "fs"],
        "read_multiple_files",
        &[FsRead],
    ),
    e(&["filesystem", "file", "fs"], "list_directory", &[FsRead]),
    e(
        &["filesystem", "file", "fs"],
        "list_directory_with_sizes",
        &[FsRead],
    ),
    e(&["filesystem", "file", "fs"], "directory_tree", &[FsRead]),
    e(&["filesystem", "file", "fs"], "search_files", &[FsRead]),
    e(&["filesystem", "file", "fs"], "get_file_info", &[FsRead]),
    e(&["filesystem", "file", "fs"], "write_file", &[FsWrite]),
    e(&["filesystem", "file", "fs"], "edit_file", &[FsWrite]),
    e(
        &["filesystem", "file", "fs"],
        "create_directory",
        &[FsWrite],
    ),
    e(&["filesystem", "file", "fs"], "move_file", &[FsWrite]),
    // ── @modelcontextprotocol/server-fetch / 各类 http 取数 ──
    e(&["fetch", "http", "web"], "fetch", &[NetOutbound]),
    // ── @modelcontextprotocol/server-git(本地仓库)──
    e(&["git"], "git_status", &[FsRead]),
    e(&["git"], "git_log", &[FsRead]),
    e(&["git"], "git_diff", &[FsRead]),
    e(&["git"], "git_show", &[FsRead]),
    e(&["git"], "git_add", &[FsWrite]),
    e(&["git"], "git_commit", &[FsWrite]),
    // ── github MCP(远端 API,用 token 鉴权 → Net + Secret;写操作另含对外发布)──
    e(
        &["github"],
        "search_repositories",
        &[NetOutbound, SecretUse],
    ),
    e(&["github"], "get_file_contents", &[NetOutbound, SecretUse]),
    e(&["github"], "get_issue", &[NetOutbound, SecretUse]),
    e(&["github"], "list_issues", &[NetOutbound, SecretUse]),
    e(
        &["github"],
        "create_issue",
        &[NetOutbound, SecretUse, CommSend],
    ),
    e(
        &["github"],
        "create_pull_request",
        &[NetOutbound, SecretUse, CommSend],
    ),
    e(
        &["github"],
        "add_issue_comment",
        &[NetOutbound, SecretUse, CommSend],
    ),
    e(
        &["github"],
        "create_or_update_file",
        &[NetOutbound, SecretUse, CommSend],
    ),
    e(
        &["github"],
        "push_files",
        &[NetOutbound, SecretUse, CommSend],
    ),
    // ── brave-search ──
    e(&["brave"], "brave_web_search", &[NetOutbound, SecretUse]),
    e(&["brave"], "brave_local_search", &[NetOutbound, SecretUse]),
    // ── slack(对外发消息;用 token)──
    e(
        &["slack"],
        "slack_post_message",
        &[NetOutbound, SecretUse, CommSend],
    ),
    e(
        &["slack"],
        "slack_reply_to_thread",
        &[NetOutbound, SecretUse, CommSend],
    ),
    // ── @modelcontextprotocol/server-postgres(只读 query server)──
    e(&["postgres", "postgresql", "pg"], "query", &[DbRead]),
];

/// 基于静态目录、按工具身份(server hint + tool_name)预置 baseline 效应的 extractor。
///
/// 装配为 extractor #0(在 arg-extractor 之前),让后者叠加具体路径/host/secret-ref。
#[derive(Debug, Default)]
pub struct CatalogExtractor;

impl CatalogExtractor {
    /// 构造。无状态。
    pub fn new() -> Self {
        Self
    }
}

impl EffectExtractor for CatalogExtractor {
    fn name(&self) -> &'static str {
        "catalog"
    }

    fn extract(&self, call: &ToolInvocation, out: &mut EffectVector) {
        let server_lc = call.server_id.to_ascii_lowercase();
        for entry in CATALOG {
            if entry.tool != call.tool_name {
                continue;
            }
            // server hint:空 = 任意 server;否则要求 server_id 含任一提示子串。
            let server_ok = entry.server_hints.is_empty()
                || entry.server_hints.iter().any(|h| server_lc.contains(h));
            if !server_ok {
                continue;
            }
            // 合并契约:只追加(dedup),从不清空。engine 还有 dedup_effects 兜底。
            for &eff in entry.effects {
                if !out.effects.contains(&eff) {
                    out.effects.push(eff);
                }
            }
            // destructive 只置 true,从不下调。
            if entry.destructive {
                out.destructive = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn call(server_id: &str, tool_name: &str) -> ToolInvocation {
        ToolInvocation {
            invocation_id: "i".into(),
            session_id: "s".into(),
            server_id: server_id.into(),
            tool_name: tool_name.into(),
            args: json!({}),
            descriptor_hash: "h".into(),
            requested_at: 0,
        }
    }

    fn effects_of(server_id: &str, tool_name: &str) -> EffectVector {
        let mut ev = EffectVector::default();
        CatalogExtractor::new().extract(&call(server_id, tool_name), &mut ev);
        ev
    }

    #[test]
    fn filesystem_read_write_classified() {
        assert_eq!(effects_of("filesystem", "read_file").effects, vec![FsRead]);
        assert_eq!(effects_of("my-fs", "write_file").effects, vec![FsWrite]);
        // 别名 "files" 也命中 hint。
        assert_eq!(effects_of("files", "edit_file").effects, vec![FsWrite]);
    }

    #[test]
    fn github_write_is_net_secret_comm() {
        let ev = effects_of("github", "create_issue");
        assert!(ev.effects.contains(&NetOutbound));
        assert!(ev.effects.contains(&SecretUse));
        assert!(ev.effects.contains(&CommSend));
        // 读操作无 CommSend。
        let r = effects_of("github", "get_issue");
        assert!(r.effects.contains(&NetOutbound) && !r.effects.contains(&CommSend));
    }

    #[test]
    fn unknown_tool_or_server_no_effect() {
        // 未知工具 → 不改。
        assert!(effects_of("filesystem", "totally_unknown_tool")
            .effects
            .is_empty());
        // tool 名匹配但 server hint 不匹配 → 不改(write_file 在一个与 fs 无关的 server 上)。
        assert!(effects_of("weather-api", "write_file").effects.is_empty());
    }

    #[test]
    fn monotonic_append_only_never_clears() {
        // 预置已有效应 + 路径,extract 后既不清空、只追加、destructive 只增不减。
        let mut ev = EffectVector {
            effects: vec![EffectKind::SecretUse],
            paths_write: vec!["/x".into()],
            destructive: true,
            ..Default::default()
        };
        CatalogExtractor::new().extract(&call("filesystem", "write_file"), &mut ev);
        assert!(ev.effects.contains(&EffectKind::SecretUse)); // 原有保留
        assert!(ev.effects.contains(&FsWrite)); // 追加
        assert_eq!(ev.paths_write, vec!["/x".to_string()]); // 其它字段不动
        assert!(ev.destructive); // 不被下调
    }

    #[test]
    fn dedup_within_extractor() {
        // 同一效应已存在时不重复追加。
        let mut ev = EffectVector {
            effects: vec![FsRead],
            ..Default::default()
        };
        CatalogExtractor::new().extract(&call("filesystem", "read_file"), &mut ev);
        assert_eq!(ev.effects, vec![FsRead]);
    }
}

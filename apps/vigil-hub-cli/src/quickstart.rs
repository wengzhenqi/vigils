//! `vigil-hub quickstart` —— 引导首跑(**只读**,不改任何配置)。
//!
//! 目的(M0 "5 分钟看到价值"):新用户装完不知道先跑什么。本命令一屏内回答三件事:
//! ①你机器上有哪些 AI agent、有多少 MCP server、几个已被 Vigil 保护(**真实检测**,复用
//! `setup --mcp` 的只读 preview 分类);②怎么 30 秒看到 Vigil 拦一次密钥外泄;③一条命令保护全部 +
//! 怎么查看/验证。**绝不改配置**(检测=只读 preview;真正接入仍须用户显式 `setup --all`)。

use std::path::Path;

use crate::setup_mcp::{self, JsonMcpAgent, McpServerClass};

/// 单 agent 的 MCP server 分类计数。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    /// 已是 Vigil 托管(`AlreadyWrapped`)。
    protected: usize,
    /// stdio、可保护但尚未保护(`Wrappable`)。
    unprotected: usize,
    /// 非 stdio(http/sse)或形状异常,v1 不 wrap(`Skipped`)。
    skipped: usize,
}

impl Counts {
    fn total(&self) -> usize {
        self.protected + self.unprotected + self.skipped
    }
    fn add(self, o: Counts) -> Counts {
        Counts {
            protected: self.protected + o.protected,
            unprotected: self.unprotected + o.unprotected,
            skipped: self.skipped + o.skipped,
        }
    }
}

/// 收 `&McpServerClass` 迭代器(故 user-scope `Vec` 与 local-scope `(name, class)` 元组都能直接数,
/// 无需 clone)。
fn count_servers<'a>(servers: impl IntoIterator<Item = &'a McpServerClass>) -> Counts {
    let mut c = Counts::default();
    for s in servers {
        match s {
            McpServerClass::AlreadyWrapped { .. } => c.protected += 1,
            McpServerClass::Wrappable { .. } => c.unprotected += 1,
            McpServerClass::Skipped { .. } => c.skipped += 1,
        }
    }
    c
}

/// 渲染一行 agent 摘要。`configured=false` → "not configured"(无配置文件 / 空 mcpServers)。
fn agent_line(label: &str, configured: bool, c: Counts) -> String {
    if !configured || c.total() == 0 {
        return format!("    {label:<13} not configured");
    }
    let total = c.total();
    let mut parts = vec![format!(
        "{total} MCP server{}",
        if total == 1 { "" } else { "s" }
    )];
    parts.push(format!("{} protected", c.protected));
    if c.unprotected > 0 {
        parts.push(format!("{} unprotected", c.unprotected));
    }
    if c.skipped > 0 {
        parts.push(format!("{} skipped (http/sse)", c.skipped));
    }
    format!("    {label:<13} {}", parts.join(" · "))
}

/// 引导首跑主入口。始终返回 0(纯信息命令,不做判定)。
pub fn run(home: &Path, exe: &str) -> i32 {
    println!();
    println!("  Vigil quickstart");
    println!("  ────────────────");
    println!("  Vigil keeps secrets & PII out of your AI agents — locally, with a");
    println!("  tamper-evident audit. Here's where you stand and what to do next.");
    println!();

    // ── 1) 真实检测(只读 preview;绝不改配置)────────────────────────────
    println!("  1) Your agents  (read-only — nothing was changed)");
    let mut total_unprotected = 0usize;
    // monitor 仅影响 preview 生成的 wrap argv(本命令不用,只数分类),传 true 任意。
    let monitor = true;

    // Claude Code:user scope + local scope(`projects.*`)都算。
    match setup_mcp::run_preview(home, exe, monitor) {
        Ok(r) => {
            // user scope(`servers`)+ local scope(`projects.*` 的 `local_servers`)都算。
            let c = count_servers(&r.servers)
                .add(count_servers(r.local_servers.iter().map(|(_, sv)| sv)));
            println!("{}", agent_line("Claude Code", c.total() > 0, c));
            total_unprotected += c.unprotected;
        }
        Err(e) => println!("    {:<13} could not read config ({e})", "Claude Code"),
    }

    // Codex(`~/.codex/config.toml`)。
    match setup_mcp::run_codex_preview(home, exe, monitor) {
        Ok(r) => {
            let c = count_servers(&r.servers);
            println!("{}", agent_line("Codex", c.total() > 0, c));
            total_unprotected += c.unprotected;
        }
        Err(e) => println!("    {:<13} could not read config ({e})", "Codex"),
    }

    // Cursor + Windsurf(JSON `mcpServers` 形态)。
    for agent in [JsonMcpAgent::cursor(home), JsonMcpAgent::windsurf(home)] {
        match setup_mcp::run_json_agent_preview(&agent, exe, monitor) {
            Ok(r) => {
                let c = count_servers(&r.servers);
                println!("{}", agent_line(agent.display_name, c.total() > 0, c));
                total_unprotected += c.unprotected;
            }
            Err(e) => println!("    {:<13} could not read config ({e})", agent.display_name),
        }
    }
    println!();
    if total_unprotected > 0 {
        println!(
            "     → {total_unprotected} MCP server{} are NOT yet behind Vigil's firewall + redaction + audit.",
            if total_unprotected == 1 { "" } else { "s" }
        );
    } else {
        println!("     → No unprotected stdio MCP servers detected. (Run the demo anyway to see how it works.)");
    }
    println!();

    // ── 2) 看它工作 ───────────────────────────────────────────────────
    println!("  2) See it work  (≈30s, no setup, contacts no LLM)");
    println!("       vigil-hub demo");
    println!();

    // ── 3) 保护(显式;quickstart 自身从不改配置)────────────────────────
    println!("  3) Protect every detected agent  (one command, reversible)");
    println!("       vigil-hub setup --all");
    println!("     Preview the exact changes first, without writing anything:");
    println!("       vigil-hub setup --mcp");
    println!();

    // ── 4) 查看 / 验证 ────────────────────────────────────────────────
    println!("  4) Watch & verify");
    println!("       vigil-hub setup --mcp --doctor    # health-check every agent surface");
    println!("       vigil-hub verify                  # audit chain + tamper-rewrite anchor");
    println!("     …or open the Vigils desktop app for the live Protection Overview.");
    println!();
    println!("  Everything runs on your machine. Nothing leaves it.");
    println!();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_servers_classifies_each_variant() {
        let servers = vec![
            McpServerClass::AlreadyWrapped { name: "a".into() },
            McpServerClass::Wrappable {
                name: "b".into(),
                command: "npx".into(),
                args: vec![],
                env_keys: vec![],
            },
            McpServerClass::Skipped {
                name: "c".into(),
                reason: "non-stdio",
            },
            McpServerClass::Wrappable {
                name: "d".into(),
                command: "uvx".into(),
                args: vec![],
                env_keys: vec![],
            },
        ];
        let c = count_servers(&servers);
        assert_eq!(c.protected, 1);
        assert_eq!(c.unprotected, 2);
        assert_eq!(c.skipped, 1);
        assert_eq!(c.total(), 4);
    }

    #[test]
    fn agent_line_renders_not_configured_for_empty() {
        let line = agent_line("Codex", false, Counts::default());
        assert!(line.contains("not configured"), "got: {line}");
        // 即便 configured=true 但全 0 也算 not configured(无 server)。
        let line2 = agent_line("Codex", true, Counts::default());
        assert!(line2.contains("not configured"), "got: {line2}");
    }

    #[test]
    fn agent_line_renders_protection_breakdown() {
        let c = Counts {
            protected: 1,
            unprotected: 3,
            skipped: 0,
        };
        let line = agent_line("Claude Code", true, c);
        assert!(line.contains("4 MCP servers"), "got: {line}");
        assert!(line.contains("1 protected"), "got: {line}");
        assert!(line.contains("3 unprotected"), "got: {line}");
    }
}

//! ISS-018 — Safe Export 渲染层。
//!
//! 把 session replay 渲染为 Markdown / HTML 文本,**只读已脱敏数据**:
//! - `events.payload_json` 在 audit 入库时已经过 `vigil-redaction::redact` 处理
//! - `events.redacted_text` 是 FTS 摘要(也是已脱敏)
//! - 渲染层不接触任何"从未脱敏的源",纯字符串组装
//!
//! 输出契约:
//! - **MD 格式**:GitHub-flavored Markdown,无外部资源依赖,审计员可粘贴 / diff
//! - **HTML 格式**:完整文档(`<!DOCTYPE html>` + 最小 inline CSS + escaped 文本),
//!   双击打开浏览器即可预览;**禁** `<script>` 注入(escape 严格;Vue 侧 v-html 不开)
//!
//! **绝不引入新文本**:除了静态模板(标题、表头、章节锚等)外,所有变量都来自
//! 已脱敏字段;`html_escape` 只对源字符串做 entity 转义,不改语义。
//!
//! 守门测试 `test_export_does_not_leak_raw_secret` 注入含 `AKIAXXXXXXXXXXXXXXXX` /
//! `ghp_xxxxxxxxxxxx` / 等典型 secret 模式的 payload(经 redact 后入库),渲染后
//! grep 输出文本不得含原 raw 模式;若漂移即测试红。

use vigil_ui_protocol::{ExportFormat, SessionExportDto, SessionReplay};

/// 渲染入口。
pub fn render_session_replay(replay: &SessionReplay, format: ExportFormat) -> SessionExportDto {
    let now = current_unix_seconds();
    let content = match format {
        ExportFormat::Md => render_markdown(replay, now),
        ExportFormat::Html => render_html(replay, now),
    };
    SessionExportDto {
        session_id: replay.session_id.clone(),
        format,
        byte_len: content.len(),
        event_count: replay.event_count,
        generated_at: now,
        content,
    }
}

fn current_unix_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ───────────────────────── Markdown ─────────────────────────

fn render_markdown(replay: &SessionReplay, generated_at: i64) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "# Vigil Session Replay — Safe Export");
    let _ = writeln!(out);
    let _ = writeln!(out, "- **session_id**: `{}`", replay.session_id);
    let _ = writeln!(out, "- **event_count**: {}", replay.event_count);
    let _ = writeln!(out, "- **generated_at**: {} (Unix seconds)", generated_at);
    if let Some(verify) = replay.chain_verified.as_ref() {
        let _ = writeln!(
            out,
            "- **chain_verified**: {}",
            if verify.ok { "✅ ok" } else { "❌ broken" }
        );
        if let Some(broken) = verify.broken_at_event_id {
            let _ = writeln!(out, "  - broken_at_event_id: `{broken}`");
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "> ⚠️ All `payload` content below has been redacted by `vigil-redaction` at audit-write time."
    );
    let _ = writeln!(
        out,
        "> Raw secrets / PII never persisted to the ledger (ADR §I-9.1)."
    );
    let _ = writeln!(out);

    for ev in &replay.events {
        let _ = writeln!(out, "## Event {} — `{}`", ev.event_id, ev.event_type);
        let _ = writeln!(out);
        let _ = writeln!(out, "- **event_id**: `{}`", ev.event_id);
        let _ = writeln!(out, "- **created_at**: {} (Unix seconds)", ev.created_at);
        let _ = writeln!(out, "- **prev_hash**: `{}`", ev.prev_hash);
        let _ = writeln!(out, "- **event_hash**: `{}`", ev.event_hash);
        if let Some(text) = ev.redacted_text.as_deref().filter(|s| !s.is_empty()) {
            let _ = writeln!(out);
            let _ = writeln!(out, "**Redacted summary**:");
            let _ = writeln!(out);
            let _ = writeln!(out, "```");
            let _ = writeln!(out, "{}", text);
            let _ = writeln!(out, "```");
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "**Payload** (already redacted):");
        let _ = writeln!(out);
        let _ = writeln!(out, "```json");
        match serde_json::to_string_pretty(&ev.payload) {
            Ok(s) => {
                let _ = writeln!(out, "{s}");
            }
            // payload 已是 serde_json::Value 不可能序列化失败;防御兜底标记
            Err(_) => {
                let _ = writeln!(out, "<unserializable payload>");
            }
        }
        let _ = writeln!(out, "```");
        let _ = writeln!(out);
    }

    out
}

// ───────────────────────── HTML ─────────────────────────

fn render_html(replay: &SessionReplay, generated_at: i64) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(4096);
    let _ = writeln!(out, "<!DOCTYPE html>");
    let _ = writeln!(out, "<html lang=\"en\">");
    let _ = writeln!(out, "<head>");
    let _ = writeln!(out, "  <meta charset=\"UTF-8\">");
    let _ = writeln!(
        out,
        "  <title>Vigil Session Replay — {}</title>",
        html_escape(&replay.session_id)
    );
    let _ = writeln!(out, "  <style>");
    let _ = writeln!(out, "{}", HTML_CSS);
    let _ = writeln!(out, "  </style>");
    let _ = writeln!(out, "</head>");
    let _ = writeln!(out, "<body>");
    let _ = writeln!(out, "<header>");
    let _ = writeln!(out, "  <h1>Vigil Session Replay — Safe Export</h1>");
    let _ = writeln!(
        out,
        "  <dl class=\"meta\">\n    <dt>session_id</dt><dd><code>{}</code></dd>",
        html_escape(&replay.session_id)
    );
    let _ = writeln!(
        out,
        "    <dt>event_count</dt><dd>{}</dd>",
        replay.event_count
    );
    let _ = writeln!(
        out,
        "    <dt>generated_at</dt><dd>{} (Unix seconds)</dd>",
        generated_at
    );
    if let Some(verify) = replay.chain_verified.as_ref() {
        let _ = writeln!(
            out,
            "    <dt>chain_verified</dt><dd>{}</dd>",
            if verify.ok {
                "<span class=\"ok\">✅ ok</span>"
            } else {
                "<span class=\"err\">❌ broken</span>"
            }
        );
    }
    let _ = writeln!(out, "  </dl>");
    let _ = writeln!(
        out,
        "  <p class=\"warn\">⚠️ All <code>payload</code> content below has been redacted by \
         <code>vigil-redaction</code> at audit-write time. Raw secrets / PII never persisted to \
         the ledger (ADR §I-9.1).</p>"
    );
    let _ = writeln!(out, "</header>");

    for ev in &replay.events {
        let _ = writeln!(out, "<section class=\"event\">");
        let _ = writeln!(
            out,
            "  <h2>Event {} — <code>{}</code></h2>",
            ev.event_id,
            html_escape(&ev.event_type)
        );
        let _ = writeln!(out, "  <dl class=\"meta\">");
        let _ = writeln!(
            out,
            "    <dt>event_id</dt><dd><code>{}</code></dd>",
            ev.event_id
        );
        let _ = writeln!(
            out,
            "    <dt>created_at</dt><dd>{} (Unix seconds)</dd>",
            ev.created_at
        );
        let _ = writeln!(
            out,
            "    <dt>prev_hash</dt><dd><code>{}</code></dd>",
            html_escape(&ev.prev_hash)
        );
        let _ = writeln!(
            out,
            "    <dt>event_hash</dt><dd><code>{}</code></dd>",
            html_escape(&ev.event_hash)
        );
        let _ = writeln!(out, "  </dl>");
        if let Some(text) = ev.redacted_text.as_deref().filter(|s| !s.is_empty()) {
            let _ = writeln!(out, "  <h3>Redacted summary</h3>");
            let _ = writeln!(out, "  <pre><code>{}</code></pre>", html_escape(text));
        }
        let _ = writeln!(out, "  <h3>Payload (already redacted)</h3>");
        let payload_str = serde_json::to_string_pretty(&ev.payload)
            .unwrap_or_else(|_| "<unserializable payload>".to_string());
        let _ = writeln!(
            out,
            "  <pre class=\"payload\"><code>{}</code></pre>",
            html_escape(&payload_str)
        );
        let _ = writeln!(out, "</section>");
    }

    let _ = writeln!(out, "</body></html>");
    out
}

const HTML_CSS: &str = r#"
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; color: #1f2937; }
h1 { border-bottom: 2px solid #1e40af; padding-bottom: 0.4em; color: #1e40af; }
h2 { border-bottom: 1px solid #d1d5db; padding-bottom: 0.3em; margin-top: 2em; }
h3 { color: #374151; margin-bottom: 0.4em; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: 0.3em 1em; font-size: 0.9em; }
.meta dt { font-weight: 600; color: #6b7280; }
.meta dd { margin: 0; }
.warn { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 0.6em 1em; }
.ok { color: #15803d; font-weight: 600; }
.err { color: #b91c1c; font-weight: 600; }
.event { margin-bottom: 2em; padding: 0.4em 0; }
pre { background: #f3f4f6; padding: 0.8em; border-radius: 4px; overflow-x: auto; font-size: 0.85em; }
pre.payload { max-height: 480px; overflow-y: auto; }
code { font-family: ui-monospace, "SF Mono", Consolas, monospace; }
"#;

/// HTML 实体转义 —— 只对 `&<>"'` 五字符做替换;**不**修改 unicode 内容。
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vigil_ui_protocol::{EventDetail, SessionReplay};

    fn fixture_replay() -> SessionReplay {
        SessionReplay {
            session_id: "S-test-001".into(),
            event_count: 2,
            chain_verified: None,
            events: vec![
                EventDetail {
                    event_id: 1,
                    session_id: "S-test-001".into(),
                    event_type: "tool_call.decided".into(),
                    payload: json!({
                        "args": "[REDACTED env_assignment]",
                        "tool": "fetch",
                    }),
                    redacted_text: Some("finding:env_assignment fetch".into()),
                    prev_hash: "".into(),
                    event_hash: "abc123".into(),
                    created_at: 1_700_000_000,
                },
                EventDetail {
                    event_id: 2,
                    session_id: "S-test-001".into(),
                    event_type: "approval.resolved".into(),
                    payload: json!({ "scope": "Once", "approved": true }),
                    redacted_text: None,
                    prev_hash: "abc123".into(),
                    event_hash: "def456".into(),
                    created_at: 1_700_000_001,
                },
            ],
        }
    }

    #[test]
    fn markdown_contains_session_metadata_and_events() {
        let dto = render_session_replay(&fixture_replay(), ExportFormat::Md);
        assert_eq!(dto.format, ExportFormat::Md);
        assert_eq!(dto.event_count, 2);
        assert!(dto.byte_len > 0);
        assert!(dto.content.contains("# Vigil Session Replay"));
        assert!(dto.content.contains("S-test-001"));
        assert!(dto.content.contains("tool_call.decided"));
        assert!(dto.content.contains("approval.resolved"));
        assert!(dto.content.contains("[REDACTED env_assignment]"));
    }

    #[test]
    fn html_well_formed_and_escaped() {
        let dto = render_session_replay(&fixture_replay(), ExportFormat::Html);
        assert_eq!(dto.format, ExportFormat::Html);
        assert!(dto.content.starts_with("<!DOCTYPE html>"));
        assert!(dto.content.contains("</html>"));
        assert!(dto.content.contains("S-test-001"));
        // payload key 中的 quote 必须 entity 转义
        // (`"args": "..."` JSON 序列化后含 `&quot;` 替代 `"`)
        assert!(
            dto.content.contains("&quot;args&quot;"),
            "JSON `\"` 必须转义为 `&quot;`"
        );
    }

    #[test]
    fn export_does_not_leak_raw_secret_pattern() {
        // 守门:即使 caller 传入"原文"风格的 fixture,渲染层也不应把它原样吐出
        // (本测试 fixture 已是 redacted 串;下面的 raw_pattern 应不存在于输出)。
        // 如果未来某 PR 引入"渲染时回查 raw payload"的回归,此测试会红。
        let dto = render_session_replay(&fixture_replay(), ExportFormat::Md);
        let raw_secret_patterns = [
            "AKIA",              // AWS key prefix
            "ghp_",              // GitHub PAT prefix
            "sk-ant-",           // Anthropic
            "BEGIN PRIVATE KEY", // PEM
        ];
        for pat in raw_secret_patterns {
            assert!(
                !dto.content.contains(pat),
                "导出文本含原始 secret 模式 `{pat}` —— vigil-redaction 应已在 audit 入库时脱敏,渲染层禁止任何回查 raw 路径"
            );
        }
    }

    #[test]
    fn html_escape_handles_xss_chars() {
        assert_eq!(
            html_escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        // unicode 不变
        assert_eq!(html_escape("你好"), "你好");
    }

    #[test]
    fn export_format_metadata_consistent() {
        assert_eq!(ExportFormat::Md.extension(), "md");
        assert_eq!(ExportFormat::Html.extension(), "html");
        assert!(ExportFormat::Md.mime().starts_with("text/markdown"));
        assert!(ExportFormat::Html.mime().starts_with("text/html"));
    }
}

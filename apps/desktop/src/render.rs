//! UiResponse → 文本(stdout)渲染层。
//!
//! I08a 采用结构化 JSON 输出作为**权威表达**(机器可解析 + 测试友好),
//! 人类可读的 ANSI 卡片延到 I08c。stdout 行级输出:
//! - 一行 JSON(`serde_json::to_string`)per response
//! - stderr 只放错误摘要,不混 stdout
//!
//! 这让 §12.3 I08 CLI 闭环:`vigil-desktop ... | jq` 可用,集成测试亦简单。

use std::io::{self, Write};

use vigil_ui_protocol::{UiError, UiResponse};

/// 把 Response 写 stdout(单行 JSON + newline)。
pub fn print_response<W: Write>(w: &mut W, resp: &UiResponse) -> io::Result<()> {
    // serde_json::to_string 已是脱敏数据的再编码,不产生新 secret 泄漏面
    let line = serde_json::to_string(resp).unwrap_or_else(|_| r#"{"kind":"Ack"}"#.to_string());
    writeln!(w, "{line}")
}

/// 把 Error 写 stderr(单行 JSON)。
pub fn print_error<W: Write>(w: &mut W, err: &UiError) -> io::Result<()> {
    let line = serde_json::to_string(err).unwrap_or_else(|_| "{}".to_string());
    writeln!(w, "{line}")
}

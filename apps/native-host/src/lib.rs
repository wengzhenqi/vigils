//! Vigil Native Messaging Host —— lib 层:纯 I/O 循环供集成测试直接调。
//!
//! bin 入口在 `main.rs`:打开默认 Ledger 路径,调用 `run(stdin, stdout, ledger, session)`。
//! 集成测试在 `tests/` 中注入 `Cursor<Vec<u8>>` 作 stdin / stdout,验证 framing + 分类器 + 审计。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod install;

/// β1 R1 BLOCKER 修复:判断 argv[1] 是否是管理员 CLI 子命令字面量。
///
/// Chrome 启动 Native Host 时会传 argv(Linux/macOS:`argv[1] = <extension origin>`,
/// Windows 额外 `argv[2] = --parent-window=<HWND>`)。若这些被 clap 解析,会判为未知 subcommand
/// 以 exit 2 退出,扩展看到 onDisconnect。本函数**仅** 返回 true 对白名单子命令字面量,
/// 其它(含无参 / Chrome origin / --parent-window / 任意未识别 argv)返 false → caller 直走
/// stdin/stdout run 循环。
///
/// 本函数是纯函数,接受 `argv` 作参数(`main()` 传 `std::env::args().collect::<Vec<_>>()`)。
/// 单测覆盖 Chrome 真实 argv 场景 + 管理员子命令场景,守门"Chrome 启动路径不被 clap 吃"。
pub fn is_admin_subcommand(args: &[String]) -> bool {
    args.get(1)
        .map(|s| {
            matches!(
                s.as_str(),
                "install" | "uninstall" | "status" | "help" | "--help" | "-h" | "--version" | "-V"
            )
        })
        .unwrap_or(false)
}

use std::io::{Read, Write};

use vigil_audit::Ledger;
use vigil_browser::{
    build_audit_payload, classify, event_type_for, read_frame, write_frame, BrowserAuditMeta,
    BrowserCheckRequest, BrowserErrorCode, BrowserErrorFrame, ClassifyOutcome,
};

/// 主循环:反复 read_frame → 分类 → write_frame;返 `()` 表示正常 EOF。
///
/// 任何协议错都以 `BrowserErrorFrame` 形式回写给 peer,**不**让错误冒泡到
/// stdout raw bytes(Chrome native messaging 一旦 stdout 写坏就会断连接)。
pub fn run<R: Read, W: Write>(
    stdin: &mut R,
    stdout: &mut W,
    ledger: &Ledger,
    session_id: &str,
) -> Result<(), std::io::Error> {
    loop {
        match read_frame(stdin) {
            Ok(Some(payload)) => {
                handle_one(&payload, stdout, ledger, session_id)?;
            }
            Ok(None) => return Ok(()), // 扩展断开
            Err(code) => {
                // Codex R1 MUST-FIX:protocol-level 错(TooLarge / Internal)**视为致命**,
                // 必须断开连接。不能继续 loop:若 peer 真发了 oversized frame 完整 body,
                // 后续字节会被误判为新帧的 length prefix,连接进入永久乱序。
                write_error(stdout, code, None)?;
                return Ok(());
            }
        }
    }
}

fn handle_one<W: Write>(
    payload: &[u8],
    stdout: &mut W,
    ledger: &Ledger,
    session_id: &str,
) -> Result<(), std::io::Error> {
    // 解析请求
    let req: BrowserCheckRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(_) => {
            return write_error(stdout, BrowserErrorCode::BadJson, None);
        }
    };

    // 分类
    match classify(&req) {
        ClassifyOutcome::Error(code) => {
            write_error(stdout, code, Some(req.request_id.clone()))?;
        }
        ClassifyOutcome::Response(resp) => {
            // 审计(metadata only)—— 用 `BrowserAuditMeta` 接口边界编码"不得含 raw text"
            let meta = BrowserAuditMeta {
                origin: &req.origin,
                event_kind: req.event_kind,
                request_id: &req.request_id,
                text_len: req.text.len(),
            };
            let audit_payload = build_audit_payload(&meta, &resp);
            let event_type = event_type_for(req.event_kind);
            // redacted_text 仅作 FTS 提示;不含原文
            let fts = format!(
                "{} origin:{} action:{}",
                event_type, req.origin, audit_payload["action"]
            );
            let _ = ledger.append_event(session_id, event_type, &audit_payload, Some(&fts));

            // 回写 response
            let body = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{}".to_vec());
            if let Err(code) = write_frame(stdout, &body) {
                return write_error(stdout, code, Some(req.request_id));
            }
        }
    }
    Ok(())
}

fn write_error<W: Write>(
    stdout: &mut W,
    code: BrowserErrorCode,
    request_id: Option<String>,
) -> Result<(), std::io::Error> {
    let frame = BrowserErrorFrame {
        error: code,
        request_id,
    };
    let body = serde_json::to_vec(&frame).unwrap_or_else(|_| b"{}".to_vec());
    let _ = write_frame(stdout, &body); // 忽略 framing 失败(stdout 已坏也无能为力)
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════════
// 单元测试(clippy::items-after-test-module 要求测试 module 在文件最底部)
// ═══════════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod argv_dispatch_tests {
    use super::is_admin_subcommand;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_args_goes_to_run() {
        // 手工无参启动(非 Chrome 场景;走 run 循环)
        assert!(!is_admin_subcommand(&argv(&["vigil-native-host"])));
    }

    #[test]
    fn chrome_origin_argv_goes_to_run() {
        // Chrome 实际传 extension origin 作 argv[1](Linux/macOS)
        assert!(!is_admin_subcommand(&argv(&[
            "vigil-native-host",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        ])));
    }

    #[test]
    fn chrome_windows_argv_with_parent_window_goes_to_run() {
        // Windows 额外 --parent-window;argv[1] 仍是 origin,本函数只看 argv[1]
        assert!(!is_admin_subcommand(&argv(&[
            "vigil-native-host.exe",
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            "--parent-window=12345",
        ])));
    }

    #[test]
    fn admin_subcommands_are_recognized() {
        for cmd in ["install", "uninstall", "status", "help"] {
            assert!(
                is_admin_subcommand(&argv(&["vigil-native-host", cmd])),
                "{cmd} should be recognized as admin subcommand"
            );
        }
    }

    #[test]
    fn clap_help_flags_are_recognized() {
        for flag in ["--help", "-h", "--version", "-V"] {
            assert!(
                is_admin_subcommand(&argv(&["vigil-native-host", flag])),
                "{flag} should be recognized"
            );
        }
    }

    #[test]
    fn unknown_flags_and_subcommands_go_to_run() {
        // 防御:未来 Chrome 加新 argv 风格,或其它未预期输入,一律 fallback run
        for bad in [
            "--unknown-flag",
            "install-something",
            "--parent-window=99",
            "chrome-extension://short/",
            "run",
        ] {
            assert!(
                !is_admin_subcommand(&argv(&["vigil-native-host", bad])),
                "{bad} should NOT be recognized as admin subcommand (fallback run)"
            );
        }
    }
}

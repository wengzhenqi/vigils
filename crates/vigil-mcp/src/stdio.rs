//! Upstream stdio 子进程适配器(ADR 0004 §D2)。
//!
//! 每个上游 MCP server 在 Hub 里对应一个 `StdioUpstream`:
//! - 一对 reader / writer 线程
//! - 一个 pending-request 表(`id → Sender<Response>`,`std::sync::mpsc`)
//! - 一个独立 stderr 吞吐线程,把 server 的 log 转发到 audit(I04 内做最小:写到 stderr)
//!
//! I04 范围:**最小可运行**。更鲁棒的崩溃检测 / 自动重启放 I10(HTTP MCP + 远端)
//! 一起做。

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::protocol::{read_message, write_message, JsonRpcRequest, ProtocolError};

/// Stdio adapter 错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StdioError {
    /// IO / 协议错误
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// 响应超时
    #[error("upstream response timeout after {0:?}")]
    Timeout(Duration),
    /// 上游返回 JSON-RPC error
    #[error("upstream error: code={code} message={message}")]
    Upstream {
        /// JSON-RPC error code
        code: i32,
        /// 人读 message
        message: String,
    },
    /// 锁污染
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// 进程启动失败
    #[error("failed to spawn upstream: {0}")]
    Spawn(std::io::Error),
    /// 进程已经关闭
    #[error("upstream already closed")]
    Closed,
}

type PendingTable = Arc<Mutex<HashMap<String, Sender<Value>>>>;

/// 一个上游 stdio server 的连接。
pub struct StdioUpstream {
    server_id: String,
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    pending: PendingTable,
}

impl std::fmt::Debug for StdioUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioUpstream")
            .field("server_id", &self.server_id)
            .finish()
    }
}

impl StdioUpstream {
    /// 启动一个 stdio 上游。argv 必须已由 caller 审批(UI 展示过 exact command)。
    ///
    /// - `env` 是**将要注入**的环境变量。进程先 `env_clear()`,然后:
    ///   - **Windows**:注入 `RESERVED_SYSTEM_ENV_KEYS`(SystemRoot 等,让 cmd.exe / ping
    ///     等系统命令能解析 System32 DLL;见 ADR 0007 §I-7.1 helper)
    ///   - 最后注入 caller 批准的 `env`(优先级最高,覆盖同名 system 保留键)
    /// - env 政策全路径由 `vigil_runner_types::apply_native_env_policy` 统一实现,与
    ///   `spawn_native` 共享,消除跨 crate 漂移(I07.5+ / ADR 0007 §I-7.1 / ADR 0018)。
    pub fn spawn(
        server_id: impl Into<String>,
        argv: &[String],
        env: &[(String, String)],
    ) -> Result<Self, StdioError> {
        if argv.is_empty() {
            return Err(StdioError::Spawn(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty argv",
            )));
        }

        let mut cmd = Command::new(&argv[0]);
        for a in &argv[1..] {
            cmd.arg(a);
        }
        // I07.5+ (ADR 0007 §I-7.1):与 vigil-runner::spawn_native 共享 env 政策 helper,
        // 消除历史漂移(此前 StdioUpstream 缺失 Windows SystemRoot 注入 → cmd.exe / ping
        // 作为 MCP server 时无法解析 System32 DLL)。
        // helper 签名要求 IntoIterator<Item=(K,V)>,slice iter 的 items 是 &(String,String),
        // 通过 map(|(k,v)| (k,v)) 解构为引用元组,AsRef<OsStr> blanket impl 覆盖 &String。
        vigil_runner_types::apply_native_env_policy(&mut cmd, env.iter().map(|(k, v)| (k, v)));
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(StdioError::Spawn)?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| StdioError::Spawn(std::io::Error::other("upstream stdout not piped")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| StdioError::Spawn(std::io::Error::other("upstream stderr not piped")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| StdioError::Spawn(std::io::Error::other("upstream stdin not piped")))?;

        let pending: PendingTable = Arc::new(Mutex::new(HashMap::new()));

        // reader 线程:持续读 NDJSON,分发给 pending.get(id) 的 channel
        let sid = server_id.into();
        {
            let pending_r = pending.clone();
            let tag = sid.clone();
            thread::Builder::new()
                .name(format!("vigil-mcp-stdio-reader-{tag}"))
                .spawn(move || {
                    let mut r = BufReader::new(stdout);
                    loop {
                        match read_message(&mut r) {
                            Ok(v) => {
                                let id_key = v.get("id").map(|x| x.to_string()).unwrap_or_default();
                                if id_key.is_empty() || id_key == "null" {
                                    // notification / server→client request;I04 暂不处理
                                    continue;
                                }
                                let sender_opt = {
                                    let mut g = pending_r.lock().unwrap_or_else(|p| p.into_inner());
                                    g.remove(&id_key)
                                };
                                if let Some(tx) = sender_opt {
                                    let _ = tx.send(v);
                                }
                            }
                            Err(crate::protocol::ProtocolError::Eof) => {
                                // 上游关闭:清空所有等待方,让它们立即 timeout
                                break;
                            }
                            Err(e) => {
                                // M2(Codex I04 review):非法 JSON 不再静默吞掉让 reader
                                // 永久空转;log 一条并继续尝试下一行(rust-style 宽容),
                                // 但上游如果连续坏很快触发 Eof。
                                eprintln!("[vigil-hub upstream {tag}] stdio parse error: {e}");
                                // 继续循环:下一个 read_line 会消费下一行
                                continue;
                            }
                        }
                    }
                    // 退出前把所有 pending sender 清空,让等待方立即拿到 channel close
                    let mut g = pending_r.lock().unwrap_or_else(|p| p.into_inner());
                    g.clear();
                })
                .ok();
        }

        // stderr 线程:吞掉上游日志,转发到本进程 stderr(I04 最小实装)。
        // I08 UI 接入后可改为写入 audit.
        {
            let tag = sid.clone();
            thread::Builder::new()
                .name(format!("vigil-mcp-stdio-stderr-{tag}"))
                .spawn(move || {
                    let r = BufReader::new(stderr);
                    for line in r.lines().map_while(Result::ok) {
                        eprintln!("[upstream {tag}] {line}");
                    }
                })
                .ok();
        }

        Ok(Self {
            server_id: sid,
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            pending,
        })
    }

    /// 发一条 request 并等待响应。
    ///
    /// `id` 由本函数生成(UUID);超时到达返 `Timeout`。
    ///
    /// I10b-α1 代码 R1 MUST-FIX:收窄到 `pub(crate)` —— 仅本 crate 内的
    /// `impl McpUpstream for StdioUpstream::call` 用;外部 caller 一律走 trait
    /// method `McpUpstream::call`(返统一 `UpstreamError`),**不**得绕开。
    pub(crate) fn call_raw(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, StdioError> {
        let id = Uuid::new_v4().to_string();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(Value::String(id.clone())),
            method: method.to_string(),
            params,
        };
        let (tx, rx): (Sender<Value>, Receiver<Value>) = channel();
        {
            let mut g = self.pending.lock().map_err(|_| StdioError::LockPoisoned)?;
            g.insert(format!("\"{id}\""), tx);
        }

        // 写请求
        {
            let mut g = self.stdin.lock().map_err(|_| StdioError::LockPoisoned)?;
            let stdin = g.as_mut().ok_or(StdioError::Closed)?;
            let v = serde_json::to_value(&req)
                .map_err(|e| StdioError::Protocol(ProtocolError::Json(e)))?;
            write_message(stdin, &v).map_err(StdioError::Protocol)?;
        }

        // 等响应
        let resp = match rx.recv_timeout(timeout) {
            Ok(v) => v,
            Err(_) => {
                // 清理 pending 条目
                let _ = self
                    .pending
                    .lock()
                    .map(|mut g| g.remove(&format!("\"{id}\"")));
                return Err(StdioError::Timeout(timeout));
            }
        };

        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(-1) as i32;
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(StdioError::Upstream { code, message });
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// 关闭 stdin 并等待子进程终止。best-effort,不抛异常。
    /// I10b-α1 代码 R1 MUST-FIX:改 `pub(crate)`;外部走 trait method `McpUpstream::shutdown`。
    pub(crate) fn shutdown_raw(&self) {
        if let Ok(mut g) = self.stdin.lock() {
            *g = None; // drop ChildStdin → 上游 stdin 关闭
        }
        if let Ok(mut g) = self.child.lock() {
            if let Some(mut c) = g.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}

impl crate::upstream::McpUpstream for StdioUpstream {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn transport(&self) -> vigil_types::TransportKind {
        vigil_types::TransportKind::Stdio
    }

    fn call(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, crate::upstream::UpstreamError> {
        use crate::upstream::UpstreamError;
        match self.call_raw(method, params, timeout) {
            Ok(v) => Ok(v),
            Err(StdioError::Timeout(d)) => Err(UpstreamError::TimedOut(d)),
            Err(StdioError::Upstream { code, message }) => {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(message.as_bytes());
                Err(UpstreamError::JsonRpc {
                    code: code as i64,
                    message_sha256: hex::encode(h.finalize()),
                })
            }
            Err(StdioError::Protocol(_)) => Err(UpstreamError::TransportIo("stdio_protocol")),
            Err(StdioError::Closed) => Err(UpstreamError::TransportIo("stdio_closed")),
            Err(StdioError::Spawn(_)) => Err(UpstreamError::TransportIo("stdio_spawn_failed")),
            Err(StdioError::LockPoisoned) => Err(UpstreamError::Internal("stdio_lock_poisoned")),
        }
    }

    fn shutdown(&self) {
        self.shutdown_raw();
    }
}

impl Drop for StdioUpstream {
    fn drop(&mut self) {
        self.shutdown_raw();
    }
}

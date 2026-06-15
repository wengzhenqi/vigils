//! JSON-RPC 2.0 message types + NDJSON framer(ADR 0004 §D1, §D2)。
//!
//! 只覆盖 MCP 2025-06-18 我们实装的最小子集的载荷形态 —— 协议类型是"通用 JSON-RPC 2.0",
//! 具体 method 语义在 [`crate::hub`] 里判定。
//!
//! ### 帧协议
//! newline-delimited JSON:每条 message 末尾 `\n`,UTF-8,无 BOM。跨平台稳定。

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// JSON-RPC 2.0 request / notification。
///
/// `id` 为 `None` 表示 notification(客户端不期待响应)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// 必须为 `"2.0"`。
    pub jsonrpc: String,
    /// `None` = notification;否则是 request id(string / number)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// method 名(如 `initialize` / `tools/list` / `tools/call`)
    pub method: String,
    /// 参数(object / array / null)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// 是否为 notification(无 id)。
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// 生成对应的 success response。
    pub fn success(&self, result: Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: self.id.clone().unwrap_or(Value::Null),
            result: Some(result),
            error: None,
        }
    }

    /// 生成对应的 error response。
    pub fn error(
        &self,
        code: i32,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: self.id.clone().unwrap_or(Value::Null),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

/// JSON-RPC 2.0 response —— success 或 error 二选一。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// 必须为 `"2.0"`
    pub jsonrpc: String,
    /// 对应请求的 id。如果请求里 id 是 null,这里也返 null。
    pub id: Value,
    /// success 时为 Some
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// error 时为 Some
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error 对象(spec 定义)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// 整数错误码(MCP 使用 JSON-RPC 标准码 + 自定义正整数码)
    pub code: i32,
    /// 人读文本
    pub message: String,
    /// 额外数据(可选)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// -32700 Parse error
    pub const PARSE: i32 = -32700;
    /// -32600 Invalid Request
    pub const INVALID_REQUEST: i32 = -32600;
    /// -32601 Method not found
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// -32602 Invalid params
    pub const INVALID_PARAMS: i32 = -32602;
    /// -32603 Internal error
    pub const INTERNAL: i32 = -32603;

    /// Vigil 自定义:firewall 拒绝
    pub const VIGIL_DENIED: i32 = 32001;
    /// Vigil 自定义:approval 到期 / 拒绝 / 取消
    pub const VIGIL_APPROVAL_REJECTED: i32 = 32002;
    /// Vigil 自定义:上游 server 不可达 / 未登记
    pub const VIGIL_UPSTREAM_UNAVAILABLE: i32 = 32003;
}

/// Framer / 解析错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// IO 错误
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON 解析失败(半条 / 非法 UTF-8 / 非法 JSON)
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// JSON-RPC 字段缺失或取值错误
    #[error("protocol: {0}")]
    Malformed(&'static str),
    /// reader 读到 EOF(上游子进程已关闭 stdin/stdout)
    #[error("stream closed")]
    Eof,
}

/// 从 reader 读一条 NDJSON message。
///
/// 约定:
/// - 空行跳过(方便 `echo "" | vigil-hub` 这类交互式调试)
/// - 读到 EOF 返 `Eof`
/// - 非法 JSON 即返 `Json`,caller 决定是否关闭连接
pub fn read_message<R: BufRead>(reader: &mut R) -> Result<Value, ProtocolError> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(ProtocolError::Eof);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(trimmed)?;
        return Ok(v);
    }
}

/// 向 writer 写一条 NDJSON message(末尾换行,flush)。
pub fn write_message<W: Write>(writer: &mut W, value: &Value) -> Result<(), ProtocolError> {
    // 使用 serde_json::to_vec(非 JCS)以保持 MCP 线上兼容性:上游 server 若严格按
    // JCS 输出,我们的 framer 输入也能接受;但 MCP 规范本身并不要求 JCS,这里保持
    // 松耦合输出即可。
    let bytes = serde_json::to_vec(value)?;
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn request_serde_roundtrip() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(Value::Number(1.into())),
            method: "tools/list".into(),
            params: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""jsonrpc":"2.0""#));
        assert!(s.contains(r#""method":"tools/list""#));
        let back: JsonRpcRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.method, req.method);
    }

    #[test]
    fn success_and_error_response() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(Value::String("abc".into())),
            method: "x".into(),
            params: None,
        };
        let ok = req.success(serde_json::json!({"ok": true}));
        assert_eq!(ok.id, Value::String("abc".into()));
        assert!(ok.error.is_none());

        let err = req.error(JsonRpcError::VIGIL_DENIED, "test denial", None);
        assert!(err.result.is_none());
        assert_eq!(err.error.as_ref().unwrap().code, 32001);
    }

    #[test]
    fn ndjson_read_skips_blank_lines() {
        let data = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut r = BufReader::new(Cursor::new(&data[..]));
        let v = read_message(&mut r).unwrap();
        assert_eq!(v["method"], "ping");
    }

    #[test]
    fn ndjson_read_returns_eof_on_close() {
        let data = b"";
        let mut r = BufReader::new(Cursor::new(&data[..]));
        assert!(matches!(read_message(&mut r), Err(ProtocolError::Eof)));
    }

    #[test]
    fn ndjson_write_appends_newline() {
        let mut buf = Vec::new();
        let v = serde_json::json!({"a": 1});
        write_message(&mut buf, &v).unwrap();
        assert_eq!(buf.last(), Some(&b'\n'));
        let as_str = String::from_utf8(buf).unwrap();
        assert!(as_str.contains("\"a\":1"));
    }

    #[test]
    fn notification_detection() {
        let n = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "notifications/cancelled".into(),
            params: None,
        };
        assert!(n.is_notification());
    }
}

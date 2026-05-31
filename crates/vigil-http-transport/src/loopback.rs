//! I10b-β(ADR 0011 §5):loopback OAuth redirect server。
//!
//! 用户完成浏览器授权后,AS 把 `code` 重定向回 `http://127.0.0.1:<ephemeral>/callback`,
//! 本 server 捕获 `code` + `state`,做 CSRF 校验,然后返简短 HTML 提示用户关闭页面。
//!
//! **设计约束**(ADR 0011 β double-check):
//! - 端口绑定失败 → fail-closed,**不**降级到固定端口(防止 port squatting)
//! - 60s 超时(防 loopback server 常驻)
//! - CSRF state 精确等值;不等 → 拒绝 code
//! - 收 **1 个** 请求就退出 —— 避免长期暴露 127.0.0.1 HTTP
//! - **不**引入 tokio / hyper;用 `std::net::TcpListener` + 手工解析最小 HTTP(只识别
//!   GET + query string)—— OAuth callback 语义极简,依赖越少越干净
//! - 浏览器打开失败 → caller 打印 URL 让用户手动(`fallback = true`)

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use vigil_http_auth::HttpAuthError;

/// β R1 MUST-FIX 2:HTTP request 总字节上限(request line + headers)。
/// OAuth callback request line 通常 < 2 KiB(含 code + state);加上 host/accept 等
/// header 总字节 < 4 KiB 就足够。8 KiB 给宽裕边界,恶意 client 超过 → fail-closed 400。
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// loopback server 拿到的 OAuth 响应 —— 已做 CSRF 校验,code 已 url-decode。
#[derive(Debug, Clone)]
pub struct LoopbackCallback {
    /// AS 返回的授权 code
    pub code: String,
    /// AS 返回的 state —— 与 caller 期望值已精确等(校验通过才构造本结构)
    pub state: String,
}

/// loopback server 的占位符号 —— 供 caller 借用期望的 redirect URI(动态端口)。
#[derive(Debug)]
pub struct LoopbackServer {
    listener: TcpListener,
    addr: SocketAddr,
    expected_state: String,
    path: String,
}

impl LoopbackServer {
    /// 绑定 `127.0.0.1:0` ephemeral port。**失败** 即 fail-closed,不降级。
    ///
    /// `expected_state` 由 caller 随机生成(I10a `oauth2::CsrfToken`);server 只在
    /// 收到 callback 时精确等字符串匹配,不等 → 拒。
    ///
    /// `path` 通常是 `"/callback"`;支持自定义以便测试 / 未来兼容非 `/callback` UX。
    pub fn bind(expected_state: impl Into<String>, path: &str) -> Result<Self, HttpAuthError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|_| HttpAuthError::HttpError("loopback_bind_failed"))?;
        let addr = listener
            .local_addr()
            .map_err(|_| HttpAuthError::HttpError("loopback_addr_failed"))?;
        Ok(Self {
            listener,
            addr,
            expected_state: expected_state.into(),
            path: path.to_string(),
        })
    }

    /// 返回 caller 应传给 AS 的完整 redirect URI,例如
    /// `"http://127.0.0.1:54872/callback"`。
    pub fn redirect_uri(&self) -> String {
        format!("http://{}{}", self.addr, self.path)
    }

    /// 阻塞等一个**合法**的 OAuth callback 请求;超时 → `HttpAuthError::HttpError("loopback_timeout")`。
    ///
    /// **β R1 MUST-FIX 3**:坏请求(state mismatch / bad method / wrong path /
    /// missing code / header DoS)**不**直接关闭 listener —— 继续监听直到 timeout。
    /// 这样 stray request / 错配 UI 跳转 / 攻击者探测不会烧掉一次 onboarding;
    /// 用户在浏览器完成授权的正常请求仍有机会被处理。
    ///
    /// 成功收到**合法** callback 后立即返 200 + HTML,并退出(listener 在 self drop 时
    /// 关闭)—— **不**长期暴露 127.0.0.1 HTTP。
    pub fn wait_for_callback(self, timeout: Duration) -> Result<LoopbackCallback, HttpAuthError> {
        // 设置 listener accept 超时(通过 nonblocking + poll 循环实现)
        self.listener
            .set_nonblocking(true)
            .map_err(|_| HttpAuthError::HttpError("loopback_nonblocking_failed"))?;

        let started = Instant::now();
        let mut last_err: Option<&'static str> = None;
        loop {
            if started.elapsed() >= timeout {
                // 带上最后一次失败原因便于诊断;若从未 accept 到任何请求则纯 timeout
                return Err(HttpAuthError::HttpError(
                    last_err.unwrap_or("loopback_timeout"),
                ));
            }
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    match handle_stream(stream, &self.expected_state, &self.path) {
                        Ok(cb) => return Ok(cb),
                        Err(HttpAuthError::HttpError(reason)) => {
                            // 坏请求:记原因,继续等(不关 listener)
                            last_err = Some(reason);
                            continue;
                        }
                        Err(other) => return Err(other),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    last_err = Some("loopback_accept_failed");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

fn handle_stream(
    mut stream: TcpStream,
    expected_state: &str,
    expected_path: &str,
) -> Result<LoopbackCallback, HttpAuthError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| HttpAuthError::HttpError("loopback_read_timeout_set_failed"))?;

    // 读 HTTP request 直到 headers 结束(CRLF CRLF)。
    // OAuth callback 只关心 request line,body 可忽略。
    // **β R1 MUST-FIX 2**:限 MAX_REQUEST_BYTES 累计上限,防止恶意 client DoS。
    let mut reader = BufReader::new(&mut stream);
    let mut total_bytes: usize = 0;
    let mut request_line = String::new();
    let read_n = reader
        .by_ref()
        .take(MAX_REQUEST_BYTES as u64)
        .read_line(&mut request_line)
        .map_err(|_| HttpAuthError::HttpError("loopback_read_failed"))?;
    total_bytes += read_n;
    if !request_line.ends_with('\n') || total_bytes >= MAX_REQUEST_BYTES {
        write_error(&mut stream, 400, "request line too large");
        return Err(HttpAuthError::HttpError("loopback_request_too_large"));
    }

    // 解析:`GET /callback?code=...&state=... HTTP/1.1`
    // (split_whitespace 自带 trim 语义,不需要额外 trim_end)
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 || parts[0] != "GET" {
        // 仍要读完 headers(有限量)再返 400,免得 client 拿 reset
        let _ = consume_headers(&mut reader, MAX_REQUEST_BYTES - total_bytes);
        write_error(&mut stream, 400, "method not allowed");
        return Err(HttpAuthError::HttpError("loopback_bad_method"));
    }
    let target = parts[1];

    // 读完 headers(受总字节上限控制;超限 → fail-closed)
    if !consume_headers(&mut reader, MAX_REQUEST_BYTES - total_bytes) {
        write_error(&mut stream, 400, "headers too large");
        return Err(HttpAuthError::HttpError("loopback_headers_too_large"));
    }

    // 分离 path 和 query
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    if path != expected_path {
        write_error(&mut stream, 404, "not found");
        return Err(HttpAuthError::HttpError("loopback_wrong_path"));
    }

    // 解析 query
    let params = parse_query(query);

    // AS 返回 error 的情形(用户取消 / invalid scope 等)
    if let Some(err) = params.get("error") {
        let desc = params.get("error_description").cloned().unwrap_or_default();
        let body = format!("OAuth error: {err} {desc}");
        write_html(&mut stream, 400, &body);
        return Err(HttpAuthError::HttpError("loopback_as_returned_error"));
    }

    // state 精确等
    let got_state = params.get("state").cloned().unwrap_or_default();
    if got_state != expected_state {
        write_error(&mut stream, 400, "state mismatch");
        return Err(HttpAuthError::HttpError("loopback_state_mismatch"));
    }
    let code = match params.get("code") {
        Some(c) if !c.is_empty() => c.clone(),
        _ => {
            write_error(&mut stream, 400, "missing code");
            return Err(HttpAuthError::HttpError("loopback_missing_code"));
        }
    };

    // 返 200 + 简短 HTML
    write_html(
        &mut stream,
        200,
        "<html><body><h2>Authorization received</h2>\
         <p>You can close this window and return to the CLI.</p></body></html>",
    );

    Ok(LoopbackCallback {
        code,
        state: got_state,
    })
}

/// 读完 headers 直到 CRLF CRLF 或 EOF;返 `true` 表示读到合法结束,`false` 表示超限。
///
/// **β R1 MUST-FIX 2**:累加字节总数,超 `remaining_budget` 立即 `false`,caller
/// 返 400 + 关连接,防止恶意 client 通过巨量 headers DoS 吞内存。
fn consume_headers<R: BufRead>(reader: &mut R, mut remaining_budget: usize) -> bool {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).unwrap_or(0);
        if n == 0 {
            return true; // EOF
        }
        if n > remaining_budget {
            return false;
        }
        remaining_budget -= n;
        if line == "\r\n" || line == "\n" {
            return true;
        }
    }
}

fn write_error(stream: &mut TcpStream, status: u16, msg: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status} ERR\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{msg}",
        len = msg.len()
    );
    let _ = stream.flush();
}

fn write_html(stream: &mut TcpStream, status: u16, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status} OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len()
    );
    let _ = stream.flush();
    let _ = stream.read_to_end(&mut Vec::new()); // 吞掉 client 后续 bytes
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let k_decoded = url_decode(k);
        let v_decoded = url_decode(v);
        out.insert(k_decoded, v_decoded);
    }
    out
}

/// 最小 url-decode:`+` → 空格,`%XX` → byte。容错:非法 %escape 当 literal 保留。
fn url_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 尝试用系统默认浏览器打开 URL。失败返 `false`(caller 应打印 URL fallback)。
///
/// 不暴露具体错误(cross-platform OS message 会因 terminal/DE 状态变化);
/// caller 统一 UI:"若浏览器未自动打开,请手动访问以下 URL: ..."。
pub fn open_browser(url: &str) -> bool {
    open::that(url).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("hello"), "hello");
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("foo%3Dbar"), "foo=bar");
        assert_eq!(url_decode("a%20b"), "a b");
        // 非法 escape 保留 literal %
        assert_eq!(url_decode("100%"), "100%");
    }

    #[test]
    fn parse_query_basic() {
        let q = parse_query("code=ABC&state=xyz&empty=");
        assert_eq!(q.get("code").map(|s| s.as_str()), Some("ABC"));
        assert_eq!(q.get("state").map(|s| s.as_str()), Some("xyz"));
        assert_eq!(q.get("empty").map(|s| s.as_str()), Some(""));
    }

    #[test]
    fn parse_query_url_decoded() {
        let q = parse_query("url=https%3A%2F%2Fexample.com%2Fpath&name=hello+world");
        assert_eq!(
            q.get("url").map(|s| s.as_str()),
            Some("https://example.com/path")
        );
        assert_eq!(q.get("name").map(|s| s.as_str()), Some("hello world"));
    }

    #[test]
    fn loopback_bind_ephemeral_and_redirect_uri_contains_port() {
        let server = LoopbackServer::bind("test-state", "/callback").unwrap();
        let uri = server.redirect_uri();
        assert!(uri.starts_with("http://127.0.0.1:"));
        assert!(uri.ends_with("/callback"));
        // port 不是 0(OS 真分配了)
        let port_str = &uri["http://127.0.0.1:".len()..uri.len() - "/callback".len()];
        let port: u16 = port_str.parse().unwrap();
        assert!(port > 0);
    }

    #[test]
    fn loopback_callback_happy_path() {
        let server = LoopbackServer::bind("abc-state-α2", "/callback").unwrap();
        let uri = server.redirect_uri();
        let port = uri
            .split(':')
            .nth(2)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();

        // 客户端线程:发一个合法 callback
        let client_port = port.clone();
        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let mut stream = TcpStream::connect(format!("127.0.0.1:{client_port}")).unwrap();
            stream
                .write_all(
                    b"GET /callback?code=CODE_XYZ&state=abc-state-%CE%B12 HTTP/1.1\r\n\
                      Host: 127.0.0.1\r\n\r\n",
                )
                .unwrap();
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            buf
        });

        let cb = server.wait_for_callback(Duration::from_secs(2)).unwrap();
        assert_eq!(cb.code, "CODE_XYZ");
        assert_eq!(cb.state, "abc-state-α2");
        let resp = client.join().unwrap();
        assert!(resp.contains("Authorization received"));
    }

    #[test]
    fn loopback_callback_state_mismatch_rejects() {
        let server = LoopbackServer::bind("expected-state", "/callback").unwrap();
        let uri = server.redirect_uri();
        let port = uri
            .split(':')
            .nth(2)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();

        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            stream
                .write_all(
                    b"GET /callback?code=CODE&state=ATTACKER_STATE HTTP/1.1\r\n\
                      Host: 127.0.0.1\r\n\r\n",
                )
                .unwrap();
        });

        let err = server
            .wait_for_callback(Duration::from_secs(2))
            .unwrap_err();
        let _ = client.join();
        assert!(matches!(
            err,
            HttpAuthError::HttpError("loopback_state_mismatch")
        ));
    }

    #[test]
    fn loopback_timeout_when_no_callback() {
        let server = LoopbackServer::bind("state", "/callback").unwrap();
        let err = server
            .wait_for_callback(Duration::from_millis(100))
            .unwrap_err();
        assert!(matches!(err, HttpAuthError::HttpError("loopback_timeout")));
    }

    #[test]
    fn loopback_rejects_non_get() {
        let server = LoopbackServer::bind("state", "/callback").unwrap();
        let uri = server.redirect_uri();
        let port = uri
            .split(':')
            .nth(2)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();

        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            stream
                .write_all(
                    b"POST /callback HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });

        let err = server
            .wait_for_callback(Duration::from_secs(2))
            .unwrap_err();
        let _ = client.join();
        assert!(matches!(
            err,
            HttpAuthError::HttpError("loopback_bad_method")
        ));
    }

    #[test]
    fn loopback_rejects_as_error() {
        let server = LoopbackServer::bind("state", "/callback").unwrap();
        let uri = server.redirect_uri();
        let port = uri
            .split(':')
            .nth(2)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();

        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            stream
                .write_all(
                    b"GET /callback?error=access_denied&error_description=user%20cancelled \
                      HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                )
                .unwrap();
        });

        let err = server
            .wait_for_callback(Duration::from_secs(2))
            .unwrap_err();
        let _ = client.join();
        assert!(matches!(
            err,
            HttpAuthError::HttpError("loopback_as_returned_error")
        ));
    }

    /// **β R1 MUST-FIX 3 证据**:坏请求不关 listener —— 第一个请求 state mismatch,
    /// listener 继续监听;第二个合法请求成功被处理。
    #[test]
    fn loopback_continues_listening_after_bad_request() {
        let server = LoopbackServer::bind("good-state", "/callback").unwrap();
        let uri = server.redirect_uri();
        let port = uri
            .split(':')
            .nth(2)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();

        let port_c = port.clone();
        let client = std::thread::spawn(move || {
            // 1. 先发一个 state 错的请求(坏请求)
            std::thread::sleep(Duration::from_millis(100));
            let mut s1 = TcpStream::connect(format!("127.0.0.1:{port_c}")).unwrap();
            s1.write_all(
                b"GET /callback?code=CODE1&state=WRONG HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .unwrap();
            let _ = s1.flush();
            drop(s1);

            // 2. 稍等,再发一个合法请求
            std::thread::sleep(Duration::from_millis(200));
            let mut s2 = TcpStream::connect(format!("127.0.0.1:{port_c}")).unwrap();
            s2.write_all(
                b"GET /callback?code=CODE_OK&state=good-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .unwrap();
            let _ = s2.flush();
        });

        let cb = server.wait_for_callback(Duration::from_secs(5)).unwrap();
        let _ = client.join();
        // 关键断言:listener 没被第一个坏请求烧掉,第二个请求 code 真被接受
        assert_eq!(cb.code, "CODE_OK");
        assert_eq!(cb.state, "good-state");
    }

    /// **β R1 MUST-FIX 2 证据**:request line 超 MAX_REQUEST_BYTES → fail-closed。
    #[test]
    fn loopback_rejects_oversized_request_line() {
        let server = LoopbackServer::bind("state", "/callback").unwrap();
        let uri = server.redirect_uri();
        let port = uri
            .split(':')
            .nth(2)
            .unwrap()
            .split('/')
            .next()
            .unwrap()
            .to_string();

        let port_c = port.clone();
        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let mut stream = TcpStream::connect(format!("127.0.0.1:{port_c}")).unwrap();
            // 构造一个巨大 request line:GET /callback?pad=<MAX_REQUEST_BYTES 字节>
            let padding = "A".repeat(MAX_REQUEST_BYTES + 1024);
            let request = format!("GET /callback?pad={padding} HTTP/1.1\r\nHost: x\r\n\r\n");
            let _ = stream.write_all(request.as_bytes());
            let _ = stream.flush();
        });

        // 2s timeout — 坏请求会被拒但 listener 继续监听,最终 timeout 返回 last_err
        let err = server
            .wait_for_callback(Duration::from_secs(2))
            .unwrap_err();
        let _ = client.join();
        assert!(matches!(
            err,
            HttpAuthError::HttpError("loopback_request_too_large")
        ));
    }
}

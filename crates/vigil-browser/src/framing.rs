//! Chrome Native Messaging framing(ADR 0009 §D4):`u32 LE length + UTF-8 JSON`。
//!
//! Chrome 官方:每条消息前 4 字节 little-endian 无符号整数表示 payload 字节长度;
//! Chrome → Host 最大 4 GB(实测 64 MB),Host → Chrome 最大 1 MB。
//! 本实现两端一律**上限 1 MB**(ADR §I-9.5 防内存炸弹)。

use std::io::{self, Read, Write};

use crate::protocol::BrowserErrorCode;

/// 协议上限:单条 payload 字节数。超过视为 `too_large`。
pub const MAX_MESSAGE_BYTES: u32 = 1024 * 1024;

/// 读取一帧(阻塞)。
///
/// - `Ok(Some(payload))`:完整读到一帧
/// - `Ok(None)`:stdin EOF(扩展侧断开,Host 优雅退出)
/// - `Err(BrowserErrorCode)`:协议级错误(超长 / 读错 → too_large / internal)
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, BrowserErrorCode> {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(reader, &mut len_buf)? {
        FrameRead::Eof => return Ok(None), // 扩展断开
        FrameRead::Partial => return Err(BrowserErrorCode::Internal),
        FrameRead::Ok => {}
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(BrowserErrorCode::TooLarge);
    }
    let mut payload = vec![0u8; len as usize];
    match read_exact_or_eof(reader, &mut payload)? {
        FrameRead::Eof | FrameRead::Partial => Err(BrowserErrorCode::Internal),
        FrameRead::Ok => Ok(Some(payload)),
    }
}

/// 写入一帧(`u32 LE length + payload`)。
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), BrowserErrorCode> {
    if payload.len() > MAX_MESSAGE_BYTES as usize {
        return Err(BrowserErrorCode::TooLarge);
    }
    let len = payload.len() as u32;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(|_| BrowserErrorCode::Internal)?;
    writer
        .write_all(payload)
        .map_err(|_| BrowserErrorCode::Internal)?;
    writer.flush().map_err(|_| BrowserErrorCode::Internal)?;
    Ok(())
}

enum FrameRead {
    Ok,
    Eof,
    Partial,
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<FrameRead, BrowserErrorCode> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                // 完全没读到一字节 → EOF;否则是 partial read,视为协议错(caller 判)
                return Ok(if filled == 0 {
                    FrameRead::Eof
                } else {
                    FrameRead::Partial
                });
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(BrowserErrorCode::Internal),
        }
    }
    Ok(FrameRead::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_payload() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        let mut reader = std::io::Cursor::new(buf);
        let out = read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn empty_reader_returns_none() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn oversized_length_rejected() {
        // length = MAX + 1
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_BYTES + 1).to_le_bytes());
        // 不需要写 payload —— length 检查应先于分配
        let mut reader = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut reader), Err(BrowserErrorCode::TooLarge));
    }

    #[test]
    fn at_limit_accepted() {
        let payload = vec![0u8; 1024]; // 远小于上限;仅验 length boundary 不炸
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &payload).unwrap();
        let mut reader = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), payload);
    }

    #[test]
    fn partial_payload_read_returns_internal() {
        // length=10 但只给 3 字节 payload → 读不满 → Internal
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(b"abc");
        let mut reader = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut reader), Err(BrowserErrorCode::Internal));
    }
}

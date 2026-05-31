//! Hash chain —— 见 ADR 0002 §D3。
//!
//! event_hash = SHA-256(
//!     DOMAIN_TAG
//!   ‖ u32_be(32) ‖ prev_hash_bytes(32 字节;genesis 全 0)
//!   ‖ u64_be(len(payload_jcs)) ‖ payload_jcs
//!   ‖ u32_be(8)  ‖ created_at_be(i64)
//! )

use crate::error::{AuditError, Result};
use sha2::{Digest, Sha256};

/// domain tag 固定常量。修改 = breaking change,需升级 ADR 并提供迁移策略。
pub const DOMAIN_TAG: &[u8] = b"vigil.ledger.event.v1";

/// Genesis 事件的 `prev_hash` 在字节形式上是 32 个 0x00;在 SQL 列里存空串。
pub const GENESIS_PREV_HASH_BYTES: [u8; 32] = [0u8; 32];

/// 计算一个事件的 hash(十六进制小写,64 字符)。
///
/// - `prev_hash_hex` 取空串表示 genesis,非空时必须是 64 字符十六进制。
/// - `payload` 按 RFC 8785 JCS 规范化后参与摘要。
pub fn compute_event_hash(
    prev_hash_hex: &str,
    payload: &serde_json::Value,
    created_at: i64,
) -> Result<String> {
    let prev_bytes = parse_prev_hash(prev_hash_hex)?;
    // JCS 把 object key 排序、数字最短形式、字符串最小 escape、无多余空白
    let payload_bytes = serde_jcs::to_vec(payload)?;

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG);

    // 字段 1:prev_hash(定长 32 字节,但仍带显式长度前缀,防未来常量变化)
    hasher.update((prev_bytes.len() as u32).to_be_bytes());
    hasher.update(prev_bytes);

    // 字段 2:payload JCS 字节(变长)
    hasher.update((payload_bytes.len() as u64).to_be_bytes());
    hasher.update(&payload_bytes);

    // 字段 3:created_at 大端 i64(定长 8 字节)
    hasher.update(8u32.to_be_bytes());
    hasher.update(created_at.to_be_bytes());

    Ok(hex::encode(hasher.finalize()))
}

fn parse_prev_hash(hex_str: &str) -> Result<[u8; 32]> {
    if hex_str.is_empty() {
        return Ok(GENESIS_PREV_HASH_BYTES);
    }
    if hex_str.len() != 64 {
        return Err(AuditError::InvalidInput {
            reason: "prev_hash must be 64-char lower-hex or empty for genesis",
        });
    }
    let v = hex::decode(hex_str).map_err(|_| AuditError::InvalidInput {
        reason: "prev_hash is not valid hex",
    })?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_prev_hash_accepts_genesis_empty() {
        assert_eq!(parse_prev_hash("").unwrap(), GENESIS_PREV_HASH_BYTES);
    }

    #[test]
    fn parse_prev_hash_rejects_wrong_length() {
        assert!(parse_prev_hash("abcd").is_err());
    }

    #[test]
    fn compute_event_hash_is_deterministic() {
        let p = json!({"a": 1, "b": "测试"});
        let h1 = compute_event_hash("", &p, 1700000000).unwrap();
        let h2 = compute_event_hash("", &p, 1700000000).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_event_hash_is_jcs_stable() {
        // key 顺序不同,hash 必须相同(JCS 排序)
        let p1 = json!({"a": 1, "b": "测试"});
        let p2 = json!({"b": "测试", "a": 1});
        assert_eq!(
            compute_event_hash("", &p1, 1700000001).unwrap(),
            compute_event_hash("", &p2, 1700000001).unwrap()
        );
    }

    #[test]
    fn compute_event_hash_changes_with_prev() {
        let p = json!({});
        let h1 = compute_event_hash("", &p, 1700000000).unwrap();
        // 用 h1 作为 prev 算下一个(非 genesis)
        let h2 = compute_event_hash(&h1, &p, 1700000000).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_event_hash_changes_with_timestamp() {
        let p = json!({});
        assert_ne!(
            compute_event_hash("", &p, 1700000000).unwrap(),
            compute_event_hash("", &p, 1700000001).unwrap()
        );
    }
}

//! Descriptor hash(ADR 0004 §D3)。
//!
//! 跨版本契约,**修改需升级 ADR + domain tag**。独立于 `vigil-audit::hash`
//! 的 event domain tag,避免跨用途摘要碰撞。
//!
//! 摘要输入字节布局:
//! ```text
//! domain_tag("vigil.descriptor.tool.v1", 24 bytes)
//!   ‖ u32_be(len) ‖ JCS({
//!       "server_id": ..., "tool_name": ...,
//!       "schema": ..., "description": ..., "annotations": ...
//!     })
//! ```

use serde_json::json;
use sha2::{Digest, Sha256};

/// domain tag 常量(修改 = breaking change)。
pub const DESCRIPTOR_DOMAIN_TAG: &[u8] = b"vigil.descriptor.tool.v1";

/// 计算一个工具描述符的 hash(hex-lower 64 字符)。
pub fn descriptor_hash(
    server_id: &str,
    tool_name: &str,
    schema: &serde_json::Value,
    description: Option<&str>,
    annotations: &serde_json::Value,
) -> Result<String, serde_json::Error> {
    let canonical_input = json!({
        "server_id": server_id,
        "tool_name": tool_name,
        "schema": schema,
        "description": description,
        "annotations": annotations,
    });
    let payload_bytes = serde_jcs::to_vec(&canonical_input)?;
    let mut h = Sha256::new();
    h.update(DESCRIPTOR_DOMAIN_TAG);
    h.update((payload_bytes.len() as u32).to_be_bytes());
    h.update(&payload_bytes);
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_is_deterministic() {
        let schema = json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let annotations = json!({"readOnlyHint": true});
        let h1 = descriptor_hash(
            "fs",
            "read_file",
            &schema,
            Some("Read a file"),
            &annotations,
        )
        .unwrap();
        let h2 = descriptor_hash(
            "fs",
            "read_file",
            &schema,
            Some("Read a file"),
            &annotations,
        )
        .unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn hash_jcs_stable_under_key_reorder() {
        // schema / annotations 内的 key 乱序不应改变 hash(JCS 会排序)
        let s1 = json!({"a": 1, "b": 2});
        let s2 = json!({"b": 2, "a": 1});
        let h1 = descriptor_hash("srv", "t", &s1, None, &json!({})).unwrap();
        let h2 = descriptor_hash("srv", "t", &s2, None, &json!({})).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_changes_with_description() {
        let s = json!({});
        let a = json!({});
        let h1 = descriptor_hash("srv", "t", &s, Some("v1"), &a).unwrap();
        let h2 = descriptor_hash("srv", "t", &s, Some("v2"), &a).unwrap();
        assert_ne!(h1, h2, "description 变化必须改变 hash(防 tool poisoning)");
    }

    #[test]
    fn hash_changes_with_annotations() {
        // annotations.readOnlyHint 从 true 变 false 必须被识别为漂移
        let s = json!({});
        let h1 = descriptor_hash("srv", "t", &s, None, &json!({"readOnlyHint": true})).unwrap();
        let h2 = descriptor_hash("srv", "t", &s, None, &json!({"readOnlyHint": false})).unwrap();
        assert_ne!(h1, h2, "annotations 变化必须改变 hash");
    }

    #[test]
    fn domain_tag_is_stable() {
        assert_eq!(DESCRIPTOR_DOMAIN_TAG, b"vigil.descriptor.tool.v1");
    }
}

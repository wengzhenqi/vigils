//! ADR 0002 §D3 的 hash chain 测试向量。**本文件定义的向量即跨版本契约**:
//! 未来对 `compute_event_hash` 的任何重写必须使本文件通过,或先升级 ADR 0002 + domain tag。
//!
//! 向量使用固定的 prev_hash / payload / created_at,期望 hash 值也是**钉死的十六进制**。
//! 若你因修改 hash 算法而看到本文件失败:除非你同时升级了 `DOMAIN_TAG` 并在 ADR 中记录
//! 了迁移计划,否则这是一个 regression,不要"就地更新向量"。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use vigil_audit::hash::{compute_event_hash, DOMAIN_TAG, GENESIS_PREV_HASH_BYTES};

/// TV1 - Genesis 事件:空对象 payload,固定时间戳,prev_hash 为空串(genesis)。
#[test]
fn tv1_genesis_empty_object() {
    let hash = compute_event_hash("", &json!({}), 1_700_000_000).unwrap();
    // 预计算值:在首版本算出,锁定作为契约。
    assert_eq!(
        hash, "737a49049deb3e2d1e30f17e26c3da34c88dc745ed3ef708882528b320507132",
        "TV1 hash 发生变化,请参见本文件头部说明"
    );
}

/// TV2 - 继 TV1 之后的第二条事件。payload 含中文 + 数字,key 按输入顺序是 "a","b"。
#[test]
fn tv2_after_tv1_with_unicode() {
    let prev = "737a49049deb3e2d1e30f17e26c3da34c88dc745ed3ef708882528b320507132";
    let hash = compute_event_hash(prev, &json!({"a": 1, "b": "测试"}), 1_700_000_001).unwrap();
    assert_eq!(
        hash, "bef1ccd4dfb6f8a585bed36c5ab24a81d4cec3950d503b2543ff804fd91d48ee",
        "TV2 hash 发生变化,请参见本文件头部说明"
    );
}

/// TV3 - JCS 稳定性:key 乱序的 payload 必须产出与 TV2 相同的 hash。
#[test]
fn tv3_jcs_stability_under_key_reorder() {
    let prev = "737a49049deb3e2d1e30f17e26c3da34c88dc745ed3ef708882528b320507132";
    let payload_reordered = json!({"b": "测试", "a": 1});
    let hash = compute_event_hash(prev, &payload_reordered, 1_700_000_001).unwrap();
    assert_eq!(
        hash, "bef1ccd4dfb6f8a585bed36c5ab24a81d4cec3950d503b2543ff804fd91d48ee",
        "JCS 应让 key 顺序不影响 hash"
    );
}

/// 元测试:domain tag 和 genesis 常量也作为契约组成。修改即为 breaking change。
#[test]
fn domain_constants_are_stable() {
    assert_eq!(DOMAIN_TAG, b"vigil.ledger.event.v1");
    assert_eq!(GENESIS_PREV_HASH_BYTES, [0u8; 32]);
}

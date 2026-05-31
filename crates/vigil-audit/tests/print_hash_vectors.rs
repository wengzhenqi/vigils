//! 一次性辅助:打印 TV1/TV2 的实际 hash,方便首版锁定向量。
//! 运行:`cargo test -p vigil-audit --test print_hash_vectors -- --nocapture --ignored`
//! 锁定后本文件可删除,或长期保留供后续 TV 扩展。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use vigil_audit::hash::compute_event_hash;

#[test]
#[ignore = "utility test for printing TV hash fixture values; run with `cargo test -p vigil-audit --test print_hash_vectors -- --ignored --nocapture`"]
fn print_tv_hashes() {
    let tv1 = compute_event_hash("", &json!({}), 1_700_000_000).unwrap();
    println!("TV1 = {tv1}");

    let tv2 = compute_event_hash(&tv1, &json!({"a": 1, "b": "测试"}), 1_700_000_001).unwrap();
    println!("TV2 = {tv2}");

    let tv3 = compute_event_hash(&tv1, &json!({"b": "测试", "a": 1}), 1_700_000_001).unwrap();
    println!("TV3 = {tv3}  (should == TV2)");
    assert_eq!(tv2, tv3);
}
